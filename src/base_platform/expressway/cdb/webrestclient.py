# Ignore "Line too long" warnings.  pylint: disable=C0301
# Ignore "RestClient.__init__: Instance of" warnings  pylint: disable=E1103

"""
This module contains tools for accessing a generic REST API.

If you want to access the cluster database,
:class:`~base_platform.expressway.cdb.restclient.ClusterDatabaseRestClient` is much more
convenient.
"""

# Library modules
import json
import socket
import threading
import time
from urllib import parse as urllib_parse
import logging
import re
import base64
# This import is done on the fly within httplib2.
# Unfortunately, the filesystem on target is locked during execution to prevent the import to
# succeed. As a consequence, we "prefetch" the necessary lib.
# Ignore "Unused import" warnings.  pylint: disable=W0611
import email.message
import httplib2
from base_platform.expressway import httplib2ssl
from base_platform.expressway.taacrypto.taacrypto import decrypt_with_system_key
from base_platform.expressway.taacrypto.taacrypto import TaaCryptoException, SystemCallException

DEV_LOGGER = logging.getLogger("developer.web.restclient")


class HttpResponseError(Exception):
    """
    Exception class to represent a HTTP error response.
    """

    def __init__(self, error_code, error_reason, content, method, url, body):
        Exception.__init__(self)
        self.error_code = error_code
        self.error_reason = error_reason
        self.content = content
        self.method = method
        self.url = url
        self.body = body

    def __str__(self):
        return "".join(["HTTP Response error from ", self.method, " on ", self.url, "\nBody:", self.body, "\nAnswer: (",
                        str(self.error_code), ') ', self.error_reason, "\n"])


class RestClientException(Exception):
    """
    Exception class to represent a rest client usage errors.
    """
    pass


class CryptoBasicAuthentication(httplib2.Authentication):
    """
        Replacement for httplib2's BasicAuthentication class that
        handles decryption of the password prior to use.
    """

    def __init__(self,
                 credentials,
                 host,
                 request_uri,
                 headers,
                 response,
                 content,
                 http):

        httplib2.Authentication.__init__(self,
                                         credentials,
                                         host,
                                         request_uri,
                                         headers,
                                         response,
                                         content,
                                         http)

    # --------------------------------------------------------------------------

    def request(self, _method, _request_uri, headers, _content):
        """
            Modify the request headers to add the appropriate Authorization
            header

            Decrypt password as late as possible
        """
        (user, encrypted_password) = self.credentials

        try:
            b64 = base64.b64encode("%s:%s" % (user, decrypt_with_system_key(encrypted_password))).strip()

            headers['authorization'] = 'Basic %s' % (b64,)

        except (TaaCryptoException, SystemCallException) as ex:
            DEV_LOGGER.warning('Detail="Problem decrypting password" ' \
                               'Status="%r"' % (ex.error,))
            raise


class RestClient(object):
    """
    A HTTP client for accessing generic REST APIs.
    """

    _supported_receive_types = ['application/json',
                                'text/plain',
                                'text/html',
                                'text/csv']

    _supported_send_types = ['text/plain',
                             'text/csv',
                             'application/x-www-form-urlencoded',
                             'application/json']

    FULL_URI = re.compile("https?://[a-zA-Z0-9_.]+")

    wait_interval = 5
    request_timeout = 180

    def __init__(self,
                 rest_server_address,
                 rest_server_port,
                 url_prefix='',
                 auth_name=None,
                 auth_password=None,
                 use_tls=False,
                 cert_validation=False,
                 hostname_validation=False,
                 ca_chain_file='/tandberg/persistent/certs/ca.pem'):
        self.use_tls = use_tls
        if self.use_tls:
            DEV_LOGGER.debug('Detail="Using TLS for connection"')
            self.http = httplib2ssl.HttpsWithValidation(ca_chain_file,
                                                        cert_validation,
                                                        hostname_validation,
                                                        timeout=self.request_timeout)
        else:
            DEV_LOGGER.debug('Detail="NOT using TLS for connection"')
            self.http = httplib2.Http(timeout=self.request_timeout)

        self.rest_server_address = rest_server_address
        self.rest_server_port = rest_server_port
        self.connection_lock = threading.Lock()

        if auth_name is not None and auth_password is not None:
            DEV_LOGGER.debug('Detail="Adding credentials" Username="%s"' % \
                             (auth_name,))

            # auth_password is encrypted and we don't want the plaintext held
            #   by the HTTP library so let's use our own authentication handler
            httplib2.AUTH_SCHEME_CLASSES['basic'] = CryptoBasicAuthentication
            self.http.add_credentials(auth_name, auth_password)

        self._url_prefix = url_prefix

        self.default_headers = {'accept': ', '.join(self._supported_receive_types)}

    @staticmethod
    def _lowercase_header_names(headers):
        """
        Set header names to lowercase as it seems that httplib2 requires it.
        """
        return dict((key.lower(), value) for key, value in headers.items())

    def set_default_headers(self, headers_dict):
        """
        Set the default HTTP headers for all subsequent requests, unless overriden.

        :param headers_dict: a dictionary of headers and values.
        """
        self.default_headers = {}
        self.add_default_headers(headers_dict)

    def add_default_headers(self, headers_dict):
        """
        Add a set of default headers to the current set of default HTTP headers, for all subsequent requests.

        :param headers_dict: a dictionary of headers and values.
        """
        self.default_headers.update(self._lowercase_header_names(headers_dict))

    @staticmethod
    def _encode_unicode_post_data(data):
        """
        data can either be a dictionary or a list of (key, value) tuples.
        Returns a copy of the dictionary where any unicode-typed values have
        been encoded as utf-8 strings.
        """

        def maybe_encode(thing):
            """
            If thing is a unicode string, encodes it, otherwise returns it
            unmodified.
            """

            if isinstance(thing, str):
                return thing.encode("utf-8")
            return thing

        if isinstance(data, dict):
            return dict([(k, maybe_encode(v)) for k, v in data.items()])
        elif isinstance(data, (list, tuple)):
            return [(k, maybe_encode(v)) for k, v in data]

        return data

    def _prepare_request(self, url, method, data, headers):
        """
        Prepare the necessary data the http request.

        :param url: URL to be used. Should not include a rfc3986[3.4] query component.
        :param data: None, or dict of KVs to form a rfc3986[3.4] query component.
        The preferred way to form a query component is with 'data'; if 'data' is non-null
        and 'url' already contains a query component then behaviour is undefined.

        Return the necessary (url, method, body, headers) tuple to proceed with the request.
        """

        if not self.FULL_URI.match(url):
            url_pieces = {
                'protocol': 'https' if self.use_tls else 'http',
                'address': self.rest_server_address,
                'port': str(self.rest_server_port),
                'prefix': self._url_prefix,
                'url': url
            }

            url = "%(protocol)s://%(address)s:%(port)s%(prefix)s%(url)s" % \
                  url_pieces

        if not headers:
            headers = self.default_headers
        else:
            defaulted_headers = dict(self.default_headers)
            defaulted_headers.update(self._lowercase_header_names(headers))
            headers = defaulted_headers

        body = None

        if data is not None:
            if 'content-type' not in headers:
                headers['content-type'] = 'application/x-www-form-urlencoded'

            if headers['content-type'] not in self._supported_send_types:
                raise RestClientException(
                    "Unsupported content-type when preparing HTTP request : " + headers['content-type'])
            else:
                if headers['content-type'] == 'application/x-www-form-urlencoded':
                    # urllib_parse.urlencode doesn't cope with unicode strings so we
                    # have to encode everything as utf-8.
                    data = self._encode_unicode_post_data(data)

                    urlencoded = urllib_parse.urlencode(data)

                    if method == 'GET':
                        # https://bugs.rd.tandberg.com/show_bug.cgi?id=115257
                        # Apparently, the common consensus is that urlencoded data should be sent
                        # in the url for GET methods.
                        # Note that is the size of the urlencoded data gets big, I've noticed that
                        # 413 (too large) responses were given back (I therefore dropped the idea of
                        # making it a generic behaviour across methods, as most POST, PUT will break)
                        url = url + '?' + urlencoded
                        del headers['content-type']
                    else:
                        body = urlencoded
                elif headers['content-type'] == 'application/json':
                    body = json.dumps(data)
                else:
                    if data is not None:
                        body = str(data)

        return url, method, body, headers

    def _process_response(self, response, response_data, object_hook=None):
        """
        Process the HTTP response:
         - format the returned data depending on the content-type.
         - raise an exception of the status
        """

        transformed_data = None

        if response_data:
            if 'content-type' in response:
                if response['content-type'] not in self._supported_receive_types:
                    raise RestClientException(
                        "Unsupported content-type when processing HTTP response : " + response['content-type'])
                else:
                    if response['content-type'] == 'application/json':
                        transformed_data = json.loads(response_data, object_hook=object_hook)
                    elif response['content-type'] in ('text/plain',
                                                      'text/html',
                                                      'text/csv'):
                        transformed_data = response_data
            else:
                transformed_data = response_data

        return response, transformed_data

    def send_request(self, method, url, data=None, headers=None, object_hook=None, exception_on_failure=True):
        """
        Perform an http request to the REST API.
        :param url: URL to be used. Should not include a rfc3986[3.4] query component.
        :param data: None, or dict of KVs to form a rfc3986[3.4] query component.
        The preferred way to form a query component is with 'data'; if 'data' is non-null
        and 'url' already contains a query component then behaviour is undefined.
        """

        url, method, body, headers = self._prepare_request(url, method, data, headers)

        with self.connection_lock:
            response, response_data = self.http_request(url, method, body, headers)

        # Generate an exception in the case where the response is an error
        if exception_on_failure and (response.status < 200 or response.status > 299):
            raise HttpResponseError(response.status, response.reason, response_data, method, url, str(body))

        return self._process_response(response, response_data.decode(), object_hook)

    def http_request(self, url, method, body, headers):
        """Perform an http request to the REST API, retrying on 503."""
        start_time = time.time()
        while True:
            try:
                response, response_data = self.http.request(url, method, body, headers)
                if response.status == 503:
                    if self.request_timeout <= (time.time() - start_time):
                        response.status = 408
                        break
                else:
                    break
            except BrokenPipeError:
                DEV_LOGGER.debug(f"Retrying {url} on failure - BrokenPipeError")
            time.sleep(.5)
        return response, response_data

    def send_post(self, url, parameters=None, headers=None, object_hook=None):
        """Perform an http POST request to the REST API."""
        return self.send_request('POST', url, parameters, headers, object_hook)[1]

    def send_patch(self, url, parameters=None, headers=None, object_hook=None):
        """
        Perform an http PATCH request to the REST API - differs from POST in that
        non-existent entries are *not* created. (see RFC 5789)
        """
        return self.send_request('PATCH', url, parameters, headers, object_hook)[1]

    def send_get(self, url, parameters=None, headers=None, object_hook=None):
        """
        Perform an http GET request to the REST API.

        :param url: URL to be used. Should not include a rfc3986[3.4] query component.
        :param parameters: None, or dict of KVs to form a rfc3986[3.4] query component.
        The preferred way to form a query component is with 'parameters'; if 'parameters' is non-null
        and 'url' already contains a query component then behaviour is undefined.

        Returns a decoded response.
        """
        return self.send_request('GET', url, parameters, headers, object_hook)[1]

    def send_delete(self, url, parameters=None, headers=None, object_hook=None):
        """Perform an http DELETE request to the REST API."""
        return self.send_request('DELETE', url, parameters, headers, object_hook)[1]

    def send_put(self, url, parameters=None, headers=None, object_hook=None):
        """Perform an http PUT request to the REST API."""
        return self.send_request('PUT', url, parameters, headers, object_hook)[1]

    def is_server_active(self, url='/'):
        """Returns True if the REST server is active."""
        try:
            self.send_request('GET', url, exception_on_failure=False)
            return True
        except socket.error:
            return False

    def wait_for_active_server(self, max_wait_time=30):
        """Wait until the REST server is active. Returns True if the
        REST server became active, False if the wait timed out"""
        time_waited = 0
        while not self.is_server_active():
            if time_waited >= max_wait_time:
                return False
            time.sleep(self.wait_interval)
            time_waited += self.wait_interval

        return True
