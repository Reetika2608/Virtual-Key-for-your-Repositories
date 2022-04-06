""" HTTP """
import threading
import json
from urllib import request as urllib_request
from urllib import error as urllib_error
import http.client
import os
import ssl
import socket
import uuid
import jsonschema

from managementconnector.platform.certnamematch import match_hostname, CertificateError
from managementconnector.config.databasehandler import DatabaseHandler
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()

try:
    import taacrypto
except ImportError:
    DEV_LOGGER.info('Detail="Running unittests? Could not import taacrypto, mocking it"')
    import sys
    import mock
    sys.modules['taacrypto'] = mock.Mock()
    import taacrypto  # pylint: disable=ungrouped-imports


class CertificateExceptionFusionCA(Exception):
    """ CertificateExceptionFusionCA """
    pass


class CertificateExceptionNameMatch(Exception):
    """ CertificateExceptionNameMatch """
    pass


class CertificateExceptionInvalidCert(Exception):
    """ CertificateExceptionInvalidCert """
    pass


class InvalidProtocolException(Exception):
    """InvalidProtocolException"""
    pass


class Http(object):
    """
    HTTP Class
    """
    _config = None
    _proxy = {}

    def __str__(self):
        return 'Management Connector HTTP Class'

    __repr__ = __str__

    @staticmethod
    def init(config):
        """Initialize Http"""
        Http._config = config
        Http._config.add_observer(Http.on_config_update)
        Http.install_urllib_opener()

    @staticmethod
    def download(url, path, silent=False):
        ''' store html in file '''
        page = None
        DEV_LOGGER.debug('Detail="_download: getting html for: path=%s, url=%s"' % (path, url))

        headers = dict()
        headers['Content-Type'] = 'application/json; charset=UTF-8'

        page = Http._http_request_wrapper(url, headers, None, 'GET', silent=silent, load_validate_json=False)

        file_size = int(page.getheader("Content-Length"))
        DEV_LOGGER.debug(
            'Detail="_download: html file size for: path=%s, url=%s: file size=%d"' % (path, url, file_size))
        chunk_size = 16 * 1024
        with open(path, 'wb') as file_to_write:
            while True:
                chunk = page.read(chunk_size)
                if not chunk:
                    break
                file_to_write.write(chunk)

        return file_size

    @staticmethod
    def on_config_update():
        """Config update"""
        Http.install_urllib_opener()

    @staticmethod
    def delete(url, headers, silent=False):
        """ delete """
        return Http._http_request_wrapper(url, headers, None, 'DELETE', silent=silent)

    @staticmethod
    def put(url, headers, data, silent=False, schema=None):
        """ put """
        return Http._http_request_wrapper(url, headers, data, 'PUT', silent=silent, schema=schema)

    @staticmethod
    def post(url, headers, data, silent=False, schema=None):
        """ post """
        return Http._http_request_wrapper(url, headers, data, 'POST', silent=silent, schema=schema)

    @staticmethod
    def get(url, headers, silent=False, schema=None):
        """ get """
        return Http._http_request_wrapper(url, headers, None, 'GET', silent=silent, schema=schema)

    @staticmethod
    def patch(url, headers, data, silent=False, schema=None):
        """ patch """
        return Http._http_request_wrapper(url, headers, data, 'PATCH', silent=silent, schema=schema)

    @staticmethod
    def create_tracking_id():
        """ create_tracking_id """
        tracking_id = str(uuid.uuid4())
        serial_number = Http._config.read(ManagementConnectorProperties.SERIAL_NUMBER)

        if (serial_number):
            tracking_id = tracking_id[:-len(serial_number)] + serial_number

        return "EXP_" + tracking_id

    @staticmethod
    def _http_request_wrapper(url, headers, data, request_type, silent=False, schema=None, load_validate_json=True):
        """ wrapper """
        headers['TrackingID'] = Http.create_tracking_id()

        agent_key = ManagementConnectorProperties.USER_AGENT

        if agent_key not in headers:
            headers[agent_key] = ManagementConnectorProperties.USER_AGENT_VALUE

        try:
            response = _http_request(url, headers, data, request_type, silent=silent, schema=schema,
                                     load_validate_json=load_validate_json)

        except Exception:
            Http.error_url = url
            raise

        return response

    @staticmethod
    def get_proxy():
        """Get proxy settings from database"""

        if Http._config is None:
            DEV_LOGGER.debug('Detail="Configuration file is not loaded"')
            return None

        proxy = {
            'address': Http._config.read(ManagementConnectorProperties.PROXY_ADDRESS),
            'port': Http._config.read(ManagementConnectorProperties.PROXY_PORT),
            'username': Http._config.read(ManagementConnectorProperties.PROXY_USERNAME),
            'enabled': Http._config.read(ManagementConnectorProperties.PROXY_ENABLED)
        }

        if proxy['address'] is None or proxy['port'] is None:
            DEV_LOGGER.debug('Detail="Proxy is not configured."')
            return None

        password = Http._config.read(ManagementConnectorProperties.PROXY_PASSWORD)
        if password:
            try:
                proxy['password'] = taacrypto.decrypt_with_system_key(password)
            except taacrypto.CryptoError:
                try:
                    DEV_LOGGER.debug('Detail="Http.get_proxy: Attempting to read password from CDB"')
                    database_handler = DatabaseHandler()
                    proxy_details = database_handler.read('https_proxy')
                    proxy['password'] = taacrypto.decrypt_with_system_key(proxy_details['password'])
                except taacrypto.CryptoError:
                    DEV_LOGGER.debug(
                        'Detail="Http.get_proxy: CDB password was not decrypted, defaulting to no password"')
                    proxy['password'] = None
        else:
            proxy['password'] = None

        return proxy

    @staticmethod
    def create_proxy_handler():
        """Create proxy handler"""
        # Due to the problems in the urllib2, we do not support digest authentication
        # at this time and only support basic authentication.
        # We also support no authentication mode, too.
        # Bug:
        # Note that currently employed basic auth method, by its nature, advertises
        # the username:password to the proxy server in clear text, unlike digest method.

        DEV_LOGGER.debug('Detail="Create proxy handler"')

        proxy = Http.get_proxy()

        if proxy is None:
            DEV_LOGGER.debug('Detail="There is no proxy configuration"')
            return None

        if proxy['enabled'] == 'false':
            DEV_LOGGER.debug('Detail="Proxy is disabled"')
            return urllib_request.ProxyHandler({})

        proxy_credentials = ""
        if proxy['username'] is not None and proxy['password'] is not None:
            proxy_credentials = proxy['username'] + ':' + proxy['password'] + '@'

        proxy_credentials = proxy_credentials + proxy['address'] + ':' + proxy['port']

        DEV_LOGGER.debug('Detail="Created proxy handler"')

        return urllib_request.ProxyHandler({'https': proxy_credentials})

    @staticmethod
    def install_urllib_opener():
        """Build and install urllib installer with necessary handlers"""
        DEV_LOGGER.debug('Detail="Install urllib opener"')

        if Http._proxy == Http.get_proxy():
            DEV_LOGGER.debug('Detail="No change in proxy config"')
            return
        else:
            DEV_LOGGER.debug('Detail="Proxy config has changed"')
            Http._proxy = dict(Http.get_proxy()) if Http.get_proxy() is not None else None

        handlers = []
        for handler in [Http.create_proxy_handler(), ValidHTTPSHandler]:
            if handler is not None:
                handlers.append(handler)

        DEV_LOGGER.debug('Detail="handlers: {}"'.format(handlers))
        opener = urllib_request.build_opener(*handlers)

        urllib_request.install_opener(opener)

        DEV_LOGGER.debug('Detail="Installed urllib opener"')
        return handlers


# -------------------------------------------------------------------------

THREAD_LOCK = threading.RLock()


def _validate_json_response(response, json_schema):
    """ Validates a json response according to the schema passed in"""

    if json_schema is not None:
        try:
            response = json.load(response)
            jsonschema.validate(response, json_schema)
        except ValueError as value_error:
            DEV_LOGGER.error('Detail="ValueError occured when loading json - raise exception"')
            raise value_error
        except (jsonschema.ValidationError, KeyError) as validation_exc:
            DEV_LOGGER.error('Detail="ValidationError when validating json - raise exception"')
            raise validation_exc
    else:
        DEV_LOGGER.info('Detail="_validate_json_response: Not validating - return response as-is"')

    return response


def _http_request(url, headers, data, request_type, silent=False, schema=None, load_validate_json=True):
    """ used for mock test intercept
        throws CertificateExceptionInvalidCert,
        CertificateExceptionFusionCA,
        CertificateExceptionNameMatch"""

    THREAD_LOCK.acquire()
    try:
        if not url.startswith('https'):
            unsupported_protocol_err = "Unexpected protocol, only https is supported, url: {}".format(url)
            DEV_LOGGER.error('Detail=' + unsupported_protocol_err)
            raise InvalidProtocolException({"message": "problem accessing tlp", "reason": unsupported_protocol_err})

        if data is not None and type(data) is not bytes:
            data = data.encode()

        if not (request_type == 'DELETE' or request_type == 'PUT' or request_type == 'POST' or request_type == 'PATCH'):
            request_type = 'GET'

        req = urllib_request.Request(url=url, data=data, headers=headers, method=request_type)  # nosec - must be https

        # Remove token as we don't want it written to logs

        auth_key = 'Authorization'
        headers_copy = headers.copy()

        if auth_key in headers:
            del headers_copy[auth_key]

        try:
            response = urllib_request.urlopen(req, timeout=ManagementConnectorProperties.HTTP_TIMEOUT)  # nosec - must be https
        except urllib_error.URLError as url_exception:
            if silent:
                DEV_LOGGER.error(
                    'Detail="RAW: _http_request silent: load_validate_json=%s, type=%s, url=%s, headers=%s"' %
                    (load_validate_json, request_type, url, headers_copy))
            else:
                DEV_LOGGER.error(
                    'Detail="RAW: _http_request: load_validate_json=%s, type=%s, url=%s, headers=%s, data=%s"' %
                    (load_validate_json, request_type, url, headers_copy, data))

            if str(url_exception).count("certificate") > 0:
                if ManagementConnectorProperties.is_fusion_certs_added():
                    # our CA, so we need to raise an appropriate alarm
                    raise CertificateExceptionFusionCA()
                else:
                    raise CertificateExceptionInvalidCert()
            else:
                raise
    finally:
        THREAD_LOCK.release()

    # post_json might need response.info().dict to supply the delete_url
    # delete_url = headers['location']

    if silent:
        DEV_LOGGER.info(
            'Detail="RAW: _http_request_response silent: type=%s, url=%s, load_validate_json=%s, headers=%s"' %
            (request_type, url, load_validate_json, headers_copy))
    else:
        DEV_LOGGER.info(
            'Detail="RAW: _http_request_response: type=%s, url=%s, load_validate_json=%s, headers=%s, data=%s, '
            'response = %s"' %
            (request_type, url, load_validate_json, headers_copy, data, response))

    if load_validate_json:
        response = _validate_json_response(response, schema)

    return response


class ValidHTTPSConnection(http.client.HTTPConnection):
    """ SSL communication
      uses ca file to validate cert.
      Will always validate and use strict checking (match_hostname)"""

    default_port = http.client.HTTPS_PORT

    def __init__(self, *args, **kwargs):
        """ Constructor """
        http.client.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        """ Connect to a host on a given (SSL) port. """
        # On first fuse there is a chance that this file doesn't exist so now we are checking
        # here every time.
        if os.path.exists(ManagementConnectorProperties.COMBINED_CA_FILE):
            ca_file = ManagementConnectorProperties.COMBINED_CA_FILE
        else:
            ca_file = ManagementConnectorProperties.DEFAULT_EXPRESSWAY_CA_FILE

        sock = socket.create_connection((self.host, self.port),
                                        ManagementConnectorProperties.HTTP_TIMEOUT,
                                        self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            actual_host = self._tunnel_host
        else:
            actual_host = self.host

        cipher_spec = "HIGH:!MD5:!3DES:!RC4:!ADH:!aNULL:!eNULL:@STRENGTH"

        # ssl.PROTOCOL_SSLv23: Selects the highest protocol version that both the client and server support.
        # Despite the name, this option can select TLS protocols as well as SSL

        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.set_ciphers(cipher_spec)
        ctx.load_verify_locations(cafile=ca_file)

        self.sock = ctx.wrap_socket(sock, server_hostname=actual_host)  # pylint: disable=R0204

        cert = self.sock.getpeercert()
        san = cert.get("subjectAltName", ())
        serial_number = cert.get("serialNumber", ())

        if san:
            san = san[0]
        else:
            san = "Not found"

        DEV_LOGGER.debug('Detail="Certificate information: subjectAltName: %s serial_number: %s"'
                         % (san, serial_number))

        try:
            match_hostname(cert, actual_host)
        except CertificateError:
            if ManagementConnectorProperties.is_fusion_certs_added():
                raise CertificateExceptionFusionCA()  # our CA, so we need to raise an appropriate alarm
            else:
                raise CertificateExceptionNameMatch()


class ValidHTTPSHandler(urllib_request.HTTPSHandler):
    """ ValidHTTPSHandler """

    def https_open(self, req):
        """ https_open """
        return self.do_open(ValidHTTPSConnection, req)
