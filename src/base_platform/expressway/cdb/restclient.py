# Ignore "Line too long" warnings.              pylint: disable=C0301
# Ignore "Method could be a function" warnings  pylint: disable=R0201
# Ignore "Arguments number differs from X method" warnings pylint: disable=W0221
# Ignore "Access to a protected member of a client class" warnings pylint: disable=W0212
# Ignore "Exception doesn't inherit from standard "Exception" class" warnings pylint: disable=W0710

"""Manage REST API operations to the cluster database.
"""

# Standard library imports
import errno
import httplib
import logging
import socket
import urllib

# Local application/library specific imports
from base_platform.expressway.cdb import webrestclient

DEFAULT_CDB_ADDRESS = "127.0.0.1"
DEFAULT_CDB_PORT = 4370

DEV_LOGGER = logging.getLogger("developer.platform.clusterdatabase")

IGNORED_HTTP_ERRORS = (httplib.SERVICE_UNAVAILABLE, httplib.REQUEST_TIMEOUT)
def ignore_clusterdatabase_error(cdb_func):
    """\
    Decorator to catch errors with the cluster database and log them instead of
    triggering crash reports.
    This decorator should only be used for cases where a non-functional cluster
    database is not a fatal error e.g. updating minor status information.
    """
    def cdb_func_wrapper(*args, **kwds):
        """Wrapped cdb funtion"""
        try:
            return cdb_func(*args, **kwds)
        except socket.timeout as excpt:
            # Swallow timeouts which may occur during cluster reconciliation
            DEV_LOGGER.error('Detail="Cluster database failed" Context="%s" Exception="%r"' % (cdb_func.func_name, excpt))
        except socket.error as excpt:
            # Swallow connection refused errors indicating the cluster database
            # is not running
            if excpt.errno == errno.ECONNREFUSED:
                DEV_LOGGER.error('Detail="Cluster database not running" Context="%s" Exception="%r"' % (cdb_func.func_name, excpt))
            # Swallow connection reset be peer errors indicating the cluster database
            # has restarted or is overloaded
            elif excpt.errno == errno.ECONNRESET:
                DEV_LOGGER.error('Detail="Cluster database reset connection" Context="%s" Exception="%r"' % (cdb_func.func_name, excpt))
            else:
                raise excpt
        except webrestclient.HttpResponseError as excpt:
            # Swallow errors seen if the cluster database is restarted
            if excpt.error_code in IGNORED_HTTP_ERRORS:
                DEV_LOGGER.error('Detail="Cluster database not fully running" Context="%s" Exception="%r"' % (cdb_func.func_name, excpt))
            else:
                raise excpt

    return cdb_func_wrapper


class CDBDownException(socket.timeout, socket.error):
    '''
    Exception class to represent CDB server down errors.
    '''
    pass


BOOLEAN_SUBSTITUTION_VALUES = {True:'true', False:'false'}


def workaround_boolean_fixup(params):
    '''
    Fix for cluster database not accepting uppercase bool literals.
    '''
    for key, value in params.items():
        if isinstance(value, bool):
            params[key] = BOOLEAN_SUBSTITUTION_VALUES[value]


def make_url(table_path, filters=None, **query_args):
    """
    Easy way to create safely encoded URLs to use in requests to the cluster
    database.

    This function will return URLs that look like this::

        /configuration/adminaccount/name/fred?peer=192.168.0.42
        |------table_path---------| |filters| |--query_args---|

    :param table_path: the base path of the table.  It should start with a slash,
        but does not need to end with one.  Here the table_path is
        ``/configuration/adminaccount``.
    :param filters: a list of (field, value) tuples that are added on to the URL's
        path to select one or more rows in the cluster database.  Here the filters
        are ``[("name", "fred")]``.  These are URL encoded for you.
    :param query_args: additional keyword arguments passed to the make_url function.
        They are URL encoded and put into the URL's query string.  Here the
        query_args are ``peer="192.168.0.42"``.

    Examples:

    >>> make_url("/configuration/adminaccount", [("name", "fred")], peer="192.168.0.42")
    '/configuration/adminaccount/name/fred?peer=192.168.0.42'

    >>> make_url("/configuration/dns", peer="local")
    '/configuration/dns?peer=local'

    >>> make_url("/configuration/networkinterface", [("name", "LAN2")])
    '/configuration/networkinterface/name/LAN2'

    """

    if filters is None:
        filters = []

    path_components = [table_path.rstrip("/")]

    # Encode the components of each filter
    for field, value in filters:
        if isinstance(field, int):
            field = str(field)
        if isinstance(value, int):
            value = str(value)
        if isinstance(field, str):
            field = unicode(field, 'utf-8') # pylint: disable=R0204
        if isinstance(value, str):
            value = unicode(value, 'utf-8') # pylint: disable=R0204

        path_components += [
            urllib.quote_plus(field.encode("utf-8")),
            urllib.quote_plus(value.encode("utf-8")),
        ]

    url = "/".join(path_components)

    # Encode and add any query string elements
    if query_args:
        url += "?" + urllib.urlencode([
            (key.encode("utf-8"), value.encode("utf-8"))
            for key, value in query_args.items()
        ])

    return url


class RequestFilter(object):
    """
    Register your subclass of :class:`RequestFilter` with
    :func:`ClusterDatabaseRestClient.register_filter` to be able to alter the
    results of all queries in this process.
    """

    def filter_records(self, _path, records):
        """
        Called when a GET request is made with the path and the list of records
        that would have normally been returned.

        You should override this in your derived class.  The default
        implementation just returns the list of records unaltered.
        """

        return records

class ClusterDatabaseRestClient(webrestclient.RestClient):
    """Class to manage REST API operations to the cluster database.
    """

    # Ignore "ClusterDatabaseRestClient._send_request: Use super on an old style class" warnings.              pylint: disable=E1002

    # Increase the request timeout to 180. This value must be greater than the
    # erlang net_ticktime (we have the default value of 60 seconds) which is the
    # maximum time taken to detect an erlang node is down. We may see the
    # cluster database take up to 75ish seconds to respond to transactional
    # requests if the database has just become partitioned. Additionally,
    # operating on large datasets can take a lengthy amount of time.
    request_timeout = 180

    registered_filters = []

    def __init__(self,
                  rest_server_address=None,
                  rest_server_port=None,
                  url_prefix='',
                  auth_name=None,
                  auth_password=None,
                  use_tls=False):

        if rest_server_address is None:
            rest_server_address = DEFAULT_CDB_ADDRESS
        if rest_server_port is None:
            rest_server_port = DEFAULT_CDB_PORT

        webrestclient.RestClient.__init__(self, rest_server_address, rest_server_port, url_prefix, auth_name, auth_password, use_tls)

        self.default_headers['content-type'] = 'application/x-www-form-urlencoded'
        self.default_headers['accept'] = 'application/json'

    @classmethod
    def register_filter(cls, request_filter):
        """
        Registers a :class:`RequestFilter` instance that is used to modify the
        records returned by :func:`get_records` for all instances of
        :class:`ClusterDatabaseRestClient`.
        """
        if request_filter in cls.registered_filters:
            DEV_LOGGER.error('Detail="Cluster database filter register" Failure="Duplicate registration" '
                             'Value="%s"', request_filter)
        else:
            cls.registered_filters.append(request_filter)

    @classmethod
    def unregister_filter(cls, request_filter):
        """
        Unregisters a :class:`RequestFilter` previously registered with register_filter
        """
        try:
            cls.registered_filters.remove(request_filter)
        except ValueError as ex:
            DEV_LOGGER.error('Detail="Cluster database filter unregister" Failure="%s" '
                             'Value="%s"' % (ex, request_filter))

    def _prepare_request(self, url, method, data, headers):
        '''
        Decorator method. Invokes base method after having transformed
        boolean parameters to lowercased string representations as the
        CDB doesn't (yet) support the python string representations of booleans.
        '''

        if isinstance(data, dict):
            workaround_boolean_fixup(data)

        return super(ClusterDatabaseRestClient, self)._prepare_request(url, method, data, headers)

    def get_records(self, uri, **kw):
        """Performs a REST get on the specified uri and returns a flattened
        list of the records in the response.
        """

        cdb_down_exception = kw.get('cdb_down_exception')

        if cdb_down_exception is not None:
            # delete the key from kw so that it is not passed to the base class methods
            del kw['cdb_down_exception']
        else:
            cdb_down_exception = True

        try:
            response = super(ClusterDatabaseRestClient, self).send_get(uri, **kw)
        except socket.timeout as excpt:
            if cdb_down_exception:
                # Swallow timeouts which may occur during cluster reconciliation
                raise CDBDownException('Cluster database failed, Exception="%r"' % excpt)
            else:
                raise excpt
        except socket.error as excpt:
            # Swallow connection refused errors indicating the cluster database is not running
            if excpt.errno == errno.ECONNREFUSED and cdb_down_exception:
                raise CDBDownException('Cluster database not running, Exception="%r"' % excpt)
            # Swallow connection reset be peer errors indicating the cluster database
            # has restarted or is overloaded
            elif excpt.errno == errno.ECONNRESET and cdb_down_exception:
                raise CDBDownException('Cluster database reset connection, Exception="%r"' % excpt)
            else:
                # Raise the same exception to keep it backward compatible.
                raise excpt

        records = []
        for peer_result in response:
            records.extend(peer_result['records'])

        for request_filter in self.registered_filters:
            records = request_filter.filter_records(uri, records)

        return records

    def get_count(self, uri, cdb_down_exception=True):
        '''
        Counts the number of entries in the given table URL.
        Ignores any filtering or paging options.
        Undefined behaviour on sharded tables.
        uri should not contain a rfc3986[3.4] query component.
        '''
        parameters = {'sizeonly':'true'}
        response = self._get_count_response(uri, parameters, cdb_down_exception)
        count = response[0]['num_recs']
        return count

    def get_count_filtered(self, uri, local_peer_only=True, cdb_down_exception=True):
        '''
        Counts the number of entries in the given table URL.
        Honours filtering options. Ignores paging options.
        For sharded tables, the entry counts are summed.
        uri should not contain a rfc3986[3.4] query component.
        This function is not as fast as get_count(), but is considerably faster than
        len(get_records()).
        '''
        parameters = {'sizeonly':'norecs'}
        if local_peer_only:
            parameters.update({'peer':'local'})
        response = self._get_count_response(uri, parameters, cdb_down_exception)

        # NOTE: The following gives expected behaviour when response==[]
        count = 0
        for peer_result in response:
            count += peer_result['num_recs']

        return count

    def _get_count_response(self, uri, parameters, cdb_down_exception):
        '''
        Issues a CDB count request and handles exceptions.
        The response will be of the form:
          [ { "peer": <IP>, "num_recs": 123, "records": [] }, ... ]
        or
          []
        '''
        try:
            response = super(ClusterDatabaseRestClient, self).send_get(uri, parameters)
        except socket.timeout as excpt:
            if cdb_down_exception:
                # Swallow timeouts which may occur during cluster reconciliation
                raise CDBDownException('Cluster database failed, Exception="%r"' % excpt)
            else:
                raise excpt
        except socket.error as excpt:
            # Swallow connection refused errors indicating the cluster database is not running
            if excpt.errno == errno.ECONNREFUSED and cdb_down_exception:
                raise CDBDownException('Cluster database not running, Exception="%r"' % excpt)
            # Swallow connection reset be peer errors indicating the cluster database
            # has restarted or is overloaded
            elif excpt.errno == errno.ECONNRESET and cdb_down_exception:
                raise CDBDownException('Cluster database reset connection, Exception="%r"' % excpt)
            else:
                # Raise the same exception to keep it backward compatible.
                raise excpt

        return response

    # We look for the clusterpeer status rather than the root of the server
    def is_server_active(self):
        """Returns True if the cluster database is active."""
        # to avoid not found errors in the logs
        return super(ClusterDatabaseRestClient, self).is_server_active('/status/clusterpeer')


    def _submit_csv_from_file(self, method, url, csv_file, cdb_down_exception=True):
        '''
        Submit a CSV contained within a given file object.
        '''
        ret = None

        try:
            ret = self.send_request(method,
                                     url,
                                     csv_file.read(),
                                     {'content-type':'text/csv'})[1]
        except socket.timeout as excpt:
            if cdb_down_exception:
                # Swallow timeouts which may occur during cluster reconciliation
                raise CDBDownException('Cluster database failed, Exception="%r"' % excpt)
            else:
                raise excpt
        except socket.error as excpt:
            # Swallow connection refused errors indicating the cluster database is not running
            if excpt.errno == errno.ECONNREFUSED and cdb_down_exception:
                raise CDBDownException('Cluster database not running, Exception="%r"' % excpt)
            # Swallow connection reset be peer errors indicating the cluster database
            # has restarted or is overloaded
            elif excpt.errno == errno.ECONNRESET and cdb_down_exception:
                raise CDBDownException('Cluster database reset connection, Exception="%r"' % excpt)
            else:
                # Raise the same exception to keep it backward compatible.
                raise excpt

        return ret

    def delete_csv_from_file(self, url, csv_file, cdb_down_exception=True):
        '''
        DELETE the content of a given CSV file to the given url.
        Note that the CSV file should have a unique uuid field.
        '''
        self._submit_csv_from_file('DELETE', url, csv_file, cdb_down_exception=cdb_down_exception)

    def delete_csv_file(self, url, csv_file_name, cdb_down_exception=True):
        '''
        Open a CSV file and DELETE its content to the given url.
        '''

        with open(csv_file_name, "rb") as csv_file:
            return self.delete_csv_from_file(url, csv_file, cdb_down_exception=cdb_down_exception)


    def post_csv_from_file(self, url, csv_file, cdb_down_exception=True):
        '''
        POST the content of a given CSV file to the given url.
        '''
        self._submit_csv_from_file('POST', url, csv_file, cdb_down_exception=cdb_down_exception)


    def post_csv_file(self, url, csv_file_name, cdb_down_exception=True):
        '''
        Open a CSV file and POST its content to the given url.
        '''

        with open(csv_file_name, "rb") as csv_file:
            return self.post_csv_from_file(url, csv_file, cdb_down_exception=cdb_down_exception)

    def send_post(self, url, parameters=None, headers=None, object_hook=None, cdb_down_exception=True):
        """
        Overriding the RestClient send_post to capture the Cluster Database
        unavailability conditions and raise CDBDownException if requested.
        """
        try:
            resp = super(ClusterDatabaseRestClient, self).send_post(url,
                                                                    parameters=parameters,
                                                                    headers=headers,
                                                                    object_hook=object_hook)
        except socket.timeout as excpt:
            if cdb_down_exception:
                # Swallow timeouts which may occur during cluster reconciliation
                raise CDBDownException('Cluster database failed, Exception="%r"' % excpt)
            else:
                raise excpt
        except socket.error as excpt:
            # Swallow connection refused errors indicating the cluster database is not running
            if excpt.errno == errno.ECONNREFUSED and cdb_down_exception:
                raise CDBDownException('Cluster database not running, Exception="%r"' % excpt)
            # Swallow connection reset be peer errors indicating the cluster database
            # has restarted or is overloaded
            elif excpt.errno == errno.ECONNRESET and cdb_down_exception:
                raise CDBDownException('Cluster database reset connection, Exception="%r"' % excpt)
            else:
                # Raise the same exception to keep it backward compatible.
                raise excpt

        return resp

    def send_patch(self, url, parameters=None, headers=None, object_hook=None, cdb_down_exception=True):
        """
        Overriding the RestClient send_patch to capture the Cluster Database
        unavailability conditions and raise CDBDownException if requested.
        """
        try:
            resp = super(ClusterDatabaseRestClient, self).send_patch(url,
                                                                     parameters=parameters,
                                                                     headers=headers,
                                                                     object_hook=object_hook)
        except socket.timeout as excpt:
            if cdb_down_exception:
                # Swallow timeouts which may occur during cluster reconciliation
                raise CDBDownException('Cluster database failed, Exception="%r"' % excpt)
            else:
                raise excpt
        except socket.error as excpt:
            # Swallow connection refused errors indicating the cluster database is not running
            if excpt.errno == errno.ECONNREFUSED and cdb_down_exception:
                raise CDBDownException('Cluster database not running, Exception="%r"' % excpt)
            # Swallow connection reset be peer errors indicating the cluster database
            # has restarted or is overloaded
            elif excpt.errno == errno.ECONNRESET and cdb_down_exception:
                raise CDBDownException('Cluster database reset connection, Exception="%r"' % excpt)
            else:
                # Raise the same exception to keep it backward compatible.
                raise excpt

        return resp

    def send_get(self, url, parameters=None, headers=None, object_hook=None, cdb_down_exception=True):
        """
        Overriding the RestClient send_get to capture the Cluster Database
        unavailability conditions and raise CDBDownException if requested.
        """
        try:
            resp = super(ClusterDatabaseRestClient, self).send_get(url,
                                                                   parameters=parameters,
                                                                   headers=headers,
                                                                   object_hook=object_hook)
        except socket.timeout as excpt:
            if cdb_down_exception:
                # Swallow timeouts which may occur during cluster reconciliation
                raise CDBDownException('Cluster database failed, Exception="%r"' % excpt)
            else:
                raise excpt
        except socket.error as excpt:
            # Swallow connection refused errors indicating the cluster database is not running
            if excpt.errno == errno.ECONNREFUSED and cdb_down_exception:
                raise CDBDownException('Cluster database not running, Exception="%r"' % excpt)
            # Swallow connection reset be peer errors indicating the cluster database
            # has restarted or is overloaded
            elif excpt.errno == errno.ECONNRESET and cdb_down_exception:
                raise CDBDownException('Cluster database reset connection, Exception="%r"' % excpt)
            else:
                # Raise the same exception to keep it backward compatible.
                raise excpt

        return resp

    def send_delete(self, url, parameters=None, headers=None, object_hook=None, cdb_down_exception=True):
        """
        Overriding the RestClient send_delete to capture the Cluster Database
        unavailability conditions and raise CDBDownException if requested.
        """
        try:
            resp = super(ClusterDatabaseRestClient, self).send_delete(url,
                                                                      parameters=parameters,
                                                                      headers=headers,
                                                                      object_hook=object_hook)
        except socket.timeout as excpt:
            if cdb_down_exception:
                # Swallow timeouts which may occur during cluster reconciliation
                raise CDBDownException('Cluster database failed, Exception="%r"' % excpt)
            else:
                raise excpt
        except socket.error as excpt:
            # Swallow connection refused errors indicating the cluster database is not running
            if excpt.errno == errno.ECONNREFUSED and cdb_down_exception:
                raise CDBDownException('Cluster database not running, Exception="%r"' % excpt)
            # Swallow connection reset be peer errors indicating the cluster database
            # has restarted or is overloaded
            elif excpt.errno == errno.ECONNRESET and cdb_down_exception:
                raise CDBDownException('Cluster database reset connection, Exception="%r"' % excpt)
            else:
                # Raise the same exception to keep it backward compatible.
                raise excpt

        return resp

    def send_put(self, url, parameters=None, headers=None, object_hook=None, cdb_down_exception=True):
        """
        Overriding the RestClient send_delete to capture the Cluster Database
        unavailability conditions and raise CDBDownException if requested.
        """
        try:
            resp = super(ClusterDatabaseRestClient, self).send_put(url,
                                                                   parameters=parameters,
                                                                   headers=headers,
                                                                   object_hook=object_hook)
        except socket.timeout as excpt:
            if cdb_down_exception:
                # Swallow timeouts which may occur during cluster reconciliation
                raise CDBDownException('Cluster database failed, Exception="%r"' % excpt)
            else:
                raise excpt
        except socket.error as excpt:
            # Swallow connection refused errors indicating the cluster database is not running
            if excpt.errno == errno.ECONNREFUSED and cdb_down_exception:
                raise CDBDownException('Cluster database not running, Exception="%r"' % excpt)
            # Swallow connection reset be peer errors indicating the cluster database
            # has restarted or is overloaded
            elif excpt.errno == errno.ECONNRESET and cdb_down_exception:
                raise CDBDownException('Cluster database reset connection, Exception="%r"' % excpt)
            else:
                # Raise the same exception to keep it backward compatible.
                raise excpt

        return resp
