"""
    Class to manage all REST API operations for components
"""

# Standard library imports

# Local application / library specific imports
from ni.managementconnector.config.cafeproperties import CAFEProperties
from ni.clusterdatabase.restclient import ClusterDatabaseRestClient

DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class CAFEDatabase(ClusterDatabaseRestClient):
    """
        Class to manage all REST API operations for components
    """

    def __init__(self):
        """
            CAFE Database initialiser
        """
        DEV_LOGGER.debug('Detail="Initialising CAFE Database"')
        ClusterDatabaseRestClient.__init__(self)

    # -------------------------------------------------------------------------

    def get_cdb_records(self, cdb_url):
        """
            Gets the deployment records from the database
        """
        DEV_LOGGER.debug('Detail="Querying CDB for records" '
                         'Table="%s"' % cdb_url)
        return self.get_records(cdb_url)

    # -------------------------------------------------------------------------

    def get_internal_network_address(self, ip_version='ipv4'):
        """
            Method to get internal ipv6/ipv6 network address
        """
        convenience = {'data': None, 'cdb_tables': None}
        address = ''
        net, convenience['cdb_tables'] = self._get_internal_network_config()

        if ip_version == 'ipv4':
            if net['mode'] == 'IPv4' or net['mode'] == 'Both':
                if net['ipv4_address'] and not net['ipv4_address'] == '127.0.0.1':
                    address = net['ipv4_address']
        elif ip_version == 'ipv6':
            if net['mode'] == 'IPv6' or net['mode'] == 'Both':
                if net['ipv6_address'] and not net['ipv6_address'] == '::1/128':
                    address = net['ipv6_address']
        else:
            DEV_LOGGER.error('Detail="Programmer error. IP Protocol mode should be ipv4 or ipv6." ')

        convenience['data'] = address
        return convenience

    # -------------------------------------------------------------------------

    def _get_internal_network_config(self):
        """
            Gets internal network interface. If only one interface, then returns this
        """
        ext_interface_info = self.get_cdb_records('/configuration/network/?peer=local')[0]
        records = self.get_cdb_records('/configuration/networkinterface/enabled/true/?peer=local')
        if len(records) > 0:
            internal_int = records[0]
        else:
            internal_int = None
        for record in records:
            DEV_LOGGER.debug('Detail="Network Interface" '
                             'record[enabled]="%s" '
                             'record[name]="%s" '
                             'ext_interface_info[external_interface_name]="%s"',
                             record['enabled'], record['name'], ext_interface_info['external_interface_name'])
            if record['name'] != ext_interface_info['external_interface_name']:
                DEV_LOGGER.debug('Detail="set internal_int (match) to record[name]=%s"', record['name'])
                internal_int = record
                break
        DEV_LOGGER.debug('Detail="return internal_int[name]=%s"', internal_int['name'])
        if internal_int:
            internal_int['mode'] = ext_interface_info['mode']

        return internal_int, ['/configuration/network', '/configuration/networkinterface']


# =============================================================================
