# Standard library imports

# Local application / library specific imports
from ni.cafedynamic.cafedatabase import CAFEDatabase
from ni.managementconnector.config.cafeproperties import CAFEProperties
from ni.utils.web.restclient import HttpResponseError


DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class MockCAFEDatabase(CAFEDatabase):
    """
        Mocking out pieces of CAFEDatabase
    """
    def __init__(self):
        """
            MockCAFEDatabase initialiser
        """
        self.internal_ipv4_address = '10.53.50.187'
        self.internal_ipv6_address = '2001:420:4041:2006:250:56ff:fe00:1017'
        self.internal_mode = 'Both'

    # -------------------------------------------------------------------------

    def get_cdb_records(self, cdb_url):
        """
            Override the CAFEDatabase get_cdb_records() method
            and mock the returned records from the database.
        """
        DEV_LOGGER.debug('Detail="Mock querying CDB for records" '
                         'Table="%s"' % cdb_url)

        records = None

        if cdb_url == '/configuration/network/?peer=local':
            records = \
                [
                    {
                        'uuid': '',
                        'mode': self.internal_mode,
                        'ipv4_gateway': '',
                        'ipv6_gateway': '',
                        'ephemeral_port_range_start': 32768,
                        'ephemeral_port_range_end': 61000,
                        'rfc4821_mode': 'Disabled',
                        'external_interface_name': 'LAN1'
                    }
                ]
        elif cdb_url == '/configuration/networkinterface/enabled/true/?peer=local':
            records = \
                [
                    {
                        'uuid': '2ea7c154-f734-4c3e-8ed8-ff60f74b3033',
                        'name': 'LAN1',
                        'device': 'eth0',
                        'enabled': 'true',
                        'speed': 'Auto',
                        'ipv4_address': self.internal_ipv4_address,
                        'ipv4_subnet_mask': '255.255.255.0',
                        'ipv6_address': self.internal_ipv6_address,
                        'mtu_size': 1500
                    }
                ]
        elif cdb_url == '/configuration/edgeconfigprovisioning/cucm':
            records = \
                [
                    {
                        'uuid': '35ad4920-0d04-4ba1-9b54-7193e40e9370',
                        'publisher': '10.53.60.12',
                        'name': 'gwydlvm634.cucm.donalync-dev.com',
                        'role': 'Subscriber',
                        'cmname': 'CM_gwydlvm634.cucm.donalync-dev.com',
                        'address': 'gwydlvm634.cucm.donalync-dev.com',
                        'common_name': '',
                        'tls_address': '',
                        'sip_tcp_port': 5060,
                        'sip_tls_port': 0,
                        'provisioning_port': 8443,
                        'provisioning_protocol': 'http',
                        'tls_verify': 'false',
                        'version': '10.5.1',
                        'axl_username': 'admin',
                        'axl_password': '{cipher}TowDRgDX/f/eNLxmTrDiD9fOtRfhQ85ttRSZOhIKWUc=',
                        'tcp_zone': 'CEtcp-gwydlvm634.cucm.donalync-dev.com',
                        'tls_zone': '',
                        'ipv4_addresses': [],
                        'ipv6_addresses': [],
                        'uds_servers': ['gwydlvm480.cucm.donalync-dev.com', 'gwydlvm634.cucm.donalync-dev.com'],
                        'deployment_id': 1
                    },
                    {
                        'uuid': 'd58d616c-d8e7-4f1f-8cca-f413ffbd00cf',
                        'publisher': '10.53.60.12',
                        'name': 'gwydlvm480.cucm.donalync-dev.com',
                        'role': 'Publisher',
                        'cmname': 'CM_gwydlvm480',
                        'address': 'gwydlvm480.cucm.donalync-dev.com',
                        'common_name': '',
                        'tls_address': '',
                        'sip_tcp_port': 5060,
                        'sip_tls_port': 0,
                        'provisioning_port': 8443,
                        'provisioning_protocol': 'http',
                        'tls_verify': 'false',
                        'version': '10.5.1',
                        'axl_username': 'admin',
                        'axl_password': '{cipher}EtUo9aevUCewc9qvLWpszqrJcpXp2IJanUObQ8jfdV0=',
                        'tcp_zone': 'CEtcp-gwydlvm480.cucm.donalync-dev.com',
                        'tls_zone': '',
                        'ipv4_addresses': [],
                        'ipv6_addresses': [],
                        'uds_servers': ['gwydlvm480.cucm.donalync-dev.com', 'gwydlvm634.cucm.donalync-dev.com'],
                        'deployment_id': 1
                    }
                ]
        # can be '/configuration/sipdomain' or a particular entry e.g '/configuration/sipdomain/name/test-domain3.com'
        elif cdb_url.startswith('/configuration/sipdomain'):
            records = \
                [
                    {
                        'uuid': '7a66f1e6-3e5f-431f-be8d-8f6bb66e564f',
                        'index': 1,
                        'name': 'test-domain1.com',
                        'sip': 'true',
                        'edgesip': 'true',
                        'edgexmpp': 'false',
                        'xmppfederation': 'false',
                        'edgejabberc': 'false',
                        'authzone': '',
                        'deployment_id': 1,
                        'idp_table_uuid': ''
                    },
                    {
                        'uuid': 'a68bb2eb-bfcd-4879-9921-13da1451ef20',
                        'index': 2,
                        'name': 'test-domain2.com',
                        'sip': 'true',
                        'edgesip': 'false',
                        'edgexmpp': 'true',
                        'xmppfederation': 'false',
                        'edgejabberc': 'false',
                        'authzone': '',
                        'deployment_id': 1,
                        'idp_table_uuid': ''
                    },
                    {
                        'uuid': '18ac7d65-d926-469e-be5e-fa6682433b2b',
                        'index': 3,
                        'name': 'test-domain3.com',
                        'sip': 'true',
                        'edgesip': 'false',
                        'edgexmpp': 'false',
                        'xmppfederation': 'true',
                        'edgejabberc': 'false',
                        'authzone': '',
                        'deployment_id': 1,
                        'idp_table_uuid': ''
                    },
                    {
                        'uuid': '5400a13f-9e1b-44e2-b749-83668f5ae60a',
                        'index': 4,
                        'name': 'test-domain4.com',
                        'sip': 'true',
                        'edgesip': 'true',
                        'edgexmpp': 'true',
                        'xmppfederation': 'true',
                        'edgejabberc': 'false',
                        'authzone': '',
                        'deployment_id': 1,
                        'idp_table_uuid': ''
                    },
                    {
                        'uuid': '9b7a70e6-afcb-4eac-b242-8022a1cdb54f',
                        'index': 5,
                        'name': 'test-domain5.com',
                        'sip': 'true',
                        'edgesip': 'false',
                        'edgexmpp': 'false',
                        'xmppfederation': 'false',
                        'edgejabberc': 'false',
                        'authzone': '',
                        'deployment_id': 1,
                        'idp_table_uuid': ''
                    }
                ]
            if cdb_url == '/configuration/sipdomain':
                # return all domain records
                pass
            else:
                name = cdb_url.split('/configuration/sipdomain/name/', 1)[1]
                # return only records that have a matching name
                records = [record for record in records if record['name'] == name]
        else:
            raise HttpResponseError('Invalid CDB URL: "%s"' % cdb_url)

        return records

    # -------------------------------------------------------------------------
