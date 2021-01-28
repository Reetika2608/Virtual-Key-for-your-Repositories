""" Atlas Test """

import logging
import json
import sys
import unittest
import mock
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from pyfakefs import fake_filesystem_unittest
from productxml import PRODUCT_XML_CONTENTS
from managementconnector.cloud.atlas import Atlas
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.platform import http

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()

EMPTY_CONFIG = False
HEADERS = {'Content-Type': 'application/json'}
PROVISIONING = {"connectors": "some_connectors", "heartbeat": 30}


def get_version(name):
    return 'test_version'


def _http_request(url, headers, data, request_type, silent=False, schema=None, load_validate_json=True):
    ''' used for mock test intercept'''
    DEV_LOGGER.info("Mocked Post:" )

    rtn =  json.loads(data)
    rtn['provisioning'] = PROVISIONING

    return rtn


def config_read(path):
    """ config class mock """
    DEV_LOGGER.debug("ConfigMock: read path %s" % path)

    if path == ManagementConnectorProperties.ATLAS_URL_PREFIX:
        return "mock.ladidadi.org"
    elif path == ManagementConnectorProperties.REGISTER_URL:
        return "/v1/fusion_reg_url"
    elif path == ManagementConnectorProperties.TARGET_TYPE:
        return "c_ccucmgmt"
    elif path == ManagementConnectorProperties.SERIAL_NUMBER:
        return "serialnumber"
    elif path == ManagementConnectorProperties.IPV4_ADDRESS:
        return "ipv4_address"
    elif path == ManagementConnectorProperties.IPV6_ADDRESS:
        return "ipv6_address"
    elif path == ManagementConnectorProperties.CLUSTER_ID:
        return "guid"
    elif path == ManagementConnectorProperties.CLUSTER_NAME:
        return "clustername"
    elif path == ManagementConnectorProperties.HOSTNAME:
        return "hostname"
    elif path == ManagementConnectorProperties.DOMAINNAME:
        return "domain.com"
    elif path == ManagementConnectorProperties.ALARMS_RAISED:
        rtn_str = '[{ "uuid" : "cbbf0813-09cb-4e23-9182-f3996d24cc9e", "id" : "60051", ' \
                '"first_reported" :  "1417011612", "last_reported" :  "1417011811", "severity" :  "error", ' \
                '"parameters":  [500, "https://hercules.hitest.huron-dev.com/v1/connectors"] }]'
        return json.loads(rtn_str)
    else:
        DEV_LOGGER.debug("ConfigMock: Unexpected path passed: %s" % path)


class AtlasTest(fake_filesystem_unittest.TestCase):
    """ Management Connector Atlas Test Class """

    def setUp(self):
        """ Management Connector Atlas setUp """
        # Create an Atlas Class
        self.setUpPyfakefs()
        self.fs.create_file('/info/product_info.xml', contents=PRODUCT_XML_CONTENTS)
        _config = mock.MagicMock()
        _config.read.side_effect = config_read
        self.atlas = Atlas(_config)
        http.Http.init(_config)

    def test_parse_mc_config(self):
        """ Test Parse MC Config"""

        DEV_LOGGER.info('test_parse_mc_config: start')
        connectors = {'connectors': [{'connector_type': 'c_ccucmgmt', 'version': '12.7.1-1.0.322', 'display_name' : 'ccuc_telemetry', 'packages': [{'tlp_url': 'https://sqfusion-jenkins.cisco.com/ccuc-connector/ccuc-connector_8.5-1.0.322.tlp'}], 'enabled': False}]}
        response_config, response_services = self.atlas.parse_mc_config(connectors)

        self.assertTrue(len(response_config) == 1)
        self.assertTrue(response_config[0]['name'] == "c_mgmt")
        self.assertTrue(response_config[0]['version'] == "12.7.1-1.0.322")
        self.assertTrue(response_config[0]['display_name'] == "ccuc_telemetry")

        self.assertTrue(len(response_services) == 1)
        self.assertTrue(response_services[0]['name'] == "c_mgmt")

        # No Packages
        connectors = {'connectors': [{'connector_type': 'calendar-connector', 'version' : '8.5-1.0.322', 'display_name' : 'expressway_exchange', 'packages': [], 'enabled': False}]}
        response_config, response_services = self.atlas.parse_mc_config(connectors)

        self.assertTrue(len(response_config) == 1)

    def test_parse_dependency_config(self):
        """ Test Parse Dependency Config"""

        DEV_LOGGER.info('test_parse_dependency_config: start')
        connectors = {"dependencies":[{"tlpUrl": "ftp://10.53.63.198/Edge/Blend/java_8.5-1.0.322.tlp",
                                       "version": "8.5-1.0.322", "dependencyType": "java"}]}
        response_config = self.atlas.parse_dependency_config(connectors)

        self.assertTrue(len(response_config) == 1)
        self.assertTrue(response_config[0]['name'] == "java")
        self.assertTrue(response_config[0]['version'] == "8.5-1.0.322")

        # Some negative tests
        connectors = {"dependencies":[]}
        response_config = self.atlas.parse_dependency_config(connectors)
        self.assertTrue(len(response_config) == 0)

        connectors = {}
        response_config = self.atlas.parse_dependency_config(connectors)
        self.assertTrue(len(response_config) == 0)

    @mock.patch('managementconnector.cloud.atlas.System')
    @mock.patch('managementconnector.cloud.atlas.jsonhandler.read_json_file')
    @mock.patch('managementconnector.service.service.Service')
    @mock.patch('managementconnector.cloud.atlas.ServiceUtils.get_version', side_effect=get_version)
    def test_register_connector(self, mock_version, mock_service, mock_json, mock_system):
        """ Test register_connector"""
        _orig_http_request = http._http_request
        http._http_request = _http_request

        DEV_LOGGER.info('test_register_device: start')

        mock_json.return_value= {"provisioning":{"maintenanceMode":"off"}}
        mock_service.get_composed_status.return_value = 'installed'
        mock_service.has_alarm.return_value = True
        mock_service.get_name.return_value = 'c_mgmt'
        mock_system.get_system_mem.return_value = {'total_gb': '0.1', 'percent': '8.0', 'total_kb': 128266.3896484375}
        mock_system.get_system_disk.return_value = {'total_gb': '0.1', 'percent': '8.0', 'total_kb': 128266.3896484375}
        mock_system.get_platform_type.return_value = "virtual"
        mock_system.get_cpu_cores.return_value = "2"

        alarm_list_str = '[{ "uuid" : "cbbf0813-09cb-4e23-9182-f3996d24cc9e", "id" : "60051", ' \
                    '"first_reported" :  "1417011612", "last_reported" :  "1417011811", "severity" :  "error", ' \
                    '"parameters":  [500, "https://hercules.hitest.huron-dev.com/v1/connectors"], ' \
                    '"solution_links" : "" }]'

        DEV_LOGGER.info('test_post_status: alarm_list_str %s' %(alarm_list_str))

        mock_service.get_alarms.return_value = json.loads(alarm_list_str)

        json_response =  self.atlas.register_connector(HEADERS, mock_service)

        DEV_LOGGER.info('test_post_status: RESPONSE %s' %(json_response))

        self.assertTrue(json_response['version'] == "test_version")
        self.assertTrue(json_response['id'] == "c_ccucmgmt@serialnumber")
        self.assertTrue(json_response['host_name'] == "hostname.domain.com")
        self.assertTrue(json_response['cluster_id'] == "guid")
        self.assertTrue(json_response['status']['state'] == "installed")
        self.assertTrue(len(json_response['status']['alarms']) == 1)
        self.assertTrue(json_response['status']['connectorStatus'] == {})

        # host hardware
        self.assertEquals(json_response['hostHardware']['cpus'], "2")
        self.assertEquals(json_response['hostHardware']['totalMemory'], "131344384")
        self.assertEquals(json_response['hostHardware']['totalDisk'], "131344384")
        self.assertEquals(json_response['hostHardware']['hostType'], "virtual")

        self.assertTrue(json_response['provisioning'] == PROVISIONING)

        http._http_request = _orig_http_request


        DEV_LOGGER.info('test_register_device: end')


    @mock.patch('managementconnector.cloud.atlas.System')
    @mock.patch('managementconnector.cloud.atlas.jsonhandler.read_json_file')
    @mock.patch('managementconnector.service.service.Service')
    @mock.patch('managementconnector.cloud.atlas.ServiceUtils.get_version', side_effect=get_version)
    def test_get_post_request_data(self, mock_version, mock_service, mock_json, mock_system):
        """ Test get_post_request_data"""

        _orig_http_request = http._http_request
        http._http_request = _http_request

        alarm_prefix_url = "https://hostname.domain.com/"

        DEV_LOGGER.info('test_get_post_request_data: start')

        mock_json.return_value= {"provisioning":{"maintenanceMode":"off"}}

        mock_service.get_composed_status.return_value = 'installed'
        mock_service.has_alarm.return_value = True

        mock_service.get_name.return_value = 'c_mgmt'
        mock_system.get_system_mem.return_value = {'total_gb': '0.1', 'percent': '8.0', 'total_kb': 128266.3896484375}
        mock_system.get_system_disk.return_value = {'total_gb': '0.1', 'percent': '8.0', 'total_kb': 128266.3896484375}
        mock_system.get_platform_type.return_value = "virtual"
        mock_system.get_cpu_cores.return_value = "2"

        # alarm 1
        alarm_list_str = '[{ "uuid" : "cbbf0813-09cb-4e23-9182-f3996d24cc9e", "id" : "60051", ' \
                    '"first_reported" :  "1417011612", "last_reported" :  "1417011811", "severity" :  "error", ' \
                    '"parameters":  [500, "https://hercules.hitest.huron-dev.com/v1/connectors"], ' \
                    '"solution_links" : "" }]'

        mock_service.get_alarms.return_value = json.loads(alarm_list_str)

        json_request =  self.atlas._get_post_request_data(mock_service)

        DEV_LOGGER.info('test_get_post_request_data: RESPONSE %s' %(json_request))

        self.assertEqual(json_request['connector_type'], 'c_ccucmgmt')
        self.assertEqual(json_request['id'], 'c_ccucmgmt@serialnumber')
        self.assertEqual(json_request['status']['alarms'][0]['solution_replacement_values'], [])
        self.assertIn( "60051", json_request['status']['alarms'][0]['id'])

        # alarm 2
        alarm_list_str = '[{ "uuid" : "635afce6-0ae8-4b84-90f5-837a2234002b", "id" : "60058", ' \
                    '"first_reported" :  "1417011612", "last_reported" :  "1417011811", "severity" :  "error", ' \
                    '"parameters":  ["https://hercules.hitest.huron-dev.com/v1/connectors"], ' \
                    '"solution_links" : "trustedcacertificate" }]'

        mock_service.get_alarms.return_value = json.loads(alarm_list_str)

        json_request =  self.atlas._get_post_request_data(mock_service)

        DEV_LOGGER.info('test_get_post_request_data: RESPONSE %s' %(json_request))

        self.assertEqual(json_request['status']['alarms'][0]['solution_replacement_values'][0]['link'], alarm_prefix_url + "trustedcacertificate")
        #self.assertEqual(json_request['status']['alarms'][0]['solution'], "Check the Expressway's trusted CA list for the CA that signed the received certificate")


        # alarm 3
        links = '["txt.DNS", "dns","txt.PROXY", "fusionproxy","txt.PING", "ping"]'
        alarm_list_str = '[{ "uuid" : "ba883968-4b5a-4f83-9e71-50c7d7621b44", "id" : "60058", ' \
                    '"first_reported" :  "1417011612", "last_reported" :  "1417011811", "severity" :  "error", ' \
                    '"parameters":  ["https://hercules.hitest.huron-dev.com/v1/connectors"], ' \
                    '"solution_links" : ' + links  + ' }]'

        mock_service.get_alarms.return_value = json.loads(alarm_list_str)

        json_request =  self.atlas._get_post_request_data(mock_service)

        DEV_LOGGER.info('test_get_post_request_data: RESPONSE %s' %(json_request))

        expected_val = [{'text': u'DNS Settings', 'link': alarm_prefix_url + 'dns'},
                        {'text': u'Proxy Settings', 'link': alarm_prefix_url + 'fusionproxy'},
                        {'text': u'Ping', 'link': alarm_prefix_url + 'ping'}]

        alarm = json_request['status']['alarms'][0]
        self.assertEqual(alarm['solution_replacement_values'][0]['link'], expected_val[0]['link'])
        self.assertEqual(alarm['solution_replacement_values'][1]['link'], expected_val[1]['link'])
        self.assertEqual(alarm['solution_replacement_values'][2]['link'], expected_val[2]['link'])
        self.assertEqual(alarm['id'], "60058")

        http._http_request = _orig_http_request


        DEV_LOGGER.info('test_get_post_request_data: end')


    def test_order_connectors(self):
        """
        DE1749 - mgmt connector should be first in download sequence
        Steps:

        1. Assert c_mgmt is first in the list when it exists.
        2. Assert no issues if not in list.
        """

        c_cal = {"connector_type": "c_cal",'display_name': "Calendar Connector", 'name': "c_cal"}
        c_mgmt = {"connector_type": "c_mgmt",'display_name': "Management Connector", 'name': "c_mgmt"}
        c_ucmc = {"connector_type": "c_ucmcl",'display_name': "Call Connector", 'name': "c_cal"}

        expected = [c_mgmt, c_cal, c_ucmc]

        DEV_LOGGER.info("***TEST*** Step 1. ")
        to_be_ordered = [c_cal, c_ucmc, c_mgmt]

        Atlas._order_connectors(to_be_ordered)
        # Compare by zipping the expected and ordered list if the elements are equal,
        # and compare the final length.

        same = [i for i, j in zip(to_be_ordered, expected) if i == j]
        DEV_LOGGER.info("***TEST Same list: %s" % same)
        self.assertTrue(len(same) == len(to_be_ordered), "did not match: actual: %s expected: %s" % (same, expected))

        DEV_LOGGER.info("***TEST*** Step 3. ")
        expected = [c_cal, c_ucmc]
        not_there = [c_cal, c_ucmc]
        ordered_not_there = Atlas._order_connectors(not_there)
        self.assertTrue(not_there == expected)
        self.assertTrue(c_mgmt not in not_there)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
