""" Test xstatus """

import sys
import mock

from pyfakefs import fake_filesystem_unittest
from productxml import PRODUCT_XML_CONTENTS
import unittest
import logging
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

import managementconnector.xstatus.c_mgmt_xstatus as c_mgmt

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class MockConfig2Alarms():
    def read(self, config):
        if config == ManagementConnectorProperties.ALARMS_RAISED:
            return [{
              "uuid" : "ba883968-4b5a-4f83-9e71-50c7d7621b44",
              "id" : "60050",
              "first_reported" :  "1421858268",
              "last_reported" :  "1421858268",
              "severity" :  "error",
              "parameters":  []},
              {
              "uuid" : "cbbf0813-09cb-4e23-9182-f3996d24cc9e",
              "id" : "60051",
              "first_reported" :  "1421853435",
              "last_reported" :  "1421853435",
              "severity" :  "error",
              "parameters":  []
            }
            ]
        elif config == ManagementConnectorProperties.ENTITLED_SERVICES:
            return  [{"name": "c_mgmt", "display_name": "Manamgent Connector"},
                     {"name": "c_cal", "display_name": "Calendar Connector"}]

class MockConfigNoAlarms():
    def read(self, config):
        if config == ManagementConnectorProperties.ALARMS_RAISED:
            return []

class MockServiceManifest():
    def __init__(self, service_name):
        pass

    def setup(self, service_name):
        pass
      
    def contains_alarm(self, alarm_id):
        DEV_LOGGER.info('***TEST*** MockServiceManifest')
        return True

    def get_cgroup_limits(self):
        return {'cpu': 100, 'memory': 100}

    def get_external_alarms(self):
        return []

    def get_suppressed_alarms(self):
        return ["60051","15004"]


class XStatusTest(fake_filesystem_unittest.TestCase):
    """ XStatus  Test Class """

    def setUp(self):
        self.setUpPyfakefs()
        self.fs.create_file('/info/product_info.xml', contents=PRODUCT_XML_CONTENTS)

    @mock.patch("managementconnector.platform.system.System.get_system_mem")
    @mock.patch("cafedynamic.cafexutil.CafeXUtils")
    def test_alarms(self, mock_get_package_version, mock_get_system_mem):
        """ Test alarms"""
        def alarms():
            DEV_LOGGER.info('***TEST*** XStatusTest start')

            xstatus = c_mgmt._get_status([{'uuid': 'e53229c3-c64f-4408-9ef1-319951e07a30', 'value': '[{"display_name": "Calendar Service", "name": "c_cal"}, {"display_name": "Fusion Management", "name": "c_mgmt"}, {"display_name": "UCM Service", "name": "c_ucmc"}]', 'name': 'c_mgmt_entitled_services'}],
                      MockConfigNoAlarms(),
                      MockServiceManifest)

            node = xstatus.find("c_mgmt")
            alarms = node.find("alarms")
            self.assertEquals(alarms.text, "0")

            DEV_LOGGER.info('***TEST*** XStatusTest, finished first test')

            xstatus = c_mgmt._get_status([{'uuid': 'e53229c3-c64f-4408-9ef1-319951e07a30', 'value': '[{"display_name": "Calendar Service", "name": "c_cal"}, {"display_name": "Fusion Management", "name": "c_mgmt"}, {"display_name": "UCM Service", "name": "c_ucmc"}]', 'name': 'c_mgmt_entitled_services'}],
                                      MockConfig2Alarms(),
                                      MockServiceManifest)

            node = xstatus.find("c_mgmt")
            alarms = node.find("alarms")
            self.assertEquals(alarms.text, "2")

            DEV_LOGGER.info('***TEST*** XStatusTest end')

        with mock.patch('managementconnector.xstatus.c_mgmt_xstatus.Service.get_status'):
            alarms()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
