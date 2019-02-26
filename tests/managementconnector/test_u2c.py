"""
    Test U2C
"""
# Ignore "Method could be a function" warnings        pylint: disable=R0201

import unittest
import logging
import mock
import sys
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.cloud.u2c import U2C
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()

def config_read(path):
    """ config class mock """
    DEV_LOGGER.debug("ConfigMock: read path %s" % path)

    if path == ManagementConnectorProperties.U2C_HOST:
        return "U2C_HOST"
    elif path == ManagementConnectorProperties.U2C_SERVICE_URL:
        return "U2C_SERVICE_URL"
    elif path == ManagementConnectorProperties.U2C_USER_SERVICE_URL:
        return "U2C_USER_SERVICE_URL"

    return "config_value"


class U2CTest(unittest.TestCase):
    """RemoteDispatcher unit tests"""

    def setUp(self):
        self.oauth = mock.MagicMock()
        self.config_mock = mock.MagicMock()

    @mock.patch('managementconnector.cloud.u2c.Http.get')
    @mock.patch('managementconnector.cloud.u2c.DatabaseHandler')
    def test_update_user_catalog(self, mock_db, mock_http_get):
        """ Test U2C User Catalog Processed Correctly"""

        self.config_mock.read.side_effect = config_read
        mock_http_get.return_value = {"services": [{
            "serviceName": "atlas",
            "logicalNames": ["https://atlas-intb.ciscospark.com/admin/api/v1"],
            "serviceUrls": [{
                "baseUrl": "https://atlas-intb.ciscospark.com/admin/api/v1",
                "priority": 1
            }
            ],
            "ttl": -1}]
        }

        test_u2c = U2C(self.config_mock, self.oauth)
        test_u2c.update_user_catalog()

        self.config_mock.write.assert_called_with('/configuration/cafe/cafeblobconfiguration/name/c_mgmt_logging_host_u2c', 
                                                  {'value': '"https://atlas-intb.ciscospark.com/admin/api/v1"'})

    @mock.patch('managementconnector.cloud.u2c.Http.get')
    @mock.patch('managementconnector.cloud.u2c.DatabaseHandler')
    def test_update_user_catalog_service_missing(self, mock_db, mock_http_get):
        """ Test U2C User Catalog Processed Correctly with missing value"""

        self.config_mock.read.side_effect = config_read
        mock_http_get.return_value = {"services": [{
            "serviceName": "xxx",
            "logicalNames": ["https://atlas-intb.ciscospark.com/admin/api/v1"],
            "serviceUrls": [{
                "baseUrl": "https://atlas-intb.ciscospark.com/admin/api/v1",
                "priority": 1
            },
            ],
            "ttl": -1}]
        }

        test_u2c = U2C(self.config_mock, self.oauth)
        test_u2c.update_user_catalog()

        self.config_mock.write.assert_not_called()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
