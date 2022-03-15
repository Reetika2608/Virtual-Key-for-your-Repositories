"""
    Test U2C
"""
# Ignore "Method could be a function" warnings        pylint: disable=R0201

import logging
import sys
import unittest

import mock

from .constants import SYS_LOG_HANDLER

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
        return "https://u2c-a.wbx2.com/u2c/api/v1"
    elif path == ManagementConnectorProperties.U2C_USER_SERVICE_URL:
        return "/user/catalog?types=TEAM,IDENTITY"

    return "config_value"


def config_read_with_wrong_u2c_host(path):
    """ config class mock """
    DEV_LOGGER.debug("ConfigMock: read path %s" % path)

    if path == ManagementConnectorProperties.U2C_HOST:
        return {"value": "\\\"https://u2c-a.wbx2.com/u2c/api/v1\\\""}
    else:
        return config_read(path)


def database_read(path):
    """ database class mock """

    if path == ManagementConnectorProperties.U2C_IDENTITY_HOST:
        return "some_identity_host"
    elif path == ManagementConnectorProperties.U2C_HOST:
        return "some_u2c_host"

    return None


def database_read_u2c_not_set(path):
    """ database class mock """

    if path == ManagementConnectorProperties.U2C_IDENTITY_HOST:
        return "some_identity_host"
    elif path == ManagementConnectorProperties.U2C_HOST:
        return None

    return None


def database_read_with_wrong_u2c_host_value(path):
    """ database class mock """

    if path == ManagementConnectorProperties.U2C_IDENTITY_HOST:
        return "some_identity_host"

    elif path == ManagementConnectorProperties.U2C_HOST:
        return "{\"value\": \"\\\"https://u2c-a.wbx2.com/u2c/api/v1\\\"\"}"

    return None


class U2CTest(unittest.TestCase):
    """RemoteDispatcher unit tests"""

    def setUp(self):
        self.oauth = mock.MagicMock()
        self.config_mock = mock.MagicMock()

        self.http = mock.Mock()
        self.http.get.return_value = {"services": [{
            "serviceName": "clientLogs",
            "logicalNames": ["https://client-logs-a.wbx2.com/api/v1"],
            "serviceUrls": [{
                "baseUrl": "https://client-logs-a.wbx2.com/api/v1",
                "priority": 1
            }
            ],
            "ttl": -1}]
        }
        self.database = mock.Mock()
        self.database.read.side_effect = database_read

    def test_update_user_catalog(self):
        """ Test U2C User Catalog Processed Correctly"""
        self.config_mock.read.side_effect = config_read
        test_u2c = U2C(self.config_mock, self.oauth, self.http, self.database)

        test_u2c.update_user_catalog()

        self.config_mock.write.assert_called_with(
            '/configuration/cafe/cafeblobconfiguration/name/c_mgmt_logging_host_u2c',
            {'value': '"https://client-logs-a.wbx2.com/api/v1"'})

    def test_update_user_catalog_service_missing(self):
        """ Test U2C User Catalog Processed Correctly with missing value"""
        self.config_mock.read.side_effect = config_read
        self.http.get.return_value = {"services": [{
            "serviceName": "xxx",
            "logicalNames": ["https://client-logs-a.wbx2.com/api/v1"],
            "serviceUrls": [{
                "baseUrl": "https://client-logs-a.wbx2.com/api/v1",
                "priority": 1
            }
            ],
            "ttl": -1}]
        }
        test_u2c = U2C(self.config_mock, self.oauth, self.http, self.database)

        test_u2c.update_user_catalog()

        self.config_mock.write.assert_not_called()

    def test_correct_u2c_url_is_called(self):
        """ Test that we use the right U2C Url, with correct params"""
        self.config_mock.read.side_effect = config_read
        test_u2c = U2C(self.config_mock, self.oauth, self.http, self.database)

        test_u2c.update_user_catalog()

        self.http.get.assert_called_with(
            "https://u2c-a.wbx2.com/u2c/api/v1/user/catalog?types=TEAM,IDENTITY&services=atlasFusionAdminPortal,clientLogs,feature,fms,idbroker,identity,metrics,remoteDispatcher,ucmgmt-controller,ucmgmt-gateway,ucmgmt-licensing,ucmgmt-migration,ucmgmt-telemetry-mgmt,ucmgmt-upgrade,ucmgmt-web,wdm",
            headers=mock.ANY,
            schema=mock.ANY)

    def test_services_list_is_correct(self):
        """ Test that we build up a correct service list from our service map to pass
        in to the U2C service. Keep it sorted, for testability """
        self.config_mock.read.side_effect = config_read
        test_u2c = U2C(self.config_mock, self.oauth, self.http, self.database)

        services_list = test_u2c.build_services_list(U2C.service_map)

        self.assertEqual(services_list, "atlasFusionAdminPortal,clientLogs,feature,fms,idbroker,identity,metrics,remoteDispatcher,ucmgmt-controller,ucmgmt-gateway,ucmgmt-licensing,ucmgmt-migration,ucmgmt-telemetry-mgmt,ucmgmt-upgrade,ucmgmt-web,wdm",
                         "services list is not correct")

    def test_write_u2c_host_to_cdb_if_u2c_is_none(self):
        """ Reported as SPARK-68250: we did only write the U2C host URL
        on fuse. The U2C thread should do a test and write in the default value to CDB, if value not set in CDB'"""
        self.config_mock.read.side_effect = config_read
        test_u2c = U2C(self.config_mock, self.oauth, self.http, self.database)
        self.database.read.side_effect = database_read_u2c_not_set

        test_u2c.update_user_catalog()

        self.config_mock.write_blob.assert_called_with('u2c_u2cHost', 'https://u2c-a.wbx2.com/u2c/api/v1')

    def test_rewrite_u2c_host_to_cdb_if_u2c_is_incorrect(self):
        """ Reported as SPARK-91437: If the u2c url was NOT set, we wrote the wrong value to the DB
        This will ensure we get the new value (and rewrite it correctly)'"""
        self.config_mock.read.side_effect = config_read_with_wrong_u2c_host
        test_u2c = U2C(self.config_mock, self.oauth, self.http, self.database)
        self.database.read.side_effect = database_read_with_wrong_u2c_host_value

        test_u2c.update_user_catalog()

        # TODO: Make this prettier, shouldn't reach into the object under test like this
        self.assertEqual(self.http.get.call_args[0][0], "https://u2c-a.wbx2.com/u2c/api/v1/user/catalog?types=TEAM,IDENTITY&services=" + test_u2c.build_services_list(U2C.service_map))
        self.config_mock.write_blob.assert_called_with('u2c_u2cHost', 'https://u2c-a.wbx2.com/u2c/api/v1')


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
