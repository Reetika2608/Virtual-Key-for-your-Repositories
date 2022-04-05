import unittest
import mock
import logging
import sys
import io

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

from urllib import error as urllib_error
from pyfakefs import fake_filesystem_unittest
from .productxml import PRODUCT_XML_CONTENTS
from .constants import SYS_LOG_HANDLER

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud import federationorgmigration
from managementconnector.cloud.oauth import OAuth

logging.getLogger().addHandler(SYS_LOG_HANDLER)
DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()

ACCESS_TOKEN = "Access Token"
REFRESH_TOKEN = "Refresh Token"
REFRESHED_TOKEN = "Refreshed Access Token"

ORG_MIGRATION_DATA = {
            "org-id": "5b1b4724-e796-4d59-bd2e-02d81af05b43",
            "migration-id": "248d09ef-bc33-4c91-b1db-7fd8acfd1b6c",
            "identity-source": "urn:IDENTITY:PF84",
            "identity-target": "urn:IDENTITY:PE93",
            "teams-source": "urn:TEAM:us-east-1_int13",
            "teams-target": "urn:TEAM:us-west-2_int24",
            "meetings-source": "urn:MEETING:prod-dwwd",
            "meetings-target": "urn:MEETING:prod-vvwd",
            "start-at": "2021-12-16T21:10:00.000Z",
            "workstream-startedAt": "2022-01-12T15:49:23.139327Z",
            "fms-migration-state": "STARTED"
        }

FMS_MIGRATION_STATE = "COMPLETED"  # STARTED/COMPLETED


def config_read_side_effect(*args, **kwargs):
    """ Config Side Effect """
    if args[0] == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return {"username": "username", "organization_id": "org_id", "location": "somewhere",
                "password": "{cipher}LT4V5Hr02ejy326BWD+3TgmyS2GK6TPm6UyxxgmxgzOe96Zr52c9HOk7hKBtDeI1iob1OTTFom+bzvFXKMgPwQ==",
                "id": "id"}

    if args[0] == ManagementConnectorProperties.OAUTH_BASE:
        return {"idpHost": "idpHost", "clientId": "clientId", "clientSecret": "clientSecret"}

    if args[0] == ManagementConnectorProperties.FMS_MIGRATION_STATE:
        global FMS_MIGRATION_STATE
        return FMS_MIGRATION_STATE


class OrgMigrationTest(fake_filesystem_unittest.TestCase):
    """ Management Connector FederationOrgMigration Test Class """

    def setUp(self):
        """ Test Setup"""
        self.setUpPyfakefs()
        self.fs.create_file('/info/product_info.xml', contents=PRODUCT_XML_CONTENTS)

    def tearDown(self):
        """ Test tearDown """

    @mock.patch('managementconnector.cloud.federationorgmigration.CafeXUtils.get_installed_connectors',
                return_value=['c_xyz', 'c_abc', 'c_mgmt'])
    @mock.patch('managementconnector.cloud.oauth.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_get_other_connectors(self, mock_config, mock_oauth, mock_get_installed_connectors):
        """ Test get other connectors except c_mgmt """
        org_migration = federationorgmigration.FederationOrgMigration(mock_config, mock_oauth)
        self.assertListEqual(org_migration.get_other_connectors(), ['c_xyz', 'c_abc'])
        mock_get_installed_connectors.assert_called()

    @mock.patch('managementconnector.cloud.federationorgmigration.DatabaseHandler.read', return_value=[])
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.get_other_connectors', return_value=['c_xyz', 'c_abc'])
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.get_enabled_connectors',
                return_value={"services": [mock.MagicMock()], "names": ['c_xyz']})
    @mock.patch('managementconnector.cloud.oauth.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_get_enabled_connectors_no_prev_stopped(self, mock_config, mock_oauth, mock_servicemanager_enabled_connectors,
                                    mock_other_connectors, mock_dbhandler):
        """ Test get enabled connectors without previously stopped connectors """
        org_migration = federationorgmigration.FederationOrgMigration(mock_config, mock_oauth)
        self.assertListEqual(sorted(org_migration.get_enabled_connectors()["names"]), sorted(['c_xyz']))
        mock_servicemanager_enabled_connectors.assert_called_once()
        mock_other_connectors.assert_called_once()

        # check generic exception - exception should not disturb process flow
        mock_other_connectors.side_effect = Exception
        self.assertListEqual(sorted(org_migration.get_enabled_connectors()["names"]), sorted([]))


    @mock.patch('managementconnector.cloud.federationorgmigration.DatabaseHandler.read', return_value=['c_def'])
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.get_other_connectors', return_value=['c_xyz', 'c_abc'])
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.get_enabled_connectors',
                return_value={"services": [mock.MagicMock(), mock.MagicMock()], "names": ['c_xyz', 'c_def']})
    @mock.patch('managementconnector.cloud.oauth.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_get_enabled_connectors_with_prev_stopped(self, mock_config, mock_oauth,
                                                      mock_servicemanager_enabled_connectors,
                                                      mock_other_connectors, mock_dbhandler):
        """ Test get enabled connectors with previously stopped connectors """
        org_migration = federationorgmigration.FederationOrgMigration(mock_config, mock_oauth)
        self.assertTrue(sorted(org_migration.get_enabled_connectors()["names"]), sorted(['c_xyz', 'c_def']))
        mock_servicemanager_enabled_connectors.assert_called_once()
        mock_other_connectors.assert_called_once()

    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.refresh_access_token')
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.disable_connectors')
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.enable_connectors')
    @mock.patch('managementconnector.cloud.federationorgmigration.DatabaseHandler.read')
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.get_other_connectors', return_value=['c_xyz', 'c_abc'])
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.get_enabled_connectors',
                return_value={"services": [mock.MagicMock()], "names": ['c_xyz']})
    @mock.patch('managementconnector.cloud.oauth.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_migrate_completed(self, mock_config, mock_oauth, mock_servicemanager_enabled_connectors,
                               mock_orgmigration_other_connectors, mock_dbhandler, mock_start_connectors,
                               mock_stop_connectors, mock_refresh_access_token):
        """ Test migration completed workflow """
        global FMS_MIGRATION_STATE
        FMS_MIGRATION_STATE = "COMPLETED"
        mock_config.read.side_effect = config_read_side_effect

        org_migration = federationorgmigration.FederationOrgMigration(mock_config, mock_oauth)
        mock_config.write_blob.return_value = None
        org_migration.migrate(status_code=302)

        # should have called db write, get_enabled_connectors and start_connectors
        mock_config.write_blob.assert_called()
        mock_servicemanager_enabled_connectors.assert_called_once()
        mock_orgmigration_other_connectors.assert_called_once()
        mock_start_connectors.assert_called()

        # should not have called stop_connectors() and refresh_access_token()
        self.assertFalse(mock_stop_connectors.called, 'failed')
        self.assertFalse(mock_refresh_access_token.called, 'failed')

    @mock.patch('managementconnector.cloud.oauth.U2C.update_user_catalog')
    @mock.patch('managementconnector.cloud.oauth.Http')
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.disable_connectors')
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.enable_connectors')
    @mock.patch('managementconnector.cloud.federationorgmigration.DatabaseHandler.read', return_value=[])
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.get_other_connectors', return_value=['c_xyz', 'c_abc'])
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.get_enabled_connectors',
                return_value={"services": [mock.MagicMock()], "names": ['c_xyz']})
    @mock.patch('managementconnector.cloud.oauth.OAuth.exponential_backoff_retry')
    @mock.patch('managementconnector.config.config.Config')
    def test_migrate_started(self, mock_config, mock_oauth_polling, mock_servicemanager_enabled_connectors,
                             mock_orgmigration_other_connectors, mock_dbhandler, mock_start_connectors,
                             mock_stop_connectors, mock_http, mock_u2c):
        """ Test migration started workflow """
        time_in_past = OAuth.get_current_time() - 100

        global FMS_MIGRATION_STATE
        FMS_MIGRATION_STATE = "STARTED"

        test_oauth = OAuth(mock_config)
        mock_config.read.side_effect = config_read_side_effect

        refresh_token_response = {'access_token': REFRESHED_TOKEN, 'refresh_token': REFRESHED_TOKEN, 'expires_in': 100,
                                  'accountExpiration': 100}
        headers = {'Content-Type': 'application/json', 'TrackingID': ''}
        stream = io.TextIOWrapper(io.BytesIO(b''))
        url = "https://idbroker.webex.com/idb/oauth2/v1/access_token"
        refresh_token_exception = urllib_error.HTTPError(url, 401, "invalid", headers, stream)
        mock_http.post.side_effect = [refresh_token_exception, refresh_token_response, refresh_token_exception,
                                      refresh_token_response]

        test_oauth.http = mock_http

        org_migration = federationorgmigration.FederationOrgMigration(mock_config, test_oauth)

        mock_config.write_blob.return_value = None
        test_oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        mock_u2c.update_user_catalog.return_value = None

        # if cache is not cleared, the workflow should clear the cache
        mock_config.is_cache_cleared.return_value = False

        org_migration.migrate(status_code=302)

        # should have called get_enabled_connectors, stop_connectors, exponential_backoff_retry and start_connectors
        mock_servicemanager_enabled_connectors.assert_called_once()
        mock_orgmigration_other_connectors.assert_called_once()
        mock_stop_connectors.assert_called_once()
        mock_oauth_polling.assert_called()
        mock_start_connectors.assert_called()

        # ensure cache clear and check calls are made
        mock_config.is_cache_cleared.assert_called()
        mock_config.clear_cache.assert_called()

        # assert token refresh
        self.assertTrue(test_oauth.oauth_response['refresh_time_read'] > time_in_past)
        self.assertTrue(test_oauth.oauth_response['access_token'] == REFRESHED_TOKEN)

        # check generic exception - exception should not disturb process flow
        mock_stop_connectors.side_effect = Exception
        mock_start_connectors.side_effect = Exception
        mock_oauth_polling.side_effect = None
        mock_servicemanager_enabled_connectors.return_value = {"services": [mock.MagicMock()], "names": ['c_xyz']}
        mock_orgmigration_other_connectors.return_value = ['c_xyz', 'c_abc']

        org_migration.migrate(status_code=302)

        # should have called get_enabled_connectors, stop_connectors, exponential_backoff_retry and start_connectors
        self.assertEqual(mock_servicemanager_enabled_connectors.call_count, 2)
        self.assertEqual(mock_orgmigration_other_connectors.call_count, 2)
        self.assertEqual(mock_stop_connectors.call_count, 2)
        self.assertEqual(mock_oauth_polling.call_count, 2)
        self.assertEqual(mock_start_connectors.call_count, 2)

    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.process_migration_data')
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.refresh_access_token')
    @mock.patch('managementconnector.cloud.oauth.Http')
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.disable_connectors')
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.enable_connectors')
    @mock.patch('managementconnector.cloud.federationorgmigration.DatabaseHandler.read', return_value=[])
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.get_other_connectors',
                return_value=['c_xyz', 'c_abc'])
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.get_enabled_connectors',
                return_value={"services": [mock.MagicMock()], "names": ['c_xyz']})
    @mock.patch('managementconnector.config.config.Config')
    def test_migrate_status_not_302_with_migration_data(self, mock_config, mock_servicemanager_enabled_connectors,
                                                        mock_orgmigration_other_connectors, mock_dbhandler,
                                                        mock_start_connectors,
                                                        mock_stop_connectors, mock_http, mock_refresh_access_token,
                                                        mock_process_migration_data):
        """ Test migration status != 302 workflow with migration data """
        global FMS_MIGRATION_STATE
        FMS_MIGRATION_STATE = "STARTED"

        test_oauth = OAuth(mock_config)
        mock_config.read.side_effect = config_read_side_effect

        test_oauth.http = mock_http
        mock_http.post.return_value = {'access_token': REFRESHED_TOKEN, 'refresh_token': REFRESHED_TOKEN,
                                       'expires_in': 100, 'accountExpiration': 100}

        org_migration = federationorgmigration.FederationOrgMigration(mock_config, test_oauth)

        mock_config.write_blob.return_value = None

        org_migration.migrate(status_code=200, federation_org_migration_data=ORG_MIGRATION_DATA)

        # should have called process migration to write migration data to db
        mock_process_migration_data.assert_called()
        # should have called get_enabled_connectors and start_connectors
        mock_servicemanager_enabled_connectors.assert_called_once()
        mock_orgmigration_other_connectors.assert_called_once()

        # should not have called get_enabled_connectors, stop_connectors
        # refresh_access_token, enable_connectors, disable_connectors
        self.assertFalse(mock_stop_connectors.called, 'failed')
        self.assertFalse(mock_refresh_access_token.called, 'failed')
        self.assertFalse(mock_start_connectors.called, 'failed')

    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.process_migration_data')
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.refresh_access_token')
    @mock.patch('managementconnector.cloud.oauth.Http')
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.disable_connectors')
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.enable_connectors')
    @mock.patch('managementconnector.cloud.federationorgmigration.DatabaseHandler.read', return_value=[])
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.get_other_connectors',
                return_value=['c_xyz', 'c_abc'])
    @mock.patch('managementconnector.cloud.federationorgmigration.ServiceManager.get_enabled_connectors',
                return_value={"services": [mock.MagicMock()], "names": ['c_xyz']})
    @mock.patch('managementconnector.config.config.Config')
    def test_migrate_status_not_302_without_migration_data(self, mock_config, mock_servicemanager_enabled_connectors,
                                                           mock_orgmigration_other_connectors, mock_dbhandler,
                                                           mock_start_connectors,
                                                           mock_stop_connectors, mock_http, mock_refresh_access_token,
                                                           mock_process_migration_data):
        """ Test migration status != 302 workflow without migration data """

        test_oauth = OAuth(mock_config)
        mock_config.read.side_effect = config_read_side_effect

        test_oauth.http = mock_http
        mock_http.post.return_value = {'access_token': REFRESHED_TOKEN, 'refresh_token': REFRESHED_TOKEN,
                                       'expires_in': 100, 'accountExpiration': 100}

        org_migration = federationorgmigration.FederationOrgMigration(mock_config, test_oauth)

        mock_config.write_blob.return_value = None

        mock_process_migration_data.return_value = None

        org_migration.migrate(status_code=200)

        mock_orgmigration_other_connectors.assert_called()
        mock_servicemanager_enabled_connectors.assert_called()
        mock_dbhandler.assert_called()

        # should not have called stop_connectors
        # refresh_access_token, enable_connectors, disable_connectors

        self.assertFalse(mock_stop_connectors.called, 'failed')
        self.assertFalse(mock_refresh_access_token.called, 'failed')
        self.assertFalse(mock_start_connectors.called, 'failed')
        # should not have called process migration
        self.assertFalse(mock_process_migration_data.called, 'failed')

    @mock.patch('managementconnector.cloud.oauth.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_process_migration_data(self, mock_config, mock_oauth):
        """ Test process migration data from FMS """
        org_migration = federationorgmigration.FederationOrgMigration(mock_config, mock_oauth)
        mock_config.write_blob.return_value = None
        org_migration.process_migration_data(ORG_MIGRATION_DATA)
        mock_config.write_blob.assert_called()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
