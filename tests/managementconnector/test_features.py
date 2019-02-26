"""
    Test Features
"""

# Ignore "Unused argument" warnings                   pylint: disable=W0613
# Ignore "Method could be a function" warnings        pylint: disable=R0201
# Ignore "Invalid name" warnings                      pylint: disable=C0103
# Ignore "Access to a protected member of a client class" warnings pylint: disable=W0212
# Ignore "C0413(wrong-import-position)"               pylint: disable=C0413

import logging
import sys
import unittest
import json
import mock
from constants import SYS_LOG_HANDLER
# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud.features import Features
from managementconnector.lifecycle.featurethread import FeatureThread

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


def config_build_url(*args, **kwargs):
    """ returns config for build url method """
    if args[0] == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return {"username": "fusion-mgmnt-d73899a9-94f7-4245-a400-21d16bf9b7ee",
                "id": "bfc1a42e-0afc-4943-9c62-ee4b0744e54a"}
    elif args[0] == ManagementConnectorProperties.FEATURES_HOST:
        return "feature-a.wbx2.com"
    elif args[0] == ManagementConnectorProperties.FEATURES_URL:
        return "/feature/api/v1/features/users/"


class FeaturesTest(unittest.TestCase):
    """ Unit test class for Features """

    def test_audit_features_with_valid(self):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_audit_features_with_valid")

        # Set up some junk feature config, copied from real response
        fmc_test_feature = {'key': 'fmc-test-feature', 'value': True, 'val': 'true', 'group': 'ORG',
                     'lastModified': '2016-09-14T15:27:08.687Z', 'deletedTime': 0,
                     'orgId': 'd0d31660-1984-4557-946c-230b9b202f68', 'mutable': True, 'percentage': 0, 'type': 'DEV'}

        atlas_hs_services = {'key': 'atlas-hybrid-services-resource-list', 'value': True, 'val': 'true',
                              'lastModified': '2016-09-12T12:01:05.409Z', 'group': 'ALL', 'deletedTime': 0,
                              'mutable': False,	'percentage': 0, 'type': 'DEV'}

        ios_search = {'key': 'ios-search-service2', 'value': True, 'val': 'true',
                      'lastModified': '2016-09-15T20:42:45.030Z',  'mutable': True, 'type': 'DEV'}

        # Set expectations
        features = [fmc_test_feature, atlas_hs_services, ios_search]
        expected_features = {"fmc-test-feature": "true"}

        # Run command
        clean_features = Features.audit_features(features)

        # Verify
        self.assertEquals(expected_features, clean_features,
                          msg="Expected Features: {} - didn't match Cleaned features: {}".
                          format(expected_features, clean_features))

    def test_audit_with_no_fmc_features(self):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_audit_with_no_fmc_features")

        # Set up some junk feature config, copied from real response
        atlas_hs_services = {'key': 'atlas-hybrid-services-resource-list', 'value': True, 'val': 'true',
                              'lastModified': '2016-09-12T12:01:05.409Z', 'group': 'ALL', 'deletedTime': 0,
                              'mutable': False,	'percentage': 0, 'type': 'DEV'}

        ios_search = {'key': 'ios-search-service2', 'value': True, 'val': 'true',
                      'lastModified': '2016-09-15T20:42:45.030Z',  'mutable': True, 'type': 'DEV'}

        # Set expectations
        features = [atlas_hs_services, ios_search]
        expected_features = {}

        # Run command
        clean_features = Features.audit_features(features)

        # Verify
        self.assertEquals(expected_features, clean_features,
                          msg="Expected Features: {} - didn't match Cleaned features: {}".
                          format(expected_features, clean_features))

    @mock.patch('managementconnector.cloud.oauth.OAuth')
    @mock.patch('managementconnector.cloud.features.Http')
    @mock.patch('managementconnector.config.config.Config')
    def test_update_features_writes_to_db_on_init(self, mock_config, mock_http, mock_oauth):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_update_features_writes_to_db_on_init")
        fmc_test_feature = {'key': 'fmc-test-feature', 'value': True, 'val': 'true', 'group': 'ORG',
                                'lastModified': '2016-09-14T15:27:08.687Z', 'deletedTime': 0,
                                'orgId': 'd0d31660-1984-4557-946c-230b9b202f68', 'mutable': True,
                                'percentage': 0, 'type': 'DEV'}

        expected_features = {"value": json.dumps({"fmc-test-feature": "true"})}

        mock_http.get.return_value = {"user": [], ManagementConnectorProperties.FEATURES_GROUP: [fmc_test_feature]}
        mock_config.read.side_effect = config_build_url

        features = Features(mock_config, mock_oauth)
        features.update_latest_features()
        full_path = ManagementConnectorProperties.BLOB_CDB_PATH + ManagementConnectorProperties.FEATURES_ENTRIES

        mock_config.write.assert_called_with(full_path, expected_features)
        self.assertTrue(mock_config.write.called, msg="Blob write not called as expected")

    @mock.patch('managementconnector.cloud.oauth.OAuth')
    @mock.patch('managementconnector.cloud.features.Http')
    @mock.patch('managementconnector.config.config.Config')
    def test_update_features_does_not_write_on_empty_group_twice(self, mock_config, mock_http, mock_oauth):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_update_features_does_not_write_on_empty_group_features")

        mock_http.get.return_value = {"user": [], ManagementConnectorProperties.FEATURES_GROUP: []}
        mock_config.read.side_effect = config_build_url

        features = Features(mock_config, mock_oauth)

        DEV_LOGGER.info("***TEST*** first update features call, should hit the db")
        features.update_latest_features()

        self.assertTrue(mock_config.write.called, msg="Blob write not called when expected")
        mock_config.reset_mock()

        DEV_LOGGER.info("***TEST*** second update features call, should not hit db with no change")
        features.update_latest_features()
        self.assertFalse(mock_config.write.called, msg="Blob write called when not expected")

    @mock.patch('managementconnector.config.config.Config')
    def test_compare_features_init_added_to_live(self, mock_config):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_compare_features_init_added_to_live")
        # Set database value after update from thread/cloud.
        expected = {"fmc-test-feature": "true"}
        cloud_list = {"fmc-test-feature": "true"}
        mock_config.read.return_value = cloud_list

        cached_list = {}
        full_list, delta = Features.compare_features(mock_config, cached_list)
        self.assertEquals(delta, expected)
        self.assertEquals(full_list, cloud_list)

    @mock.patch('managementconnector.config.config.Config')
    def test_compare_features_feature_disabled(self, mock_config):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_compare_features_feature_disabled")
        # Set database value after update from thread/cloud.
        expected = {"fmc-test-feature": "false"}
        cloud_list = {"fmc-test-feature": "false"}
        mock_config.read.return_value = cloud_list

        cached_list = {"fmc-test-feature": "true"}
        full_list, delta = Features.compare_features(mock_config, cached_list)
        self.assertEquals(delta, expected)
        self.assertEquals(full_list, cloud_list)

    @mock.patch('managementconnector.config.config.Config')
    def test_compare_features_buddy_added_to_live(self, mock_config):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_compare_features_buddy_added_to_live")
        # Set database value after update from thread/cloud.
        expected_delta = {"fmc-another-feature": "false"}
        cloud_list = {"fmc-test-feature": "true", "fmc-another-feature": "false"}
        mock_config.read.return_value = cloud_list

        cached_list = {"fmc-test-feature": "true"}
        full_list, delta = Features.compare_features(mock_config, cached_list)
        self.assertEquals(delta, expected_delta)
        self.assertEquals(full_list, cloud_list)

    @mock.patch('managementconnector.config.config.Config')
    def test_compare_features_removed_from_live(self, mock_config):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_compare_features_removed_from_live")
        # Don't want anything to happen when toggle removed as
        # we will not about it at this point, but cached
        # should be updated, explicit 'false' required to stop.
        expected_delta = {}
        cloud_list = {}
        mock_config.read.return_value = cloud_list

        cached_list = {"fmc-test-feature": "true"}
        full_list, delta = Features.compare_features(mock_config, cached_list)
        self.assertEquals(delta, expected_delta)
        self.assertEquals(full_list, cloud_list)

    @mock.patch('managementconnector.config.config.Config')
    def test_compare_features_no_change(self, mock_config):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_compare_features_no_change")
        expected_delta = {}
        cloud_list = {"fmc-test-feature": "true"}
        mock_config.read.return_value = cloud_list

        cached_list = {"fmc-test-feature": "true"}
        full_list, delta = Features.compare_features(mock_config, cached_list)
        self.assertEquals(delta, expected_delta)
        self.assertEquals(full_list, cloud_list)


    @mock.patch('threading.Event')
    @mock.patch('managementconnector.cloud.features.Http')
    @mock.patch('managementconnector.config.config.Config')
    def test_features_http_exception_handling(self, mock_config, mock_http, mock_event):
        """
        User Story: US13040 F394 org level feature toggle
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_features_http_exception_handling")

        # Fail with a none object error as feature is never initialised
        feature_thread = FeatureThread(mock_config, mock_event)
        feature_thread._oauth_init = True

        # Feature object will be None, and throw and exception
        feature_thread._do_heartbeat()

        self.assertTrue(mock_event.wait.called, msg="Event wait was not called as expected, called: %s" % mock_event.wait.called)

    @mock.patch('managementconnector.cloud.oauth.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_get_user_id(self, mock_config, mock_oauth):
        """
        User Story: DE3865 Presidio Not picking up on RemoteDispatcher
        Notes: id doesn't always exist in oauth details
        """
        DEV_LOGGER.info("***TEST*** test_get_user_id")

        mock_config.read.return_value = {
            "username": "fusion-mgmnt-d73899a9-94f7-4245-a400-21d16bf9b7ee",
            "location":
                "https://identitytx-s.webex.com/organization/d0d31660-1111-4557-946c-230b9b202f68/v1/Machines/"
                "0352d38c-1111-4274-a918-881e2f09603a"
        }

        features = Features(mock_config, mock_oauth)
        uid = features.get_user_id()
        self.assertEquals(uid, "0352d38c-1111-4274-a918-881e2f09603a")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
