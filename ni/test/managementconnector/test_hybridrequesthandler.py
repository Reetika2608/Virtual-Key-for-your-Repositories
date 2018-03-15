""" Hybrid Request Handler Tests """

# Ignore "Method could be a function" warnings        pylint: disable=R0201
# Ignore "Invalid name" warnings                      pylint: disable=C0103

import unittest
import mock

from ni.managementconnector.platform.hybridrequesthandler import on_request
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

from ni.managementconnector.platform.hybridlogsetup import initialise_logging_hybrid_services
initialise_logging_hybrid_services("managementconnector")

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class HybridRequestHandler(unittest.TestCase):
    """ Unit test class for HybridRequestHandler """

    def test_hybrid_request_handler_rejects_invalid_or_missing_json(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure request handler api rejects invalid json
        Notes:
        """
        DEV_LOGGER.info("test_hybrid_request_handler_rejects_invalid_json")

        mock_db = mock.Mock()
        self.assertFalse(on_request(mock_db, "someInvalidJson"))
        self.assertFalse(on_request(mock_db, '{"connector": "c_something", "value": "true"}'))
        self.assertFalse(on_request(mock_db, ""))

    def test_hybrid_request_call_db_handler_with_valid_values(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure valid commands hit the DB handler as expected
        Notes:
        """
        DEV_LOGGER.info("test_hybrid_request_call_db_handler_with_valid_values")

        mock_db = mock.Mock()
        on_request(mock_db, '{"connector": "c_test", "request": "setconfiguredstatus", "value": "true"}')
        mock_db.update_blob_entries.assert_called_with(ManagementConnectorProperties.CONFIGURED_SERVICES_STATE,
                                                       ["c_test"],
                                                       "true")

        mock_db.reset_mock()
        on_request(mock_db, '{"connector": "c_test", "request": "setconfiguredstatus", "value": "TRUE"}')
        mock_db.update_blob_entries.assert_called_with(ManagementConnectorProperties.CONFIGURED_SERVICES_STATE,
                                                       ["c_test"],
                                                       "true")

        mock_db.reset_mock()
        on_request(mock_db, '{"connector": "c_test", "request": "setconfiguredstatus", "value": "FALSE"}')
        mock_db.update_blob_entries.assert_called_with(ManagementConnectorProperties.CONFIGURED_SERVICES_STATE,
                                                       ["c_test"],
                                                       "false")

        mock_db.reset_mock()
        on_request(mock_db, '{"connector": "c_test", "request": "setconfiguredstatus", "value": "false"}')
        mock_db.update_blob_entries.assert_called_with(ManagementConnectorProperties.CONFIGURED_SERVICES_STATE,
                                                       ["c_test"],
                                                       "false")

        mock_db.reset_mock()
        on_request(mock_db, '{"connector": "c_test", "request": "setconfiguredstatus", "value": true}')
        mock_db.update_blob_entries.assert_called_with(ManagementConnectorProperties.CONFIGURED_SERVICES_STATE,
                                                       ["c_test"],
                                                       "true")

        mock_db.reset_mock()
        on_request(mock_db, '{"connector": "c_test", "request": "setconfiguredstatus", "value": false}')
        mock_db.update_blob_entries.assert_called_with(ManagementConnectorProperties.CONFIGURED_SERVICES_STATE,
                                                       ["c_test"],
                                                       "false")

        mock_db.reset_mock()
        on_request(mock_db, '{"connector": "c_test", "request": "setconfiguredstatus", "value": true}')
        mock_db.update_blob_entries.assert_not_called()

    def test_hybrid_request_unsupported_request_are_not_handled(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure unsupported commands don't run
        Notes:
        """
        DEV_LOGGER.info("test_hybrid_request_unsupported_request_are_not_handled")

        mock_db = mock.Mock()
        on_request(mock_db, '{"connector": "c_test", "request": "some_unsupported_command", "value": "true"}')
        mock_db.update_blob_entries.assert_not_called()