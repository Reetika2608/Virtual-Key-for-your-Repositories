""" Test Databasehandler Class """

import unittest
import mock
import sys
import logging

sys.path.append("/opt/c_mgmt/bin/")

from ni.managementconnector.config.databasehandler import DatabaseHandler
from ni.managementconnector.config.databasehandler import register_all_default_loggers

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class DatabaseHandlerTest(unittest.TestCase):
    """ DatabaseHandler Test Class """

    @mock.patch("ni.managementconnector.config.databasehandler.ManagementConnectorProperties")
    @mock.patch("ni.managementconnector.config.databasehandler.DatabaseHandler.get_records")
    def test_get_service_records(self, mock_get_records, mock_properties):
        """
        User Story: US7718 - Offsite feedback: snapshot CDB on upgrade and reapply on rollback
        Purpose: To verify correct service records are returned in a path:value dictionary pair.
        Note:
        Steps:
        1. Mock RestClient and set expected get_records return value
        2. Call get_service_records
        3. Assert actual == expected
        """
        DEV_LOGGER.info("*** test_get_service_records ***")

        mock_get_records.return_value = [{"name": "c_cal_first", "value": "one", "uuid": "1"},
                                         {"name": "c_ucmc_first", "value": "one", "uuid": "2"},
                                         {"name": "c_cal_second", "value": "two", "uuid": "3"},
                                         {"name": "c_ucmc_second", "value": "two", "uuid": "4"}]

        mock_properties.DATABASE_TABLES = ["table1", "table2"]

        # Assert for c_cal
        expected_cal = {"table1": {"c_cal_first": "one", "c_cal_second": "two"},
                        "table2": {"c_cal_first": "one", "c_cal_second": "two"}}

        database_handler = DatabaseHandler()

        cal_records = database_handler.get_service_database_records("c_cal")

        mock_get_records.assert_called()
        self.assertEquals(cal_records, expected_cal, "Actual: %s did not match Expected: %s"
                          % (cal_records, expected_cal))

        # Assert for c_ucmc
        expected_c_ucm = {"table1": {"c_ucmc_first": "one", "c_ucmc_second": "two"},
                          "table2": {"c_ucmc_first": "one", "c_ucmc_second": "two"}}

        c_ucmc_records = database_handler.get_service_database_records("c_ucmc")

        mock_get_records.assert_called()
        self.assertEquals(c_ucmc_records, expected_c_ucm, "Actual: %s did not match Expected: %s"
                          % (c_ucmc_records, expected_c_ucm))



    @mock.patch("ni.managementconnector.config.databasehandler.ManagementConnectorProperties")
    @mock.patch("ni.managementconnector.config.databasehandler.DatabaseHandler.get_records")
    def test_get_service_database_records_empty(self, mock_get_records, mock_properties):
        """
        User Story: US7718 - Offsite feedback: snapshot CDB on upgrade and reapply on rollback
        Purpose: To verify correct service records are returned in a path:value dictionary pair.
        Note:
        Steps:
        1. Mock RestClient and set expected get_records return value
        2. Call get_service_database_records
        3. Assert actual == expected
        """
        DEV_LOGGER.info("*** test_get_service_database_records_empty ***")

        mock_get_records.return_value = []
        mock_properties.DATABASE_TABLES = ["table1", "table2"]

        # Assert for c_cal
        expected_cal = {}
        database_handler = DatabaseHandler()

        cal_records = database_handler.get_service_database_records("c_cal")

        mock_get_records.assert_called()
        self.assertEquals(cal_records, expected_cal, "Actual: %s did not match Expected: %s"
                          % (cal_records, expected_cal))


    @mock.patch("ni.managementconnector.config.databasehandler.DatabaseHandler.write_blob")
    @mock.patch("ni.managementconnector.config.databasehandler.DatabaseHandler.read")
    def test_update_blob(self, mock_read, mock_write_blob):
        """
        Defect: DE2607 - GitHub #269 - Firestarter attempts to restart c_ucmc after the call service is deactivated / deregistered
        Purpose: To verify that parts of blob entries are being updated correctly
        Note:
        Steps:
        1. Mock RestClient and set expected read return value
        2. Call update_blob with new entry
        3. Assert write_blob called correctly
        4. Set expected read return value
        5. Call update_blob with value to change
        6. Assert write_blob called correctly
        """

        DEV_LOGGER.info("*** test_update_blob ***")

        path = "system_enabledServicesState"
        mock_read.return_value = {}
        
        database_handler = DatabaseHandler()

        database_handler.update_blob(path, "c_test", "false")
        mock_read.assert_called()
        mock_write_blob.assert_called_with(path, {'c_test': 'false'})

        mock_read.return_value = {'c_mgmt': 'true', 'c_test': 'true'}
        database_handler.update_blob(path, "c_test", "false")
        mock_read.assert_called()
        mock_write_blob.assert_called_with(path,{'c_mgmt': 'true', 'c_test': 'false'})


    @mock.patch("ni.managementconnector.config.databasehandler.ManagementConnectorProperties")
    @mock.patch("ni.managementconnector.config.databasehandler.DatabaseHandler.write_blob")
    @mock.patch("ni.managementconnector.config.databasehandler.DatabaseHandler.read")
    def test_delete_enabled_service_blob(self, mock_read, mock_write_blob,mock_properties):
        """
        Defect: DE2607 - GitHub #269 - Firestarter attempts to restart c_ucmc after the call service is deactivated / deregistered
        Purpose: To verify that individual enabled services entries are deleted correctly
        Note:
        Steps:
        1. Mock RestClient and set expected read return value
        2. Call delete_enabled_service_blob with nonexistent entry
        3. Assert write_blob not called
        4. Set expected read return value
        5. Call update_blob with entry to remove
        6. Assert write_blob called correctly
        """

        DEV_LOGGER.info("*** test_delete_enabled_service_blob ***")

        mock_properties.ENABLED_SERVICES_STATE = "system_enabledServicesState"
        mock_read.return_value = {}
        
        database_handler = DatabaseHandler()
        database_handler.delete_enabled_service_blob("c_test")
        mock_read.assert_called()
        self.assertFalse(mock_write_blob.called, "write_blob should not have been called.")

        mock_read.return_value = {'c_mgmt': 'true', 'c_test': 'true'}
        database_handler.delete_enabled_service_blob("c_test")
        mock_read.assert_called()
        mock_write_blob.assert_called_with("system_enabledServicesState",{'c_mgmt': 'true'})


    @mock.patch("ni.managementconnector.config.databasehandler.CafeXUtils.get_installed_connectors")
    @mock.patch('ni.managementconnector.config.databasehandler.register_default_loggers')
    def test_register_all_default_loggers_happy(self, mock_register, mock_installed):
        """
        Defect: DE3119 - c_cal and c_ucmc require default entries to be created for Hybrid Services Log Levels on startup
        Purpose: To verfiy that register all default loggers sanitises the list correctly
        Note:
        Steps:
        1. Mock required methods
        2. Call register_all_default_loggers
        3. Ensure register_default_loggers was called with expected logger names
        """

        # Path 1: Happy Expected path
        expected_call = [ManagementConnectorProperties.HYBRID_PREFIX + "c_cal",
                         ManagementConnectorProperties.HYBRID_PREFIX + "c_ucmc",
                         ManagementConnectorProperties.HYBRID_LOGGER_NAME,
                         ManagementConnectorProperties.CAFE_LOGGER_NAME]

        mock_installed.return_value = ["c_mgmt", "c_cal", "c_ucmc"]
        register_all_default_loggers()
        mock_register.assert_called_once_with(expected_call)

    @mock.patch("ni.managementconnector.config.databasehandler.CafeXUtils.get_installed_connectors")
    @mock.patch('ni.managementconnector.config.databasehandler.register_default_loggers')
    def test_register_all_default_loggers_c_mgmt_only(self, mock_register, mock_installed):
        """
        Defect: DE3119 - c_cal and c_ucmc require default entries to be created for Hybrid Services Log Levels on startup
        Purpose: To verfiy that register all default loggers sanitises the list correctly
        Note:
        Steps:
        1. Mock required methods
        2. Call register_all_default_loggers
        3. Ensure register_default_loggers was called with expected logger names
        """

        # Path 2: nothing installed - except c_mgmt
        expected_call = [ManagementConnectorProperties.HYBRID_LOGGER_NAME,
                         ManagementConnectorProperties.CAFE_LOGGER_NAME]

        mock_installed.return_value = ["c_mgmt"]
        register_all_default_loggers()
        mock_register.assert_called_once_with(expected_call)

    @mock.patch('ni.managementconnector.config.databasehandler.DEV_LOGGER.error')
    @mock.patch("ni.managementconnector.config.databasehandler.CafeXUtils.get_installed_connectors")
    @mock.patch('ni.managementconnector.config.databasehandler.register_default_loggers')
    def test_register_all_default_loggers_error(self, mock_register, mock_installed, mock_logger):
        """
        Defect: DE3119 - c_cal and c_ucmc require default entries to be created for Hybrid Services Log Levels on startup
        Purpose: To verfiy that register all default loggers sanitises the list correctly
        Note:
        Steps:
        1. Mock required methods
        2. Call register_all_default_loggers
        3. Ensure register_default_loggers was called with expected logger names
        """

        # Path 3: nothing installed (error case)
        mock_installed.return_value = None
        register_all_default_loggers()
        mock_register.assert_not_called()
        mock_logger.assert_called()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
