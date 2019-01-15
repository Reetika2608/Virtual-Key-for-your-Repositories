""" Hybrid Services Tests """

import logging
import mock
import unittest
import sys
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config.databasehandler import register_default_loggers


class HybridSyslogTests(unittest.TestCase):
    """ This class is used to test Hybrid Services Syslog setup """

    hybrid_log_file = "/mnt/harddisk/log/hybrid_services_log"
    logging_data = "Logging_Data_Test"

    @mock.patch('managementconnector.config.databasehandler.DatabaseHandler.write')
    @mock.patch('managementconnector.config.databasehandler.DatabaseHandler.get_records')
    def test_register_default_loggers(self, mock_get, mock_write):
        """
        User Story: US9311: Platform Logging
        Purpose: Verify FMC registers default loggers to database as expected.
        Steps:
        1. 8.8 First Start up - write with FMC & Cafe.
        2. 8.8 Second Start up - no write as written already.
        3. Service install - write with c_cal as not already added.
        Notes:
        """
        # Sample Records
        fmc_entry = {u'level': u'DEBUG', u'uuid': u'uuid', u'name': u'hybridservices.managementconnector'}
        cafe_entry = {u'level': u'INFO', u'uuid': u'8a1d1825-3432-43a6-978a-35097b736cf3', u'name': u'hybridservices.cafedynamic'}

        # Sample Calls
        fmc_call = mock.call("/configuration/hybridserviceslogger/name/hybridservices.managementconnector",
                             {"name": "hybridservices.managementconnector"})
        cafe_call = mock.call("/configuration/hybridserviceslogger/name/hybridservices.cafedynamic",
                              {"name": "hybridservices.cafedynamic"})

        # Step. 1
        mock_get.return_value = None

        expected_step1_calls = [fmc_call, cafe_call]
        register_default_loggers(ManagementConnectorProperties.DEFAULT_LOGGERS)
        mock_write.assert_has_calls(expected_step1_calls)
        self.assertEquals(mock_write.call_count, 2)
        mock_write.reset_mock()

        # Step. 2
        mock_get.return_value = [fmc_entry, cafe_entry]
        register_default_loggers(ManagementConnectorProperties.DEFAULT_LOGGERS)
        mock_write.assert_not_called()
        mock_write.reset_mock()

        # Step. 3
        mock_get.return_value = [fmc_entry, cafe_entry]
        register_default_loggers([ManagementConnectorProperties.HYBRID_PREFIX + "c_cal"])
        mock_write.assert_called_with("/configuration/hybridserviceslogger/name/hybridservices.c_cal",
                               {"name": "hybridservices.c_cal"})
        self.assertEquals(mock_write.call_count, 1)
        mock_write.reset_mock()

    def test_hybrid_services_init(self):
        """
        User Story: FMC 2.0
        Purpose: Verify Hybrid services log can initialise correctly
        Steps:
        1. import initialise_logging_hybrid_services
        2. invoke init
        3. ensure there are two loggers; SysLogHandler and CrashReportHandler
        Notes:
        """
        from managementconnector.platform.hybridlogsetup import initialise_logging_hybrid_services
        initialise_logging_hybrid_services("test_hybrid_services_init")
        self.assertEquals(len(logging.getLogger("hybridservices").handlers), 2)


if __name__ == "__main__":
    unittest.main()
