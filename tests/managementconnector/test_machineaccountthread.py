"""
    Test MachineAccountThread
"""

import logging
import mock
import sys
import threading
import unittest
from urllib import error as urllib_error

from time import sleep
from .constants import SYS_LOG_HANDLER

# Pre-import a mocked pyinotify
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.lifecycle.machineaccountthread import MachineAccountThread

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


def config_read_side_effect(*args, **kwargs):
    """ Config Side Effect """
    if args[0] == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return {"location": "somewhere", "password": "somepassword", "organization_id": "abcd"}
    if args[0] == ManagementConnectorProperties.TARGET_TYPE:
        return "c_mgmt"
    if args[0] == ManagementConnectorProperties.SERIAL_NUMBER:
        return "AF10S"
    if args[0] == ManagementConnectorProperties.MACHINE_ACC_EXPIRY:
        return "45"
    elif args[0] == ManagementConnectorProperties.MACHINE_POLL_TIME:
        return "3"


class MachineAccountThreadTest(unittest.TestCase):
    """ Unit test class for MachineAccountThread """

    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.Http.patch')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MachineAccountThread.write_machine_account_config_to_disk')
    @mock.patch("managementconnector.platform.logarchiver.EventSender.post")
    @mock.patch('managementconnector.lifecycle.machineaccountthread.decrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.encrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MCAlarm')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.OAuth')
    def test_machine_account_password_refresh_thread_stop_event_test(self, mock_oauth, mock_alarm, mock_encrypt, mock_decrypt, mock_event, mock_write_config, mock_patch, mock_config):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """

        DEV_LOGGER.info("***TEST*** test_machine_account_password_refresh_thread_stop_thread")
        mock_config.read.side_effect = config_read_side_effect
        mock_encrypt.return_value = "enc_password"
        mock_decrypt.return_value = "password"
        mock_oauth.get_account_expiration.return_value = "10"
        stop_event = threading.Event()

        ma_thread = MachineAccountThread(mock_config, stop_event)
        ma_thread._oauth = mock_oauth

        ma_thread.start()
        sleep(4)
        stop_event.set()

        # Backup join if required
        ma_thread.join(5)
        self.assertTrue(mock_write_config.called)
        self.assertTrue(mock_patch.called, "machine_runner start was not called when expected, called: %s" % mock_patch.called)
        mock_config.write_blob.assert_called_with(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS,
                                                  {"location": "somewhere", "password": "enc_password", "organization_id": "abcd"})


    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.Http.patch')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MachineAccountThread.write_machine_account_config_to_disk')
    @mock.patch("managementconnector.platform.logarchiver.EventSender.post")
    @mock.patch('managementconnector.lifecycle.machineaccountthread.decrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.encrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MCAlarm')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.OAuth')
    def test_machine_account_password_refresh_thread_failure_count_test(self, mock_oauth, mock_alarm, mock_encrypt, mock_decrypt, mock_event, mock_write_config, mock_patch, mock_config):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """

        DEV_LOGGER.info("***TEST*** test_machine_account_password_refresh_thread_failure_count_test")
        mock_config.read.side_effect = config_read_side_effect
        mock_encrypt.return_value = "enc_password"
        mock_decrypt.return_value = "password"
        # mock_oauth.get_account_expiration.return_value = "10"
        mock_oauth.get_account_expiration.return_value = None

        stop_event = threading.Event()

        ma_thread = MachineAccountThread(mock_config, stop_event)
        ma_thread._oauth = mock_oauth
        ma_thread.failure_count = 2
        
        ma_thread.start()
        sleep(4)
        stop_event.set()

        # Backup join if required
        ma_thread.join(5)

        test_uuid = "bb1cf2ca-20fd-43cc-9ae2-8a33206fb9fd"
        self.assertTrue(mock_write_config.called)
        self.assertTrue(mock_patch.called, "machine_runner start was not called when expected, called: %s" % mock_patch.called)
        self.assertTrue(mock_alarm.lower_alarm.called_with(test_uuid),
                        "mock_alarm lower_alarm not called with %s, called: %s"
                        % (test_uuid, mock_alarm.raise_alarm.called_with))
        mock_config.write_blob.assert_called_with(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS,
                                                  {"location": "somewhere", "password": "enc_password", "organization_id": "abcd"})


    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.Http.patch')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MachineAccountThread.write_machine_account_config_to_disk')    
    @mock.patch("managementconnector.platform.logarchiver.EventSender.post")
    @mock.patch('managementconnector.lifecycle.machineaccountthread.decrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.encrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MCAlarm')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.OAuth')
    def test_machine_account_alarm_raised(self, mock_oauth, mock_alarm, mock_encrypt, mock_decrypt, mock_event, mock_write_config, mock_patch, mock_config):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """

        DEV_LOGGER.info("***TEST*** test_machine_account_alarm_raised")
        mock_config.read.side_effect = config_read_side_effect
        mock_encrypt.return_value = "enc_password"
        mock_decrypt.return_value = "password"
        mock_oauth.get_account_expiration.return_value = "10"

        mock_patch.side_effect = Exception()

        stop_event = threading.Event()

        ma_thread = MachineAccountThread(mock_config, stop_event)
        ma_thread._oauth = mock_oauth

        ma_thread.failure_count = 0
        test_uuid = "bb1cf2ca-20fd-43cc-9ae2-8a33206fb9fd"
        detail = "FMC_Lifecycle MachineAccountThread: Failed to update machine account password"

        ma_thread.start()
        sleep(4)

        stop_event.set()
        # Backup join if required
        ma_thread.join(5)

        mock_event.assert_called_with(mock_oauth, mock_config, 'failure_update_machine_account', detailed_info=detail)
        self.assertTrue(mock_alarm.raise_alarm.called_with(test_uuid),
                        "mock_alarm raise_alarm not called with %s, called: %s"
                        % (test_uuid, mock_alarm.raise_alarm.called_with))
        self.assertTrue(ma_thread.update_failure)
        self.assertEqual(ma_thread.poll_time, ManagementConnectorProperties.MACHINE_POLL_TIME_FAIL)



    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.Http.patch')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.decrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.encrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MCAlarm')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.OAuth')
    def test_password_not_refreshed(self, mock_oauth, mock_alarm, mock_encrypt, mock_decrypt, mock_patch, mock_config):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """

        DEV_LOGGER.info("***TEST*** test_password_not_refreshed")
        mock_config.read.side_effect = config_read_side_effect
        mock_encrypt.return_value = "enc_password"
        mock_decrypt.return_value = "password"
        test_uuid = "bb1cf2ca-20fd-43cc-9ae2-8a33206fb9fd"

        mock_oauth.get_account_expiration.return_value = "272"

        stop_event = threading.Event()

        ma_thread = MachineAccountThread(mock_config, stop_event)
        ma_thread._oauth = mock_oauth

        ma_thread.start()
        sleep(2)

        stop_event.set()
        # Backup join if required
        ma_thread.join(5)

        self.assertFalse(mock_patch.called, "machine_runner start was called when not expected, called: %s" % mock_patch.called)

        self.assertTrue(mock_alarm.lower_alarm.called_with(test_uuid),
                        "mock_alarm lower_alarm not called with %s, called: %s"
                        % (test_uuid, mock_alarm.lower_alarm.called_with))

    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.Http.patch')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.decrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.encrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MCAlarm')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.OAuth')
    def test_account_expiration_not_set(self, mock_oauth, mock_alarm, mock_encrypt, mock_decrypt, mock_patch, mock_config):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """

        DEV_LOGGER.info("***TEST*** test_account_expiration_not_set")
        mock_config.read.side_effect = config_read_side_effect
        mock_encrypt.return_value = "enc_password"
        mock_decrypt.return_value = "password"
        test_uuid = "bb1cf2ca-20fd-43cc-9ae2-8a33206fb9fd"

        mock_oauth.get_account_expiration.return_value = None

        stop_event = threading.Event()

        ma_thread = MachineAccountThread(mock_config, stop_event)
        ma_thread._oauth = mock_oauth

        ma_thread.start()
        sleep(2)

        stop_event.set()
        # Backup join if required
        ma_thread.join(5)

        self.assertFalse(mock_patch.called, "machine_runner start was called when not expected, called: %s" % mock_patch.called)

        self.assertTrue(mock_alarm.lower_alarm.called_with(test_uuid),
                        "mock_alarm lower_alarm not called with %s, called: %s"
                        % (test_uuid, mock_alarm.lower_alarm.called_with))


    @mock.patch('managementconnector.lifecycle.machineaccountthread.ManagementConnectorProperties.MACHINE_POLL_TIME_FAIL', 1)
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.Http.patch')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.decrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.encrypt_with_system_key')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MCAlarm')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.OAuth')
    def test_machine_account_alarm_raised_and_cleared(self, mock_oauth, mock_alarm, mock_encrypt, mock_decrypt, mock_patch, mock_config):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """

        DEV_LOGGER.info("***TEST*** test_machine_account_alarm_raised_and_cleared")
        mock_config.read.side_effect = config_read_side_effect
        mock_encrypt.return_value = "enc_password"
        mock_decrypt.return_value = "password"
        mock_oauth.get_account_expiration.return_value = "10"

        mock_patch.side_effect = Exception()

        stop_event = threading.Event()

        ma_thread = MachineAccountThread(mock_config, stop_event)
        ma_thread._oauth = mock_oauth

        ma_thread.start()
        sleep(4)
        mock_patch.side_effect = None
        sleep(2)

        # Stop the test
        stop_event.set()
        # Backup join if required
        ma_thread.join(5)

        test_uuid = "bb1cf2ca-20fd-43cc-9ae2-8a33206fb9fd"

        self.assertTrue(mock_alarm.raise_alarm.called_with(test_uuid),
                        "mock_alarm raise_alarm not called with %s, called: %s"
                        % (test_uuid, mock_alarm.raise_alarm.called_with))
        self.assertTrue(mock_alarm.lower_alarm.called_with(test_uuid),
                        "mock_alarm lower_alarm not called with %s, called: %s"
                        % (test_uuid, mock_alarm.raise_alarm.called_with))

    @mock.patch('managementconnector.config.config.Config')
    @mock.patch("managementconnector.platform.logarchiver.EventSender.post")    
    @mock.patch('managementconnector.lifecycle.machineaccountthread.MCAlarm')
    @mock.patch('managementconnector.lifecycle.machineaccountthread.OAuth')
    def test_failure_to_retrieve_machine_account_details_raise_alarm(self, mock_oauth, mock_alarm, mock_event, mock_config):
        """
        User Story: DE3822 - FMC: Robustness: Machine Account Alarm Raised in Error and then not cleared
        """

        DEV_LOGGER.info("***TEST*** test_failure_to_retrieve_machine_account_details_raise_alarm")
        mock_config.read.side_effect = config_read_side_effect

        mock_oauth.get_account_expiration.side_effect = urllib_error.URLError("broken URL")

        stop_event = threading.Event()

        ma_thread = MachineAccountThread(mock_config, stop_event)
        ma_thread._oauth = mock_oauth
        # Alarm will be raised, failure_count will increased to 1, update_failure will be marked as 
        # True and failure event details will be sent to the cloud if machine account details are not 
        # retrieved.
        test_uuid = "bb1cf2ca-20fd-43cc-9ae2-8a33206fb9fd"
        ma_thread.start()
        sleep(4)

        # Stop the test
        stop_event.set()
        # Backup join if required
        ma_thread.join(5)
        detail = "FMC_Lifecycle MachineAccountThread: Failed to update machine account password"

        self.assertEqual(ma_thread.failure_count, 1)
        mock_event.assert_called_with(mock_oauth, mock_config, 'failure_update_machine_account', detailed_info=detail)
    
        self.assertTrue(mock_alarm.raise_alarm.called_with(test_uuid),
                        "mock_alarm raise_alarm not called with %s, called: %s"
                        % (test_uuid, mock_alarm.raise_alarm.called_with))
        self.assertTrue(ma_thread.update_failure)
        self.assertEqual(ma_thread.poll_time, ManagementConnectorProperties.MACHINE_POLL_TIME_FAIL)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
