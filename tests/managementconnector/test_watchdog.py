# Ignore "Missing docstring" warnings                 pylint: disable=C0111
# Ignore "Method could be a function" warnings        pylint: disable=R0201
# Ignore "Invalid name" warnings                      pylint: disable=C0103
# Ignore "Unused argument" warnings                   pylint: disable=W0613
# Ignore "No exception type(s) specified" warnings    pylint: disable=W0702
# Ignore "C0413(wrong-import-position)"               pylint: disable=C0413

import logging
import unittest
import sys
import mock
import time
import datetime
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.lifecycle.watchdog import WatchdogThread

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class WatchdogTest(unittest.TestCase):

    @mock.patch('time.sleep')
    @mock.patch('threading.Event')
    @mock.patch('managementconnector.lifecycle.watchdog.jsonhandler.read_json_file')
    @mock.patch('managementconnector.lifecycle.watchdog.jsonhandler.get_last_modified')
    @mock.patch('managementconnector.lifecycle.watchdog.WatchdogThread.restart')
    @mock.patch('managementconnector.platform.http.Http')
    @mock.patch('managementconnector.lifecycle.watchdog.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_no_heartbeat_for_longer_than_poll_time_causes_restart(self, mock_config, mock_auth, mock_http, mock_restart, mock_get_last, mock_read, mock_event, _):

        DEV_LOGGER.info("##### test_no_heartbeat_for_longer_than_poll_time_causes_restart")

        def config_read(path, default=None):
            if path == ManagementConnectorProperties.WATCHDOG_POLL_TIME:
                return 60
            elif path == ManagementConnectorProperties.INITIAL_WATCHDOG_POLL:
                return 60

        mock_event.is_set.return_value = False
        mock_config.read.side_effect = config_read
        mock_read.return_value = None

        modified_time = {ManagementConnectorProperties.HEARTBEAT_EXTENSION: 0}
        mock_get_last.return_value = modified_time

        watchdog_thread = WatchdogThread(mock_config, mock_event)
        watchdog_thread.run()

        self.assertTrue(mock_restart.called, "Restart was not called")

    @mock.patch('time.sleep')
    @mock.patch('threading.Event')
    @mock.patch('managementconnector.lifecycle.watchdog.jsonhandler.read_json_file')
    @mock.patch('managementconnector.lifecycle.watchdog.jsonhandler.get_last_modified')
    @mock.patch('managementconnector.lifecycle.watchdog.WatchdogThread.restart')
    @mock.patch('managementconnector.platform.http.Http')
    @mock.patch('managementconnector.lifecycle.watchdog.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_no_mercury_heartbeat_for_longer_than_poll_time_causes_restart(self, mock_config, mock_auth, mock_http, mock_restart, mock_get_last, mock_read, mock_event, _):

        DEV_LOGGER.info("##### test_no_mercury_heartbeat_for_longer_than_poll_time_causes_restart")

        def config_read(path, default=None):
            if path == ManagementConnectorProperties.WATCHDOG_POLL_TIME:
                return 60
            elif path == ManagementConnectorProperties.INITIAL_WATCHDOG_POLL:
                return 60

        modified_time = {ManagementConnectorProperties.HEARTBEAT_EXTENSION: time.time(),
                         ManagementConnectorProperties.MERCURY_EXTENSION: 0}

        mock_get_last.return_value = modified_time
        mock_read.return_value = None

        mock_event.is_set.return_value = False
        mock_config.read.side_effect = config_read

        watchdog_thread = WatchdogThread(mock_config, mock_event)
        watchdog_thread.run()

        self.assertTrue(mock_restart.called, "Restart was not called")

    @mock.patch('time.sleep')
    @mock.patch('threading.Event')
    @mock.patch('managementconnector.lifecycle.watchdog.Metrics.send_watchdog_restart_metrics')
    @mock.patch('managementconnector.lifecycle.watchdog.jsonhandler.read_json_file')
    @mock.patch('managementconnector.lifecycle.watchdog.jsonhandler.get_last_modified')
    @mock.patch('managementconnector.lifecycle.watchdog.WatchdogThread.restart')
    @mock.patch('managementconnector.platform.http.Http')
    @mock.patch('managementconnector.lifecycle.watchdog.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_metrics_sent_after_restart_and_no_subsequent_restart_scenario(self, mock_config, mock_auth, mock_http, mock_restart, mock_get_last, mock_read, mock_metrics, mock_event, _):
        DEV_LOGGER.info('##### test_metrics_sent_after_restart_and_no_subsequent_restart_scenario')
        # Throw exception to break out of thread loop
        watch_dog_poll = 59

        def wait_side_effect(sleep_time):
            """ throw exception if called with poll interval """
            if sleep_time == watch_dog_poll:
                raise GeneratorExit("Ignore")

        def config_read(path, default=None):
            if path == ManagementConnectorProperties.WATCHDOG_POLL_TIME:
                return watch_dog_poll
            elif path == ManagementConnectorProperties.INITIAL_WATCHDOG_POLL:
                return 60

        modified_time = {ManagementConnectorProperties.HEARTBEAT_EXTENSION: time.time(),
                         ManagementConnectorProperties.MERCURY_EXTENSION: time.time()}

        mock_get_last.return_value = modified_time
        mock_read.return_value = {"something": "broken"}

        mock_event.is_set.return_value = False

        mock_event.wait.side_effect = wait_side_effect
        mock_config.read.side_effect = config_read

        watchdog_thread = WatchdogThread(mock_config, mock_event)
        try:
            watchdog_thread.run()
        except GeneratorExit:
            # Ensure metrics gets sent if watchdog file read found something
            self.assertTrue(mock_metrics.called, "Metrics were not sent even though they should have been")

            # Ensure no restart occurs if both connections are happy
            self.assertFalse(mock_restart.called, "Restart was called even though it shouldn't have been")

            self.assertTrue(mock_get_last.called, "Get last modified not called even though it should have")

    def test_get_connection_state(self):
        """  """
        DEV_LOGGER.info('##### test_get_connection_state: happy path')
        mock_config = mock.MagicMock()
        mock_event = mock.MagicMock()

        watchdog_thread = WatchdogThread(mock_config, mock_event)

        watchdog_thread._watchdog_poll_interval = 60
        current_time = time.time()
        expected_time = datetime.datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%dT%H:%M:%SZ')
        mock_status = {ManagementConnectorProperties.HEARTBEAT_EXTENSION: current_time}

        actual_state = watchdog_thread.get_connection_state(mock_status,
                                                            ManagementConnectorProperties.HEARTBEAT_EXTENSION)

        self.assertTrue(actual_state['working'], msg="working state was False, expected True")
        self.assertEquals(actual_state['timestamp'], expected_time)

        DEV_LOGGER.info('##### test_get_connection_state: timeout exceeded')
        current_time = 0
        expected_time = datetime.datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%dT%H:%M:%SZ')
        mock_status = {ManagementConnectorProperties.HEARTBEAT_EXTENSION: current_time}
        actual_state = watchdog_thread.get_connection_state(mock_status,
                                                            ManagementConnectorProperties.HEARTBEAT_EXTENSION)

        self.assertFalse(actual_state['working'], msg="working state was True, expected False")
        self.assertEquals(actual_state['timestamp'], expected_time)

        DEV_LOGGER.info('##### test_get_connection_state: empty status files')
        mock_status = {}
        actual_state = watchdog_thread.get_connection_state(mock_status,
                                                            ManagementConnectorProperties.MERCURY_EXTENSION)

        self.assertEquals(actual_state, {}, msg="expected empty dict returned when no file exists")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
