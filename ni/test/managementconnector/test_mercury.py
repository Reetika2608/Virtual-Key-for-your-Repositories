"""
    Test Mercury
"""

import json
import io
import logging
import mock
import sys
import unittest
import time

from urllib2 import HTTPError

sys.path.append("/opt/c_mgmt/bin/")

# Append all required paths to the syspath for library imports.
from ni.managementconnector.platform.libraryutils import LibraryUtils
LibraryUtils.append_library_path()

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.cloud.mercury import Mercury

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


def config_read(path):
    """ config class mock """
    DEV_LOGGER.debug("ConfigMock: read path %s" % path)

    if path == ManagementConnectorProperties.VERSION:
        return "version"
    elif path == ManagementConnectorProperties.SERIAL_NUMBER:
        return "serialnumber"
    elif path == ManagementConnectorProperties.IPV4_ADDRESS:
        return "ipv4_address"
    elif path == ManagementConnectorProperties.HOSTNAME:
        return "hostname"
    elif path == ManagementConnectorProperties.DOMAINNAME:
        return "domain.com"
    elif path == ManagementConnectorProperties.WDM_HOST:
        return "wdm_host"
    elif path == ManagementConnectorProperties.WDM_URL:
        return "wdm_url"
    elif path == ManagementConnectorProperties.WDM_REFRESH:
        return 10
    elif path == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return {"organization_id" : "organization_id"}


class MercuryTest(unittest.TestCase):
    """ Unit test class for Mercury """

    @mock.patch('ni.managementconnector.cloud.remotedispatcher.RemoteDispatcher.register')
    @mock.patch('ni.managementconnector.cloud.wdm.time.time')
    @mock.patch('ni.managementconnector.cloud.mercury.Mercury._run_probe_timer')
    @mock.patch('ni.managementconnector.cloud.mercury.threading.Thread')
    @mock.patch('ni.managementconnector.cloud.mercury.websocket')
    @mock.patch('ni.managementconnector.cloud.wdm.jsonhandler.write_json_file')
    @mock.patch('ni.managementconnector.cloud.wdm.Http.post')
    @mock.patch('ni.managementconnector.cloud.wdm.os.path.isfile')
    @mock.patch('ni.managementconnector.cloud.mercury.Metrics')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_heartbeat_when_not_running(self, mock_config, mock_oauth, mock_metrics, mock_isfile, mock_post, mock_json, mock_socket, mock_thread, mock_timer, mock_time, mock_remotedispatcher_register):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """
        DEV_LOGGER.info("***TEST*** test_heartbeat_when_not_running")
        device_id = "9b971812-417e-4e59-98ad-4a721b6324e6"
        url = "https://wdm-a.wbx2.com/wdm/api/v1/devices/%s" % device_id
        web_socket_url = "wss://mercury-connection-a.wbx2.com"
        time_refreshed = 12345

        mock_time.return_value = time_refreshed
        mock_isfile.return_value = False
        mock_config.read.side_effect = config_read
        mock_post.return_value = {"webSocketUrl": web_socket_url,
                                  "url": url}

        expected_write_data = {"route": device_id, "device_url": url, "last_refreshed": time_refreshed}
        mercury = Mercury(mock_config, mock_oauth)
        mercury.heartbeat()
        mercury.run()

        self.assertTrue(mock_post.called, "mock_post not called as expected %s" % mock_post.called)

        mock_json.assert_called_with(ManagementConnectorProperties.MERCURY_FILE
                                     % ManagementConnectorProperties.SERVICE_NAME, expected_write_data)

    @mock.patch('ni.managementconnector.cloud.remotedispatcher.RemoteDispatcher.register')
    @mock.patch('ni.managementconnector.cloud.wdm.time.time')
    @mock.patch('ni.managementconnector.cloud.mercury.Mercury._run_probe_timer')
    @mock.patch('ni.managementconnector.cloud.mercury.threading.Thread')
    @mock.patch('ni.managementconnector.cloud.mercury.websocket')
    @mock.patch('ni.managementconnector.cloud.wdm.jsonhandler.write_json_file')
    @mock.patch('ni.managementconnector.cloud.wdm.jsonhandler.read_json_file')
    @mock.patch('ni.managementconnector.cloud.wdm.Http.put')
    @mock.patch('ni.managementconnector.cloud.wdm.os.path.isfile')
    @mock.patch('ni.managementconnector.cloud.mercury.Metrics.send_mercury_metrics')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_heartbeat_when_running(self, mock_config, mock_oauth, mock_metrics, mock_isfile, mock_put, mock_read_json, mock_write_json, mock_socket, mock_thread, mock_timer, mock_time, mock_remotedispatcher_register):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """
        DEV_LOGGER.info("***TEST*** test_heartbeat_when_running")
        device_id = "9b971812-417e-4e59-98ad-4a721b6324e6"
        device_url = "https://wdm-a.wbx2.com/wdm/api/v1/devices/%s" % device_id
        web_socket_url = "wss://mercury-connection-a.wbx2.com"
        time_refreshed = 12345
        header_val = "header"

        expected_metrics = {"running": True, "proxy_set": False,
                            "error": None, "device_url": device_url,
                            "ws_url": web_socket_url, "last_refreshed": time_refreshed}

        mock_oauth.get_header.return_value = header_val
        mock_time.return_value = time_refreshed
        mock_isfile.return_value = False
        mock_config.read.side_effect = config_read
        mock_put.return_value = {"webSocketUrl": web_socket_url, "url": device_url}

        expected_write_data = {"route": device_id, "device_url": device_url, "last_refreshed": time_refreshed}
        mock_read_json.return_value = expected_write_data

        mercury = Mercury(mock_config, mock_oauth)
        mercury._running = True
        mercury._last_refreshed = time_refreshed - 20
        mercury.heartbeat()

        self.assertTrue(mock_put.called, "mock_put not called as expected %s" % mock_put.called)
        self.assertTrue(mock_metrics.called, "send_mercury_metrics not called as expected %s" % mock_metrics.called)
        mock_write_json.assert_called_with(ManagementConnectorProperties.MERCURY_FILE
                                           % ManagementConnectorProperties.SERVICE_NAME, expected_write_data)
        mock_metrics.assert_called_with(header_val, ManagementConnectorProperties.SERVICE_NAME,
                                        expected_metrics)
        mock_remotedispatcher_register.assert_called_with(mock_oauth, mock_config)

    @mock.patch('ni.managementconnector.cloud.wdm.Http.post')
    @mock.patch('ni.managementconnector.cloud.wdm.os.path.isfile')
    @mock.patch('ni.managementconnector.cloud.mercury.Metrics')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_heartbeat_exception_on_initial_startup(self, mock_config, mock_oauth, mock_metrics, mock_isfile, mock_post):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """
        DEV_LOGGER.info("***TEST*** test_heartbeat_exception_on_initial_startup")

        mock_isfile.return_value = False
        mock_config.read.side_effect = config_read

        mock_post.side_effect = Exception()

        mercury = Mercury(mock_config, mock_oauth)
        with self.assertRaises(Exception):
            mercury.heartbeat()

    @mock.patch('ni.managementconnector.cloud.mercury.Http.get_proxy')
    @mock.patch('ni.managementconnector.cloud.wdm.DeviceManager.register_with_wdm')
    @mock.patch('ni.managementconnector.cloud.remotedispatcher.jsonhandler.delete_file')
    @mock.patch('ni.managementconnector.cloud.remotedispatcher.Http.post')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_remote_dispatcher_exception_on_initial_startup(self, mock_config, mock_oauth, mock_post, mock_delete_config, mock_wdm_register, mock_proxy):
        """
        User Story: Remote Dispatcher: Improve Mercury Connection Resiliency
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_remote_dispatcher_exception_on_initial_startup")

        mock_config.read.side_effect = config_read

        mock_proxy.return_value =  {
                'address': 'address',
                'port': 'port',
                'username': 'user_name',
                'enabled': True
            }

        mock_wdm_register.return_value = {"last_refreshed": "123"}
        mock_post.side_effect = Exception()

        mercury = Mercury(mock_config, mock_oauth)
        mercury.heartbeat()

        mock_delete_config.assert_called_with(ManagementConnectorProperties.MERCURY_FILE
                                              % ManagementConnectorProperties.SERVICE_NAME)

    @mock.patch('ni.managementconnector.cloud.wdm.time.time')
    @mock.patch('ni.managementconnector.cloud.mercury.websocket')
    @mock.patch('ni.managementconnector.cloud.wdm.jsonhandler.delete_file')
    @mock.patch('ni.managementconnector.cloud.wdm.jsonhandler.read_json_file')
    @mock.patch('ni.managementconnector.cloud.wdm.Http.put')
    @mock.patch('ni.managementconnector.cloud.wdm.os.path.isfile')
    @mock.patch('ni.managementconnector.cloud.mercury.Metrics.send_mercury_metrics')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_heartbeat_exception_when_running(self, mock_config, mock_oauth, mock_metrics, mock_isfile, mock_put, mock_read_json, mock_file_delete, mock_socket, mock_time):
        """
        User Story: US11651 FMC Hardening of WDM/Mercury Integration
        Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                    in order to create multiple objects in other threads.
        """
        DEV_LOGGER.info("***TEST*** test_heartbeat_exception_when_running")
        device_id = "9b971812-417e-4e59-98ad-4a721b6324e6"
        url = "https://wdm-a.wbx2.com/wdm/api/v1/devices/%s" % device_id
        time_refreshed = 12345

        mock_time.return_value = time_refreshed
        mock_isfile.return_value = True

        mock_config.read.side_effect = config_read
        mock_put.side_effect = Exception()

        expected_write_data = {"route": device_id, "device_url": url, "last_refreshed": time_refreshed}
        mock_read_json.return_value = expected_write_data

        mercury = Mercury(mock_config, mock_oauth)
        mercury._running = True
        mercury._last_refreshed = time_refreshed - 20
        mercury._ws = mock_socket

        with self.assertRaises(Exception):
            mercury.heartbeat()
        mock_file_delete.assert_called_with(ManagementConnectorProperties.MERCURY_FILE
                                            % ManagementConnectorProperties.SERVICE_NAME)
        self.assertTrue(mock_socket.close.called, "ws close not called as expected: %s" % mock_socket.close.called)

    @mock.patch('ni.managementconnector.cloud.mercury.Mercury.handle_mercury_exception')
    @mock.patch('ni.managementconnector.cloud.wdm.jsonhandler.read_json_file')
    @mock.patch('ni.managementconnector.cloud.wdm.Http.delete')
    @mock.patch('ni.managementconnector.cloud.wdm.os.path.isfile')
    @mock.patch('ni.managementconnector.cloud.mercury.websocket')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_wdm_deregister_exception_cleans_up_correctly(self, mock_config, mock_oauth, mock_socket, mock_delete, mock_isfile, mock_read_json, mock_handle_exception):
        """
        User Story: DE1439 - WDM Shutdown leaves Mercury Handler in bad state
        """

        DEV_LOGGER.info('***TEST*** test_wdm_deregister_exception_cleans_up_correctly')

        mock_delete.side_effect = Exception()
        mock_isfile.return_value = True

        mercury = Mercury(mock_config, mock_oauth)
        mercury._running = True
        mercury._ws = mock_socket

        mercury.on_close(None)

        mock_handle_exception.assert_called()
        self.assertFalse(mercury._running, "Mercury running is True, expected False")
        self.assertIsNone(mercury._ws, "Websocket still alive, expected None")


    @mock.patch('ni.managementconnector.cloud.remotedispatcher.jsonhandler.delete_file')
    @mock.patch('ni.managementconnector.cloud.remotedispatcher.Http.post')
    @mock.patch('ni.managementconnector.cloud.wdm.DeviceManager.refresh_with_wdm')
    @mock.patch('ni.managementconnector.cloud.wdm.time.time')
    @mock.patch('ni.managementconnector.cloud.mercury.websocket')
    @mock.patch('ni.managementconnector.cloud.mercury.Metrics.send_mercury_metrics')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_remote_dispatcher_exception_when_running(self, mock_config, mock_oauth, mock_metrics, mock_socket, mock_time, mock_wdm_refactor, mock_post, mock_delete_config):
        """
        User Story: Remote Dispatcher: Improve Mercury Connection Resiliency
        Notes:
        """
        DEV_LOGGER.info("***TEST*** test_remote_dispatcher_exception_when_running")
        time_refreshed = 12345

        mock_time.return_value = time_refreshed
        mock_config.read.side_effect = config_read

        mock_wdm_refactor.return_value = {"last_refreshed": time_refreshed}
        mock_post.side_effect = Exception()

        mercury = Mercury(mock_config, mock_oauth)
        mercury._running = True
        mercury._last_refreshed = time_refreshed - 20
        mercury._ws = mock_socket

        mercury.heartbeat()

        mock_delete_config.assert_called_with(ManagementConnectorProperties.REMOTE_DISPATCHER_FILE
                                              % ManagementConnectorProperties.SERVICE_NAME)

    @mock.patch('ni.managementconnector.cloud.mercury.Metrics.send_mercury_error_metrics')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    @mock.patch('ni.managementconnector.cloud.mercury.RemoteDispatcher.handle_command')
    def test_mercury_on_message(self, mock_handle, mock_config, mock_oauth, mock_send_err):
        """
        User Story: US12401 - Implement (start/stop/restart) command processing support in FMC
        Notes:
        """
        mercury = Mercury(mock_config, mock_oauth)
        sig = "DJncdDpoYSmYG1f3ssFjNKdYRST5/Nm4igF6JHZSo2EO5s1pezv2pFJudXIPb4P95wFcM7bwolbWTwMuZABGr2fB7PEeqRqzHtYUSV+mC2p6HOuMU3FiT1N9vsOLU9nTB6zm+u2ov5Ab08VpH2kueQ+eVxavshVHrMGXdZUk7HI8WEJmgNFle1xEZaLRF0VALT5bx+Z5TpPiLvbmpMjFzN2a00JTORgwaCvwGS0AfndlEPjoLQMsau1AouZLQaSipM2KLUv51hrUtZ0ZLXODaaaFgiIw4L1YgUpCzTJkS0pWRDg3yHzS6myeMFERRSGG89rc3wh3yObuBnyV+NPzXg=="

        # Assert missing data in the mercury message doesn't call
        # handle_command when a json schema validation error occurs
        empty = "{}"
        mercury.on_message(None, empty)
        mock_handle.assert_not_called()

        # Assert missing sig or eventType in the mercury message doesn't call
        # handle_command when a json schema validation error occurs

        no_sig = '{"data": {}}'
        mercury.on_message(None, no_sig)
        mock_handle.assert_not_called()

        # Assert valid data that matches schema passes through to handle command
        good_command = '{"data": {"command": {"action": "start", "commandId": "12345", "parameters": ["param1", "param2"], "dispatcher": "me"}, "eventType": "type", "signature": "%s"}, "trackingId": "NA_6cc9c187-cd7f-4da0-9086-3557bedecdc1"}' % sig
        mercury.on_message(None, good_command)
        mock_handle.assert_called_with(json.loads(good_command))

    @mock.patch('ni.managementconnector.cloud.mercury.Metrics')
    @mock.patch('ni.managementconnector.cloud.mercury.Mercury.get_device_url')
    @mock.patch('ni.managementconnector.cloud.mercury.traceback.format_exc')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_handle_mercury_exception(self, mock_config, mock_oauth, mock_format, mock_get_device, mock_metrics):
        """
        User Story: US12401 - Implement (start/stop/restart) command processing support in FMC
        Notes:
        """

        DEV_LOGGER.info("***TEST*** test_handle_mercury_exception")
        device_url = "12345"
        error_response = "error_response"
        stream = io.TextIOWrapper(io.BytesIO(error_response))
        header_val = "header"
        mocked_format = "stacktrace"

        http_exception = HTTPError('http://cafe-test.cisco.com', "404", "reason", "hdrs", stream)

        expected_content = {"error_type": str(http_exception.__class__), "stacktrace": mocked_format,
                            "error_reason": "reason", "error_response": error_response, "device_url": device_url}

        mock_oauth.get_header.return_value = header_val
        mock_format.return_value = mocked_format
        mock_get_device.return_value = device_url

        # Create Mercury Object and call handle
        mercury = Mercury(mock_config, mock_oauth)
        mercury._metrics = mock_metrics
        mercury.handle_mercury_exception(http_exception)

        # Assert Send error is called when an exception is passed
        mock_metrics.send_mercury_error_metrics.assert_called_with(header_val, ManagementConnectorProperties.SERVICE_NAME, expected_content)

    @mock.patch('ni.managementconnector.cloud.mercury.Mercury.handle_missing_mercury_probe')
    @mock.patch('ni.managementconnector.cloud.mercury.threading.Thread')
    @mock.patch('ni.managementconnector.cloud.mercury.websocket')
    @mock.patch('ni.managementconnector.cloud.wdm.jsonhandler.read_json_file')
    @mock.patch('ni.managementconnector.cloud.wdm.Http')
    @mock.patch('ni.managementconnector.cloud.wdm.os.path.isfile')
    @mock.patch('ni.managementconnector.cloud.wdm.time.time')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_missing_mercury_probe_increments_counter(self, mock_config, mock_oauth, mock_time, mock_isfile, mock_http, mock_read_json, mock_socket, mock_thread, mock_handler):
        """
        User Story: US9628 - FMC: Mercury Probe Implementation
        """
        DEV_LOGGER.info("***TEST*** test_missing_mercury_probe_increments_counter")
        device_id = "9b971812-417e-4e59-98ad-4a721b6324e6"
        device_url = "https://wdm-a.wbx2.com/wdm/api/v1/devices/%s" % device_id
        web_socket_url = "wss://mercury-connection-a.wbx2.com"
        time_refreshed = 12345
        header_val = "header"

        mock_oauth.get_header.return_value = header_val
        mock_time.return_value = time_refreshed
        mock_isfile.return_value = False
        mock_config.read.side_effect = config_read
        mock_http.put.return_value = {"webSocketUrl": web_socket_url, "url": device_url}

        expected_write_data = {"route": device_id, "device_url": device_url, "last_refreshed": time_refreshed}
        mock_read_json.return_value = expected_write_data

        previous_value = ManagementConnectorProperties.MERCURY_PROBE_TIMEOUT
        ManagementConnectorProperties.MERCURY_PROBE_TIMEOUT = 5
        mercury = Mercury(mock_config, mock_oauth)
        mercury._running = True
        mercury._last_refreshed = time_refreshed - 20
        mercury.heartbeat()

        time.sleep(ManagementConnectorProperties.MERCURY_PROBE_TIMEOUT)

        ManagementConnectorProperties.MERCURY_PROBE_TIMEOUT = previous_value
        mock_handler.assert_called()

    @mock.patch('ni.managementconnector.cloud.mercury.Mercury._run_probe_timer')
    @mock.patch('ni.managementconnector.cloud.remotedispatcher.RemoteDispatcher.register')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_missing_mercury_probe_registers_with_remote_dispatcher(self, mock_config, mock_oauth, mock_register, mock_timer):
        """
        User Story: US9628 - FMC: Mercury Probe Implementation
        """

        DEV_LOGGER.info("***TEST*** test_missing_multiple_mercury_probes_resets_websocket")
        mercury = Mercury(mock_config, mock_oauth)
        mercury._running = True
        mercury._missed_mercury_probes = 0

        mercury.handle_missing_mercury_probe()
        mock_register.assert_called_with(mock_oauth, mock_config)
        self.assertEqual(mercury._missed_mercury_probes, 1)


    @mock.patch('ni.managementconnector.cloud.mercury.Mercury.heartbeat')
    @mock.patch('ni.managementconnector.cloud.mercury.Mercury.shutdown')
    @mock.patch('ni.managementconnector.cloud.mercury.websocket.WebSocketApp')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_missing_multiple_mercury_probes_resets_websocket(self, mock_config, mock_oauth, mock_socket, mock_shutdown, mock_heartbeat):
        """
        User Story: US9628 - FMC: Mercury Probe Implementation
        """

        DEV_LOGGER.info("***TEST*** test_missing_multiple_mercury_probes_resets_websocket")
        mercury = Mercury(mock_config, mock_oauth)
        mercury._running = True
        mercury._ws = mock_socket
        mercury._missed_mercury_probes = ManagementConnectorProperties.MERCURY_PROBE_LIMIT

        mercury.handle_missing_mercury_probe()
        mock_shutdown.assert_called()
        mock_heartbeat.assert_called()
        self.assertEqual(mercury._missed_mercury_probes, 0)

    @mock.patch('ni.managementconnector.cloud.mercury.Mercury._run_probe_timer')
    @mock.patch('ni.managementconnector.cloud.remotedispatcher.RemoteDispatcher.handle_command')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_receiving_mercury_probe_clears_counter(self, mock_config, mock_oauth, mock_handle, mock_runner):
        """
        User Story: US9628 - FMC: Mercury Probe Implementation
        """

        DEV_LOGGER.info("***TEST*** test_receiving_mercury_probe_clears_counter")

        command = '{"data": {"eventType": "type", "signature": "test"}}'

        mercury = Mercury(mock_config, mock_oauth)
        mercury._missed_mercury_probes = 2
        mercury._mercury_probe_timer = "test"
        mercury.on_message(None, command)

        self.assertEqual(mercury._missed_mercury_probes, 0)
        mock_runner.assert_called_with(False)
        mock_handle.assert_not_called()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()