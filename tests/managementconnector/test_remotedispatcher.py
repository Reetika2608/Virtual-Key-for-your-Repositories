"""
    Test RemoteDispatcher
"""
# Ignore "Method could be a function" warnings        pylint: disable=R0201

import unittest
import logging
import mock
import sys

from .constants import SYS_LOG_HANDLER
# Pre-import a mocked pyinotify
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from pyfakefs import fake_filesystem_unittest
from .productxml import PRODUCT_XML_CONTENTS
from managementconnector.cloud.remotedispatcher import RemoteDispatcher
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


def config_read(path):
    """ config class mock """
    DEV_LOGGER.debug("ConfigMock: read path %s" % path)

    if path == ManagementConnectorProperties.ENABLED_SERVICES_STATE:
        return {"c_cal": "true", "c_ucmc": "true", "c_mgmt": "true"}
    elif path == ManagementConnectorProperties.ENTITLED_SERVICES:
        return [{"display_name": "Call Connector", "name": "c_ucmc"},
                {"display_name": "Management Connector", "name": "c_mgmt"},
                {"display_name": "Calendar Connector", "name": "c_cal"}]
    elif path == ManagementConnectorProperties.LOGGING_QUANTITY:
        return "50"
    elif path == ManagementConnectorProperties.SERIAL_NUMBER:
        return "ABC12345"


class RemoteDispatcherTest(fake_filesystem_unittest.TestCase):
    """RemoteDispatcher unit tests"""

    def setUp(self):
        self.command = {
            "id": "1",
            "data": {
                "command": {
                    "commandId": "159b5d02-127b-469f-b33a-4dfde4526b1c",
                    "connectorId": "c_mgmt@52A00612",
                    "action": "ping",
                    "created": "2016-08-05T14:48:05.656Z",
                    "updated": "2016-08-05T14:48:05.656Z",
                    "status": "dispatched",
                    "dispatcher": "167ff991-1360-4bfb-8319-b85e240e1ccb"
                },
                "signature": "DJncdDpoYSmYG1f3ssFjNKdYRST5/Nm4igF6JHZSo2EO5s1pezv2pFJudXIPb4P95wFcM7bwolbWTwMuZABGr2fB7PEeqRqzHtYUSV+mC2p6HOuMU3FiT1N9vsOLU9nTB6zm+u2ov5Ab08VpH2kueQ+eVxavshVHrMGXdZUk7HI8WEJmgNFle1xEZaLRF0VALT5bx+Z5TpPiLvbmpMjFzN2a00JTORgwaCvwGS0AfndlEPjoLQMsau1AouZLQaSipM2KLUv51hrUtZ0ZLXODaaaFgiIw4L1YgUpCzTJkS0pWRDg3yHzS6myeMFERRSGG89rc3wh3yObuBnyV+NPzXg==",
                "eventType": "hybrid.command"
            },
            "timestamp": 1470408486731,
            "trackingId": "NA_4016d871-3ccc-4d89-a61a-9c0f9c10ed0c",
            "headers": {},
            "sequenceNumber": 1
        }

    @mock.patch('managementconnector.cloud.remotedispatcher.json')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.write_config_to_disk')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.get_mercury_config')
    @mock.patch('managementconnector.cloud.remotedispatcher.Http.post')
    def test_register(self, mock_http_post, mock_get_mercury_config, mock_write_config, _):
        """ User Story: US13960 Implement FMC and RemoteDispatcher interaction (Register/Ping)"""
        DEV_LOGGER.info("***TEST*** test_register")

        config = mock.MagicMock()
        oauth = mock.MagicMock()
        mock_response = {'connectorId': "test", "connectorType": "test"}
        mock_get_mercury_config.return_value = {'route': 'abc'}
        mock_http_post.return_value = mock_response
        self.assertIsNotNone(RemoteDispatcher.get_mercury_config())
        RemoteDispatcher.register(oauth, config)
        self.assertTrue(mock_http_post.called, 'Register http post is not called.')
        mock_write_config.assert_called_with(mock_response)

    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.delete_config_from_disk')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.get_mercury_config')
    @mock.patch('managementconnector.cloud.remotedispatcher.Http')
    def test_register_no_mercury(self, mock_http, mock_get_mercury_config, mock_delete_config):
        """ User Story: US13960 Implement FMC and RemoteDispatcher interaction (Register/Ping)"""
        DEV_LOGGER.info("***TEST*** test_register_no_mercury")

        config = mock.MagicMock()
        oauth = mock.MagicMock()
        mock_get_mercury_config.return_value = ''
        RemoteDispatcher.register(oauth, config)
        self.assertFalse(mock_http.post.called, 'Register is called but it should not be.')
        self.assertTrue(mock_delete_config.called, 'Config file delete was not called')

    def test_verifying_signature(self):
        """ User Story: US13960 Implement FMC and RemoteDispatcher interaction (Register/Ping)"""
        DEV_LOGGER.info("***TEST*** test_verifying_signature")
        RemoteDispatcher.config = mock.Mock()
        RemoteDispatcher.config.read.return_value = 'true'

        self.assertTrue(RemoteDispatcher.verify_signature(self.command), "Signature should be authentic in test mode")

        # RemoteDispatcher.config.read.return_value = 'false'
        # self.assertFalse(RemoteDispatcher.verify_signature(self.command), "Signature should not be authentic")

    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.verify_signature')
    @mock.patch('os.system')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.process_connectivity_check')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.process_push_logs')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.process_ping')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.send_result_to_remotedispatcher')
    def test_handling_command(self, mock_send_result, mock_process_ping, mock_process_push_logs,
                              mock_process_connectivity_check, mock_os_system, _):
        """ User Story: US13960 Implement FMC and RemoteDispatcher interaction (Register/Ping)"""
        DEV_LOGGER.info("***TEST*** test_handling_command")

        config_mock = mock.MagicMock()
        config_mock.read.side_effect = config_read
        RemoteDispatcher.config = config_mock

        # test ping command
        mock_process_ping.return_value = 'ping output'
        RemoteDispatcher.handle_command(self.command)
        mock_send_result.assert_called_with('complete', self.command['data']['command']['commandId'],
                                            {ManagementConnectorProperties.SERVICE_NAME: 'ping output'})

        # test stop command
        self.command['data']['command']['action'] = 'stop'
        self.command['data']['command']['parameters'] = ["c_cal"]
        service_command = "echo 'stop c_cal' > %s" % ManagementConnectorProperties.SERVICE_CONTROL_REQUEST
        RemoteDispatcher.handle_command(self.command)
        mock_os_system.assert_called_with(service_command)
        mock_send_result.assert_called_with('complete', self.command['data']['command']['commandId'], {})

        # test command with string parameter
        self.command['data']['command']['action'] = 'stop'
        self.command['data']['command']['parameters'] = "c_cal"
        service_command = "echo 'stop c_cal' > %s" % ManagementConnectorProperties.SERVICE_CONTROL_REQUEST
        RemoteDispatcher.handle_command(self.command)
        mock_os_system.assert_called_with(service_command)
        mock_send_result.assert_called_with('complete', self.command['data']['command']['commandId'], {})

        # test stop not called on c_mgmt command
        c_mgmt_command = self.command
        c_mgmt_command['data']['command']['action'] = 'stop'
        c_mgmt_command['data']['command']['parameters'] = ["c_mgmt"]
        mock_os_system.reset_mock()
        mock_send_result.reset_mock()

        RemoteDispatcher.handle_command(c_mgmt_command)
        mock_os_system.assert_not_called()
        mock_send_result.assert_called_with('complete', c_mgmt_command['data']['command']['commandId'], {'c_mgmt': 'Stopping c_mgmt is not permitted.'})

        # test push_logs command
        mock_send_result.reset_mock()
        c_mgmt_command['data']['command']['action'] = 'push_logs'
        mock_process_push_logs.return_value = {}, 'complete'
        RemoteDispatcher.handle_command(c_mgmt_command)
        mock_send_result.assert_called_with('complete', c_mgmt_command['data']['command']['commandId'], {})

        # test an invalid command
        self.command['data']['command']['action'] = 'invalid_action'
        RemoteDispatcher.handle_command(self.command)
        mock_send_result.assert_called_with('unrecognized_command', self.command['data']['command']['commandId'], {})

        # test a connectivity check command
        mock_process_connectivity_check.return_value = {}, 'complete'
        self.command['data']['command']['action'] = 'check_connection'
        c_mgmt_command['data']['command']['parameters'] = ['https://www.123.abc']
        RemoteDispatcher.handle_command(self.command)
        mock_process_connectivity_check.assert_called_with('https://www.123.abc')

        # Clean-up optional params
        del(self.command['data']['command']['parameters'])

    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.verify_signature')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.send_result_to_remotedispatcher')
    def test_command_without_id(self, mock_send_result, _):
        """ User Story: US13960 Implement FMC and RemoteDispatcher interaction (Register/Ping)"""        # if there is no commandId, it should not send the result back to remotedispatcher
        DEV_LOGGER.info("***TEST*** test_command_without_id")

        self.command['data']['command']['commandId'] = None
        RemoteDispatcher.handle_command(self.command)
        self.assertFalse(mock_send_result.called, 'send_result_to_remotedispatcher is called when it should not be.')

    @mock.patch('managementconnector.cloud.remotedispatcher.CafeXUtils.get_installed_connectors')
    @mock.patch('managementconnector.cloud.remotedispatcher.ServiceUtils.get_service_start_time')
    @mock.patch('managementconnector.cloud.remotedispatcher.ServiceUtils.get_connector_status_by_name')
    @mock.patch('managementconnector.cloud.remotedispatcher.ServiceManager.get')
    def test_processing_ping(self, mock_service_mgr, mock_connector_status, mock_start_time, mock_connectors):
        """ User Story: US13960 Implement FMC and RemoteDispatcher interaction (Register/Ping)"""
        DEV_LOGGER.info("***TEST*** test_processing_ping")
        self.setUpPyfakefs()
        self.fs.create_file('/info/product_info.xml', contents=PRODUCT_XML_CONTENTS)

        class MockService():
            def get_composed_status(self):
                return "running"

        RemoteDispatcher.config = mock.Mock()
        installed_connectors = ["c_mgmt", "c_cal"]
        start_time = "12345"
        expected_status = {"c_mgmt": {"state": "running", "status": "operational", "startTime": start_time},
                           "c_cal": {"state": "running", "status": "operational", "startTime": start_time}}

        mock_service_mgr.return_value = MockService()
        mock_connectors.return_value = installed_connectors
        mock_connector_status.return_value = "operational"
        mock_start_time.return_value = start_time

        status = RemoteDispatcher.process_ping()
        DEV_LOGGER.info("RemoteDispatcher process_ping: status: %s", status)

        self.assertEqual(status, expected_status)

    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.verify_signature')
    @mock.patch('managementconnector.cloud.remotedispatcher.System.am_i_master')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.send_result_to_remotedispatcher')
    def test_handling_enable_with_two_params(self, mock_send_result, mock_master, _):
        """ User Story: US14321 Implement (enable/disable) command processing support in FMC """

        config_mock = mock.MagicMock()
        config_mock.read.side_effect = config_read

        RemoteDispatcher.config = config_mock
        mock_master.return_value = True

        # Test enable can be called on two params
        self.command['data']['command']['action'] = 'enable'
        self.command['data']['command']['parameters'] = ["c_cal", "c_ucmc"]

        RemoteDispatcher.handle_command(self.command)
        mock_send_result.assert_called_with('complete', self.command['data']['command']['commandId'], {})
        self.assertTrue(RemoteDispatcher.config.update_blob_entries.called)

        # Clean-up optional params
        del(self.command['data']['command']['parameters'])

    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.verify_signature')
    @mock.patch('managementconnector.cloud.remotedispatcher.System.am_i_master')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.send_result_to_remotedispatcher')
    def test_handling_enable_with_no_params(self, mock_send_result, mock_master, _):
        """ User Story: US14321 Implement (enable/disable) command processing support in FMC """
        # Test enable with no params
        config_mock = mock.MagicMock()
        config_mock.read.side_effect = config_read

        RemoteDispatcher.config = config_mock
        mock_master.return_value = True

        mock_send_result.reset_mock()
        RemoteDispatcher.config.reset_mock()
        self.command['data']['command']['action'] = 'enable'
        self.command['data']['command']['parameters'] = None

        RemoteDispatcher.handle_command(self.command)
        self.assertFalse(RemoteDispatcher.config.update_blob_entries.called)
        mock_send_result.assert_called_with('complete', self.command['data']['command']['commandId'],
                                            {'c_mgmt': 'Invalid command - parameters were expected'})

        # Clean-up optional params
        del(self.command['data']['command']['parameters'])

    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.verify_signature')
    @mock.patch('managementconnector.cloud.remotedispatcher.System.am_i_master')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.send_result_to_remotedispatcher')
    def test_handling_enable_with_unrecognised_connector(self, mock_send_result, mock_master, _):
        """ User Story: US14321 Implement (enable/disable) command processing support in FMC """

        config_mock = mock.MagicMock()
        config_mock.read.side_effect = config_read

        RemoteDispatcher.config = config_mock
        mock_master.return_value = True

        # Test unrecognised connector
        mock_send_result.reset_mock()
        RemoteDispatcher.config.reset_mock()
        self.command['data']['command']['action'] = 'enable'
        self.command['data']['command']['parameters'] = ["c_cal", "c_doesnt_exist"]

        RemoteDispatcher.handle_command(self.command)
        self.assertFalse(RemoteDispatcher.config.update_blob_entries.called)
        mock_send_result.assert_called_with('complete', self.command['data']['command']['commandId'],
                                            {'c_mgmt': 'audit_connectors - not entitled for c_doesnt_exist'})

        # Clean-up optional params
        del(self.command['data']['command']['parameters'])

    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.verify_signature')
    @mock.patch('managementconnector.cloud.remotedispatcher.System.am_i_master')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.send_result_to_remotedispatcher')
    def test_handling_enable_not_allowed_on_c_mgmt(self, mock_send_result, mock_master, _):
        """ User Story: US14321 Implement (enable/disable) command processing support in FMC """

        config_mock = mock.MagicMock()
        config_mock.read.side_effect = config_read

        RemoteDispatcher.config = config_mock
        mock_master.return_value = True

        # Test enable/disable not allowed for c_mgmt
        mock_send_result.reset_mock()
        RemoteDispatcher.config.reset_mock()
        self.command['data']['command']['action'] = 'enable'
        self.command['data']['command']['parameters'] = ["c_mgmt", "c_cal"]

        RemoteDispatcher.handle_command(self.command)
        self.assertFalse(RemoteDispatcher.config.update_blob_entries.called)
        mock_send_result.assert_called_with('complete', self.command['data']['command']['commandId'],
                                            {'c_mgmt': 'Enable/Disable on c_mgmt not permitted'})

        # Clean-up optional params
        del(self.command['data']['command']['parameters'])

    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.verify_signature')
    @mock.patch('managementconnector.cloud.remotedispatcher.System.am_i_master')
    @mock.patch('managementconnector.cloud.remotedispatcher.RemoteDispatcher.send_result_to_remotedispatcher')
    def test_handling_enable_not_handled_on_peers(self, mock_send_result, mock_master, _):
        """ User Story: US14321 Implement (enable/disable) command processing support in FMC """

        config_mock = mock.MagicMock()
        config_mock.read.side_effect = config_read

        RemoteDispatcher.config = config_mock
        mock_master.return_value = False

        # Test Enable/Disable shouldn't be run on peer nodes
        # scenario doesn't make sense to enable a peer even if master is down
        # start or stop or restart would make more sense
        self.command['data']['command']['action'] = 'enable'
        self.command['data']['command']['parameters'] = ["c_cal", "c_ucmc"]

        RemoteDispatcher.handle_command(self.command)
        mock_send_result.assert_called_with('complete', self.command['data']['command']['commandId'],
                                            {'c_mgmt': 'Enable/Disable will be handled by master node in cluster'})
        self.assertFalse(RemoteDispatcher.config.update_blob_entries.called)

        # Clean-up optional params
        del(self.command['data']['command']['parameters'])

    @mock.patch('managementconnector.cloud.remotedispatcher.json')
    @mock.patch('managementconnector.cloud.remotedispatcher.Http')
    def test_sending_result_to_remotedispatcher(self, mock_http, mock_json):
        """ User Story: US13960 Implement FMC and RemoteDispatcher interaction (Register/Ping)"""
        data = {
            "commandId": "aaa-bbb-ccc",
            "status": "completed",
            "commandOutput": mock_json.dumps("ping output")
        }

        RemoteDispatcher.send_result_to_remotedispatcher("completed", "aaa-bbb-ccc", "ping output")
        mock_http.patch.assert_called_with(RemoteDispatcher.get_command_url(), RemoteDispatcher.oauth.get_header(), mock_json.dumps(data))

    @mock.patch('managementconnector.platform.logarchiver.LogArchiver.push_logs')
    def test_processing_push_logs(self, mock_logarchiver_push_log):
        """ User Story: US13960 Implement FMC and RemoteDispatcher interaction (Register/Ping) """
        mock_logarchiver_push_log.return_value = {'logsearchId': '12345', 'status' : 'complete'}
        RemoteDispatcher.oauth = mock.Mock()
        command_output, status = RemoteDispatcher.process_push_logs('12345')
        self.assertEqual(status, 'complete')
        self.assertEqual(command_output['c_mgmt'], {'logsearchId': '12345', 'status' : 'complete'})

    def test_processing_push_logs_without_logsearchId(self):
        """ User Story: US13960 Implement FMC and RemoteDispatcher interaction (Register/Ping) """
        command_output, status = RemoteDispatcher.process_push_logs(None)
        self.assertEqual(status, 'error')
        self.assertEqual(command_output['c_mgmt'], {'logsearchId': 'Not provided'})

    @mock.patch('managementconnector.platform.corearchiver.CoreArchiver.retrieve_and_archive_cores')
    def test_processing_core_dump(self, mock_core_dump):
        """ User Story: US13627 RD: New Command for Gathering Cores """
        mock_core_dump.return_value = {'searchId': '12345', 'status' : 'complete'}
        RemoteDispatcher.oauth = mock.Mock()
        command_output, status = RemoteDispatcher.process_core_dump('12345')
        self.assertEqual(status, 'complete')
        self.assertEqual(command_output['c_mgmt'], {'searchId': '12345', 'status' : 'complete'})

    def test_processing_core_dump_without_searchId(self):
        """ User Story: US13627 RD: New Command for Gathering Cores """
        command_output, status = RemoteDispatcher.process_core_dump(None)
        self.assertEqual(status, 'error')
        self.assertEqual(command_output['c_mgmt'], {'searchId': 'Not provided'})

    @mock.patch('managementconnector.platform.connectivitycheck.ConnectivityCheck.check_connectivity_to_url')
    def test_processing_connectivity_check(self, mock_connectivity_check):
        """ User Story: SPARK-31235 RD: New Command to Test Connectivity """
        url = 'https://www.123.abc'
        #GET passed, ping passed
        mock_connectivity_check.return_value = {'pingResult': 'passed', 'getResult': 'passed', 'url': url}
        RemoteDispatcher.oauth = mock.Mock()
        command_output, status = RemoteDispatcher.process_connectivity_check(url)
        self.assertEqual(status, 'complete')
        self.assertEqual(command_output['c_mgmt'], {'pingResult': 'passed', 'getResult': 'passed', 'url': url})

        #GET passed, ping failed
        mock_connectivity_check.resest_mock()
        mock_connectivity_check.return_value = {'pingResult': 'failed', 'getResult': 'passed', 'url': url}
        command_output, status = RemoteDispatcher.process_connectivity_check(url)
        self.assertEqual(status, 'complete')
        self.assertEqual(command_output['c_mgmt'], {'pingResult': 'failed', 'getResult': 'passed', 'url': url})

        #GET not_found, ping passed
        mock_connectivity_check.resest_mock()
        mock_connectivity_check.return_value = {'pingResult': 'passed', 'getResult': 'not_found', 'url': url}
        command_output, status = RemoteDispatcher.process_connectivity_check(url)
        self.assertEqual(status, 'complete')
        self.assertEqual(command_output['c_mgmt'], {'pingResult': 'passed', 'getResult': 'not_found', 'url': url})

        #GET cert_error, ping failed
        mock_connectivity_check.resest_mock()
        mock_connectivity_check.return_value = {'pingResult': 'failed', 'getResult': 'not_found', 'url': url}
        command_output, status = RemoteDispatcher.process_connectivity_check(url)
        self.assertEqual(status, 'complete')
        self.assertEqual(command_output['c_mgmt'], {'pingResult': 'failed', 'getResult': 'not_found', 'url': url})

    def test_processing_connectivity_check_without_url(self):
        """ User Story: SPARK-31235 RD: New Command to Test Connectivity """
        command_output, status = RemoteDispatcher.process_connectivity_check(None)
        self.assertEqual(status, 'error')
        self.assertEqual(command_output['c_mgmt'], {'url': 'Not provided'})

    def test_processing_connectivity_check_with_http_url(self):
        """ User Story: SPARK-31235 RD: New Command to Test Connectivity """
        command_output, status = RemoteDispatcher.process_connectivity_check('http://www.123.abc')
        self.assertEqual(status, 'error')
        self.assertEqual(command_output['c_mgmt'], {'url': 'HTTP not supported'})

    @mock.patch('glob.glob')
    @mock.patch('os.path.basename')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.getsize')
    @mock.patch('os.path.getmtime')
    @mock.patch('subprocess.check_output')
    @mock.patch("managementconnector.config.config.Config")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch("managementconnector.cloud.remotedispatcher.AtlasLogger")
    @mock.patch("managementconnector.platform.logarchiver.EventSender.post")
    @mock.patch('managementconnector.platform.logarchiver.time.time')
    @mock.patch('managementconnector.platform.logarchiver.LogArchiver.gather_status_files')
    @mock.patch('managementconnector.platform.logarchiver.LogArchiver.generate_log_name')
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_archive")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_config_files")
    @mock.patch('managementconnector.platform.logarchiver.LogArchiver.gather_config_files')
    def test_config_sent_rd_logs(self, mock_gather_config, mock_rm_config, mock_rm_archive, mock_logname,
                                        mock_gstatus, mock_time, mock_event, mock_atlas, mock_json, mock_config,
                                        mock_sub, mock_getmtime, mock_size, mock_exists, mock_base, mock_glob):
        """ User Story: US25211 RemoteDispatcher should not include JSON File """
        # Configure mocks
        config_mock = mock.MagicMock()
        config_mock.read.side_effect = config_read

        RemoteDispatcher.config = config_mock
        RemoteDispatcher.oauth = mock.Mock()
        command_output, status = RemoteDispatcher.process_push_logs('12345')
        self.assertTrue(mock_gather_config.called)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
