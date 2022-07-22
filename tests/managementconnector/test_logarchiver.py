import unittest
import mock
import logging
import sys
from .constants import SYS_LOG_HANDLER

# Pre-import a mocked pyinotify
sys.modules['pyinotify'] = mock.MagicMock()
logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.platform.logarchiver import LogArchiver
from managementconnector.platform.http import CertificateExceptionInvalidCert

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class LogArchiverTest(unittest.TestCase):
    """ Unit test class for LogArchiver """

    @mock.patch("managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("managementconnector.config.config.Config")
    def test_validate_request_with_no_last_known_log_id_returns_true(self, mock_config, mock_read_json_file):
        """ User Story: US16645: Add Push Log Command """
        log_request_id = "12345"
        mock_read_json_file.return_value = None
        expected_log_entry = (True, {"logsearchId": log_request_id, "status": "starting"})
        log_entry = LogArchiver.validate_request(mock_config, log_request_id)
        self.assertEqual(log_entry, expected_log_entry)

    @mock.patch("managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("managementconnector.config.config.Config")
    def test_validate_request_with_same_last_known_log_id_returns_false(self, mock_config, mock_read_json_file):
        """ User Story: US16645: Add Push Log Command """
        log_request_id = "12345"        
        mock_read_json_file.return_value = {"logsearchId": log_request_id}
        expected_log_entry = (False, {"logsearchId": log_request_id, "status": "log_uuid_unchanged"})
        log_entry = LogArchiver.validate_request(mock_config, log_request_id)
        self.assertEqual(log_entry, expected_log_entry)

    @mock.patch("managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("managementconnector.config.config.Config")
    def test_validate_request_with_no_a_log_request_id_not_passed_or_in_config_returns_false(self, mock_config, mock_read_json_file):
        """ User Story: US16645: Add Push Log Command """
        log_request_id = ""
        mock_read_json_file.return_value = None
        mock_config.read.return_value = None
        expected_log_entry = (False, {"logsearchId": log_request_id, "status": "no_log_uuid"})
        log_entry = LogArchiver.validate_request(mock_config, log_request_id)
        self.assertEqual(log_entry, expected_log_entry)

    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.validate_request")
    @mock.patch("managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("managementconnector.config.config.Config")
    def test_push_logs_doesnt_push_log_if_request_is_not_valid(self, mock_config, mock_atlas_logger, mock_validate_request):
        """ User Story: US16645: Add Push Log Command """
        log_request_id = ""
        log_entry = {"logsearchId": log_request_id, "status" : "no_log_uuid"}
        mock_validate_request.return_value = False, log_entry
        push_log_response = LogArchiver.push_logs(mock_config, mock_atlas_logger, log_request_id)
        self.assertEqual(log_entry, push_log_response)

    @mock.patch("managementconnector.platform.logarchiver.time.time")
    @mock.patch("managementconnector.platform.logarchiver.EventSender.post")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch("os.path.getsize")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_archive")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_config_files")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.build_archive")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.validate_request")
    @mock.patch("managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("managementconnector.config.config.Config")
    def test_push_logs_does_push_log_if_request_is_valid(self, mock_config, mock_atlas_logger, mock_validate_request, mock_build_archive,
                                                  mock_rm_config, mock_rm_archive, mock_get_size, mock_write_json_file, mock_event_post,
                                                  mock_time):
        """ User Story: US16645: Add Push Log Command """
        log_request_id = "12345"
        log_entry = {"logsearchId": log_request_id, "status" : "starting"}
        mock_validate_request.return_value = True, log_entry
        mock_build_archive.return_value = [0, "command output", "log_file_name", 0]
        mock_get_size.return_value = 0
        mock_time.return_value = 1234
        mock_atlas_logger.post_log.return_value = [0, 54321]

        mock_get_oauth = mock.Mock()
        mock_atlas_logger.get_oauth.return_value = mock_get_oauth

        push_log_response = LogArchiver.push_logs(mock_config, mock_atlas_logger, log_request_id)
        mock_build_archive.mock_build_archive("blah")
        log_entry = {"logsearchId": log_request_id, "status": "complete"}
        mock_write_json_file.assert_called_with(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)
        tracking_info = {'serial_number': mock_config.read(ManagementConnectorProperties.SERIAL_NUMBER), 'tracking_id': log_request_id}
        mock_atlas_logger.post_log.assert_called_with(tracking_info, "log_file_name")

        mock_rm_archive.assert_called_with("log_file_name")
        mock_event_post.assert_called_with(mock_get_oauth,
                                           mock_config,
                                           "logpush",
                                           "c_mgmt",
                                           1234,
                                           {"fields": {"archiveDuration": 0, "batchSize": 1,
                                                       "uploadDuration": 54321,
                                                       "logsearchId": "12345", "fileSize": 0},
                                            "tags": {"state": "success"},
                                            "measurementName": "logPushEvent"})

        self.assertEqual(log_entry, push_log_response)

    @mock.patch("os.path.getsize")
    @mock.patch("managementconnector.platform.logarchiver.time.time")
    @mock.patch("managementconnector.platform.logarchiver.EventSender.post")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_archive")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_config_files")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.build_archive")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.validate_request")
    @mock.patch("managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("managementconnector.config.config.Config")
    def test_push_log_emits_event_on_exception(self, mock_config, mock_atlas_logger, mock_validate_request, mock_build_archive,
                                                  mock_rm_config, mock_rm_archive, mock_write_json_file, mock_event_post,
                                                  mock_time, mock_get_size):
        """ User Story: US17337: Metrics: Key Events: FMC log push metrics """
        log_request_id = "12345"
        log_entry = {"logsearchId": log_request_id, "status": "starting"}
        mock_validate_request.return_value = True, log_entry
        mock_build_archive.return_value = [0, "command output", "log_file_name", 0]
        mock_time.return_value = 1234
        mock_get_size.return_value = 3

        mock_atlas_logger.post_log.side_effect = CertificateExceptionInvalidCert()
        mock_get_oauth = mock.Mock()
        mock_atlas_logger.get_oauth.return_value = mock_get_oauth

        LogArchiver.push_logs(mock_config, mock_atlas_logger, log_request_id)
        log_entry = {"logsearchId": log_request_id, 'cause': 'unmanaged-certs', "status": "error"}
        mock_write_json_file.assert_called_with(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)
        tracking_info = {'serial_number': mock_config.read(ManagementConnectorProperties.SERIAL_NUMBER), 'tracking_id': log_request_id}
        mock_atlas_logger.post_log.assert_called_with(tracking_info, "log_file_name")

        mock_rm_archive.assert_called_with("log_file_name")
        mock_event_post.assert_called_with(mock_get_oauth,
                                           mock_config,
                                           "logpush",
                                           "c_mgmt",
                                           1234,
                                           {"fields": {"exception": "CertificateExceptionInvalidCert",
                                                       "fileSize": 3, "batchSize": 1, "logsearchId": "12345"},
                                            "tags": {"state": "failure", "reason": "pushFailure"},
                                            "measurementName": "logPushEvent"})

    @mock.patch("managementconnector.platform.logarchiver.time.time")
    @mock.patch("managementconnector.platform.logarchiver.EventSender.post")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_archive")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_config_files")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.build_archive")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.validate_request")
    @mock.patch("managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("managementconnector.config.config.Config")
    def test_push_log_emits_event_on_archive_failure(self, mock_config, mock_atlas_logger, mock_validate_request, mock_build_archive,
                                                  mock_rm_config, mock_rm_archive, mock_write_json_file, mock_event_post, mock_time):
        """ User Story: US17337: Metrics: Key Events: FMC log push metrics """
        log_request_id = "12345"
        log_entry = {"logsearchId": log_request_id, "status": "starting"}
        mock_validate_request.return_value = True, log_entry
        mock_build_archive.return_value = [2, "failure output", "log_file_name", 0]
        mock_time.return_value = 1234

        mock_atlas_logger.post_log.side_effect = CertificateExceptionInvalidCert()
        mock_get_oauth = mock.Mock()
        mock_atlas_logger.get_oauth.return_value = mock_get_oauth

        LogArchiver.push_logs(mock_config, mock_atlas_logger, log_request_id)
        log_entry = {"logsearchId": log_request_id, "status": "archive failed"}
        mock_write_json_file.assert_called_with(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)

        mock_atlas_logger.post_log.assert_not_called()
        mock_rm_archive.assert_not_called()

        mock_event_post.assert_called_with(mock_get_oauth,
                                           mock_config,
                                           "logpush",
                                           "c_mgmt",
                                           1234,
                                           {"fields": {"batchSize": 1, "logsearchId": "12345"},
                                            "tags": {"state": "failure", "reason": "archiveFailure"},
                                            "measurementName": "logPushEvent"})

    def test_strip_pii_from_string(self):
        """ User Story: US25210: Add Connector JSON (config) Files to the Send Log Output """
        pii_string = '{"proxy": [{"username": "admin", "password": "{cipher}sRxsC/lxw5N1bLDec4e46g==", "enabled": "true", "port": "3128", "address": "gwyedgeproxy2.cisco.com"}], "email": "abc.123@cisco.com"}'

        new_pii_string = '{"proxy": [{"username": "admin", "password": "####PII-EXPOSURE####", "enabled": "true", "port": "3128", "address": "gwyedgeproxy2.cisco.com"}], "email": "####PII-EXPOSURE####"}'

        stripped_pii_string = LogArchiver.strip_pii_from_string(pii_string)
        self.assertEqual(stripped_pii_string, new_pii_string)

    @mock.patch('builtins.open')
    def test_strip_pii_from_file(self, mock_file):
        """ User Story: US25210: Add Connector JSON (config) Files to the Send Log Output """
        pii_file = "/tmp/pii.json"
        pii_string = '{"proxy": [{"username": "admin", "password": "{cipher}sRxsC/lxw5N1bLDec4e46g==", "enabled": "true", "port": "3128", "address": "gwyedgeproxy2.cisco.com"}], "email": "abc.123@cisco.com"}'

        new_pii_string = '{"proxy": [{"username": "admin", "password": "####PII-EXPOSURE####", "enabled": "true", "port": "3128", "address": "gwyedgeproxy2.cisco.com"}], "email": "####PII-EXPOSURE####"}'
        mock.mock_open(mock_file,read_data=pii_string)

        LogArchiver.strip_pii_from_file(pii_file, pii_file)

        mock_file.assert_has_calls([mock.call(pii_file),
                                    mock.call(pii_file, "w")],
                                    any_order=True)
        mock_write = mock_file()
        mock_write.write.assert_has_calls([mock.call().write(new_pii_string)], any_order=False)

    @mock.patch('os.makedirs')
    @mock.patch('managementconnector.platform.logarchiver.LogArchiver.strip_pii_from_file')
    @mock.patch('os.path.exists')
    @mock.patch('glob.glob')
    def test_gather_status_files(self, mock_glob, mock_exists, mock_pii, mock_makedirs):
        """ User Story: US25210: Add Connector JSON (config) Files to the Send Log Output """

        # confgiure mocks
        mock_glob.return_value = ['/var/run/c_mgmt/status.json','/var/run/dummy/status.json','/var/run/c_conn/status.json']

        # Test 1: tmp directory does not exist
        mock_exists.return_value = False

        LogArchiver.gather_status_files()

        mock_makedirs.assert_called_with('/tmp/config_files/')

        mock_pii.assert_has_calls([mock.call('/var/run/c_mgmt/status.json', '/tmp/config_files/c_mgmt_status.json'),
                                   mock.call('/var/run/dummy/status.json', '/tmp/config_files/dummy_status.json'),
                                   mock.call('/var/run/c_conn/status.json', '/tmp/config_files/c_conn_status.json')],
                                   any_order=True)

        # Test 2: tmp directory already exists
        mock_makedirs.reset_mock()
        mock_exists.return_value = True

        LogArchiver.gather_status_files()

        mock_makedirs.assert_not_called()
        mock_pii.assert_has_calls([mock.call('/var/run/c_mgmt/status.json', '/tmp/config_files/c_mgmt_status.json'),
                                   mock.call('/var/run/dummy/status.json', '/tmp/config_files/dummy_status.json'),
                                   mock.call('/var/run/c_conn/status.json', '/tmp/config_files/c_conn_status.json')],
                                   any_order=True)

    @mock.patch('glob.glob')
    @mock.patch('os.makedirs')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.basename')
    @mock.patch('managementconnector.platform.logarchiver.LogArchiver.strip_pii_from_file')
    def test_gather_config_files(self, mock_pii, mock_basename, mock_exists, mock_makedirs, mock_glob):
        """ User Story: US25210: Add Connector JSON (config) files to the Send Log Output """

        mock_glob.return_value = ['/opt/c_mgmt/etc/config/c_mgmt.json',
                                  '/opt/c_mgmt/etc/config/dummy.json',
                                  '/opt/c_mgmt/etc/config/c_ucmc.json']

        def get_basename(filepath):
            if filepath == '/opt/c_mgmt/etc/config/c_mgmt.json':
                return 'c_mgmt.json'
            elif filepath == '/opt/c_mgmt/etc/config/dummy.json':
                return 'dummy.json'
            else:
                return 'c_ucmc.json'

        mock_basename.side_effect = get_basename

        # Test 1: tmp directory doesn't exist
        mock_exists.return_value = False

        LogArchiver.gather_config_files()

        mock_makedirs.assert_called_with('/tmp/config_files/')

        mock_pii.assert_has_calls([mock.call('/opt/c_mgmt/etc/config/c_mgmt.json', '/tmp/config_files/c_mgmt.json'),
                                   mock.call('/opt/c_mgmt/etc/config/dummy.json', '/tmp/config_files/dummy.json'),
                                   mock.call('/opt/c_mgmt/etc/config/c_ucmc.json', '/tmp/config_files/c_ucmc.json')],
                                  any_order=True)

        # Test 2: tmp directory already exists
        mock_makedirs.reset_mock()
        mock_exists.return_value = True

        LogArchiver.gather_config_files()

        mock_makedirs.assert_not_called()

        mock_pii.assert_has_calls([mock.call('/opt/c_mgmt/etc/config/c_mgmt.json', '/tmp/config_files/c_mgmt.json'),
                                   mock.call('/opt/c_mgmt/etc/config/dummy.json', '/tmp/config_files/dummy.json'),
                                   mock.call('/opt/c_mgmt/etc/config/c_ucmc.json', '/tmp/config_files/c_ucmc.json')],
                                  any_order=True)

    @mock.patch("cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.validate_request")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_archive")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_config_files")
    @mock.patch("os.path.getsize")
    @mock.patch("managementconnector.platform.logarchiver.time.time")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.build_archive")
    @mock.patch("managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("managementconnector.config.config.Config")
    def test_rd_log_request_does_not_call_include_config_function(self, mock_config, mock_atlas_logger, mock_build_archive,
                                                  mock_write_json_file, mock_time, mock_get_size, mock_rm_config,
                                                  mock_rm_archive, mock_validate_request, mock_get_package_version):
        """ User Story: US25210: Add Connector JSON (config) files to the Send Log Output """
        log_request_id = "12345"
        quantity = 1
        serial_number = mock_config.read(ManagementConnectorProperties.SERIAL_NUMBER)
        log_entry = {"logsearchId": log_request_id, "status": "starting"}

        mock_time.return_value = 1234
        mock_build_archive.return_value = [0, "command output", "log_file_name", 0]
        mock_get_size.return_value = 3
        mock_atlas_logger.post_log.return_value = [0, 54321]
        mock_validate_request.return_value = True, log_entry
        mock_get_oauth = mock.Mock()
        mock_atlas_logger.get_oauth.return_value = mock_get_oauth

        LogArchiver.push_logs(mock_config, mock_atlas_logger, log_request_id)
        log_entry = {"logsearchId": log_request_id, "status": "complete"}

        mock_validate_request.assert_called_with(mock_config, log_request_id)

        mock_write_json_file.assert_called_with(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)

        mock_build_archive.assert_called_with(quantity, serial_number)

        mock_rm_archive.assert_called_with("log_file_name")

    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.validate_request")
    @mock.patch("managementconnector.platform.logarchiver.EventSender.post")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_archive")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.rm_config_files")
    @mock.patch("os.path.getsize")
    @mock.patch("managementconnector.platform.logarchiver.time.time")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch("managementconnector.platform.logarchiver.LogArchiver.build_archive")
    @mock.patch("managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("managementconnector.config.config.Config")
    def test_admin_log_request_calls_include_config_function(self, mock_config, mock_atlas_logger,mock_build_archive,
                                                mock_write_json_file, mock_time, mock_get_size, mock_rm_config,
                                                mock_rm_archive, mock_event_post, mock_validate_request):
        """ User Story: US25210: Add Connector JSON (config) files to the Send Log Output """
        log_request_id = ""
        quantity = 1
        serial_number = mock_config.read(ManagementConnectorProperties.SERIAL_NUMBER)
        log_entry = {"logsearchId": "12345", "status": "starting"}

        mock_time.return_value = 1234
        mock_build_archive.return_value = [0, "command output", "log_file_name", 0]
        mock_get_size.return_value = 3
        mock_atlas_logger.post_log.return_value = [0, 54321]
        mock_get_oauth = mock.Mock()
        mock_atlas_logger.get_oauth.return_value = mock_get_oauth
        mock_validate_request.return_value = True, log_entry

        LogArchiver.push_logs(mock_config, mock_atlas_logger, log_request_id)
        log_entry = {"logsearchId": "12345", "status": "complete"}

        mock_validate_request.assert_called_with(mock_config, log_request_id)

        mock_write_json_file.assert_called_with(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)

        mock_build_archive.assert_called_with(quantity, serial_number)

        mock_rm_archive.assert_called_with("log_file_name")
        mock_rm_config.assert_called_with()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
