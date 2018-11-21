""" Unittest for Core Archiver """
# Ignore "Unused argument" warnings                   pylint: disable=W0613
import unittest
import logging
import ssl
import mock

from ni.managementconnector.platform.corearchiver import CoreArchiver
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class CoreArchiverTest(unittest.TestCase):
    """ Unit test class for Core Archiver """

    @mock.patch("ni.managementconnector.platform.corearchiver.CoreArchiver.retrieve_core_paths")
    @mock.patch("ni.managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("ni.managementconnector.config.config.Config")
    @mock.patch("time.sleep")
    def test_no_core_dumps_found_case(self, mock_sleep, mock_config, mock_logger, mock_retrieve):
        """ Test scenario where no core dumps are found """
        mock_retrieve.return_value = None
        expected_value = {"status": "no core dumps found"}
        return_value = CoreArchiver.retrieve_and_archive_cores(mock_config, mock_logger, "12345678")
        self.assertEqual(expected_value, return_value)

    @mock.patch('ni.managementconnector.platform.corearchiver.CoreArchiver.archive_core')
    @mock.patch("ni.managementconnector.platform.corearchiver.CoreArchiver.retrieve_core_paths")
    @mock.patch("ni.managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("ni.managementconnector.config.config.Config")
    @mock.patch("os.remove")
    @mock.patch("time.sleep")
    def test_failure_to_archive_case(self, mock_sleep, mock_remove, mock_config, mock_logger, mock_retrieve, mock_archive):
        """ Test scenario where archival fails """
        mock_retrieve.return_value = ['/test2']
        mock_archive.return_value = 1
        expected_value = {"status": "archive failed"}
        return_value = CoreArchiver.retrieve_and_archive_cores(mock_config, mock_logger, "12345678")
        self.assertEqual(expected_value, return_value)
        mock_remove.assert_called_with('/test2')

    @mock.patch('ni.managementconnector.platform.corearchiver.CoreArchiver.archive_core')
    @mock.patch("ni.managementconnector.platform.corearchiver.CoreArchiver.retrieve_core_paths")
    @mock.patch('ni.managementconnector.cloud.atlaslogger.AtlasLogger.post_log')
    @mock.patch("ni.managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("ni.managementconnector.config.config.Config")
    @mock.patch("traceback.format_exc")
    @mock.patch("os.remove")
    @mock.patch("time.sleep")
    def test_failure_to_upload_case(self, mock_sleep, mock_remove, mock_trace, mock_config, mock_logger, mock_post, mock_retrieve, mock_archive):
        """ Test scenario where uploading file fails """
        mock_retrieve.return_value = ['/test2']
        mock_archive.return_value = 0
        mock_post.side_effect = ssl.SSLError()
        expected_value = {"status": "error uploading core dump"}
        return_value = CoreArchiver.retrieve_and_archive_cores(mock_config, mock_logger, "12345678")
        self.assertEqual(expected_value, return_value)
        mock_remove.assert_called_with('/test2')

    @mock.patch('ni.managementconnector.platform.corearchiver.CoreArchiver.archive_core')
    @mock.patch("ni.managementconnector.platform.corearchiver.CoreArchiver.retrieve_core_paths")
    @mock.patch('ni.managementconnector.cloud.atlaslogger.AtlasLogger.post_log')
    @mock.patch("ni.managementconnector.cloud.atlaslogger.AtlasLogger")
    @mock.patch("ni.managementconnector.config.config.Config")
    @mock.patch("traceback.format_exc")
    @mock.patch("os.remove")
    @mock.patch("os.path.getsize")
    @mock.patch("time.sleep")
    def test_working_scenario(self, mock_sleep, mock_getsize, mock_remove, mock_trace, mock_config, mock_logger, mock_post, mock_retrieve, mock_archive):
        """ Test for successful scenario """
        mock_retrieve.return_value = ['/test2']
        mock_archive.return_value = 0
        mock_post.return_value = [0, 0]
        expected_value = {"status": "complete", "searchId": "12345678"}
        return_value = CoreArchiver.retrieve_and_archive_cores(mock_config, mock_logger, "12345678")
        self.assertEqual(expected_value, return_value)
        mock_remove.assert_called_with('/test2')

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
