import logging
import unittest
import mock
import sys
from .constants import SYS_LOG_HANDLER

# Pre-import a mocked pyinotify
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.service.eventdampener import EventDampener
from managementconnector.config.config import Config
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


def config_read(path):
    """ config class mock """
    DEV_LOGGER.debug("ConfigMock: read path %s" % path)

    if path == ManagementConnectorProperties.TARGET_TYPE:
        return "c_mgmt"


class EventDampenerTest(unittest.TestCase):

    @mock.patch("managementconnector.config.jsonhandler.read_json_file")
    def test_no_file_gets_defaulted_to_empty_dictionary(self, mock_read):
        """
        SPARK-1983: Make fms-connector-upgrades dashboard useable
        Test when no file exists the default value is a dictionary
        """
        DEV_LOGGER.info("test_no_file_gets_defaulted_to_empty_dictionary")
        #config = Config(inotify=False)
        mock_read.return_value = None

        dampener = EventDampener()
        self.assertEqual(dampener._upgrade_event_attempts, {})

    @mock.patch("managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch('managementconnector.config.config.Config')
    def test_upgrade_event_pair_empty_dictionary(self, mock_config, mock_write, mock_read):
        """
        SPARK-1983: Make fms-connector-upgrades dashboard useable
        Test when there's an empty dictionary, no previous event has been sent
        """
        DEV_LOGGER.info("test_upgrade_event_pair_empty_dictionary")
        #config = Config(inotify=False)
        mock_read.return_value = {}

        dampener = EventDampener()
        self.assertEqual(dampener._upgrade_event_attempts, {})

        # First time seeing this connector pair, allow the event and update both local and on box references
        self.assertFalse(dampener.has_upgrade_event_been_sent("c_mgmt", "8.10-1.0.12347"),
                         msg="There should not have been an event sent")
        self.assertEqual(dampener._upgrade_event_attempts, {"c_mgmt": "8.10-1.0.12347"})
        mock_write.assert_called_with("/var/run/c_mgmt/upgrade_events.json", {"c_mgmt": "8.10-1.0.12347"})

    @mock.patch("managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch('managementconnector.config.config.Config')
    def test_upgrade_event_pair_version_difference(self, mock_config, mock_write, mock_read):
        """
        SPARK-1983: Make fms-connector-upgrades dashboard useable
        Test when the pair does not match that no event has been sent
        """
        DEV_LOGGER.info("test_upgrade_event_pair_version_difference")
        #config = Config(inotify=False)
        mock_read.return_value = {"c_mgmt": "8.10-1.0.1234"}

        dampener = EventDampener()
        self.assertEqual(dampener._upgrade_event_attempts, {"c_mgmt": "8.10-1.0.1234"})

        # First time seeing this connector pair, allow the event and update both local and on box references
        self.assertFalse(dampener.has_upgrade_event_been_sent("c_mgmt", "8.10-1.0.12347"),
                         msg="There should not have been an event sent")
        self.assertEqual(dampener._upgrade_event_attempts, {"c_mgmt": "8.10-1.0.12347"})
        mock_write.assert_called_with("/var/run/c_mgmt/upgrade_events.json", {"c_mgmt": "8.10-1.0.12347"})

    @mock.patch("managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch('managementconnector.config.config.Config')
    def test_event_not_sent_with_multiple_connectors(self, mock_config, mock_write, mock_read):
        """
        SPARK-1983: Make fms-connector-upgrades dashboard useable
        Test event has not been sent with version difference and multiple values in dictionary
        """
        DEV_LOGGER.info("test_upgrade_event_pair_version_difference")
        #config = Config(inotify=False)
        mock_config.read.side_effect = config_read
        mock_read.return_value = {"c_mgmt": "8.10-1.0.1234", "c_ucmc": "12345"}

        dampener = EventDampener()
        self.assertEqual(dampener._upgrade_event_attempts, {"c_mgmt": "8.10-1.0.1234", "c_ucmc": "12345"})

        # First time seeing this connector pair, allow the event and update both local and on box references
        self.assertFalse(dampener.has_upgrade_event_been_sent("c_mgmt", "8.10-1.0.12347"),
                         msg="There should not have been an event sent")
        self.assertEqual(dampener._upgrade_event_attempts, {"c_mgmt": "8.10-1.0.12347", "c_ucmc": "12345"})
        mock_write.assert_called_with("/var/run/c_mgmt/upgrade_events.json", {"c_mgmt": "8.10-1.0.12347", "c_ucmc": "12345"})

    @mock.patch("managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("managementconnector.config.jsonhandler.write_json_file")
    @mock.patch('managementconnector.config.config.Config')
    def test_event_not_allowed_when_version_sent_already(self, mock_config, mock_write, mock_read):
        """
        SPARK-1983: Make fms-connector-upgrades dashboard useable
        Test event already sent if connector type and version ar the same
        """
        DEV_LOGGER.info("test_upgrade_event_pair_version_difference")
        #config = Config(inotify=False)
        mock_config.read.side_effect = config_read
        mock_read.return_value = {"c_mgmt": "8.10-1.0.1234"}

        dampener = EventDampener()
        self.assertEqual(dampener._upgrade_event_attempts, {"c_mgmt": "8.10-1.0.1234"})

        # First time seeing this connector pair, allow the event and update both local and on box references
        self.assertTrue(dampener.has_upgrade_event_been_sent("c_mgmt", "8.10-1.0.1234"),
                        msg="There should not have been an event sent")
        self.assertEqual(dampener._upgrade_event_attempts, {"c_mgmt": "8.10-1.0.1234"})
        mock_write.assert_not_called()
