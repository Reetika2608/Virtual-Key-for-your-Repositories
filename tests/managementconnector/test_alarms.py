import unittest
import sys
import logging
import mock
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.platform.alarms import MCAlarm
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class AlarmsTest(unittest.TestCase):
    """ Alarms Test Class """
    
    def setUp(self):
        """ Alarms Test Setup """
        
        DEV_LOGGER.debug('***TEST Setup***')

    @mock.patch('managementconnector.platform.alarms.AlarmProcessor')
    @mock.patch('managementconnector.config.config.Config')
    def test_clear_alarms(self, mock_config, mock_alarmmanager):
        """ Clear Alarms Test """

        test_uuid = "test_uuid"
        test_id = "test_id"

        mock_config.read.return_value = [{"id": test_id, "uuid": test_uuid}]
        alarm = MCAlarm(mock_config)

        alarm.clear_alarms([])

        mock_alarmmanager.lower_alarm.assert_called_with(test_uuid)

    @mock.patch('managementconnector.platform.alarms.AlarmProcessor')
    @mock.patch('managementconnector.config.config.Config')
    def test_clear_alarm(self, mock_config, mock_alarmmanager):
        """ Clear Alarm Test """

        test_uuid = "test_uuid"
        test_id = "test_id"

        test_uuid2 = "test2_uuid"

        mock_config.read.return_value = [{"id": test_id, "uuid": test_uuid}]
        alarm = MCAlarm(mock_config)

        # test_uuid2 not raised
        alarm.clear_alarm(test_uuid2)
        self.assertFalse(mock_alarmmanager.lower_alarm.called, "Lower Alarm should not have been called.")

        # test_uuid  raised
        alarm.clear_alarm(test_uuid)
        mock_alarmmanager.lower_alarm.assert_called_with(test_uuid)

    @mock.patch('managementconnector.platform.alarms.AlarmProcessor')
    @mock.patch('managementconnector.config.config.Config')
    def test_clear_alarm_with_exclude_list(self, mock_config, mock_alarmmanager):
        """
        User Story: US11591: Call Connector Alarm Cleanup
        Purpose: Verify clear alarms handles an exclude list.
        Steps:
        1. Clear alarms with an exclude list
        2. Verify lower alarm only called once with expected alarm and not excluded alarm.
        Notes:
        """

        test_uuid = "test_uuid"
        test_id = "test_id"

        test_uuid2 = "test2_uuid"
        test_id2 = "test2_id"

        mock_config.read.return_value = [{"id": test_id, "uuid": test_uuid}, {"id": test_id2, "uuid": test_uuid2}]
        alarm = MCAlarm(mock_config)

        alarm.clear_alarms([test_id2])

        mock_alarmmanager.lower_alarm.assert_called_once_with(test_uuid)



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
