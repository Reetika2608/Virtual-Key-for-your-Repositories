"""
    Test CrashMonitor
"""
# Ignore "Method could be a function" warnings        pylint: disable=R0201

import unittest
import logging
import mock
import datetime
import sys
from .constants import SYS_LOG_HANDLER

# Pre-import a mocked pyinotify
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.service.crashmonitor import CrashMonitor
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()

def config_read(path, alarm_list):
    """ config class mock """
    DEV_LOGGER.debug("ConfigMock: read path %s" % path)

    if path == ManagementConnectorProperties.PLATFORM_ALARMS_RAISED:
        return alarm_list
    elif path == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return {"organization_id" : "organization_id"}
    elif path == ManagementConnectorProperties.EVENT_URL:
        return "org%sid%s"
    elif path == ManagementConnectorProperties.ENTITLED_SERVICES:
        return [{"display_name": "Management Connector", "name": "c_mgmt"},
                {"display_name": "Calendar Connector", "name": "c_cal"}]

    return "config_value"

def get_test_time(subtract=0):
    "Util Method"
    time_now = ManagementConnectorProperties.get_utc_time('%Y-%m-%dT%H:%M:%SZ')
    date_time = datetime.datetime.strptime(time_now, '%Y-%m-%dT%H:%M:%SZ')
    # python < 3.3 has no method to convert a datetime object to timestamp
    current_time = int((date_time - datetime.datetime(1970, 1, 1)).total_seconds()) - subtract

    return current_time


def config_no_platform_crash_read(path):
    """ config class mock """
    # Simulate Alarm inside hearbeat, but associated with Non-Fusion Process

    alarm_list = [{'severity': 'error', 'parameters': ['XXXX'], 'last_reported': '1493289652', 'solution_links': 'restartoptions?restart', 'first_reported': '1493220035', 'id': '15019', 'uuid': '1a18bfa6-f822-11e1-b0db-c35cb1b8e3e5'}]

    return config_read(path, alarm_list)


def config_java_crash_read(path):
    """ config mock """
    # Simulate Calendar connector alarm
    alarm_list = [{'severity': 'error', 'parameters': ['java', 1], 'last_reported': get_test_time(0), 'solution_links': 'restartoptions?restart', 'first_reported': '1493220035', 'id': '15019', 'uuid': '1a18bfa6-f822-11e1-b0db-c35cb1b8e3e5'}]

    return config_read(path, alarm_list)


def config_default_crash_read(path):
    """ config mock """
    # Simulate Calendar connector alarm
    alarm_list = [{'severity': 'error', 'parameters': ['c_mgmt', 1], 'last_reported': get_test_time(0), 'solution_links': 'restartoptions?restart', 'first_reported': '1493220035', 'id': '15019', 'uuid': '1a18bfa6-f822-11e1-b0db-c35cb1b8e3e5'}]

    return config_read(path, alarm_list)


def config_no_platform_alarms_read(path):
    """ config class mock """
    alarm_list = []
    return config_read(path, alarm_list)


class CrashMonitorTest(unittest.TestCase):
    """RemoteDispatcher unit tests"""

    def setUp(self):
        self.header = mock.MagicMock()
        self.config_mock = mock.MagicMock()

    @mock.patch('managementconnector.service.crashmonitor.jsonhandler')
    @mock.patch('managementconnector.service.eventsender.EventSender.post')
    def test_crash_not_reported_if_no_alarms(self, mock_post, mock_json):
        """ User Story: US15777: Metrics: Pass Connector Crash Info to new Events API"""
        #  Mock Config Object has no platform alarms
        self.config_mock.read.side_effect = config_no_platform_alarms_read
        mock_json.get_last_modified_timestamp.return_value = get_test_time(0)
        CrashMonitor(self.config_mock).crash_check(self.header, self.config_mock)
        self.assertFalse(mock_post.called, 'Event post is called.')

    @mock.patch('managementconnector.service.crashmonitor.jsonhandler')
    @mock.patch('managementconnector.service.eventsender.EventSender.post')
    def test_crash_not_reported_if_alarms_does_not_contain_connector_keywords(self, mock_post, mock_json):
        """ User Story: US15777: Metrics: Pass Connector Crash Info to new Events API"""
        #  Mock Config  Object has platform alarms, but none that match keywords
        self.config_mock.read.side_effect = config_no_platform_crash_read
        mock_json.get_last_modified_timestamp.return_value = get_test_time(0)
        CrashMonitor(self.config_mock).crash_check(self.header, self.config_mock)
        self.assertFalse(mock_post.called, 'Event post is called.')


    @mock.patch('managementconnector.service.crashmonitor.jsonhandler')
    @mock.patch('managementconnector.service.eventsender.EventSender.post')
    def test_java_crash_reported_if_it_happened_after_last_heartbeat(self, mock_post, mock_json):
        """ User Story: DE1849: Calendar Connector Crashes not being detected by FMC """
        # Mock Config Object has calendar connector alarm that happened since last heartbeat
        self.config_mock.read.side_effect = config_java_crash_read
        mock_json.get_last_modified_timestamp.return_value = get_test_time(60)
        CrashMonitor(self.config_mock).crash_check(self.header, self.config_mock)
        self.assertTrue(mock_post.called, 'Event post is not called.')

    @mock.patch('managementconnector.service.crashmonitor.jsonhandler')
    @mock.patch('managementconnector.service.eventsender.EventSender.post')
    def test_default_service_name_reported_if_it_happened_after_last_heartbeat(self, mock_post, mock_json):
        """ User Story: DE2105: Metrics Test Broken """
        # Mock Config Object ensure entitled service names are used as keywords for non overrides
        self.config_mock.read.side_effect = config_default_crash_read
        mock_json.get_last_modified_timestamp.return_value = get_test_time(60)
        CrashMonitor(self.config_mock).crash_check(self.header, self.config_mock)
        self.assertTrue(mock_post.called, 'Event post is not called.')

    @mock.patch('managementconnector.service.crashmonitor.jsonhandler')
    @mock.patch('managementconnector.service.eventsender.EventSender.post')
    def test_last_crash_check_time_is_updated(self, mock_post, mock_json):
        # Mock Config Object ensure entitled service names are used as keywords for non overrides
        self.config_mock.read.side_effect = config_default_crash_read
        mock_json.get_last_modified_timestamp.return_value = get_test_time(60)
        crash_monitor = CrashMonitor(self.config_mock)
        old_time = crash_monitor._last_crash_check
        crash_monitor.crash_check(self.header, self.config_mock)
        new_time = crash_monitor._last_crash_check
        self.assertTrue(new_time > old_time, 'Last crash check time was not updated.')

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
