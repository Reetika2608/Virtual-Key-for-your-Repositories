"""
    Test EventSender
"""

# Ignore "Invalid name" warnings                      pylint: disable=C0103

import json
import time
import unittest
import logging
import mock

from ni.managementconnector.platform.serviceutils import ServiceUtils
from ni.managementconnector.service.eventsender import EventSender
from ni.managementconnector.events.upgradeevent import UpgradeEvent
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.service.eventdampener import EventDampener

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


def config_read(path):
    """ config class mock """

    if path == ManagementConnectorProperties.SERIAL_NUMBER:
        return "serial"
    elif path == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return {"organization_id": "org"}
    elif path == ManagementConnectorProperties.SERIAL_NUMBER:
        return "serial"
    elif path == ManagementConnectorProperties.CLUSTER_ID:
        return "cluster"
    elif path == ManagementConnectorProperties.EVENT_URL:
        return "org%sid%s"
    elif path == ManagementConnectorProperties.ATLAS_URL_PREFIX:
        return "atlas_url"
    elif path == ManagementConnectorProperties.EXPRESSWAY_FULL_VERSION:
        return "X8.11PreAlpha10"
    elif path == ManagementConnectorProperties.EVENT_SUCCESS:
        return "success"
    elif path == ManagementConnectorProperties.EVENT_FAILURE:
        return "failure"
    elif path == ManagementConnectorProperties.SERVICE_NAME:
        return "c_ucmc"

    return "config_value"


class EventSenderTest(unittest.TestCase):
    """ EventSenderTest """

    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch("ni.managementconnector.service.eventsender.Http.post")
    def test_sending_event(self, mock_post, mock_get_package_version):
        """ User Story: US15777: Metrics: Pass Connector Crash Info to new Events API """
        oauth = mock.Mock()
        config = mock.Mock()
        config.read.side_effect = config_read
        mock_get_package_version.return_value = "1.2.3"

        # header.read.return_value = "dummy_config"
        EventSender.post(oauth, config, EventSender.CRASH)
        self.assertTrue(mock_post.called, "Http post is not called.")

    @mock.patch("ni.managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("ni.managementconnector.config.jsonhandler.write_json_file")
    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch("ni.managementconnector.service.eventsender.Http.post")
    def test_upgrade_event_sent(self, mock_post, mock_get_package_version, mock_write, mock_read):
        """
            SPARK-1983: Make fms-connector-upgrades dashboard useable
            Upgrade success event sent when not previously sent
        """
        oauth = mock.Mock()
        config = mock.Mock()
        config.read.side_effect = config_read
        mock_get_package_version.return_value = "1.2.3"
        mock_read.return_value = {"c_mgmt": "12345", "c_ucmc": "12345"}

        dampener = EventDampener()

        service = config.read(ManagementConnectorProperties.SERVICE_NAME)
        platform_version = config.read(ManagementConnectorProperties.EXPRESSWAY_FULL_VERSION)
        event_success = config.read(ManagementConnectorProperties.EVENT_SUCCESS)

        upgrade_event = UpgradeEvent(
            event_success,
            "c_ucmc",
            "download_duration",
            "install_duration",
            "downloaded_file_size",
            "url",
            "1.2.3",
            platform_version,
            None,
            None)

        EventSender.post(oauth,
                         config,
                         EventSender.UPGRADE,
                         service,
                         int(time.time()),
                         upgrade_event.get_detailed_info(),
                         dampener=dampener)

        self.assertTrue(mock_post.called, "Http post is not called.")
        mock_write.assert_called_with("/var/run/c_mgmt/upgrade_failures.json",
                                      {"c_mgmt": "12345", "c_ucmc": "1.2.3"})


    @mock.patch("ni.managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("ni.managementconnector.config.jsonhandler.write_json_file")
    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch("ni.managementconnector.service.eventsender.Http.post")
    def test_upgrade_event_not_sent_when_invoked_multiple_times(self, mock_post, mock_get_package_version, mock_write, mock_read):
        """
            SPARK-1983: Make fms-connector-upgrades dashboard useable
            failure not allowed to be sent if sent before, calling three times

            ManagementConnectorProperties values would ordinarily be mocked, but mock objects cannot
            be JSON serialized, which is required here. Instead the mocked config object can substitute values.
        """
        oauth = mock.Mock()
        config = mock.Mock()
        config.read.side_effect = config_read
        version = "1.2.3"
        mock_get_package_version.return_value = version
        mock_read.return_value = {}  # Nothing sent previously

        timestamp = int(time.time())
        service = config.read(ManagementConnectorProperties.SERVICE_NAME)
        service_version = ServiceUtils.get_version(service) or 'None'
        platform_version = config.read(ManagementConnectorProperties.EXPRESSWAY_FULL_VERSION)
        serial = config.read(ManagementConnectorProperties.SERIAL_NUMBER)
        org_id = config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)['organization_id']
        atlas_url_prefix = config.read(ManagementConnectorProperties.ATLAS_URL_PREFIX)
        event_url = config.read(ManagementConnectorProperties.EVENT_URL) % (org_id, service + "@" + serial)
        event_failure = config.read(ManagementConnectorProperties.EVENT_FAILURE)

        dampener = EventDampener()

        upgrade_event = UpgradeEvent(
            event_failure,
            service,
            None,  # downloadDuration
            None,  # installDuration
            None,  # fileSize
            event_url,
            service_version,
            platform_version,
            "Download timed out",
            "download_exception")

        # First event - should be called
        EventSender.post(oauth,
                         config,
                         EventSender.UPGRADE,
                         service,
                         timestamp,
                         upgrade_event.get_detailed_info(),
                         dampener=dampener)
        event = {
            "orgId": org_id,
            "connectorId": service + "@" + serial,
            "connectorType": service,
            "connectorVersion": service_version,
            "clusterId": "cluster",
            "timestamp": timestamp,
            "type": EventSender.UPGRADE,
            "details": {
                "releaseChannel": "",
                "detailed_info": json.dumps({"fields": {"url": event_url,
                                                        "platformVersion": platform_version,
                                                        "connectorVersion": service_version,
                                                        "value": -999,  # All upgrade values are now -999
                                                        "exception": "download_exception"},
                                             "measurementName": "connectorUpgradeEvent",
                                             "tags": {"state": event_failure,
                                                      "connectorType": service,
                                                      "reason": "Download timed out"}})
            }
        }

        mock_post.assert_called_with(atlas_url_prefix + event_url, oauth.get_header(), json.dumps(event))
        mock_write.assert_called_with("/var/run/c_mgmt/upgrade_failures.json", {"c_ucmc": "1.2.3"})

        # Second event - should not be called
        EventSender.post(oauth,
                         config,
                         EventSender.UPGRADE,
                         service,
                         int(time.time()),
                         upgrade_event.get_detailed_info(),
                         dampener=dampener)

        # Third event - should not be called
        EventSender.post(oauth,
                         config,
                         EventSender.UPGRADE,
                         service,
                         int(time.time()),
                         upgrade_event.get_detailed_info(),
                         dampener=dampener)

        self.assertEqual(mock_post.call_count, 1)
        self.assertEqual(mock_write.call_count, 1)

    @mock.patch("ni.managementconnector.config.jsonhandler.read_json_file")
    @mock.patch("ni.managementconnector.config.jsonhandler.write_json_file")
    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch("ni.managementconnector.service.eventsender.Http.post")
    def test_first_event_sent_for_two_different_upgrades(self, mock_post, mock_get_package_version, mock_write, mock_read):
        """
            SPARK-1983: Make fms-connector-upgrades dashboard useable
            Expected: V1 failure sent, V1 second failure not sent, V2 failure sent

            ManagementConnectorProperties values would ordinarily be mocked, but mock objects cannot
            be JSON serialized, which is required here. Instead the mocked config object can substitute values.
        """
        oauth = mock.Mock()
        config = mock.Mock()
        config.read.side_effect = config_read
        version = "1.2.3"
        mock_get_package_version.return_value = version
        mock_read.return_value = {}  # Nothing sent previously

        timestamp = int(time.time())
        service = config.read(ManagementConnectorProperties.SERVICE_NAME)
        service_version = ServiceUtils.get_version(service) or 'None'
        platform_version = config.read(ManagementConnectorProperties.EXPRESSWAY_FULL_VERSION)
        serial = config.read(ManagementConnectorProperties.SERIAL_NUMBER)
        org_id = config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)['organization_id']
        atlas_url_prefix = config.read(ManagementConnectorProperties.ATLAS_URL_PREFIX)
        event_url = config.read(ManagementConnectorProperties.EVENT_URL) % (org_id, service + "@" + serial)
        event_failure = config.read(ManagementConnectorProperties.EVENT_FAILURE)

        dampener = EventDampener()

        upgrade_event = UpgradeEvent(
            event_failure,
            service,
            None,  # downloadDuration
            None,  # installDuration
            None,  # fileSize
            event_url,
            service_version,
            platform_version,
            "Download timed out",
            "download_exception")

        # First event - should be called
        EventSender.post(oauth,
                         config,
                         EventSender.UPGRADE,
                         service,
                         timestamp,
                         upgrade_event.get_detailed_info(),
                         dampener=dampener)
        event = {
            "orgId": org_id,
            "connectorId": service + "@" + serial,
            "connectorType": service,
            "connectorVersion": service_version,
            "clusterId": "cluster",
            "timestamp": timestamp,
            "type": EventSender.UPGRADE,
            "details": {
                "releaseChannel": "",
                "detailed_info": json.dumps({"fields": {"url": event_url,
                                                        "platformVersion": platform_version,
                                                        "connectorVersion": service_version,
                                                        "value": -999,  # All upgrade values are now -999
                                                        "exception": "download_exception"},
                                             "measurementName": "connectorUpgradeEvent",
                                             "tags": {"state": event_failure,
                                                      "connectorType": service,
                                                      "reason": "Download timed out"}})
            }
        }

        mock_post.assert_called_with(atlas_url_prefix + event_url, oauth.get_header(), json.dumps(event))
        mock_write.assert_called_with("/var/run/c_mgmt/upgrade_failures.json", {"c_ucmc": "1.2.3"})

        # Second event - should not be called
        EventSender.post(oauth,
                         config,
                         EventSender.UPGRADE,
                         service,
                         int(time.time()),
                         upgrade_event.get_detailed_info(),
                         dampener=dampener)

        # Ensure the post and file write have only been called once so far, with same version repeat failure
        self.assertEqual(1, mock_post.call_count)
        self.assertEqual(1, mock_write.call_count)

        v2_version = "1.2.3.4"
        mock_get_package_version.return_value = v2_version
        upgrade_event_v2 = UpgradeEvent(
            event_failure,
            service,
            None,  # downloadDuration
            None,  # installDuration
            None,  # fileSize
            event_url,
            v2_version,  # New version to allow next event to be sent
            platform_version,
            "Download timed out",
            "download_exception")

        # Third event - should be called because the version is different
        EventSender.post(oauth,
                         config,
                         EventSender.UPGRADE,
                         service,
                         int(time.time()),
                         upgrade_event_v2.get_detailed_info(),
                         dampener=dampener)

        self.assertEqual(2, mock_post.call_count)
        self.assertEqual(2, mock_write.call_count)

    def test_get_connector_type_and_version_from_detailed_info(self):
        """
        SPARK-1983: Make fms-connector-upgrades dashboard useable
        Get the connectorVersion and type from the event detailed info
        """
        # Test get does not blow up with a none value
        actual_type, actual_version = EventSender.get_connector_type_and_version(None)
        self.assertEqual(None, actual_type)
        self.assertEqual(None, actual_version)

        # Try and real event now with type and version
        expected_type = "c_ucmc"
        expected_version = "1.2.3"
        upgrade_event = UpgradeEvent(
            ManagementConnectorProperties.EVENT_SUCCESS,
            expected_type,
            None,
            None,
            None,
            "https://someurl",
            expected_version,
            ManagementConnectorProperties.EXPRESSWAY_FULL_VERSION,
            None,
            None)

        actual_type, actual_version = EventSender.get_connector_type_and_version(upgrade_event.get_detailed_info())
        self.assertEqual(expected_type, actual_type)
        self.assertEqual(expected_version, actual_version)

    def test_get_connector_type_and_version_does_not_blow_up(self):
        """
        SPARK-1983: Make fms-connector-upgrades dashboard useable
        Get the connectorVersion and type from the event detailed info
        """
        actual_type, actual_version = EventSender.get_connector_type_and_version(None)
        self.assertEqual(None, actual_type)
        self.assertEqual(None, actual_version)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
