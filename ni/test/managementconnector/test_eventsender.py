"""
    Test EventSender
"""
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

    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch("ni.managementconnector.service.eventsender.Http.post")
    def test_upgrade_event_sent(self, mock_post, mock_get_package_version):
        """
            User Story: US22967: FMC: Introduce back off logic in event sending
            if FMC can't download/install a connector
        """
        oauth = mock.Mock()
        config = mock.Mock()
        config.read.side_effect = config_read
        mock_get_package_version.return_value = "1.2.3"

        dampener = EventDampener()

        service = config.read(ManagementConnectorProperties.SERVICE_NAME)
        platform_version = config.read(ManagementConnectorProperties.EXPRESSWAY_FULL_VERSION)
        event_success = config.read(ManagementConnectorProperties.EVENT_SUCCESS)

        upgrade_event = UpgradeEvent(
            event_success,
            "self._name",
            "download_duration",
            "install_duration",
            "downloaded_file_size",
            "url",
            "version",
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

        dampener.reset_counters()

    @mock.patch("ni.cafedynamic.cafexutil.CafeXUtils.get_package_version")
    @mock.patch("ni.managementconnector.service.eventsender.Http.post")
    def test_upgrade_event_not_sent(self, mock_post, mock_get_package_version):
        """
            User Story: US22967: FMC: Introduce back off logic in event sending
            if FMC can't download/install a connector

            ManagementConnectorProperties values would ordinarily be mocked, but mock objects cannot
            be JSON serialized, which is required here. Instead the mocked config object can substitute values.
        """
        oauth = mock.Mock()
        config = mock.Mock()
        config.read.side_effect = config_read
        mock_get_package_version.return_value = "1.2.3"

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
                                                        "value": 1,
                                                        "exception": "download_exception"},
                                             "measurementName": "connectorUpgradeEvent",
                                             "tags": {"state": event_failure,
                                                      "connectorType": service,
                                                      "reason": "Download timed out"}})
            }
        }

        mock_post.assert_called_with(atlas_url_prefix + event_url, oauth.get_header(), json.dumps(event))

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

        dampener.reset_counters()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
