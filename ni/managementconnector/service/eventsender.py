""" Hybrid Event Sender """

import json
import time

from ni.managementconnector.platform.http import Http
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.platform.serviceutils import ServiceUtils
from ni.managementconnector.service.eventdampener import EventDampener

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class EventSender(object):
    """ Utility to send hybrid events to FMS """

    CRASH = "crash"
    ROLLBACK = "rollback"
    LOGPUSH = "logpush"
    WATCHDOG_RESTART = "watchdog_restart"
    MERCURY_PROBE_MISSED = "mercury_probe_missed"
    UPGRADE = "connectorUpgrade"
    event_dampener = EventDampener()

    @staticmethod
    def post(oauth, config, event_type, service=ManagementConnectorProperties.SERVICE_NAME, timestamp=int(time.time()),
             detailed_info="", dampener=event_dampener):
        """ Sends Details of a Hybrid Event to FMS """

        org_id = config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)['organization_id']
        serial_number = config.read(ManagementConnectorProperties.SERIAL_NUMBER)
        cluster_id = config.read(ManagementConnectorProperties.CLUSTER_ID)

        event = {
            "orgId": org_id,
            "connectorId": service + "@" + serial_number,
            "connectorType": service,
            "connectorVersion": ServiceUtils.get_version(service) or 'None',
            "clusterId": cluster_id,
            "timestamp": timestamp,
            "type": event_type,
            "details": {
                "releaseChannel": ServiceUtils.get_release_channel(),
                "detailed_info": json.dumps(detailed_info) if isinstance(detailed_info, dict) else detailed_info
            }
        }

        event_url = config.read(ManagementConnectorProperties.EVENT_URL)
        atlas_url_prefix = config.read(ManagementConnectorProperties.ATLAS_URL_PREFIX)
        event_url = event_url % (event['orgId'], event['connectorId'])
        try:
            DEV_LOGGER.debug('Detail="Sending event: {}"'.format(event))

            if event_type == EventSender.UPGRADE:
                upgrade_type, upgrade_version = EventSender.get_connector_type_and_version(detailed_info)
                if upgrade_type and upgrade_version and \
                        dampener.has_upgrade_event_been_sent(upgrade_type, upgrade_version):
                    # Event already sent or type and version could not be retrieved from the event info
                    return
                else:
                    if "fields" in str(detailed_info) and isinstance(detailed_info, dict):
                        # Value of Negative 999 is being used as an identifier for new approach
                        # This will be used in visualisation queries to indicate the new
                        # 1-1 (success/failure) first attempt approach for upgrade metrics
                        detailed_info["fields"]["value"] = -999
                        event["details"]["detailed_info"] = json.dumps(detailed_info)

            return Http.post(atlas_url_prefix + event_url, oauth.get_header(), json.dumps(event))
        except Exception as ex:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="Failed to post crash data: %s"' % ex)

    @staticmethod
    def get_connector_type_and_version(detailed_info):
        """ Get the connector type and version from detailed info """
        upgrade_type = None
        upgrade_version = None
        if isinstance(detailed_info, dict):
            if "tags" in detailed_info and "fields" in detailed_info:
                if "connectorType" in detailed_info["tags"]:
                    upgrade_type = detailed_info["tags"]["connectorType"]
                if "connectorVersion" in detailed_info["fields"]:
                    upgrade_version = detailed_info["fields"]["connectorVersion"]

        return upgrade_type, upgrade_version
