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
    CONNECTION_CHECK = "connectionCheck"
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
                if ManagementConnectorProperties.EVENT_FAILURE in str(detailed_info):
                    if not dampener.is_failure_event_permitted():
                        # If event is not permitted, return
                        return
                    else:
                        # If a failure-case upgrade event is permitted to send, the attempt number is added to
                        # detailed_info as a field called "value", which allows us to filter on no. of attempts
                        if "fields" in str(detailed_info) and isinstance(detailed_info, dict):
                            detailed_info["fields"]["value"] = dampener.get_total_failures()
                            event["details"]["detailed_info"] = json.dumps(detailed_info)
                else:
                    if ManagementConnectorProperties.EVENT_SUCCESS in str(detailed_info):
                        dampener.reset_counters()

            return Http.post(atlas_url_prefix + event_url, oauth.get_header(), json.dumps(event))
        except Exception as ex:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="Failed to post crash data: %s"' % ex)

    @staticmethod
    def post_simple(oauth, config, event_type, service=ManagementConnectorProperties.SERVICE_NAME, timestamp=int(time.time()),
                    detailed_info=""):
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
            "details": detailed_info
        }

        event_url = config.read(ManagementConnectorProperties.EVENT_URL)
        atlas_url_prefix = config.read(ManagementConnectorProperties.ATLAS_URL_PREFIX)
        event_url = event_url % (event['orgId'], event['connectorId'])
        try:
            DEV_LOGGER.debug('Detail="Sending event: {}"'.format(event))
            return Http.post(atlas_url_prefix + event_url, oauth.get_header(), json.dumps(event))
        except Exception as ex:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="Failed to post event data: %s"' % ex)
