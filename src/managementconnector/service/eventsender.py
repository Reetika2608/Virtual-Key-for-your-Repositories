""" Hybrid Event Sender """

import json
import time

from managementconnector.platform.http import Http
from managementconnector.config.config import Config
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.platform.serviceutils import ServiceUtils
from managementconnector.service.eventdampener import EventDampener

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class EventSender(object):
    """ Utility to send hybrid events to FMS """

    CRASH = "crash"
    ROLLBACK = "rollback"
    LOGPUSH = "logpush"
    WATCHDOG_RESTART = "watchdog_restart"
    WATCHDOG_FILE_MISSING = "watchdog_file_missing"
    WATCHDOG_EXCEPTION = "watchdog_exception"
    WATCHDOG_MACHINEACCOUNT_RUNNER_RESTART_THREAD = "watchdog_machineaccount_runner_restart_thread"
    MERCURY_PROBE_MISSED = "mercury_probe_missed"
    FOUND_MACHINE_ACCOUNT_EXPIRATION = "found_machine_account_expiration"
    MISSING_MACHINE_ACCOUNT_INFO_DB = "missing_machine_account_info_db"
    OAUTH_MISSING_MACHINE_ACCOUNT_EXPIRATION = "oauth_missing_machine_account_expiration"
    FAILURE_READING_MACHINE_ACCOUNT_EXPIRATION = "failure_reading_machine_account_expiration"
    MACHINE_ACCOUNT_DAYS_TO_EXPIRATION = "machine_account_days_to_expiration"
    FAILURE_UPDATE_MACHINE_ACCOUNT = "failure_update_machine_account"
    FAILURE_GETTING_OAUTH_RESPONSE_REFRESH = "failure_getting_oauth_response_refresh"
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
        target_type = config.read(ManagementConnectorProperties.TARGET_TYPE)

        event = {
            "orgId": org_id,
            "connectorId": target_type + "@" + serial_number,
            "connectorType": target_type,
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
            DEV_LOGGER.debug('Detail="Sending event: {}"'.format(event))
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
        target_type = config.read(ManagementConnectorProperties.TARGET_TYPE)

        event = {
            "orgId": org_id,
            "connectorId": target_type + "@" + serial_number,
            "connectorType": target_type,
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
