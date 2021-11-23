""" SPARK-1983: Simplify back off logic and only sent first upgrade attempt """

from managementconnector.config import jsonhandler
from managementconnector.config.config import Config
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
TARGET_TYPE = Config(inotify=False).read(ManagementConnectorProperties.TARGET_TYPE)


class EventDampener:
    """ Class to manage back-off of Event Sending. """

    def __init__(self):
        self._upgrade_event_attempts = load_upgrade_attempts_file()

    def has_upgrade_event_been_sent(self, connector_type, connector_version):
        """
        has an error event already been sent for this connectorType and connectorVersion pair
        File/JSON Example for FMC restart cases: {"connectorType": "connectorVersion"}
        """
        config = Config(False)
        target_type = config.read(ManagementConnectorProperties.TARGET_TYPE)
        if target_type is None:
            target_type = ManagementConnectorProperties.SERVICE_NAME
        if connector_type in self._upgrade_event_attempts:
            if connector_version == self._upgrade_event_attempts[connector_type]:
                DEV_LOGGER.debug('Detail="EventDampener: Not sending event, upgrade event previously sent for '
                                 'connectorType={}, connectorVersion={} previousFailures={}"'
                                 .format(connector_type, connector_version, self._upgrade_event_attempts))
                return True

        DEV_LOGGER.info('Detail="EventDampener: No previous upgrade event found for connectorType: {}, '
                        'connectorVersion={}, previousFailures={}"'
                        .format(connector_type, connector_version, self._upgrade_event_attempts))

        self._upgrade_event_attempts[connector_type] = connector_version
        jsonhandler.write_json_file((ManagementConnectorProperties.UPGRADE_EVENTS_FILE % target_type),
                                    self._upgrade_event_attempts)

        return False


# Module method rather than static class method for mocking purposes
def load_upgrade_attempts_file():
    """ read previous upgrade attempts from disk, or default to empty dictionary """
    contents = {}
    file_contents = jsonhandler.read_json_file((ManagementConnectorProperties.UPGRADE_EVENTS_FILE % TARGET_TYPE))
    if file_contents:
        contents = file_contents
    return contents
