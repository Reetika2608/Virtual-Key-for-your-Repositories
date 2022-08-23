""" Crash Monitor """

import time

from managementconnector.config.config import Config
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config import jsonhandler
from managementconnector.service.eventsender import EventSender

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()
TARGET_TYPE = Config(inotify=False).read(ManagementConnectorProperties.TARGET_TYPE)


class CrashMonitor(object):
    """
       Utilities Method for Monitoring  Crashes
    """

    # -------------------------------------------------------------------------
    def __init__(self, config):
        TARGET_TYPE = config.read(ManagementConnectorProperties.TARGET_TYPE)
        self._last_crash_check = jsonhandler.get_last_modified_timestamp(
                ManagementConnectorProperties.UPGRADE_HEARTBEAT_FILE % (TARGET_TYPE, TARGET_TYPE))

    def crash_check(self, oauth, config):
        """ Check for any crashes """

        alarm_list = config.read(ManagementConnectorProperties.PLATFORM_ALARMS_RAISED)
        DEV_LOGGER.debug('Detail="check_crashes: alarm_list: %s' % alarm_list)

        if alarm_list:
            if self._last_crash_check is None:
                self._last_crash_check = 0
            alarm_list = [alarm for alarm in alarm_list if int(alarm['last_reported']) >= self._last_crash_check]
            self._last_crash_check = time.time()
            for alarm in alarm_list:
                CrashMonitor.process_platform_alarm(oauth, alarm, config)

    # -------------------------------------------------------------------------

    @staticmethod
    def process_platform_alarm(oauth, alarm, config):
        """ Checks if a platforms alarms parameter contains fusion related keywords
            Crash related alarms contain process name in the parameters
        """
        DEV_LOGGER.debug('Detail="process_platform alarm: alarm: %s' % alarm)

        # generate keywords from entitled services details
        entitled_services = config.read(ManagementConnectorProperties.ENTITLED_SERVICES)

        # create list with both
        service_names = [service['name'] for service in entitled_services if 'name' in service]

        # Build a list of connector keywords to search for crashes
        connectors = {}
        for service in service_names:
            connectors[service] = [service]

        # Override known connectors with extra keywords
        if 'c_cal' in connectors:
            connectors['c_cal'] = ["c_cal", "calendar-connector", "java", "d_openj"]

        for parameter in alarm.get('parameters', []):
            for service_name, keywords in connectors.items():
                for connector_keyword in keywords:
                    if connector_keyword in str(parameter):
                        DEV_LOGGER.info('Detail="Detected Crash : service: %s, connector_keyword: %s"'
                                        % (service_name, parameter))

                        EventSender.post(oauth, config, EventSender.CRASH, service=service_name,
                                         timestamp=alarm['last_reported'])
                        return
