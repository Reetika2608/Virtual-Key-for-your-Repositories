""" Managment Connector Alarms """

from threading import Lock

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from base_platform.expressway.alarmprocessor import AlarmProcessor


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class MCAlarm():
    """ Management Connector Alarms
    """
    def __init__(self, config):
        """ constructor """
        self._config = config
        self._alarm_lock = Lock()

    def clear_alarms(self, excluded_alarms):
        """ clear alarms """
        DEV_LOGGER.info('Detail="FMC_Alarm clear_alarms, excluding following %s"' % excluded_alarms)
        alarm_list = self._config.read(ManagementConnectorProperties.ALARMS_RAISED)

        if alarm_list:
            for alarm in alarm_list:
                if alarm['id'] not in excluded_alarms:
                    with self._alarm_lock:
                        try:
                            AlarmProcessor.lower_alarm(alarm['uuid'])
                        except IOError:
                            # Potential permissions error when lowering other connectors' alarms,
                            # in deferred_alarms when cdb is down.  Will be lowered when unregistered.
                            DEV_LOGGER.error('Detail="FMC_Alarm clear_alarms, failed to lower %s. '
                                             'Alarm will be lowered when unregistered."' % alarm['uuid'])
                else:
                    DEV_LOGGER.debug('Detail="FMC_Alarm clear_alarms, not lowering %s"' % alarm['id'])

    def clear_alarm(self, guid):
        """ clear alarm """
        if self.is_raised(guid):
            DEV_LOGGER.debug('Detail="FMC_Alarm clear_alarm: lowering alarm:%s"' % guid)
            with self._alarm_lock:
                AlarmProcessor.lower_alarm(guid)

    def is_raised(self, guid):
        """ is alarm raised  """
        # use config instead of DB
        alarm_list = self._config.read(ManagementConnectorProperties.ALARMS_RAISED)

        if(not alarm_list):
            return False

        ret_val = False
        for alarm in alarm_list:
            alarm_id = alarm['uuid']
            ret_val = guid == alarm_id
            if ret_val is True:
                break

        DEV_LOGGER.debug('Detail="is_raised: guid alarm:%s, is_raised=%s"' % (guid, ret_val))
        return ret_val

    def raise_alarm(self, guid, params=None):
        """ raise alarm """
        DEV_LOGGER.debug('Detail="FMC_Alarm raise_alarm:%s"' % guid)
        with self._alarm_lock:
            if params is not None:
                AlarmProcessor.raise_alarm(guid, parameters=params)
            else:
                AlarmProcessor.raise_alarm(guid)
