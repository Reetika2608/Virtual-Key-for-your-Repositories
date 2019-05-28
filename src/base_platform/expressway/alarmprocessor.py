""" FMC Alarm Processor """

import subprocess
import traceback
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

ALARM_EXECUTABLE = '/sbin/alarm'

ALARM_RAISE = 'raise'
ALARM_LOWER = 'lower'

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class AlarmProcessor(object):
    """ Alarm Processor """

    @staticmethod
    def raise_alarm(alarm_id, parameters=None):
        """ raise and expressway alarm """
        command = [ALARM_EXECUTABLE, ALARM_RAISE, alarm_id]
        if parameters:
            for param in parameters:
                command += ["--param", str(param)]
        try:
            subprocess.check_output(command)
        except subprocess.CalledProcessError:
            DEV_LOGGER.error('Detail="AlarmProcessor: Failed to raise alarm alarm_id=%s"', alarm_id)
        except Exception as error:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="AlarmProcessor: Failed to raise alarm alarm_id=%s, Exception occurred:%s, '
                             'stacktrace=%s"', alarm_id, repr(error), traceback.format_exc())

    @staticmethod
    def lower_alarm(alarm_id):
        """ lower and expressway alarm """
        command = [ALARM_EXECUTABLE, ALARM_LOWER, alarm_id]

        try:
            subprocess.check_output(command)
        except subprocess.CalledProcessError:
            DEV_LOGGER.error('Detail="AlarmProcessor: Failed to lower alarm alarm_id=%s"', alarm_id)
        except Exception as error:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="AlarmProcessor: Failed to lower alarm alarm_id=%s, Exception occurred:%s, '
                             'stacktrace=%s"', alarm_id, repr(error), traceback.format_exc())
