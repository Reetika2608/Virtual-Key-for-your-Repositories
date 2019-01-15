""" Managment Connector Alarms """

import os
import errno

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config.jsonhandler import JsonHandler

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class AlarmFormatError(Exception):
    """
    Alarm Formatting Error
    """
    pass


class ServiceManifest():
    """ Model the Manifest associated with a Service """
    def __init__(self, service_name):
        """ constructor """
        self.start = None
        self.end = None
        self.exclude_range = list()
        self.suppressed = list()
        self.external_alarms = list()
        self.service = service_name

        self.cgroup_limits = {'cpu': 100,
                              'memory': 100}

        self.init = False

    def setup(self, service_name):
        """ raise alarm """

        # Dependencies will not have a manifest file
        if not self.init and ManagementConnectorProperties.DEPENDENCY_PREFIX not in service_name:

            DEV_LOGGER.debug('Detail="ServiceManifest: getting details for service %s"' % service_name)

            path_to_cat = "/mnt/harddisk/current/fusion/manifest/" + service_name + ".json"

            try:

                json = JsonHandler(path_to_cat, False)

                # Pass a List to jsonhandler
                self.start = json.get_int("alarms/start".split('/'))
                self.end = json.get_int("alarms/end".split('/'))
                exclude_range = json.get("alarms/exclude".split('/'))
                sup_alarms = json.get("alarms/suppress".split('/'))
                external_alarms = json.get("alarms/external".split('/'))
                DEV_LOGGER.debug('Detail="ServiceManifest: external_alarms {}"'.format(external_alarms))

                if exclude_range:
                    self.exclude_range = exclude_range

                if sup_alarms:
                    self.suppressed = sup_alarms

                if external_alarms:
                    self.external_alarms = [int(external_alarm) for external_alarm in external_alarms]

                cpu_limit = json.get_int("cgroupLimits/cpuPriorityPercentage".split('/'))
                memory_limit = json.get_int("cgroupLimits/memoryPercentageLimit".split('/'))

                if cpu_limit is not None:
                    self.cgroup_limits['cpu'] = cpu_limit
                if memory_limit is not None:
                    self.cgroup_limits['memory'] = memory_limit

                # Ensure Start and End exist
                if not self.start or not self.end:
                    # First pass manifest won't exist so exit and try again.
                    return

                # Quick Formatting test
                if self.end < self.start:
                    raise AlarmFormatError('Formatting Error')

                self.init = True
                DEV_LOGGER.debug('Detail="ServiceManifest: setup: %s, '
                                 'alarm start %s, alarm end %s. CPU limit %d%%,'
                                 'memory limit %d%%, exclude alarms: %s, '
                                 'suppressed alarms %s, '
                                 'external_alarms %s"'
                                 % (service_name,
                                    self.start,
                                    self.end,
                                    self.cgroup_limits['cpu'],
                                    self.cgroup_limits['memory'],
                                    self.exclude_range,
                                    self.suppressed,
                                    self.external_alarms))

            except IOError, ioex:
                DEV_LOGGER.error('Detail="ServiceManifest: No Manifest File for %s "', path_to_cat)
                DEV_LOGGER.error('Detail="ServiceManifest: I/O error, err code %s, err message %s"',
                                 errno.errorcode[ioex.errno], os.strerror(ioex.errno))
            except AlarmFormatError, afe:
                DEV_LOGGER.error('Detail="ServiceManifest: Manifest Format Error. Service %s: %s"',
                                 service_name, afe)

    def contains_alarm(self, alarm_id):
        """ check if alarm in the catalog """

        if not self.init:
            self.setup(self.service)

        rtn = False

        if self.init:
            if alarm_id >= self.start and alarm_id <= self.end:
                rtn = True

        DEV_LOGGER.debug('Detail="ServiceManifest(%s): contains_alarm returning %s, for alarm %s"' %
                         (self.service, rtn, alarm_id))

        return rtn

    def get_exclude_range(self):
        """ checks if an exclude alarm range has been supplied """
        return self.exclude_range

    def get_suppressed_alarms(self):
        """ checks if a list of suppressed alarms has been supplied """
        return self.suppressed

    def get_external_alarms(self):
        """ return external alarms """
        return self.external_alarms

    def get_cgroup_limits(self):
        """ return cgroup limit from the manifest. If the maifest has no limits
            then return {'cpu':100, 'memory':100}
        """
        if (not self.init):
            self.setup(self.service)

        return self.cgroup_limits
