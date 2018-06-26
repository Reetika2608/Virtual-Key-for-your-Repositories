""" Service metric class """

from collections import deque

from ni.managementconnector.platform.system import System
from ni.managementconnector.service.manifest import ServiceManifest
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class ServiceMetrics(object):
    ''' Service metric class'''
    def __init__(self, name, ManifestClass=ServiceManifest):
        ''' ServiceMetrics__init__'''
        self._name = name
        self._manifest = ManifestClass(self._name)
        self._total_system_memory = long(System.get_system_mem()['total_kb']) * 1024
        self._manifest_limits = self._manifest.get_cgroup_limits()
        self._current_process_cpu_time = 0
        self._current_system_cpu_time = 0

        self._percent_system_cpu = 0
        self._percent_system_memory = 0

        self._avg_cpu_data = deque(maxlen=100)
        self._avg_mem_data = deque(maxlen=100)

    # -------------------------------------------------------------------------

    def _get_cgroup_cpu_time(self):
        ''' Get a list of all processes that are running in the service's
            cgroup. For each pid read /proc/PID/stat and get columns 13 &
            14 (user time & system time). Add all these up for the total
            cpu time of the cgroup/connector
        '''

        group_cpu = 0
        try:
            with open('/cgroup/' + self._name + '/cgroup.procs', 'r') as procs_file:
                for line in procs_file:
                    try:
                        with open('/proc/' + line.rstrip('\n') + '/stat', 'r') as statfile:
                            stat_data = statfile.readline().split()
                            group_cpu = group_cpu + long(stat_data[13])
                            group_cpu = group_cpu + long(stat_data[14])
                    except (IOError, OSError) as file_err:
                        DEV_LOGGER.info('Detail="_get_cgroup_cpu_time:Error reading from file: errno=%s, strerror=%s. Service(%s) child process(%s) may have stopped"' %
                                        (file_err.errno, file_err.strerror, self._name, line.rstrip('\n')))
        except (IOError, OSError) as file_err:
            DEV_LOGGER.error('Detail="_get_cgroup_cpu_time:Error reading from file: errno=%s, strerror=%s."' %
                             (file_err.errno, file_err.strerror))
        return group_cpu

    def update_service_metrics(self):
        ''' Calculate and log process usage statistics.
            Memory: Usage comes easily from control group files. Read the
                    current usage and calculate and log basic stats.
            CPU:    Requires some calculation. On every call to this method
                    we read the systems total CPU time from /proc/stat. Then
                    we use the services cgroup.procs reporting file to get a
                    list of prcesses in the cgroup. For each process we get
                    its current system and user time directly from /proc/PID/stat
                    to calculate the CPU time of this service. For both of those
                    values we get the delta between this and the last time the
                    method was called (which happens every ~30 seconds). The
                    two deltas can then be used to calculate the percentage of
                    how much CPU time this service used since the last call.
        '''

        new_process_cpu_time = self._get_cgroup_cpu_time()
        new_system_cpu_time = System.get_system_cpu_time()
        process_cpu_delta = new_process_cpu_time - self._current_process_cpu_time
        self._current_process_cpu_time = new_process_cpu_time
        system_cpu_delta = new_system_cpu_time - self._current_system_cpu_time
        self._current_system_cpu_time = new_system_cpu_time

        self._percent_system_cpu = 100 * float(process_cpu_delta) / float(system_cpu_delta)
        if self._percent_system_cpu < 0:
            self._percent_system_cpu = 0

        try:
            with open('/cgroup/' + self._name + '/memory.usage_in_bytes', 'r') as memory_usage_file:
                memory_usage_in_bytes = long(memory_usage_file.read())
        except (IOError, OSError) as file_err:
            DEV_LOGGER.error('Detail="update_service_metrics:Error reading from file: errno=%s, strerror=%s."' %
                             (file_err.errno, file_err.strerror))
            memory_usage_in_bytes = long(0)

        self._percent_system_memory = 100 * float(memory_usage_in_bytes) / float(self._total_system_memory)

        cpu_limit = str(self._manifest_limits['cpu']) + '%' if self._manifest_limits['cpu'] < 100 else 'None'
        mem_limit = str(self._manifest_limits['memory']) + '%' if self._manifest_limits['memory'] < 100 else 'None'

        self._avg_cpu_data.append(self._percent_system_cpu)
        self._avg_mem_data.append(self._percent_system_memory)

        DEV_LOGGER.info('Detail="Resource usage fusion(%s), '
                         'CPU usage [limit: %s, current %0.1f%%], '
                         'RAM usage [limit: %s, current %0.1f%%]"'
                         % (self._name,
                            cpu_limit, self._percent_system_cpu,
                            mem_limit, self._percent_system_memory))

# =============================================================================

    def get_service_metrics(self):
        ''' Return the average of CPU and memory metrics since this method was last called'''
        average_cpu = 0
        average_mem = 0
        if len(self._avg_cpu_data) > 0:
            average_cpu = sum(self._avg_cpu_data) / len(self._avg_cpu_data)
            self._avg_cpu_data.clear()
        if len(self._avg_mem_data) > 0:
            average_mem = sum(self._avg_mem_data) / len(self._avg_mem_data)
            self._avg_mem_data.clear()
        return '{0:.1f}'.format(average_cpu), '{0:.1f}'.format(average_mem)
