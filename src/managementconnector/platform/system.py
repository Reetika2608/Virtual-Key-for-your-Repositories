''' Managment Connector System '''
# Ignore "C0413(wrong-import-position)" pylint: disable=C0413
import re
from re import split
import glob
import os
import subprocess  # nosec - usage validated
from distutils.version import StrictVersion

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config.versionchecker import get_expressway_version
from cafedynamic.cafexutil import CafeXUtils

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()

from base_platform.expressway.cdb.clusterconfigurationutils import ClusterDBPeerData, ClusterConfigurationException
from managementconnector.config.databasehandler import DatabaseHandler


class System(object):
    '''
    Management Connector System Class
    '''

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Management Connector System Class'

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self):
        '''System __init__'''
        self._cpu_data = {'user':       float(0),
                          'nice':       float(0),
                          'system':     float(0),
                          'idle':       float(0),
                          'iowait':     float(0),
                          'irq':        float(0),
                          'softirq':    float(0),
                          'steal':      float(0)
                          }

    # -------------------------------------------------------------------------

    @classmethod
    def get_system_cpu_time(cls):
        ''' Calculate the total system CPU time. Read /proc/stat which returns
            [cpu, USER, NICE, SYS, IDLE, IOWAIT, IRQ, SOFTIRQ, STEAL, GUEST].
            Add up the values for the cpu line and return. '''
        cpu_time = 0
        cpu_data = []
        for line in open("/proc/stat", "r"):
            line = line.strip()
            if 'cpu ' in line:
                cpu_data = line.split()

        for i in cpu_data[1:]:
            cpu_time += int(i)

        return cpu_time

    # -------------------------------------------------------------------------

    @classmethod
    def get_system_mem(cls):
        ''' Get system mem
            Returns {'total':total_mem in kB,
                      'percent': calculated percentage
                    }
        '''

        file = open("/proc/meminfo", "r")
        fileiter = file.readlines()
        file.close()

        mem_item = split('\s+', fileiter[0].strip())
        total_mem = float(mem_item[1])
        mem_item = split('\s+', fileiter[2].strip())
        available_mem = float(mem_item[1])

        memory_percent = (total_mem - available_mem) / total_mem * 100
        total_gb = total_mem / 1024 / 1024

        return {'total_kb': total_mem,
                'percent': '{0:.1f}'.format(memory_percent),
                'total_gb': '{0:.1f}'.format(total_gb)
                }

    # -------------------------------------------------------------------------

    def get_system_cpu(self):
        '''Get system CPU usage percentage'''
        for line in open("/proc/stat", "r"):
            line = line.strip()
            if 'cpu ' in line:
                cpu_data = line.split()
                break

        new_cpu_data = {'user':     float(cpu_data[1]),
                        'nice':     float(cpu_data[2]),
                        'system':   float(cpu_data[3]),
                        'idle':     float(cpu_data[4]),
                        'iowait':   float(cpu_data[5]),
                        'irq':      float(cpu_data[6]),
                        'softirq':  float(cpu_data[7]),
                        'steal':    float(cpu_data[8])
                        }

        prev_idle = self._cpu_data['idle'] + self._cpu_data['iowait']
        prev_non_idle = (self._cpu_data['user'] + self._cpu_data['nice'] +
                         self._cpu_data['system'] + self._cpu_data['irq'] +
                         self._cpu_data['softirq'] + self._cpu_data['steal'])
        prev_total = prev_idle + prev_non_idle

        new_idle = new_cpu_data['idle'] + new_cpu_data['iowait']
        new_non_idle = (new_cpu_data['user'] + new_cpu_data['nice'] +
                        new_cpu_data['system'] + new_cpu_data['irq'] +
                        new_cpu_data['softirq'] + new_cpu_data['steal'])
        total = new_idle + new_non_idle

        try:
            cpu_percentage = ((total - prev_total) - (new_idle - prev_idle)) / (total - prev_total) * 100
        except ZeroDivisionError:
            cpu_percentage = 0.0

        self._cpu_data = new_cpu_data
        return '{0:.1f}'.format(cpu_percentage)

    # -------------------------------------------------------------------------

    @classmethod
    def get_system_disk(cls):
        ''' Get system disk size
            Returns {'total_kb':total_disk in kB,
                      'percent': calculated percentage,
                      'total_gb':total_disk in gb
                    }
        '''

        res = subprocess.check_output(["df", "--total"]).decode()  # nosec - static input
        sys_disk = res.split('\n')[-2].split()

        total_disk = float(sys_disk[1]) / 1024

        disk_percent = int(sys_disk[4].strip('%'))
        total_gb = total_disk / 1024 / 1024

        return {'total_kb': total_disk,
                'percent': '{0:.1f}'.format(disk_percent),
                'total_gb': '{0:.1f}'.format(total_gb)
                }

    # -------------------------------------------------------------------------

    @staticmethod
    def get_cpu_cores():
        ''' Gets the number of cpus
            Returns string with number of cpus
        '''
        res = subprocess.check_output(["nproc", "--all"]).decode()  # nosec - static input
        return res.strip()
    # -------------------------------------------------------------------------

    @staticmethod
    def get_platform_type():
        ''' Gets platform type
            Returns 'physical' or 'virtual'
        '''
        cpu_info = "/proc/cpuinfo"
        platform_type = "physical"

        try:
            if 'hypervisor' in open(cpu_info).read():
                platform_type = "virtual"
        except: # pylint: disable=W0702
            platform_type = None

        return platform_type

    # -------------------------------------------------------------------------

    @classmethod
    def delete_tlps(cls, directory, exclude_list=None):
        ''' Delete TLPs from the filesystem'''
        System.delete_files(directory, ManagementConnectorProperties.PACKAGE_EXTENSION, exclude_list=exclude_list)

    # -------------------------------------------------------------------------

    @classmethod
    def delete_heartbeats(cls):
        ''' Delete heartbeat files from the filesystem'''
        System.delete_files(ManagementConnectorProperties.C_MGMT_VAR_RUN, ManagementConnectorProperties.HEARTBEAT_EXTENSION)

    # -------------------------------------------------------------------------

    @classmethod
    def delete_files(cls, directory, extension, exclude_list=None):
        ''' Delete files from the filesystem'''
        if exclude_list is None:
            exclude_list = []
        search_str = directory + '/*' + extension
        file_list = glob.glob(search_str)
        for delete_file in file_list:
            if not any(exclusion in delete_file for exclusion in exclude_list):
                os.remove(delete_file)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_current_tlp_filepath(name):
        '''
            returns get_current_tlp_filepath
        '''
        return System.get_tlp_filepath(ManagementConnectorProperties.INSTALL_CURRENT_DIR, name)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_previous_tlp_filepath(name):
        '''
            returns get_previous_tlp_filepath
        '''
        return System.get_tlp_filepath(ManagementConnectorProperties.INSTALL_PREVIOUS_DIR, name)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_tlp_filepath(directory, name):
        '''
            returns get_tlp_filepath
        '''
        path_filter = directory + '/' + name + '*' + ManagementConnectorProperties.PACKAGE_EXTENSION
        files = glob.glob(path_filter)
        DEV_LOGGER.debug('Detail="get_tlp_filepath: dir=%s, path_filter=%s, return=%s"' %
                         (directory, path_filter, files))
        if len(files):
            return files[0]
        else:
            return None

    # -------------------------------------------------------------------------

    @staticmethod
    def get_version_from_file(filename):
        """
            get version number from filename
            input:  c_mgmt_8.6-1.0.316111.tlp
            output: 8.6-1.0.316111
        """

        end = filename.rfind("_")
        start = end+1
        end = filename.rfind(".")
        version = filename[start: end]

        # Ensure the version has a number
        has_number = bool(re.search(r'\d', version))

        if not version or not has_number:
            version = None

        return version

    # -------------------------------------------------------------------------

    @staticmethod
    def am_i_clustered():
        """ Is this VCS part of a cluster? """
        cluster_peer = '/configuration/clusterpeer'

        rest_database_client = DatabaseHandler()
        cluster_recs = rest_database_client.get_records(cluster_peer)
        return len(cluster_recs) > 0

    # -------------------------------------------------------------------------

    @staticmethod
    def am_i_master():
        """ Is this node the current ParamDB cluster master? """

        am_i_master = False
        if not System.am_i_clustered():
            return True

        try:
            api = ClusterDBPeerData()
            this_peer = api.get_local_peer_index()
            master = api.get_config_master_index()

            am_i_master = master == this_peer
            DEV_LOGGER.info('Detail="Master: %s Node: %s "' % (master, this_peer))
        except ClusterConfigurationException:
            # If an exception occurs trigger defuse on any node.
            DEV_LOGGER.debug('Detail=""ClusterConfigurationException occurred when querying for master node""')
            am_i_master = True

        return am_i_master

    # -------------------------------------------------------------------------
    
    @staticmethod
    def minimum_expressway_supported_version():
        minimum_version = ManagementConnectorProperties.MINIMUM_EXPRESSWAY_VERSION
        if not minimum_version:
            DEV_LOGGER.info("No minimum supported version has been set. Please configure. It has skipped the check if Expressway platform version is supported or not")

        return minimum_version

   # -------------------------------------------------------------------------

    @staticmethod
    def is_penultimate_version():
        """ Check expressway versions"""

        expressway = get_expressway_version()
        minimum_expressway_version_support = System.minimum_expressway_supported_version()

        ultimate_supported = False
        try:
            if StrictVersion(expressway) == StrictVersion(minimum_expressway_version_support):
                DEV_LOGGER.info('Detail="Expressway version: %s will soon be an unsupported version as min Expressway supported version is: %s"' % (expressway, minimum_expressway_version_support))
                ultimate_supported = True
        except Exception as e:
            DEV_LOGGER.error("Error while validation version number: {0}".format(e))

        return ultimate_supported

    # -------------------------------------------------------------------------

    @staticmethod
    def get_platform_supported_status():
        """ Does the platform meet the min supported version. """

        expressway_major_minor_version = get_expressway_version()
        minimum_expressway_version_support = System.minimum_expressway_supported_version()
        supported = True
        try:
            if StrictVersion(expressway_major_minor_version) < StrictVersion(minimum_expressway_version_support):
                DEV_LOGGER.info('Detail="Expressway version: %s is unsupported as min Expressway supported version is: %s"' % (expressway_major_minor_version, minimum_expressway_version_support))
                supported = False
        except Exception as e:
            DEV_LOGGER.error("Error while validation version number: {0}".format(e))

        return supported