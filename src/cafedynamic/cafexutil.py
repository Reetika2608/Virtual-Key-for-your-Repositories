"""Utility class shared between Cafe XCommand and Cafe XStatus"""

import os
import subprocess  # nosec - usage validated
from subprocess import check_output  # nosec - usage validated
import imp
import pwd
import commands
import json
import errno
import re

from managementconnector.config import jsonhandler
from base_platform.expressway.cdb.restclient import ClusterDatabaseRestClient

# =============================================================================


class CafeXUtils(object):
    """
    Utilities shared between Cafe XCommand and Cafe XStatus
    """

    class CafeXModuleNotFound(Exception):
        """
        Exception if xstatus/xcommand module file not found.
        """
        pass

    @staticmethod
    def load_connector_module(module_path, module_name, exception_handle, logger, module_type=None):
        """
        Load the python module at module_path with module_name, and return it
        """

        module_filename = None
        module_pathname = None
        module_description = None
        connector_module = None

        try:
            module_filename, module_pathname, module_description = imp.find_module(module_name, [module_path])
        except ImportError as ex:
            # not logging this as an error as the connector simply may not have a need for a module
            # we'll instead raise a specific exception so that the caller can decide.
            logger.debug('Detail="Cafe Connector %s module was not found" '
                         'Module Path="%s" '
                         'Module Name="%s"' % (module_type, module_path, module_name))
            raise CafeXUtils.CafeXModuleNotFound('Cafe Connector %s Module does not exist for connector' % module_type)
        except Exception as ex:
            logger.error('Detail="Unknown error while attempting to find Cafe Connector %s module." '
                         'Module Path="%s" '
                         'Module Name="%s" '
                         'Error="%r %s"' % (module_type, module_path, module_name, ex, ex.__str__()))
            raise exception_handle('Unknown error while attempting to load Cafe Connector %s module' % module_type)

        try:
            connector_module = imp.load_module(module_name, module_filename, module_pathname, module_description)
        except ImportError as ex:
            logger.error('Detail="Error while attempting to load Cafe Connector %s module." '
                         'Module Path="%s" '
                         'Module Name="%s" '
                         'Error="%r %s"' % (module_type, module_path, module_name, ex, ex.__str__()))
            raise exception_handle('Error while attempting to load Cafe Connector %s module. '
                                   'Module does not exist for connector' % module_type)
        except Exception as ex:
            logger.error('Detail="Unknown error while attempting to load Cafe Connector %s module." '
                         'Module Path="%s" '
                         'Module Name="%s" '
                         'Error="%r %s"' % (module_type, module_path, module_name, ex, ex.__str__()))
            raise exception_handle('Unknown error while attempting to load Cafe Connector %s module' % module_type)
        finally:
            if module_filename:
                module_filename.close()

        return connector_module

    # -------------------------------------------------------------------------

    @staticmethod
    def get_package_information(package_name):
        """
        Gets package information via a dpkg -s command
        """

        try:
            with open(os.devnull, 'w') as devnull:
                command = ["dpkg", "-s", package_name]
                package_information = check_output(command, stderr=devnull)  # nosec - package name is not user supplied
        except subprocess.CalledProcessError:
            # returned non-zero exit status, returning none object
            package_information = None

        return package_information

    # -------------------------------------------------------------------------

    @staticmethod
    def is_connector_running(connector_name,logger):
        """
        Check if the connector process id running
        """
        pid_file_path = '/var/run/%s.pid' % connector_name

        if not os.path.exists(pid_file_path):
            logger.debug('Detail="is_connector_running: Pid file did not exist at %s: for component: %s"'
                         % (pid_file_path, connector_name))
            return False
        try:
            with open(pid_file_path) as pid_file:
                pid = pid_file.readline().rstrip()

            # Check if this process exists
            retval = 0
            with open(os.devnull, 'w') as devnull:
                # pid is read from os and cannot be supplied by external sources
                retval = subprocess.call(['ps', '-p', pid], stdout=devnull, stderr=subprocess.STDOUT)  # nosec

            if retval != 0:
                return False

        except (IOError, OSError) as ioe:
            # Catch and ignore IO errors, as file may not exist.
            logger.info('Detail="is_connector_running: Pid file access error at %s: for component: %s"'
                         % (pid_file_path, connector_name))

            logger.info('Detail="is_connector_running: file access error, err code %s, err message %s"'
                         % (errno.errorcode[ioe.errno], os.strerror(ioe.errno)))
            return False

        return True

    # -------------------------------------------------------------------------

    @staticmethod
    def is_package_installed(package_name, version=None):
        """
        Checks via dpkg if a particular package is installed.
        When a package is fully installed, its status is 'Status: install ok installed\n'
        """

        if package_name == 'c_mgmt':
            return True

        if package_name == 'c_ccucmgmt':
            return True

        ret_val = False
        success_output = 'Status: install ok installed\n'
        package_information = CafeXUtils.get_package_information(package_name)

        if package_information:
            if success_output in package_information:
                if version:
                    ret_val = version in package_information
                else:
                    ret_val = True
            else:
                ret_val = False

        return ret_val

    @staticmethod
    def is_package_installing(package_name, target_type, logger):
        """
        Checks if a particular package is in an installing state.
        """

        # Same path as MC Properties
        if (target_type == 'c_ccucmgmt'):
            path = "/var/run/c_ccucmgmt/installing_status.json"
        else:
            path = "/var/run/c_mgmt/installing_status.json"
        installing_state = False
        state = None

        logger.debug('Detail="is_package_installing: checking %s"' % package_name)

        # Forward lookup due to failure case more prevalent.
        if os.path.isfile(path):
            try:
                with open(path, 'r') as json_file:
                    state = json.load(json_file)
            except IOError, ioe:
                # Catch and ignore IO errors, as file may not exist.
                logger.debug('Detail="is_package_installing: Installing file did not exist at %s: for component: %s"'
                             % (path, package_name))

                logger.debug('Detail="is_package_installing: I/O error, err code %s, err message %s"'
                             % (errno.errorcode[ioe.errno], os.strerror(ioe.errno)))

        else:
            logger.debug('Detail="is_package_installing: Installing file did not exist at %s: for component: %s"'
                         % (path, package_name))

        if state:
            logger.debug('Detail="is_package_installing: package: %s, installing_state file content %s"'
                         % (package_name, state))
            if package_name in state:
                installing_state = True

        return installing_state

    @staticmethod
    def is_package_not_installed(package_name):
        """
        Checks via dpkg if a particular package is not installed
        If package is not installed (nor half/purge installed), returns true
        """
        ret_val = True
        package_information = CafeXUtils.get_package_information(package_name)

        if package_information:
            ret_val = False

        return ret_val

    # -------------------------------------------------------------------------

    @staticmethod
    def get_installed_connectors(connector_type):
        """
        Checks via dpkg for a list of installed connectors
        """

        rtn_list = None

        # grep contains a space to ensure traffic_server is not returned
        # connector_type cannot be supplied by an external process
        output = commands.getstatusoutput("dpkg -l | grep \" %s\" | awk '{print $2}'" % (connector_type))  # nosec

        if output[1]:
            rtn_list = output[1].split()

        return rtn_list

    # -------------------------------------------------------------------------

    @staticmethod
    def get_package_version(package_name):
        """
        Returns the version of a particular installed package
        """

        version = None
        package_information = CafeXUtils.get_package_information(package_name)

        if package_information:
            version_string = "Version: "
            start = package_information.find(version_string)+len(version_string)
            if start >= 0:
                end = package_information.find("\n", start)
                if end >= 0:
                    version = package_information[start:end]

        return version

    # -------------------------------------------------------------------------

    @staticmethod
    def is_connector_enabled(rest_client, connector_name):
        """
        Check the service table to see if the connector is enabled
        """

        if not isinstance(rest_client, ClusterDatabaseRestClient):
            raise Exception("Programmer Error: ClusterDatabaseRestClient instance not passed.")

        service_url = '/configuration/service/name/%s?peer=local'

        records = rest_client.get_records(service_url % connector_name)

        if len(records) >= 1:
            return records[0]['mode'] == 'on'
        else:
            return False

    # -------------------------------------------------------------------------

    @staticmethod
    def set_process_owner(username, logger):
        """
        Set the calling process's uid and gid to that if the username passed
        """
        pwnam = None

        try:
            pwnam = pwd.getpwnam(username)
        except KeyError as ex:
            logger.error('Detail="Error while attempting to retrieve user id/group id" '
                         'username="%s" '
                         'Error="%r %s"' % (username, ex, ex.__str__()))
            raise OSError(ex)

        # set the process gid first, then uid.
        # Otherwise if you set uid first then you won't have permission to set the gid
        try:
            os.setegid(pwnam.pw_gid)
            os.initgroups(username, pwnam.pw_gid)
            os.seteuid(pwnam.pw_uid)
        except OSError as ex:
            # Ignore error if running in Docker
            # (if app runs as the _app user then it won't be able to set UID/GID)
            if CafeXUtils._is_docker():
                logger.warn('Detail="is_docker: [Ignore] Error while attempting to set UID/GID" '
                            'username="%s" Error="%r %s"' % (username, ex, ex.__str__()))
            else:
                logger.error('Detail="Error while attempting to set user id/group id" '
                             'Error="%r %s"' % (ex, ex.__str__()))
                raise ex

    # -------------------------------------------------------------------------

    @staticmethod
    def _is_docker():
        """Detects if we are running inside a docker container."""
        cgroupinfo = ''.join(file('/proc/1/cgroup', 'r').readlines())
        return re.search(r'\b:/docker/\b', cgroupinfo)

    # -------------------------------------------------------------------------

    @staticmethod
    def is_backup_restore_occurring(logger):
        """
        Check if the Expressway is in a backup and restore state.
        Check's if the busy file exists at: '/tmp/backup-restore-busy'
        """

        occurring = os.path.isfile('/tmp/backup-restore-busy')  # nosec - /tmp usage validated
        if occurring:
            logger.debug('Detail="is_backup_restore_occurring: %s"' % occurring)

        return occurring

    # -------------------------------------------------------------------------
    @staticmethod
    def get_operation_status(connector_name, logger):
        """
        Check Connector operation
        """

        rtn = 'outage'
        status_path = '/var/run/%s/status.json' % connector_name

        legacy_permitted_status = ['true', 'false']
        permitted_status = ['ouatge', 'impaired', 'operational']

        try:

            if os.path.exists(status_path):

                json_status = jsonhandler.read_json_file(status_path)

                # status can be written as bool or str depending on connector
                if json_status is not None:
                    if 'state' in json_status:
                        op_status = str(json_status['state']).lower()
                        if op_status in permitted_status:
                            return op_status
                    elif 'operational' in json_status:
                        op_status = str(json_status['operational']).lower()
                        if op_status in legacy_permitted_status:
                            return op_status

        except IOError, ioerror:
            logger.error('Detail="get_operation_status: I/O error connector %s, err code %s, err message %s"' %
                         (connector_name, errno.errorcode[ioerror.errno], os.strerror(ioerror.errno)))
        except ValueError:
            logger.error('Detail="Invalid JSON at path = %s"' % (status_path))

        return rtn

    # -------------------------------------------------------------------------

    @staticmethod
    def make_path(path, mode=None):
        """
        Recursive directory creation function. Makes all intermediate-level
        directories needed to contain the leaf directory. Throws an error exception
        if the leaf directory cannot be created. Passes silently if the path
        already exists.

        The default mode is 0777 (octal) combined with the current umask. If an
        explicit mode is supplied, the umask is ignored and the directory is
        created with exactly the supplied mode.
        """

        if mode is None:
            CafeXUtils.makedirs(path, 0777)
        else:
            if CafeXUtils.makedirs(path, mode):
                os.chmod(path, mode)

    # -------------------------------------------------------------------------

    @staticmethod
    def makedirs(path, mode):
        """
        Wrapper for the os.makedirs that ignores errors if the path already
        exists.
        """
        try:
            os.makedirs(path, mode)
            return True
        except OSError as exc:
            # Ignore "already exists" exceptions
            if exc.errno != errno.EEXIST:
                raise
        return False
