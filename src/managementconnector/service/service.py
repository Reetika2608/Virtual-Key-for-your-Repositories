"""
    Class to manage blend configuration.
"""

# Standard library imports
import shutil
import logging
import time
from urllib2 import URLError
from urllib2 import HTTPError
from distutils.version import StrictVersion
import re

# Local application / library specific imports
from managementconnector.config.databasehandler import DatabaseHandler, register_default_loggers
from cafedynamic.cafexutil import CafeXUtils
from managementconnector.platform.http import Http, CertificateExceptionFusionCA, CertificateExceptionNameMatch, CertificateExceptionInvalidCert, InvalidProtocolException
from managementconnector.service.manifest import ServiceManifest
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config.versionchecker import get_expressway_full_version
from managementconnector.service.servicemetrics import ServiceMetrics
from managementconnector.platform.serviceutils import ServiceUtils

from managementconnector.service.eventsender import EventSender
from managementconnector.events.upgradeevent import UpgradeEvent

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()

# Java can take a long time to install
INSTALL_RETRIES = 90

UNINSTALL_RETRIES = 30
ENABLE_RETRIES = 20
DISABLE_RETRIES = 20

# =============================================================================


class ServiceException(Exception):
    ''' handle custom exceptions for service class '''
    pass

# =============================================================================


class InstallException(ServiceException):
    ''' handles install exceptions '''
    pass

# =============================================================================


class UninstallException(ServiceException):
    ''' handles uninstall exceptions '''
    pass

# =============================================================================


class EnableException(ServiceException):
    ''' handles enable exceptions '''
    pass

# =============================================================================


class DisableException(ServiceException):
    ''' handles disable exceptions '''
    pass


# =============================================================================


class CertNameException(ServiceException):
    ''' handles disable exceptions '''
    pass


class DownloadException(ServiceException):
    ''' handles url/tlp download exceptions '''
    pass


class ServiceCertificateExceptionFusionCA(ServiceException):
    ''' handles url/tlp download exceptions '''
    pass


class ServiceCertificateExceptionNameMatch(ServiceException):
    ''' handles url/tlp download exceptions '''
    pass


class ServiceCertificateExceptionInvalidCert(ServiceException):
    ''' handles url/tlp download exceptions '''
    pass


class DownloadTLPAccessException(DownloadException):
    ''' Invalid TLP Path '''
    pass


class DownloadServerUnavailableException(DownloadException):
    ''' Can't Reach the TLP Server '''
    pass

# =============================================================================


class Service(object):
    ''' Management Connector Service Class'''

    def __str__(self):
        return 'Management Connector Service Class'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self, name, config, oauth, ManifestClass=ServiceManifest):
        ''' Service__init__'''
        self._name = name
        # Mgmt Connector File from which list of enabled services is read
        self._config = config
        self._oauth = oauth

        self._install_details = {'url': None, 'version': CafeXUtils.get_package_version(name)}

        self._manifest = ManifestClass(self._name)
        self._rest_client = DatabaseHandler()

        self._service_metrics = ServiceMetrics(self._name, ManifestClass)
        self._cached = None
        self._expressway_full_version = get_expressway_full_version()

    # -------------------------------------------------------------------------

    def get_name(self):
        ''' Get service name from service object.
            Returns the service name. '''
        return self._name

    def get_install_details(self):
        ''' Get service config from service object.
            Returns the service config. '''
        return self._install_details

    # -------------------------------------------------------------------------

    def update_service_metrics(self):
        ''' Access method that allows the outside world to
            call the internal ServiceMetrics update method
        '''
        return self._service_metrics.update_service_metrics()

    # -------------------------------------------------------------------------

    def get_service_metrics(self):
        '''Return Any Stored Metrics via ServiceMetrics'''

        return self._service_metrics.get_service_metrics()

    # -------------------------------------------------------------------------

    def configure(self,  url, version, upgrade_disabled_from_fms):
        ''' Compares 'new_config' with the service objects existing config.
            If there are any config changes, update the system with the
            changes.

            The following exceptions can be raised when this method is
            called and need to be handled by the calling class:
                raise DownloadException({"message":"HTTP error", "reason":e.reason})
                raise InstallException({"message":"IOError", "errno":e.errno, "strerror":e.strerror})
                raise GenericException({"message":"generic exception", "reason": traceback.format_exc()})
                raise UninstallException({"message":"The tlp has not un-installed", "name"<blend name>, "version":<blend version>})
                raise EnableException({"message":"Could not enable service", "name":<ervice name>, "version":<blend version>, "url":<tlp d/l url>})
                raise DisableException({"message":"Could not disable service", "name":<service name>, "version":<blend version>})
        '''

        DEV_LOGGER.info('Detail="configure: new_config: %s, url: %s, version: %s, upgrade_disabled_from_fms:%s"' %
                        (self._install_details, url, version, upgrade_disabled_from_fms))

        # Store in case of error
        backup_details = self.get_install_details()

        prevented_upgrade_services = self._config.read(ManagementConnectorProperties.PREVENT_CONN_UPGRADE)
        if prevented_upgrade_services is not None and self._name in prevented_upgrade_services:
            DEV_LOGGER.info('Detail="FMC_Lifecycle configure: upgrade prevented for %s"' % (self._name))
            return True

        if upgrade_disabled_from_fms:
            DEV_LOGGER.info('Detail="configure noop from FMS, ignore upgrade and return true %s"' % (self._name))
            return True

        if not self.update_allowed(version):
            return False

        if not ServiceUtils.is_supported_extension(url):
            DEV_LOGGER.info('Detail="FMC_Lifecycle configure: file extension %s not supported"' % (url.split('.')[-1]))
            return False

        DEV_LOGGER.info('Detail="FMC_Lifecycle configure: apply config changes for %s"' % self._name)
        try:
            self.set_install_details(url, version)

            tmp_path, downloaded_file_size, download_duration = self._download()

            ServiceUtils.cache_service_cdb_schema(self._rest_client, self._name)

            install_duration = self._install(tmp_path)

            register_default_loggers([ManagementConnectorProperties.HYBRID_PREFIX + self._name])

            # Emit upgrade event on upgrade and not rollback, will be none if file was stored locally
            if downloaded_file_size and self._oauth:
                upgrade_event = UpgradeEvent(
                    ManagementConnectorProperties.EVENT_SUCCESS,
                    self._name,
                    download_duration,
                    install_duration,
                    downloaded_file_size,
                    url,
                    version,
                    self._expressway_full_version,
                    None,
                    None)

                EventSender.post(self._oauth,
                                 self._config,
                                 EventSender.UPGRADE,
                                 ManagementConnectorProperties.SERVICE_NAME,
                                 int(time.time()),
                                 upgrade_event.get_detailed_info())

        finally:

            version = CafeXUtils.get_package_version(self._name)

            # if for some reason version has not changed, restore old url
            if version == backup_details['version']:
                self.set_install_details(backup_details['url'], version)

            ServiceUtils.remove_installing_state(self._name)

            ServiceUtils.request_service_change(self._config)

    # -------------------------------------------------------------------------

    def get_status(self, read_from_json=True):
        ''' Gets the service status from the system.
            Return the status i.e.
             {'version': <tlp version installed>,
              'enabled': <service enabled status, True/False>,
              'installing': <tlp installing status, True/False>,
              'installed': <tlp installed status, True/False>,
              'running' : <service running status, True/False},
               configured: <dictionary with config status>'''
        version = ServiceUtils.get_version(self._name)
        installing = ServiceUtils.is_installing(self._name)
        installed = CafeXUtils.is_package_installed(self._name)
        enabled = self._is_enabled(read_from_json)
        running = CafeXUtils.is_connector_running(self._name, DEV_LOGGER)
        op_status = CafeXUtils.get_operation_status(self._name, DEV_LOGGER)

        configuration_status = ServiceUtils.is_configured_status(self._config, self._name)

        status = {'version': version,
                  'enabled': enabled,
                  'installing': installing,
                  'installed': installed,
                  'running': running,
                  'operational_status': op_status,
                  'configured': configuration_status}

        DEV_LOGGER.debug('Detail="get_status: get service status from the system: name=%s: version=%s, enabled=%s, installing=%s, '
                         'installed=%s, running=%s, op_status=%s"' % (self._name, version, enabled, installing, installed, running, op_status))

        return status

    # -------------------------------------------------------------------------

    def get_composed_status(self, read_from_json=True):
        """ Over All Status for display on the UI and reporting to Atlas """

        service_status = self.get_status(read_from_json)

        cdb_configured_flag = ServiceUtils.get_configured_via_cdb_entry(self._config, self._name)

        if cdb_configured_flag:
            state_str = Service._get_composed_state(service_status)
        else:
            state_str = Service._handle_legacy_composed_state(service_status)

        DEV_LOGGER.debug('Detail="get_composed_status: get_composed_status= %s"' % state_str)

        return state_str

    # -------------------------------------------------------------------------

    @staticmethod
    def _handle_legacy_composed_state(service_status):
        """ Handles composed state for systems using .configured flag """

        if service_status['installing'] is not None:
            state_str = service_status['installing']
        elif not service_status['installed']:
            state_str = 'not_installed'
        elif not service_status['enabled']:
            # not configured is only relevant to cases where service is not enabled
            if not service_status['configured']:
                state_str = 'not_configured'
            else:
                state_str = 'disabled'
        elif service_status['running']:
            state_str = 'running'
        else:
            state_str = 'stopped'

        return state_str

    # -------------------------------------------------------------------------

    @staticmethod
    def _get_composed_state(service_status):
        """ Handles composed state for systems using cdb flag """

        if service_status['installing'] is not None:
            state_str = service_status['installing']
        elif not service_status['installed']:
            state_str = 'not_installed'
        elif not service_status['configured']:
            state_str = 'not_configured'
        elif not service_status['enabled']:
            state_str = 'disabled'
        elif service_status['running']:
            state_str = 'running'
        else:
            state_str = 'stopped'

        return state_str

    # -------------------------------------------------------------------------

    def has_alarm(self, alarm_id):
        "indicates whether alarm is associated with service"
        return self._manifest.contains_alarm(alarm_id)

    # -------------------------------------------------------------------------

    def get_exclude_alarms(self):
        """ Gets an alarm range that won't be lowered on defuse for this service """
        return self._manifest.get_exclude_range()

    # -------------------------------------------------------------------------

    def get_suppressed_alarms(self):
        """ Gets a list of alarms range that won't be reported to FMS """
        return self._manifest.get_suppressed_alarms()

    # -------------------------------------------------------------------------

    def get_external_alarms(self):
        """ Gets a list of alarms range that won't be reported to FMS """
        return self._manifest.get_external_alarms()

    # -------------------------------------------------------------------------

    @staticmethod
    def is_related_external_alarm(alarm, config):
        """ Checks if an external alarm's parameter contains fusion related keywords
            Crash related alarms contain process name in the parameters
        """
        # known additional keywords
        connector_keywords = ['CSI', 'calendar-connector']

        # generate keywords from entitled services details
        entitled_services = config.read(ManagementConnectorProperties.ENTITLED_SERVICES)

        # create list with both name and display_name
        all_service_details = [service.values() for service in entitled_services]

        # flatten list and extract unique names
        services_keywords = [name for service in all_service_details for name in service]

        # join to list of known keywords and extract unique names
        connector_keywords = list(set(connector_keywords + services_keywords))

        for parameter in alarm.get('parameters', []):
            if any(keyword in parameter for keyword in connector_keywords if isinstance(parameter, unicode)):
                return True
        return False

    # -------------------------------------------------------------------------


    def get_alarms(self):
        "indicates whether alarm is associated with service"

        rtn_list = []

        alarm_list = self._config.read(ManagementConnectorProperties.ALARMS_RAISED)

        if(not alarm_list):
            return rtn_list

        for alarm in alarm_list:
            # See if the Fusion Alarm belongs to the Service
            alarm_id = int(alarm['id'])
            if self.has_alarm(alarm_id):
                rtn_list.append(alarm)
            if alarm_id in self._manifest.get_external_alarms():
                if Service.is_related_external_alarm(alarm, self._config):
                    rtn_list.append(alarm)


        return rtn_list

    # -------------------------------------------------------------------------

    def set_install_details(self, url, version):
        """ Set the config """
        self._install_details = {'url': url, 'version': version}

        DEV_LOGGER.debug('Detail="set_install_details: set install info for service object: config=%s"',
                         self._install_details)

    # -------------------------------------------------------------------------

    def _download(self):
        """ Download TLP to Temporary Location """

        file_size = None

        name = self._name
        url = self._install_details['url']
        version = self._install_details['version']

        try:
            ServiceUtils.set_installing_state(name, version, "downloading")

            tlp_path_tmp = "{}/{}{}".format(ManagementConnectorProperties.INSTALL_DOWNLOADS_DIR,
                                            self._name,
                                            ManagementConnectorProperties.PACKAGE_EXTENSION)

            DEV_LOGGER.info('Detail="FMC_Lifecycle _download: getting tlp for: name=%s, url=%s"', self._name, url)

            download_start_time = time.time()

            if 'ftp' in url or 'http' in url:  # pylint: disable=E1135
                file_size = Http.download(url, tlp_path_tmp)
            else:
                shutil.copy(url, tlp_path_tmp)

            download_duration = time.time() - download_start_time

            DEV_LOGGER.info('Detail="FMC_Lifecycle _download: downloading {0} tlp complete, took {1} seconds"'
                            .format(self._name, round(download_duration, 3)))

        except InvalidProtocolException, ivpe:
            raise DownloadTLPAccessException({"message": "problem accessing tlp due to invalid protocol", "reason": ivpe.reason}) # pylint: disable=E1101
        except HTTPError, httpe:
            # HTTP Error means we have found server, but had problem accessing resource
            DEV_LOGGER.error('Detail="_install:HTTP error: reason={0}, code={1}"'.format(httpe.reason, httpe.code))
            raise DownloadTLPAccessException({"message": "problem accessing tlp", "reason": httpe.reason})
        except URLError, urle:
            DEV_LOGGER.error('Detail="_install:failed to reach a server: reason=%s"', urle.reason)
            # URL Error means we could not find TLP Server. 550 is a special case where we tried to FTP
            # a file that did not exist
            if '550' in urle.reason:
                raise DownloadTLPAccessException({"message": "problem accessing tlp", "reason": urle.reason})
            else:
                raise DownloadServerUnavailableException({"message": "failed to reach a server", "reason": urle.reason})
        except CertificateExceptionFusionCA, cefca:
            DEV_LOGGER.error('Detail="_install:CertificateExceptionFusionCA: strerror=%s"', cefca)
            raise ServiceCertificateExceptionFusionCA({"message": "IOError", "strerror": cefca})
        except CertificateExceptionNameMatch, cenm:
            DEV_LOGGER.error('Detail="_install:CertificateExceptionNameMatch: strerror=%s"', cenm)
            raise ServiceCertificateExceptionNameMatch({"message": "IOError", "strerror": cenm})
        except CertificateExceptionInvalidCert, ceic:
            DEV_LOGGER.error('Detail="_install:CertificateExceptionInvalidCert: strerror=%s"',  ceic)
            raise ServiceCertificateExceptionInvalidCert({"message": "CertException", "strerror": ceic})

        return tlp_path_tmp, file_size, download_duration

    # -------------------------------------------------------------------------

    def _install(self, tlp_path_tmp):
        ''' install tlp '''
        name = self._name
        url = self._install_details['url']
        version = self._install_details['version']
        install_start_time = time.time()
        DEV_LOGGER.info('Detail="FMC_Lifecycle _install: install tlp: name=%s, url=%s"' % (name, url))

        ServiceUtils.set_installing_state(name, version, "installing")

        try:
            tlp_path_dest = "/tmp/pkgs/new/" + self._name + ManagementConnectorProperties.PACKAGE_EXTENSION
            if self._name.startswith(ManagementConnectorProperties.DEPENDENCY_PREFIX):
                shutil.move(tlp_path_tmp, tlp_path_dest)
            else:
                shutil.copy(tlp_path_tmp, tlp_path_dest)

            for i in range(INSTALL_RETRIES):
                if CafeXUtils.is_package_installed(name, version):
                    DEV_LOGGER.info('Detail="FMC_Lifecycle _install TLP: {0} tlp is installed, after {1} seconds"'
                                    .format(name, round(time.time() - install_start_time, 3)))
                    break
                time.sleep(1)
                DEV_LOGGER.info('Detail="FMC_Lifecycle _install: %s is not installed after %s seconds"' % (name, i + 1))
                if INSTALL_RETRIES == i + 1:
                    raise InstallException({"message": "The tlp has not installed", "name": name, "version": version, "url": url})

            install_duration = time.time() - install_start_time

            if not self._name.startswith(ManagementConnectorProperties.DEPENDENCY_PREFIX) and self._name != ManagementConnectorProperties.SERVICE_NAME:
                ServiceUtils.save_tlps_for_rollback(self._config,
                                                    self._name)
        except (IOError, OSError) as file_err:
            DEV_LOGGER.error('Detail="FMC_Lifecycle _install:File error: errno=%s, strerror=%s"' % (file_err.errno, file_err.strerror))
            raise InstallException({"message": "File error", "errno": file_err.errno, "strerror": file_err.strerror})

        return install_duration

    # -------------------------------------------------------------------------

    def uninstall(self, upgrade=False):
        ''' uninstall tlp'''
        DEV_LOGGER.info('Detail="FMC_Lifecycle _uninstall: un-install TLP: name=%s"' % (self._name))
        if CafeXUtils.is_package_installed(self._name):
            DEV_LOGGER.info('Detail="FMC_Lifecycle _uninstall: TLP: name=%s is currently installed"' % (self._name))
            ServiceUtils.set_installing_state(self._name, self._install_details['version'], "uninstalling")

            try:
                with open(ManagementConnectorProperties.REMOVE_FILE, "w") as rem_file:
                    rem_file.write(self._name)
            except IOError:
                DEV_LOGGER.debug('Detail="FMC_Lifecycle _uninstall: Unable to access remove file when uninstalling %s, retrying in %s seconds"'
                                  % (self._name, UNINSTALL_RETRIES/2))

            for i in range(UNINSTALL_RETRIES):
                if CafeXUtils.is_package_not_installed(self._name):
                    DEV_LOGGER.info('Detail="FMC_Lifecycle _uninstall: tlp is un-installed: name=%s after %s seconds"' % (self._name, i))

                    # Clean up service entry after it's successfully uninstalled.
                    if not upgrade:
                        self._rest_client.send_delete('/configuration/service/name/%s' % self._name)
                    break
                if i == UNINSTALL_RETRIES/2:
                    DEV_LOGGER.info('Detail="FMC_Lifecycle _uninstall: %s is not un-installed after %s seconds, attempting to remove again."'
                                    % (self._name, i))
                    try:
                        with open(ManagementConnectorProperties.REMOVE_FILE, "w") as rem_file:
                            rem_file.write(self._name)
                    except IOError:
                        DEV_LOGGER.debug('Detail="FMC_Lifecycle _uninstall: Remove file exists already when uninstalling %s"'
                                         % self._name)
                time.sleep(1)

                if UNINSTALL_RETRIES == i + 1:
                    version = CafeXUtils.get_package_version(self._name)
                    raise UninstallException({"message": "The tlp has not un-installed", "name": self._name, "version": version})
        else:
            DEV_LOGGER.info('Detail="FMC_Lifecycle _uninstall: tlp not installed: name=%s"' % (self._name))

    # -------------------------------------------------------------------------

    def disable(self, retries=DISABLE_RETRIES):
        ''' disable '''
        DEV_LOGGER.info('Detail="FMC_Lifecycle _disable: disable service: name=%s"' % (self._name))
        # always do it to ensure we have a db entry for a new 'disabled' blend
        self._rest_client.delete_enabled_service_blob(self._name)
        self._rest_client.send_post('/configuration/service/name/' + self._name, {'mode': 'off'})
        for i in range(retries):
            if not CafeXUtils.is_connector_running(self._name, DEV_LOGGER):
                DEV_LOGGER.info('Detail="FMC_Lifecycle _disable: service is disabled: name=%s"' % (self._name))
                break
            time.sleep(1)
            DEV_LOGGER.info('Detail="FMC_Lifecycle _disable: %s is not disabled after %s seconds"' % (self._name, i + 1))
            if retries == i + 1:
                version = CafeXUtils.get_package_version(self._name)
                raise DisableException({"message": "Could not disable service", "name": self._name, "version": version})

    # -------------------------------------------------------------------------
    def enable(self):
        ''' enable '''
        DEV_LOGGER.info('Detail="FMC_Lifecycle enable: enable service: name=%s"' % (self._name))
        if not (self._is_enabled()):
            self._rest_client.update_blob(ManagementConnectorProperties.ENABLED_SERVICES_STATE, self._name, "true")
            DEV_LOGGER.info('Detail="FMC_Lifecycle service: %s is %s "' % (self._name, self._is_enabled()))
        else:
            DEV_LOGGER.info('Detail="FMC_Lifecycle service: %s is %s "' % (self._name, self._is_enabled()))

        for i in range(ENABLE_RETRIES):
            if (CafeXUtils.is_connector_running(self._name, DEV_LOGGER)):
                DEV_LOGGER.info('Detail="FMC_Lifecycle enable: service is enabled: name=%s"' % (self._name))
                break

            time.sleep(1)
            # If we're half way there waiting request a service check
            if i == ENABLE_RETRIES/2:
                # Trigger service startup clean-up.
                ServiceUtils.request_service_change(self._config)

            DEV_LOGGER.info('Detail=FMC_Lifecycle "enable: %s is not enabled after %s seconds"' % (self._name, i + 1))
            if ENABLE_RETRIES == i + 1:
                version = CafeXUtils.get_package_version(self._name)
                raise EnableException({"message": "Could not enable service", "name": self._name, "version": version})

    def _is_enabled(self, read_from_json=True):
        ''' get enabled status of service. '''

        is_enabled = False

        if read_from_json:
            # Read from JSON Config
            enabled_services = self._config.read(ManagementConnectorProperties.ENABLED_SERVICES)

            if enabled_services is not None and self._name in enabled_services:
                is_enabled = True
        else:
            # Read from DB - Guaranteed up-to date response, but at expense of performance
            is_enabled = CafeXUtils.is_connector_enabled(self._rest_client, self._name)

        return is_enabled

    # -------------------------------------------------------------------------

    def requires_refresh(self, version):
        ''' methods that indicate whether installed version is need of update '''

        rtn = False

        is_installed = CafeXUtils.is_package_installed(self._name)

        # More-or-less inline with Service Equivalent - No disabling (or enabling) of these dependency types
        installed_version = CafeXUtils.get_package_version(self._name)
        if version != installed_version or (not is_installed):
            DEV_LOGGER.debug('Detail="requires_refresh: %s is installed, %s is being advertised"', installed_version, version)
            rtn = True

        return rtn

    # -------------------------------------------------------------------------

    @staticmethod
    def is_version_valid(version):
        """ Check if version is of format declared in Cafe Developer Guide
             eg. {name}_{Major.Minor.Maintenance}-{Major.Minor.Rev} or {Major.Minor.Rev}
                 8.9-1.0.321342 or 8.9-1.10
        """
        version_format_correct = False
        # Check for connector name
        if "_" in version:
            version_data = re.split('_', version)
            version = version_data[1]
        # Check for vcs & app version
        if "-" in version:
            version_app_vcs_data = re.split('-', version)
            vcs_version = version_app_vcs_data[0]
            app_version = version_app_vcs_data[1]
            if StrictVersion.version_re.match(vcs_version) and StrictVersion.version_re.match(app_version):
                version_format_correct = True
        else:
            version_format_correct = StrictVersion.version_re.match(version)

        if not version_format_correct:
            DEV_LOGGER.error('Detail="update_allowed: invalid version naming format: %s.' % version)

        return version_format_correct

    # -------------------------------------------------------------------------

    def update_allowed(self, version):
        """ Check if version has changed and ensures a backup restore is not in progress """
        version_format_correct = self.is_version_valid(version)
        requires_refresh = self.requires_refresh(version)
        restore_occurring = CafeXUtils.is_backup_restore_occurring(DEV_LOGGER)
        allowed = requires_refresh and not restore_occurring and version_format_correct

        if allowed:
            DEV_LOGGER.debug('Detail="update_allowed: %s requires refresh: %s and restore occurring: %s"'
                             % (allowed, requires_refresh, restore_occurring))

        return allowed

    # -------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
