""" Management Connector Service Manager Class """

import traceback
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from managementconnector.config import jsonhandler
from managementconnector.config.databasehandler import DatabaseHandler
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config.versionchecker import get_expressway_full_version
from managementconnector.service.service import Service, ServiceException, DisableException, EnableException, \
    DownloadServerUnavailableException, DownloadTLPAccessException, InstallException, \
    ServiceCertificateExceptionFusionCA, ServiceCertificateExceptionNameMatch, \
    ServiceCertificateExceptionInvalidCert
from base_platform.expressway.i18n import translate
from cafedynamic.cafexutil import CafeXUtils
from managementconnector.platform.alarms import MCAlarm
from managementconnector.service.connectorservice import ConnectorService
from managementconnector.service.servicedependency import ServiceDependency

from managementconnector.service.eventsender import EventSender
from managementconnector.events.upgradeevent import UpgradeEvent

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class ServiceManager():
    ''' Management Connector Service Manager Class'''

    def __str__(self):
        return 'Management Connector Service Manager Class'

    __repr__ = __str__

    def __init__(self, config, oauth):
        """ ServiceManager__init__ """
        self._config = config
        self._oauth = oauth
        self._services = []
        self._database_handler = DatabaseHandler()
        self._alarms = MCAlarm(self._config)
        self.is_upgrade_thread_running = False
        self._expressway_full_version = get_expressway_full_version()

    # -------------------------------------------------------------------------

    def _update_service(self, config):
        """ Update service information for entitled services """

        # Get the service by name from Service Manager to see if it exists.
        service = self.get(config['name'])
        upgrade_disabled_from_fms = 'allow_upgrade' in config and config['allow_upgrade'] is False

        service.configure(config['url'], config['version'], upgrade_disabled_from_fms)

    # -------------------------------------------------------------------------

    def upgrade_worker(self, connectors_config):
        """Update worker"""
        try:
            DEV_LOGGER.debug('Detail="Entered _upgrade_worker called with %s' % (connectors_config))
            upgrade_failures = {'server_unavailable': [], 'tlp_unavailable': [], 'install_error': [],
                                'cert_error': [], "cert_name_error": [], "cert_fusion_ca_error": [],
                                'version_mismatch': [], 'disable_error': [], 'enable_error': []}
            # Check For Any Connector Updates
            for config in connectors_config:
                try:
                    self._update_service(config)
                except ServiceException as download_exception:
                    reason = ServiceManager._handle_download_exception(upgrade_failures, config, download_exception)

                    upgrade_event = UpgradeEvent(
                        ManagementConnectorProperties.EVENT_FAILURE,
                        config['name'],
                        None,  # downloadDuration
                        None,  # installDuration
                        None,  # fileSize
                        config['url'],
                        config['version'],
                        self._expressway_full_version,
                        reason,
                        download_exception)

                    EventSender.post(self._oauth,
                                     self._config,
                                     EventSender.UPGRADE,
                                     ManagementConnectorProperties.SERVICE_NAME,
                                     int(time.time()),
                                     upgrade_event.get_detailed_info())

            # Audit Services + Dependencies
            # Checks for any old Dependencies (package that start with d_)
            self.purge_deleted_connectors(connectors_config, ManagementConnectorProperties.DEPENDENCY_PREFIX)
            # Checks for any old Connectors (package that start with c_)
            self.purge_deleted_connectors(connectors_config, ManagementConnectorProperties.CONNECTOR_PREFIX)

            # Alarm Processing.
            self._process_unknownhost_alarm(upgrade_failures['server_unavailable'],
                                            'b6417be9-0c57-4254-8392-896b61983ca4',
                                            'err.DOWNLOAD_COMM_ERROR_%s_%s')

            self._process_upgrade_alarm(upgrade_failures['tlp_unavailable'],
                                        '3d541e1e-1e9c-4b30-a07d-e93f8445b13e',
                                        'err.DOWNLOAD_ACCESS_ERROR_%s_%s')

            self._process_upgrade_alarm(upgrade_failures['cert_error'],
                                        '142f9bb1-74a5-460a-b609-7f33f8acdcaf',
                                        'err.DOWNLOAD_CERT_ERROR_%s_%s')

            self._process_upgrade_alarm(upgrade_failures['cert_name_error'],
                                        '1e9c9c3d-9b35-467c-af1c-90d6947ababb',
                                        'err.DOWNLOAD_CERT_NAME_ERROR_%s_%s')

            self._process_upgrade_alarm(upgrade_failures['cert_fusion_ca_error'],
                                        '598ea3b8-00f9-4674-a90a-919668fec916',
                                        'err.DOWNLOAD_CERT_FUSION_CA_ERROR_%s_%s')

            self._process_install_alarm(upgrade_failures['install_error'],
                                        '76a2fbce-97bb-4761-9fab-8ffd4b0ab9a2',
                                        'err.DOWNLOAD_INSTALL_ERROR_%s_%s_%s')

            self._process_version_alarm(upgrade_failures['version_mismatch'],
                                        '52299415-2719-45d5-bcf7-720b48929ae3',
                                        'err.VERSION_MISMATCH_%s_%s_%s')

            self._process_enable_alarm(upgrade_failures['disable_error'],
                                       '77857c20-94b4-4145-8298-cad741e905fb',
                                       'err.DOWNLOAD_DISABLE_ERROR_%s')

            self._process_enable_alarm(upgrade_failures['enable_error'],
                                       '77ad9990-4850-4191-9bc2-51d0912daef3',
                                       'err.DOWNLOAD_ENABLE_ERROR_%s')
        finally:
            self.is_upgrade_thread_running = False

    # -------------------------------------------------------------------------
    @staticmethod
    def _handle_download_exception(upgrade_failures, config, service_exception):
        """Download Exception Handing"""
        DEV_LOGGER.error('Detail="DownloadException'
                         ' Downloading Package %s from url %s , Exception Details %s, stacktrace=%s"' %
                         (config['name'], config['url'], service_exception, traceback.format_exc()))
        reason = "unknown"

        if isinstance(service_exception, ServiceCertificateExceptionFusionCA):
            reason = ManagementConnectorProperties.UPGRADE_REASON_CERT
            upgrade_failures['cert_fusion_ca_error'].append(config)

        elif isinstance(service_exception, ServiceCertificateExceptionNameMatch):
            reason = ManagementConnectorProperties.UPGRADE_REASON_CERT
            upgrade_failures['cert_name_error'].append(config)

        elif isinstance(service_exception, ServiceCertificateExceptionInvalidCert):
            reason = ManagementConnectorProperties.UPGRADE_REASON_CERT
            upgrade_failures['cert_error'].append(config)

        elif isinstance(service_exception, DownloadServerUnavailableException):
            reason = ManagementConnectorProperties.UPGRADE_REASON_DOWNLOAD
            upgrade_failures['server_unavailable'].append(config)

        elif isinstance(service_exception, DownloadTLPAccessException):
            reason = ManagementConnectorProperties.UPGRADE_REASON_DOWNLOAD
            upgrade_failures['tlp_unavailable'].append(config)

        elif isinstance(service_exception, InstallException):
            reason = ManagementConnectorProperties.UPGRADE_REASON_INSTALL
            upgrade_failures['install_error'].append(config)

        elif isinstance(service_exception, DisableException):
            reason = ManagementConnectorProperties.UPGRADE_REASON_DISABLE
            upgrade_failures['disable_error'].append(config)

        elif isinstance(service_exception, EnableException):
            reason = ManagementConnectorProperties.UPGRADE_REASON_ENABLE
            upgrade_failures['enable_error'].append(config)

        return reason

    # -------------------------------------------------------------------------
    def _process_enable_alarm(self, failed_config, alarm_id, msg):
        """Responsible for clearing/raising alarms due to service enablement issues"""

        if len(failed_config) == 0:
            self._alarms.clear_alarm(alarm_id)
        else:

            description_text = ''

            # These Alarms take display name as parameter
            for config in failed_config:
                desc_line = translate(msg) % (str(config['display_name']))
                description_text = description_text + desc_line + "\n"

            DEV_LOGGER.debug('Detail="_process_enable_alarm: description_text=%s"' % description_text)

            self._alarms.raise_alarm(alarm_id, [description_text])

    # -------------------------------------------------------------------------

    def _process_upgrade_alarm(self, failed_config, alarm_id, msg):
        """Responsible for clearing/raising alarms"""

        if len(failed_config) == 0:
            self._alarms.clear_alarm(alarm_id)
        else:

            description_text = ''

            # These Alarms take display name and url as parameter
            for config in failed_config:
                desc_line = translate(msg) % (str(config['display_name']), str(config['url']))
                description_text = description_text + desc_line + "\n"

            DEV_LOGGER.debug('Detail="_process_upgrade_alarm: description_text=%s"' % description_text)

            self._alarms.raise_alarm(alarm_id, [description_text])

    # -------------------------------------------------------------------------

    def _process_install_alarm(self, failed_config, alarm_id, msg):
        """ Responsible for clearing/raising alarms """

        if len(failed_config) == 0:
            self._alarms.clear_alarm(alarm_id)
        else:

            description_text = ''

            # These Alarms take display name and url as parameter
            for config in failed_config:
                desc_line = translate(msg) % (str(config['display_name']),
                                              str(config['version']),
                                              str(config['url']))

                description_text = description_text + desc_line + "\n"

            DEV_LOGGER.debug('Detail="_process_install_alarm: description_text=%s"' % description_text)

            self._alarms.raise_alarm(alarm_id, [description_text])

    # -------------------------------------------------------------------------

    def purge_deleted_connectors(self, connector_config, connector_type):
        """ Audit Method looking for unwanted connectors """

        DEV_LOGGER.debug(
            'Detail="purge_deleted_connectors, connector_config = %s, type = %s"' % (connector_config, connector_type))

        installed_connectors = CafeXUtils.get_installed_connectors(connector_type)

        if installed_connectors:
            for connector in installed_connectors:

                must_delete = True

                for config in connector_config:
                    if config['name'] == connector:
                        must_delete = False
                        break

                if must_delete is True:

                    try:

                        if connector not in ManagementConnectorProperties.SERVICE_LIST:
                            self.purge(connector, False)
                            time.sleep(5)

                    except ServiceException as error:
                        DEV_LOGGER.error('Detail="purge_deleted_connectors error=%s, stacktrace=%s"' %
                                         (error, traceback.format_exc()))

    # -------------------------------------------------------------------------

    def _process_version_alarm(self, failed_config, alarm_id, msg):
        """ Responsible for clear/raising alarms"""
        if len(failed_config) == 0:
            self._alarms.clear_alarm(alarm_id)
        else:
            description_text = ''
            # All the Version Mismatch Alarms take display name, advertised version and installed version.
            for config in failed_config:
                desc_line = translate(msg) % (str(config['display_name']), str(config['version']),
                                              str(config['installed_version']))
                description_text = description_text + desc_line + "\n"

            DEV_LOGGER.debug('Detail="_process_version_alarm: description_text=%s"' % description_text)

            self._alarms.raise_alarm(alarm_id, [description_text])

    # -------------------------------------------------------------------------

    def _process_unknownhost_alarm(self, failed_config, alarm_id, msg):
        """Responsible for clearing/raising alarms"""
        if len(failed_config) == 0:
            self._alarms.clear_alarm(alarm_id)
        else:
            description_text = ''
            # All the upgrade Alarms take display name and url as parameter
            for config in failed_config:
                # Stripping the hostname for an Alarm Parameter
                url = urlparse(str(config['url'])).netloc
                desc_line = translate(msg) % (url, str(config['display_name']))
                description_text = description_text + desc_line + "\n"

            DEV_LOGGER.debug('Detail="_process_unknownhost_alarm: description_text=%s"' % description_text)

            self._alarms.raise_alarm(alarm_id, [description_text])

    # -------------------------------------------------------------------------

    def get(self, service_name, dependency=False):
        """ Search for a service object in the list based on the service name.
            Returns service object if found, or None if not found. """
        service = None
        for item in self._services:
            existing_name = item.get_name()
            if existing_name == service_name:
                # found a match
                service = item

        if service is None:
            if dependency:
                service = ServiceDependency(service_name, self._config, self._oauth)
            else:
                if service_name in ManagementConnectorProperties.SERVICE_LIST:
                    service = ConnectorService(service_name, self._config, self._oauth)  # pylint: disable=R0204
                else:
                    service = Service(service_name, self._config, self._oauth)

            self.add(service)
        return service

    # -------------------------------------------------------------------------

    def add(self, service):
        """ add service to list"""
        DEV_LOGGER.debug('Detail="FMC_Lifecycle ServiceManager: add: service=%s"' % (service))
        self._services.append(service)

    # -------------------------------------------------------------------------

    def remove(self, service_name):
        """ remove a service from the list """
        for service in self._services:
            existing_name = service.get_name()
            if existing_name == service_name:
                # found a match
                self._services.pop(self._services.index(service))
                break

    # -------------------------------------------------------------------------

    def remove_all(self):
        """ empty the service list """
        self._services = []

    # -------------------------------------------------------------------------

    def get_all(self):
        """ get the service list """
        return self._services

    # -------------------------------------------------------------------------

    def purge(self, service_name, defuse_occurring=True):
        """ Remove the Service """

        DEV_LOGGER.info('Detail="FMC_Lifecycle ServiceManager: purge: service=%s"' % (service_name))

        service = self.get(service_name)

        if service:
            service.disable()
            service.uninstall()

            if defuse_occurring is False:
                # Delete any DB records for the service
                self._database_handler.delete_service_blob(service_name)

            # Delete rollback cached cdb file.
            jsonhandler.delete_file(ManagementConnectorProperties.SERVICE_CDB_CACHE_FILE % service_name)

            self.remove(service_name)

    # =============================================================================

    def get_enabled_connectors(self, connectors=None):
        """ Get enabled connectors from list """
        if connectors is None:
            connectors = []
        enabled_connectors = {"services": [], "names": []}
        for connector in connectors:
            connector_service = self.get(connector)
            if connector_service:
                connector_status = connector_service.get_status()
                if connector_status["enabled"]:
                    enabled_connectors["services"].append(connector_service)
                    enabled_connectors["names"].append(connector)
        DEV_LOGGER.info('Detail="FMC_Lifecycle ServiceManager: enabled_connectors=%s"' % enabled_connectors["names"])
        return enabled_connectors

    # =============================================================================

    @staticmethod
    def disable_connectors(connectors=None):
        """ Disable all connectors from list """
        if connectors is None:
            connectors = []
        for connector_service in connectors:
            connector_service.disable()
            DEV_LOGGER.info('Detail="FMC_Lifecycle ServiceManager: disable: connector=%s"' % connector_service.get_name())
        return

    # =============================================================================

    @staticmethod
    def enable_connectors(connectors=None):
        """ Enable connectors and ensure it is operational """
        if connectors is None:
            connectors = []
        start_time = time.time()
        # connector service enable should be sequential as it involves DB write operation to the same field
        for connector_service in connectors:
            connector_service.enable()
        # check for operational connector status in parallel
        with ThreadPoolExecutor() as executor:
            executor.map(ServiceManager.check_operational_status, connectors)
        DEV_LOGGER.info(
            'Detail="FMC_FederationOrgMigration: '
            'start_connectors: Time taken to start the connectors: %0.2f seconds' % (time.time() - start_time))
        return

    # =============================================================================

    @staticmethod
    def check_operational_status(connector):
        connector_name = connector.get_name()
        DEV_LOGGER.info(
            'Detail="FMC_Lifecycle ServiceManager: check_operational_status: connector=%s"' % connector_name)
        operational_status_wait = ManagementConnectorProperties.CONNECTOR_OPERATIONAL_STATE_WAIT_TIME
        for i in range(operational_status_wait):
            time.sleep(1)  # wait before status check
            op_status = CafeXUtils.get_operation_status(connector_name, DEV_LOGGER)
            if op_status in ManagementConnectorProperties.CONNECTOR_PERMITTED_OPERATIONAL_STATES:
                DEV_LOGGER.info(
                    'Detail="FMC_Lifecycle ServiceManager: enable_connectors: '
                    '%s connector is operational after %s seconds"' % (connector_name, i + 1))
                break
            DEV_LOGGER.error(
                'Detail="FMC_Lifecycle ServiceManager: enable_connectors: '
                '%s connector is not operational after %s seconds"' % (connector_name, i + 1))
        return

    # =============================================================================
