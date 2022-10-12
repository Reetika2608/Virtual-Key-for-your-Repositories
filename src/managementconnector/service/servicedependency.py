"""
    Class to manage blend dependency configuration.
"""
import time

from cafedynamic.cafexutil import CafeXUtils
from managementconnector.service.service import Service
from managementconnector.platform.serviceutils import ServiceUtils
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config.versionchecker import get_expressway_full_version

from managementconnector.service.eventsender import EventSender
from managementconnector.events.upgradeevent import UpgradeEvent


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class ServiceDependency(Service):
    """
        Model a Service (Connector Dependency) - such as Java, Reuse alot of Service Class Functionality
    """
    # -------------------------------------------------------------------------
    def __init__(self, name, config, oauth):
        ''' Dependency __init__'''
        DEV_LOGGER.debug('Detail="Initialising ServiceDependency object for %s"' % name)
        Service.__init__(self, name, config, oauth)
        self._expressway_full_version = get_expressway_full_version()

    # -------------------------------------------------------------------------

    def configure(self,  url, version, upgrade_disabled_from_fms):
        ''' Compares 'new_config' with the service objects existing config.
            If there are any config changes, update the system with the
            changes.
        '''

        DEV_LOGGER.info('Detail="configure: ServiceDependency: %s, url: %s, version: %s, upgrade_disabled_from_fms:%s"' % (self._install_details, url, version, upgrade_disabled_from_fms))

        prevented_upgrade_services = self._config.read(ManagementConnectorProperties.PREVENT_DEPENDENCY_UPGRADE)
        if prevented_upgrade_services is not None and self._name in prevented_upgrade_services:
            DEV_LOGGER.info('Detail="FMC_Lifecycle configure dpendency: upgrade prevented for %s"' % (self._name))
            return True

        if upgrade_disabled_from_fms:
            DEV_LOGGER.info('Detail="configure dependency: noop from FMS, ignore upgrade and return true %s"' % (self._name))
            return True

        # Store in case of error
        backup_details = self.get_install_details()

        # More-or-less inline with Service Equivalent - No disabling (or enabling) of these dependency types
        if self.update_allowed(version):
            try:
                DEV_LOGGER.info('Detail="FMC_Lifecycle ServiceDependency configure: applying config changes for %s"' % (self._name))

                self.set_install_details(url, version)

                tmp_path, downloaded_file_size, download_duration = self._download()

                install_duration = self._install(tmp_path)

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

        else:
            DEV_LOGGER.info('Detail="ServiceDependency configure no config changes to apply for %s"' % (self._name))

    # -------------------------------------------------------------------------

    def disable(self, retries=None):
        ''' disable '''

        # Does Nothing Overriding Service method

    # -------------------------------------------------------------------------

    def de_register(self):
        """ De-register from FMS """

        # Does Nothing Overriding Service method
