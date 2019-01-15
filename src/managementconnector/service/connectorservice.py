"""
    Class to manage management connector install
"""

import time

from managementconnector.service.service import Service
from cafedynamic.cafexutil import CafeXUtils
from managementconnector.platform.serviceutils import ServiceUtils
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config.versionchecker import get_expressway_full_version

from managementconnector.service.eventsender import EventSender
from managementconnector.events.upgradeevent import UpgradeEvent

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class ConnectorService(Service):
    """
        Model a Service (Management Connector)
    """
    # -------------------------------------------------------------------------
    def __init__(self, name, config, oauth):
        ''' Dependency __init__'''
        DEV_LOGGER.debug('Detail="Initialising ConnectorService object for %s"' % name)
        Service.__init__(self, name, config, oauth)

        # Remove any installing information associated with the Mgmt Connector
        ServiceUtils.remove_installing_state(name)
        self._expressway_full_version = get_expressway_full_version()

    # -------------------------------------------------------------------------

    def configure(self,  url, version, upgrade_disabled_from_fms):
        ''' Compares 'new_config' with the service objects existing config.
            If there are any config changes, update the system with the
            changes.
        '''

        if upgrade_disabled_from_fms:
            DEV_LOGGER.info('Detail="connector service configure : noop from FMS, ignore upgrade and return true %s"' % (self._name))
            return True

        # Store in case of error
        backup_details = self.get_install_details()

        prevent_upgrade = self._config.read(ManagementConnectorProperties.PREVENT_MGMT_CONN_UPGRADE)

        DEV_LOGGER.info('Detail="configure: ConnectorService: %s, url: %s, version: %s"' % (self._install_details, url, version))

        # More-or-less inline with Service Equivalent - No disabling (or enabling) of these dependency types
        if (self.update_allowed(version) and prevent_upgrade.lower() == "off"):

            DEV_LOGGER.info('Detail="ConnectorService configure: apply config changes for %s"' % (self._name))

            try:
                self.set_install_details(url, version)

                # Download First to make sure TLP ok
                tmp_path, downloaded_file_size, download_duration = self._download()

                # Emit upgrade event on upgrade and not rollback, will be none if file was stored locally
                if downloaded_file_size and self._oauth:
                    upgrade_event = UpgradeEvent(
                        ManagementConnectorProperties.EVENT_SUCCESS,
                        self._name,
                        download_duration,
                        None,
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

                # Cache database information
                ServiceUtils.cache_service_cdb_schema(self._rest_client, self._name,
                                                      ManagementConnectorProperties.EXCLUDE_LIST)

                self._install(tmp_path)
                # Restarting of Mgmt. Connector is handled by a post install scripts

            finally:

                # Roll back to old version
                version = CafeXUtils.get_package_version(self._name)

                # if for some reason version has not changed, restore old url
                if version == backup_details['version']:
                    self.set_install_details(backup_details['url'], version)

                ServiceUtils.remove_installing_state(self._name)
        else:
            DEV_LOGGER.info('Detail="ConnectorService configure no config changes to apply for %s"' % (self._name))

    # -------------------------------------------------------------------------

    def disable(self, retries=None):
        ''' disable '''

        # Does Nothing Overriding Service method

    # -------------------------------------------------------------------------
