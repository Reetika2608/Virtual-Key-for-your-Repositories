""" Federation 4.0 - Org Migration """

import time
from http import HTTPStatus

from managementconnector.config.databasehandler import DatabaseHandler
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.service.servicemanager import ServiceManager
from cafedynamic.cafexutil import CafeXUtils

from managementconnector.config.databasehandler import CDBDownException
from managementconnector.service.servicemanager import EnableException, DisableException

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class FederationOrgMigration(object):
    """ Utility to manage Federation Org Migration """

    migration_data_map = {
        "org-id": ManagementConnectorProperties.MIGRATION_ORG_ID,
        "migration-id": ManagementConnectorProperties.MIGRATION_ID,
        "identity-source": ManagementConnectorProperties.MIGRATION_IDENTITY_SOURCE,
        "identity-target": ManagementConnectorProperties.MIGRATION_IDENTITY_TARGET,
        "teams-source": ManagementConnectorProperties.MIGRATION_TEAMS_SOURCE,
        "teams-target": ManagementConnectorProperties.MIGRATION_TEAMS_TARGET,
        "meetings-source": ManagementConnectorProperties.MIGRATION_MEETINGS_SOURCE,
        "meetings-target": ManagementConnectorProperties.MIGRATION_MEETINGS_TARGET,
        "start-at": ManagementConnectorProperties.MIGRATION_START_AT,
        "workstream-startedAt": ManagementConnectorProperties.MIGRATION_WORKSTREAM_STARTED_AT,
        "fms-migration-state": ManagementConnectorProperties.FMS_MIGRATION_STATE
    }

    # -------------------------------------------------------------------------

    def __init__(self, config, oauth):
        """ Federation Org Migration __init__ """
        DEV_LOGGER.info('Detail="FMC_Utility Federation Org Migration: __init__ called"')

        self._config = config
        self._oauth = oauth
        self._servicemanager = ServiceManager(self._config, self._oauth)
        self._database_handler = DatabaseHandler()

    # -------------------------------------------------------------------------

    @staticmethod
    def get_other_connectors():
        """ Get installed connectors except mgmt """
        connector_type = ManagementConnectorProperties.CONNECTOR_PREFIX
        connectors = CafeXUtils.get_installed_connectors(connector_type)
        c_mgmt = ManagementConnectorProperties.SERVICE_NAME
        if c_mgmt in connectors:
            connectors.remove(c_mgmt)
        return connectors

    # -------------------------------------------------------------------------

    def get_enabled_connectors(self):
        """ Get enabled connectors from installed """
        enabled_connectors = {"services": [], "names": []}
        try:
            other_connectors = self.get_other_connectors()
            enabled_connectors = self._servicemanager.get_enabled_connectors(other_connectors)
            # check if enabled connectors weren't started in previous cycle
            stopped_connectors = self.read_cdb(ManagementConnectorProperties.MIGRATION_STOPPED_CONNECTORS)
            DEV_LOGGER.info(
                'Detail="FMC_Utility Federation Org Migration: already stopped_connectors %s"' % stopped_connectors)
            if stopped_connectors is not None:
                # return union of current and previously enabled connectors
                previously_enabled_connectors = enabled_connectors["names"].copy()
                for connector in stopped_connectors:
                    if connector not in previously_enabled_connectors:
                        enabled_connectors["services"].append(self._servicemanager.get(connector))
                        enabled_connectors["names"].append(connector)
            DEV_LOGGER.info(
                'Detail="FMC_Utility Federation Org Migration: get_enabled_connectors %s"' % enabled_connectors)
        except Exception as unhandled_exception:
            DEV_LOGGER.error(
                'Detail="FMC_Utility Federation Org Migration: UnhandledException get_enabled_connectors error=%s' %
                unhandled_exception)
        return enabled_connectors

    # -------------------------------------------------------------------------

    def update_stopped_connectors(self, stopped_connectors):
        """ Update MIGRATION_STOPPED_CONNECTORS in CDB """
        DEV_LOGGER.info(
            'Detail="FMC_Utility Federation Org Migration: Update MIGRATION_STOPPED_CONNECTORS %s"' % stopped_connectors)
        self.update_cdb(ManagementConnectorProperties.MIGRATION_STOPPED_CONNECTORS, stopped_connectors)

    # -------------------------------------------------------------------------

    def stop_connectors(self, connectors):
        DEV_LOGGER.info('Detail="FMC_Utility Org Migration: Stopping %s connectors"' % connectors)
        try:
            self._servicemanager.disable_connectors(connectors["services"])
            self.update_stopped_connectors(connectors["names"])
        except DisableException as stop_error:
            DEV_LOGGER.error(
                'Detail="FMC_Utility Federation Org Migration: Exception stopping connectors error=%s' % stop_error)
        except Exception as unhandled_exception:
            DEV_LOGGER.error(
                'Detail="FMC_Utility Org Migration: UnhandledException stop connectors error=%s' % unhandled_exception)
    # -------------------------------------------------------------------------

    def start_connectors(self, connectors):
        DEV_LOGGER.info('Detail="FMC_Utility Federation Org Migration: Starting %s connectors"' % connectors)
        try:
            self._servicemanager.enable_connectors(connectors["services"])
            self.update_stopped_connectors(connectors["names"])
        except EnableException as start_error:
            DEV_LOGGER.error(
                'Detail="FMC_Utility Federation Org Migration: Exception starting connectors error=%s' % start_error)
        except Exception as unhandled_exception:
            DEV_LOGGER.error(
                'Detail="FMC_Utility Federation Org Migration: UnhandledException start connectors error=%s' % unhandled_exception)

    # -------------------------------------------------------------------------

    def refresh_access_token(self):
        """ calling oauth Token refresh """
        _oauth_response = self._oauth.refresh_oauth_resp_with_idp()

    # -------------------------------------------------------------------------

    def update_cdb(self, data_field, value):
        """ Update data to on-prem Cluster DB """
        try:
            self._config.write_blob(data_field, value)
        except CDBDownException as cdb_exception:
            DEV_LOGGER.error(
                'Detail="FMC_Utility Federation Org Migration: CDBDownException update_cdb error=%s' % cdb_exception)

    # -------------------------------------------------------------------------

    def read_cdb(self, data_field):
        """ Read data from on-prem Cluster DB """
        cdb_data = None
        try:
            cdb_data = self._database_handler.read(data_field)
        except CDBDownException as cdb_exception:
            DEV_LOGGER.error(
                'Detail="FMC_Utility Federation Org Migration: CDBDownException read_cdb error=%s' % cdb_exception)
        return cdb_data

    # -------------------------------------------------------------------------

    def end_migration(self, enabled_connectors):
        """ End Migration workflow by updating migration data to connector.json & starting stopped connectors """
        # Set MIGRATION_UPDATE_CONNECTOR_JSON=True in CDB, migration info will be updated in connector.json
        DEV_LOGGER.info(
            'Detail="FMC_Utility Federation Org Migration: Update connector.json / Notify other Connectors"')
        self.update_cdb(ManagementConnectorProperties.MIGRATION_UPDATE_CONNECTOR_JSON, "true")

        # start stopped connectors - enable
        enabled_connectors["names"] = []
        self.start_connectors(enabled_connectors)

        DEV_LOGGER.info('Detail="FMC_Utility Federation Org Migration: Resume normal connector operation"')

    # -------------------------------------------------------------------------

    def migrate(self, status_code, federation_org_migration_data=None):
        """ On-Prem Federation Org Migration Workflow """
        if federation_org_migration_data is None:
            federation_org_migration_data = {}

        enabled_connectors = self.get_enabled_connectors()

        fms_migration_state = self._config.read(ManagementConnectorProperties.FMS_MIGRATION_STATE)
        DEV_LOGGER.info('Detail="FMC_Utility Federation Org Migration: migration state=%s"' % fms_migration_state)
        try:
            if status_code == HTTPStatus.FOUND.value:
                # if migration is started continue
                if fms_migration_state == ManagementConnectorProperties.FMS_MIGRATION_STARTED:
                    # stop other enabled connectors - disable
                    self.stop_connectors(enabled_connectors)

                    # Poll CI
                    DEV_LOGGER.info(
                        'Detail="FMC_Utility Federation Org Migration: Poll CI at source for token refresh"')
                    self.refresh_access_token()

                    # ensure config cache clearance
                    if not self._config.is_cache_cleared():
                        DEV_LOGGER.warn(
                            'Detail="FMC_Utility Federation Org Migration: '
                            'Config cache was not cleared, clearing it now"')
                        self._config.clear_cache()

                    DEV_LOGGER.info('Detail="FMC_Utility Federation Org Migration: Refresh access token at target CI"')
                    self.refresh_access_token()

                    self.end_migration(enabled_connectors)
            elif len(federation_org_migration_data):
                # update CDB
                DEV_LOGGER.info('Detail="FMC_Utility Federation Org Migration: Save migration info to DB"')
                self.process_migration_data(federation_org_migration_data)
        finally:
            # if migration is completed do not process further
            if fms_migration_state == ManagementConnectorProperties.FMS_MIGRATION_COMPLETED:
                self.end_migration(enabled_connectors)
        # exit
        return

    # -------------------------------------------------------------------------

    def process_migration_data(self, migration_data_blob):
        """ Process the migration data returned and update the config with the value"""
        DEV_LOGGER.info(
            'Detail="FMC_Utility Federation Org Migration: process_migration_data: processing migration data from FMS"')

        for migration_path, migration_data in list(migration_data_blob.items()):
            if migration_path in list(self.migration_data_map.keys()):
                # write federation org migration data to CDB
                self.update_cdb(FederationOrgMigration.migration_data_map[migration_path], migration_data)

    # -------------------------------------------------------------------------

    def clear_migration_data(self):
        """ Clear the migration data from CDB """
        # Set MIGRATION_UPDATE_CONNECTOR_JSON=False in CDB, migration info will not be updated in connector.json
        self.update_cdb(ManagementConnectorProperties.MIGRATION_UPDATE_CONNECTOR_JSON, "false")

        DEV_LOGGER.info(
            'Detail="FMC_Utility Federation Org Migration: clear_migration_data: Clearing migration data from CDB"')
        for migration_path, _ in list(FederationOrgMigration.migration_data_map.items()):
            if migration_path in list(self.migration_data_map.keys()):
                # clear federation org migration data from CDB
                self._database_handler.delete_blob_entry(FederationOrgMigration.migration_data_map[migration_path])

    # -------------------------------------------------------------------------
