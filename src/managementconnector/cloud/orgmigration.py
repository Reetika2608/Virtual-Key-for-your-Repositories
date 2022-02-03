""" Federation 4.0 - Org Migration """

from urllib import error as urllib_error
from http import HTTPStatus

from managementconnector.config.databasehandler import DatabaseHandler
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.service.servicemanager import ServiceManager
from cafedynamic.cafexutil import CafeXUtils

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class OrgMigration(object):
    """ Utility to manage Org Migration """

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
        """Org Migration __init__"""
        DEV_LOGGER.debug('Detail="FMC_Utility Org Migration: __init__ called"')

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
        other_connectors = self.get_other_connectors()
        enabled_connectors = self._servicemanager.get_enabled_connectors(other_connectors)
        # check if enabled connectors weren't started in previous cycle
        stopped_connectors = self._database_handler.read(ManagementConnectorProperties.MIGRATION_STOPPED_CONNECTORS)
        DEV_LOGGER.debug(
            'Detail="FMC_Utility Org Migration: already stopped_connectors %s type %s"' % (stopped_connectors,
                                                                                           type(stopped_connectors)))
        if stopped_connectors is not None:
            # return union of current and previously enabled connectors
            enabled_connectors["names"] = list(set(enabled_connectors["names"] + stopped_connectors))
        return enabled_connectors

    # -------------------------------------------------------------------------

    def update_stopped_connectors(self, stopped_connectors):
        """ Update MIGRATION_STOPPED_CONNECTORS in CDB """
        DEV_LOGGER.debug(
            'Detail="FMC_Utility Org Migration: Update MIGRATION_STOPPED_CONNECTORS %s"' % stopped_connectors)
        self._config.write_blob(ManagementConnectorProperties.MIGRATION_STOPPED_CONNECTORS, stopped_connectors)

    # -------------------------------------------------------------------------

    def stop_connectors(self, connectors):
        # self.get_enabled_connectors()
        DEV_LOGGER.debug('Detail="FMC_Utility Org Migration: Stopping %s connectors"' % connectors)
        self._servicemanager.disable_connectors(connectors["services"])
        self.update_stopped_connectors(connectors["names"])

    # -------------------------------------------------------------------------

    def start_connectors(self, connectors):
        # self.get_enabled_connectors()
        DEV_LOGGER.debug('Detail="FMC_Utility Org Migration: Starting %s connectors"' % connectors)
        self._servicemanager.enable_connectors(connectors["services"])
        self.update_stopped_connectors(connectors["names"])

    # -------------------------------------------------------------------------

    def refresh_access_token(self, migration=False):
        try:
            _oauth_response = self._oauth.refresh_oauth_resp_with_idp(migration=migration)
        except urllib_error.HTTPError as error:
            if error.code == HTTPStatus.BAD_REQUEST.value:
                # revive
                _oauth_response = self._oauth.refresh_oauth_resp_with_idp(migration=migration)

    # -------------------------------------------------------------------------

    def end_migration(self, enabled_connectors):
        """ End Migration workflow by updating migration data to connector.json & starting stopped connectors """
        # Set MIGRATION_UPDATE_CONNECTOR_JSON=True in CDB, migration info will be updated in connector.json
        DEV_LOGGER.debug('Detail="FMC_Utility Org Migration: Update connector.json / Notify other Connectors"')
        self._config.write_blob(ManagementConnectorProperties.MIGRATION_UPDATE_CONNECTOR_JSON, "true")

        # start stopped connectors - enable
        enabled_connectors["names"] = []
        self.start_connectors(enabled_connectors)

        DEV_LOGGER.info('Detail="FMC_Utility Org Migration: Resume normal connector operation"')

    # -------------------------------------------------------------------------

    def migrate(self, status_code, org_migration_data={}):
        """ On-Prem Org Migration Workflow """
        if status_code == HTTPStatus.FOUND.value:
            enabled_connectors = self.get_enabled_connectors()

            fms_migration_state = self._config.read(ManagementConnectorProperties.FMS_MIGRATION_STATE)
            DEV_LOGGER.info('Detail="FMC_Utility Org Migration: migration state=%s"' % fms_migration_state)

            # if migration is completed do not process further
            if fms_migration_state == ManagementConnectorProperties.FMS_MIGRATION_COMPLETED:
                self.end_migration(enabled_connectors)
            elif fms_migration_state == ManagementConnectorProperties.FMS_MIGRATION_STARTED:
                # enter FMC migration workflow
                # stop other enabled connectors - disable
                self.stop_connectors(enabled_connectors)

                # Poll CI
                DEV_LOGGER.debug('Detail="FMC_Utility Org Migration: Poll CI at source for token refresh"')
                self.refresh_access_token(migration=True)

                DEV_LOGGER.debug('Detail="FMC_Utility Org Migration: Refresh access token at target CI"')
                self.refresh_access_token()

                self.end_migration(enabled_connectors)
        elif len(org_migration_data):
            # update CDB
            DEV_LOGGER.debug('Detail="FMC_Utility Org Migration: Save migration info to DB"')
            self.process_migration_data(org_migration_data)

        # exit
        return

    # -------------------------------------------------------------------------

    def process_migration_data(self, migration_data_blob):
        """ Process the migration data returned and update the config with the value"""
        DEV_LOGGER.debug(
            'Detail="FMC_Utility Org Migration: process_migration_data: processing migration data blob from FMS"')

        for migration_path, migration_data in list(migration_data_blob.items()):
            if migration_path in list(self.migration_data_map.keys()):
                # can add additional parsing if required
                # write migration data to CDB
                self._config.write_blob(OrgMigration.migration_data_map[migration_path], migration_data)

    # -------------------------------------------------------------------------

    def clear_migration_data(self):
        """ Clear the migration data from CDB """
        # Set MIGRATION_UPDATE_CONNECTOR_JSON=False in CDB, migration info will not be updated in connector.json
        self._config.write_blob(ManagementConnectorProperties.MIGRATION_UPDATE_CONNECTOR_JSON, "false")

        DEV_LOGGER.debug('Detail="FMC_Utility Org Migration: clear_migration_data: Clearing migration data from CDB"')
        for migration_path, _ in list(OrgMigration.migration_data_map.items()):
            if migration_path in list(self.migration_data_map.keys()):
                # clear migration data to CDB
                self._database_handler.delete_blob_entry(OrgMigration.migration_data_map[migration_path])

    # -------------------------------------------------------------------------
