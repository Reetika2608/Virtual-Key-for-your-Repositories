""" Database Handler"""

import json

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

from cafedynamic.cafexutil import CafeXUtils
from base_platform.expressway.cdb.restclient import ClusterDatabaseRestClient, CDBDownException

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class DatabaseHandler(ClusterDatabaseRestClient):
    """
        Database Class to Handle all REST API operations for Management Connector
    """

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Management Connector Json Handler'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self):
        """ DatabaseHandler init"""
        DEV_LOGGER.debug('Detail="Initialising Management Connector Database"')
        ClusterDatabaseRestClient.__init__(self)

    # -------------------------------------------------------------------------

    def write_blob(self, path, content):
        """ Writes to the blob configuration database table """
        cdb_url = ManagementConnectorProperties.BLOB_CDB_PATH + path
        self.send_post(cdb_url, {"value": json.dumps(content)})
        DEV_LOGGER.debug('Detail="__DatabaseHandler::_write: path=%s, cdb_url: %s Content: %s"' % (path, cdb_url, content))

    # -------------------------------------------------------------------------

    def write_static(self, path, content):
        """ Writes to the blob configuration database table """
        cdb_url = ManagementConnectorProperties.STATIC_MGMT_CDB_PATH + path
        try:
            self.send_post(cdb_url, {"value": json.dumps(content)})
            DEV_LOGGER.debug('Detail="__DatabaseHandler::write_static: path=%s, cdb_url: %s Content: %s"' % (path, cdb_url, content))
        except CDBDownException:
            DEV_LOGGER.error('Detail="CDB is not running"')

    # -------------------------------------------------------------------------

    def write(self, path, content):
        """ Writes to any database table """
        self.send_post(path, content)
        DEV_LOGGER.debug('Detail="__DatabaseHandler::_write: path=%s, Content: %s"' % (path, content))

    # -------------------------------------------------------------------------

    def delete_blob(self):
        """ Writes to any database table """
        path = "/configuration/cafe/cafeblobconfiguration"
        self.send_delete(path)
        DEV_LOGGER.debug('Detail="__DatabaseHandler::_delete: path=%s"' % path)

    # -------------------------------------------------------------------------

    def delete_blob_entry(self, path):
        """ Writes to any database table """
        cdb_url = ManagementConnectorProperties.BLOB_CDB_PATH + path
        self.send_delete(cdb_url)
        DEV_LOGGER.debug('Detail="__DatabaseHandler::_delete: path=%s"' % path)

    # -------------------------------------------------------------------------

    def read(self, path):
        '''Retrieve Record from the DB'''

        cdb_url = ManagementConnectorProperties.BLOB_CDB_PATH + path

        rtn_value = None
        record = self.get_records(cdb_url + '?peer=local')
        if record is not None and len(record) > 0:
            # Convert to JSON Dict
            database_value = record[0]['value']
            rtn_value = json.loads(database_value)
        else:
            rtn_value = None

        DEV_LOGGER.debug('Detail="__DatabaseHandler::_read: path=%s, cdb_url: %s rtn_value: %s, type=%s"' %
                         (path, cdb_url, rtn_value, type(rtn_value)))
        return rtn_value
    # -------------------------------------------------------------------------

    def delete_service_blob(self, service_name):
        ''' Delete Record from the DB for service '''

        DEV_LOGGER.info('Detail="__DatabaseHandler::delete_service_blob: service_name=%s"' % service_name)
        cdb_url = ManagementConnectorProperties.CAFE_BLOB_CDB_PATH

        records = self.get_service_table_records(cdb_url, service_name)

        if records:
            for entry in records:
                self.send_delete(ManagementConnectorProperties.CAFE_BLOB_CDB_PATH + "name" + "/" + entry)
        else:
            DEV_LOGGER.debug('Detail="__DatabaseHandler::delete_service_blob no records found for path=%s"' % cdb_url)

    # -------------------------------------------------------------------------

    def get_service_database_records(self, service_name):
        """
            Returns a nested dictionary of paths and data for all tables for service.
            Example: {"table1": {"entry_path": "value"}, "table2": {"entry_path": "value"}}
        """

        DEV_LOGGER.info('Detail="__DatabaseHandler::get_service_database_records for %s"' % service_name)
        records = {}

        for table in ManagementConnectorProperties.DATABASE_TABLES:
            row = self.get_service_table_records(table, service_name)
            if row:
                records[table] = row
            else:
                DEV_LOGGER.info('Detail="__DatabaseHandler::get_service_database_records no record found for: %s in table: %s"'
                                % (service_name, table))

        return records

    # -------------------------------------------------------------------------

    def get_service_table_records(self, table, service_name):
        """ Returns a key value dictionary of path and data from CDB for service from a specified table """

        DEV_LOGGER.info('Detail="__DatabaseHandler::get_service_table_records table: %s service: %s"'
                        % (table, service_name))

        key_value_dict = {}

        records = self.get_records(table + '?peer=local')

        if records:
            for entry in records:
                if entry['name'].startswith(service_name):
                    key_value_dict[entry['name']] = entry['value']
        else:
            DEV_LOGGER.info('Detail="__DatabaseHandler::get_service_table_records no records found"')

        return key_value_dict

    # -------------------------------------------------------------------------

    def update_blob(self, path, entry, value):
        """ Update entry in blob database """

        DEV_LOGGER.info('Detail="__DatabaseHandler:: update blob entry %s at path=%s with content=%s"'
                        % (entry, path, value))
        self.update_blob_entries(path, [entry], value)

    # -------------------------------------------------------------------------

    def update_blob_entries(self, path, entries, value):
        """ Update entry in blob database """

        DEV_LOGGER.info('Detail="__DatabaseHandler:: update blob entry %s at path=%s with content=%s"'
                        % (entries, path, value))

        existing = {}
        records = self.read(path)
        if records:
            existing = records

        for entry in entries:
            existing[entry] = value
        self.write_blob(path, existing)

    # -------------------------------------------------------------------------

    def delete_enabled_service_blob(self, service_name):
        ''' Delete enabled services state for service '''

        DEV_LOGGER.info('Detail="__DatabaseHandler::delete_enabled_service_blob: service_name=%s"' % service_name)

        existing = {}
        records = self.read(ManagementConnectorProperties.ENABLED_SERVICES_STATE)

        if records:
            existing = records

        if existing.pop(service_name, None):
            self.write_blob(ManagementConnectorProperties.ENABLED_SERVICES_STATE, existing)

    # -------------------------------------------------------------------------


def register_all_default_loggers():
    """ Register loggers for first time including currently installed connectors """
    currently_installed = CafeXUtils.get_installed_connectors(ManagementConnectorProperties.CONNECTOR_PREFIX)
    DEV_LOGGER.debug('Detail="__DatabaseHandler::register_all_default_loggers currently installed: {}"'.format(currently_installed))

    if currently_installed:
        # c_mgmt is not a used logger pattern
        if ManagementConnectorProperties.SERVICE_NAME in currently_installed:
            currently_installed.remove(ManagementConnectorProperties.SERVICE_NAME)

        # In certain circumstances get_installed_connectors can return a dpkg error. By checking for c_ in the name, this
        # ensures that only valid connectors register a logger.
        full_loggers = [ManagementConnectorProperties.HYBRID_PREFIX + name for name in currently_installed if "c_" in name]

        all_loggers = full_loggers + ManagementConnectorProperties.DEFAULT_LOGGERS

        DEV_LOGGER.info('Detail="__DatabaseHandler::register_all_default_loggers default loggers: {}"'.format(all_loggers))
        register_default_loggers(all_loggers)
    else:
        DEV_LOGGER.error('Detail="__DatabaseHandler::register_all_default_loggers no connectors currently installed"')


def register_default_loggers(loggers):
    """ Register default database entry for Hybrid Services Logger """

    # Check Feature Support - database table existence
    database_handler = DatabaseHandler()
    sanitised_loggers = list()

    logger_db = ManagementConnectorProperties.LOGGER_DB_PATH
    logger_records = database_handler.get_records(logger_db)

    if logger_records:
        for record in logger_records:
            sanitised_loggers.append(record['name'])

    # Init Loggers in database
    for logger in loggers:
        if sanitised_loggers:
            if logger not in sanitised_loggers:
                # Append new loggers to Hybrid Services
                database_handler.write("{}/name/{}".format(logger_db, logger), {"name": logger})
        else:
            # Default FMC and Cafe Loggers for first time.
            database_handler.write("{}/name/{}".format(logger_db, logger), {"name": logger})
