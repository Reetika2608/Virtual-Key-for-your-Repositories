""" Config Class """

import time

from managementconnector.config.databasehandler import DatabaseHandler
from managementconnector.config.jsonhandler import JsonHandler
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()

CONFIG_UPDATE_RETRIES = 20


class Config(object):
    """
        Config Class to Handle all configuration operations for Management Connector
    """

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Management Connector Config Class'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self, inotify=True):
        """ Config class init"""
        DEV_LOGGER.debug('Detail="___Config: Initialising Management Connector Config Class"')
        self._json_handler = JsonHandler(ManagementConnectorProperties.CONFIG_FILE_LOCATION,
                                         inotify, self.change_callback)
        self._registered_callbacks = []
        self._database_handler = DatabaseHandler()
        self._cache = {}

    # -------------------------------------------------------------------------
    def change_callback(self):
        """ Notify observer when change occurs """
        DEV_LOGGER.debug('Detail="change_callback: Invoke callbacks on change notification"')
        self.clear_cache()  # clear config read cache to avoid stale data
        for callback in self._registered_callbacks:
            callback()

    def get_targetType(self):
        """
            Return CAFE developer/hybridservices logger depending on Expressway Version
        """
        return self.read(ManagementConnectorProperties.TARGET_TYPE)

    def add_observer(self, callback):
        """ Add a new observer """

        if callback not in self._registered_callbacks:
            DEV_LOGGER.debug('Detail="add_observer: Adding config callback"')
            self._registered_callbacks.append(callback)
        else:
            DEV_LOGGER.debug('Detail="add_observer: Observer already added"')

    def remove_observer(self, callback):
        """ Remove specified observer from callbacks """
        DEV_LOGGER.debug('Detail="remove_observer: Removing config callback"')
        while callback in self._registered_callbacks:
            self._registered_callbacks.remove(callback)

    def read(self, path, default=None):
        """ Read from json config using json handler """

        ret_val = None
        if self._cache.get(path) is not None:
            ret_val = self._cache[path]
        else:
            parts = path.split('_')
            ret_val = self._json_handler.get(parts)

        if default is not None and ret_val is None:
            DEV_LOGGER.debug('Detail="read: returning default: %s for path: %s"', default, path)
            ret_val = default

        return ret_val

    # -------------------------------------------------------------------------

    def write_blob(self, path, content):
        """ Write to the blob database """
        DEV_LOGGER.debug('Detail="___Config: write Writing to blob CDB at path=%s and content=%s"' % (path, content))

        self._cache[path] = content
        self._database_handler.write_blob(path, content)

    # -------------------------------------------------------------------------

    def update_blob_entries(self, path, entries, value):
        """
            updates blob entries with a value
            i,e {"c_cal": "true", "c_ucmc": "true" }
            for a path c_mgmt_system_enabledServicesState
        """
        self._database_handler.update_blob_entries(path, entries, value)

    # -------------------------------------------------------------------------

    def write(self, path, content):
        """ Write to any database path"""
        DEV_LOGGER.debug('Detail="___Config: write Writing to CDB at path=%s and content=%s"' % (path, content))

        self._database_handler.write(path, content)

    # -------------------------------------------------------------------------

    def write_static(self, path, content):
        """ Write to any database path"""
        DEV_LOGGER.debug('Detail="___Config: write Writing to static CDB at path=%s and content=%s"' % (path, content))

        self._database_handler.write_static(path, content)

    # -------------------------------------------------------------------------

    def delete_blob(self):
        """ Write to the blob database """
        DEV_LOGGER.debug('Detail="___Config: write delete_blob CDB at path=%s"'
                         % ManagementConnectorProperties.BLOB_CDB_PATH)

        self.clear_cache()
        self._database_handler.delete_blob()

    # -------------------------------------------------------------------------

    def clear_cache(self):
        """ Clear Cache"""
        DEV_LOGGER.debug('Detail="___Config: clear cache"')

        self._cache = {}
    # -------------------------------------------------------------------------

    def is_cache_cleared(self):
        """ Ensure Cache is Cleared """
        cache_cleared = False
        if len(self._cache) == 0:
            cache_cleared = True

        DEV_LOGGER.debug('Detail="___Config: is cache cleared = %s"' % cache_cleared)

        return cache_cleared

    # -------------------------------------------------------------------------

    def check_config_update(self, config_path, database_path):
        """ Ensure config file is updated """
        is_config_updated = False
        database_value = self._database_handler.read(database_path)
        for i in range(CONFIG_UPDATE_RETRIES):
            config_value = self.read(config_path)
            if config_value == database_value:
                DEV_LOGGER.info('Detail="___Config: check_config_update: config file is updated"')
                is_config_updated = True
                break

            time.sleep(1)
            DEV_LOGGER.info('Detail="___Config: check_config_update: config file is not updated after %s seconds"' % i)
        return is_config_updated

    # -------------------------------------------------------------------------
