""" JSON Handler """

import json
import os
import errno

from ni.managementframework.applications.builtin.filesystemmanager.filesystemmanager import FilesystemManager
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class JsonHandler(object):
    """ JSON Handler Class """

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Management Connector Json Handler'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self, file_path, inotify=True, change_callback=None):
        self.filesystem_manager = None
        self.file_notify_path = file_path
        self.json_config = _get_config(self.file_notify_path)
        self._change_callback = change_callback

        if inotify:
            self.initialise_filesystem()

    # -------------------------------------------------------------------------

    def initialise_filesystem(self):
        """
            Initialise the filesystem requirements Config Handler
        """
        DEV_LOGGER.debug('Detail="Initialising filesystem manager for Management Connector JSON Handler"')
        filesystem_manager = FilesystemManager("options", "_applicationManager")
        filesystem_manager.start()

        self.filesystem_manager = filesystem_manager

        self.register_file_observer(self.file_notify_path, self._on_config_file_changed)

    # -------------------------------------------------------------------------

    def register_file_observer(self, filepath, callback):
        """
            Register for INotify's using the filepath & callback specified
        """
        DEV_LOGGER.debug('Detail="Registering for INotify " '
                         'File ="%s" '
                         'Callback = "%s"' % (filepath, callback))

        if self.filesystem_manager:
            self.filesystem_manager.register_file_observer(filepath, callback)

    # -------------------------------------------------------------------------

    def get_oauth_config(self):
        """ Get configuration section of json config """
        config = self.json_config['oauth']
        DEV_LOGGER.debug('Detail="_get_oauth_config: %s "' % config)
        return config

    # -------------------------------------------------------------------------

    def _get_configuration(self):
        """ Get configuration section of json config """
        config = self.json_config['config']
        DEV_LOGGER.debug('Detail="_get_configuration: %s "' % config)
        return config

    # -------------------------------------------------------------------------

    def get_register_url(self):
        """ Get register URL from config """

        return self._get_configuration()['register_url']

    # -------------------------------------------------------------------------

    def get_poll_time(self):
        """ Get poll time from config """

        return self._get_configuration()['poll_time']

    # -------------------------------------------------------------------------

    def get_error_poll_time(self):
        """ Get error poll time from config if and error has occurred."""

        return self._get_configuration()['error_poll_time']

    # -------------------------------------------------------------------------

    def _on_config_file_changed(self, path):
        """ Handle config file changes """
        DEV_LOGGER.debug('Detail="_on_config_file_changed: Update config and invoke callbacks on change notification"')

        self.json_config = _get_config(path)
        self._change_callback()

    # -------------------------------------------------------------------------

    def get(self, parts):
        """ supplies a generic method to access different levels of granularity  """

        output = None
        try:
            if self.json_config:
                output = reduce(lambda d, k: d[k], parts, self.json_config)
        except KeyError:
            if parts not in ManagementConnectorProperties.accepted_missing:
                DEV_LOGGER.debug('Detail="Error occurred getting config. Parts %s did not exist in configuration. '
                             'Please check %s to ensure you have an up to date config."' %
                             (parts, self.file_notify_path))
        return output

    def get_int(self, parts):
        """ supplies a generic method to extract an integer value from
            json files"""

        output = self.get(parts)
        if output is not None:
            return int(output)
        else:
            return output


# =============================================================================

# add as file method due to mock tests -----------------------------

def _get_config(path):
    """ Get config from JSON file """

    config_json = None
    try:
        with open(path) as json_data:
            # Ensure JSON File has valid JSON.
            try:
                config_json = json.load(json_data)
            except ValueError:
                DEV_LOGGER.debug('Detail="Invalid JSON at path = %s, json_data = %s"' % (path, json_data))
    except IOError:
        DEV_LOGGER.debug('Detail="IO Error occurred while writing to %s"' % path)

    return config_json


# -------------------------------------------------------------------------


def read_json_file(path):
    """Read JSON file, return None if file does not exist or has invalid JSON."""
    content = None
    try:
        if os.path.isfile(path):
            with open(path, 'r') as json_file:
                content = json.load(json_file)
        else:
            DEV_LOGGER.debug('Detail="File does not exist: %s"' % (path))
    except IOError:
        DEV_LOGGER.debug('Detail="IO Error occured while reading %s"' % (path))
    except ValueError:
        DEV_LOGGER.debug('Detail="Invalid JSON at path = %s"' % (path))
    return content


def write_json_file(path, content):
    """Write JSON file with the provided content"""
    try:
        with open(path, 'w') as json_file:
            json.dump(content, json_file, indent=4)
    except IOError:
        DEV_LOGGER.debug('Detail="IO Error occured while writing to %s"' % (path))


def delete_file(path):
    """Delete file"""
    DEV_LOGGER.debug('Detail="delete_file path = %s"' % path)
    try:
        os.remove(path)
    except OSError as ex:
        # Ignore file or directory not found
        if ex.errno != errno.ENOENT:
            DEV_LOGGER.debug('Detail="delete_file = %s not found when removing."' % path)


def get_last_modified(files):
    """ gets the last modified timestamps for files """
    content = {}
    for file_path in files:
        _, extension_name = os.path.splitext(file_path)
        content[extension_name] = get_last_modified_timestamp(file_path)

    return content

def get_last_modified_timestamp(file_path):
    """ gets  last modified timestamp for individual file """
    try:
        return os.path.getmtime(file_path)
    except OSError:
        DEV_LOGGER.debug('Detail="get_last_modified = %s not found when checking timestamp."' % file_path)
