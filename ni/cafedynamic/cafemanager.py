"""
    Management framework plugin to manage the configuration of components
"""

# Standard library imports
import os
import json
import shutil
from collections import defaultdict
import errno

# Local application / library specific imports
from ni.managementconnector.config.cafeproperties import CAFEProperties
from ni.cafedynamic.cafedatabase import CAFEDatabase
from ni.cafedynamic.cafecomponentconfig import CAFEComponentConfig
from ni.cafedynamic.cafestatusmanager import CAFEStatusManager
from ni.managementframework.applications.builtin.filesystemmanager.filesystemmanager import FilesystemManager
import ni.utils.filesystem.path as nipath


DEV_LOGGER = CAFEProperties.get_dev_logger()
ADMIN_LOGGER = CAFEProperties.get_admin_logger()

# =============================================================================


class CAFEManager(object):
    """
        Management framework plugin to manage the configuration of components
    """
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # This section covers going from scratch to basic/full initialisation of
    # CAFE Manager, depending on whether Management Connector is enabled or not
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------

    def __str__(self):
        return 'CAFE Manager'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self, options):
        """
            CAFE Manager initialiser
        """
        DEV_LOGGER.debug('Detail="Initialising CAFE Manager"')
        self.cafe_database = None
        self.filesystem_manager = None
        self.cafe_status_manager = None
        self.options = options
        self.started = False
        self.component_template_dir = None
        self.component_config_staging_dir = None
        self.component_config_status_dir = None
        self.managed_component_configs = dict()
        self.cdb_path_to_inotify_path = dict()
        self.inotify_path_to_cdb_path = defaultdict(list)

    # -------------------------------------------------------------------------

    def _initialise_filesystem(self, filesystem_manager):
        """
            Initialise the filesystem requirements for this plugin
        """
        DEV_LOGGER.debug('Detail="Initialising filesystem manager for CAFE Manager"')
        self.filesystem_manager = filesystem_manager

        self._initialise_filesystem_to_full()

    # -------------------------------------------------------------------------

    def _initialise_database(self):
        """
            Initialise the database for this plugin
        """
        DEV_LOGGER.debug('Detail="Initialising database for CAFE Manager"')

        self.cafe_database = CAFEDatabase()
        self._initialise_database_to_full()

    # -------------------------------------------------------------------------

    def start(self):
        """
            CAFE Manager plugin start
        """
        DEV_LOGGER.info('Detail="Starting CAFE Manager"')
        ADMIN_LOGGER.info('Detail="Starting CAFE Manager"')

        file_system_manager = FilesystemManager("options", "_applicationManager")
        file_system_manager.start()

        self._initialise_filesystem(file_system_manager)
        self._initialise_database()

        self.started = True
        self._init_components()

    # -------------------------------------------------------------------------

    def stop(self):
        """
            CAFE Manager plugin stop
        """
        DEV_LOGGER.info('Detail="Stopping CAFE Manager"')
        ADMIN_LOGGER.info('Detail="Stopping CAFE Manager"')

        self.started = False

        self._destroy_components()

        self._deinitialise_filesystem()

    # -------------------------------------------------------------------------

    def _initialise_filesystem_to_full(self):
        """
            Fully initialise any filesystem items required by CAFE Manager
        """
        DEV_LOGGER.debug('Detail="Initialising full filesystem manager for CAFE Manager"')

        try:
            self._create_template_dir()
            self._create_config_staging_dir()
            self._create_config_status_dir()

            self._register_directory_observer(self.component_template_dir, self._on_template_change)
        except OSError as ex:
            DEV_LOGGER.error('Detail="Failed to create a component directory. Stopping CAFE Manager!" '
                             'Reason="%r %s"' % (ex, ex.__str__()))
            ADMIN_LOGGER.error('Detail="Failed to create a component directory. Stopping CAFE Manager!"')
            # Failed to create the component directory
            raise Exception(ex)

    # -------------------------------------------------------------------------

    def _initialise_database_to_full(self):
        """
            Fully initialise any database items required by CAFE Manager
        """
        DEV_LOGGER.debug('Detail="Initialising full database for CAFE Manager"')

        self.cdb_path_to_inotify_path.clear()
        self.inotify_path_to_cdb_path.clear()

        cdb_schema_file_list = os.listdir(CAFEProperties.get_cdb_json_schema_dir())

        # You cannot reliably construct the inotify path for a cdb table from its
        # cdb url, as there is no guarantee that the cdb url forms part of the path.
        # Also some cdb tables simply have no inotify path.
        # So lets construct two maps:
        #   1) to map cdb path to inotify path
        #   2) to map inotify path back to cdb path
        for cdb_json_file in cdb_schema_file_list:
            with open(CAFEProperties.get_cdb_json_schema_dir() + '/' + cdb_json_file, 'r') as schema:
                data = json.load(schema)
                # Some cdb tables have no inotify path, so we're not interested
                if 'notify_path' in data:
                    self.cdb_path_to_inotify_path['/' + data['path']] = data['notify_path']

        # CDB tables can use the same inotify path between them
        # thus using a defaultdict(list) to map inotify paths back to cdb paths
        for path, notify_path in self.cdb_path_to_inotify_path.iteritems():
            self.inotify_path_to_cdb_path[notify_path].append(path)

    # -------------------------------------------------------------------------

    def _create_template_dir(self):
        """
            Create the component template directory where component templates will
            be dropped to by Management Connector
        """
        DEV_LOGGER.debug('Detail="Creating component template directory" '
                         'Template Store="%s"' % CAFEProperties.get_component_template_dir())
        try:
            nipath.make_path(CAFEProperties.get_component_template_dir())
        except OSError as ex:
            DEV_LOGGER.error(
                'Detail="Failed to create component template directory" '
                'Template directory="%s" '
                'Reason="%r %s"' % (CAFEProperties.get_component_template_dir(), ex, ex.__str__()))
            raise ex

        self.component_template_dir = CAFEProperties.get_component_template_dir()

    # -------------------------------------------------------------------------

    def _create_config_staging_dir(self):
        """
            Create the component config staging directory where component config file will
            be initially created  by Cafe Manager
        """
        DEV_LOGGER.debug('Detail="Creating component configuration staging directory" '
                         'Staging directory="%s"' % CAFEProperties.get_config_staging_dir())
        try:
            if os.path.exists(CAFEProperties.get_config_staging_dir()):
                shutil.rmtree(CAFEProperties.get_config_staging_dir())
            nipath.make_path(CAFEProperties.get_config_staging_dir())
        except OSError as ex:
            DEV_LOGGER.error(
                'Detail="Failed to create component configuration staging directory" '
                'Staging directory="%s" '
                'Reason="%r %s"' % (CAFEProperties.get_config_staging_dir(), ex, ex.__str__()))
            raise ex

        self.component_config_staging_dir = CAFEProperties.get_config_staging_dir()

    # -------------------------------------------------------------------------

    def _create_config_status_dir(self):
        """
            Create the component config status directory where Cafe Manager will report the status of whether
            a components config was successfully written or not
        """
        DEV_LOGGER.debug('Detail="Creating component config status directory" '
                         'Status directory="%s"' % CAFEProperties.get_config_status_dir())
        try:
            if os.path.exists(CAFEProperties.get_config_status_dir()):
                shutil.rmtree(CAFEProperties.get_config_status_dir())
            nipath.make_path(CAFEProperties.get_config_status_dir())
        except OSError as ex:
            DEV_LOGGER.error(
                'Detail="Failed to create component config status directory" '
                'Status directory="%s" '
                'Reason="%r %s"' % (CAFEProperties.get_config_status_dir(), ex, ex.__str__()))
            raise ex

        self.component_config_status_dir = CAFEProperties.get_config_status_dir()
        self.cafe_status_manager = CAFEStatusManager(self.component_config_status_dir)

    # -------------------------------------------------------------------------

    def _init_components(self):
        """
            Initialise all components that have a template
        """
        DEV_LOGGER.debug('Detail="Initialising all components with templates in components template store" '
                         'Template Store="%s"' % self.component_template_dir)

        component_template_file_list = os.listdir(self.component_template_dir)

        for component_template_file in component_template_file_list:
            self._on_template_change(self.component_template_dir + '/' + component_template_file)

    # -------------------------------------------------------------------------

    def _on_template_change(self, template_file_path):
        """
            Handle a change to a components config template file
        """

        if not CAFEProperties.get_template_filename_regex().search(template_file_path):
            DEV_LOGGER.warning('Detail="File in component template store does not conform to expected filename format" '
                               'File ="%s"' % template_file_path)
            return

        # check if the file exists meaning its was added or updated
        if os.path.exists(template_file_path):
            DEV_LOGGER.debug('Detail="Added/Updated component template file" '
                             'Template ="%s"' % template_file_path)

            # valid template added or updated
            if template_file_path in self.managed_component_configs:
                self.managed_component_configs[template_file_path].schedule_config_update()
            else:
                try:
                    self.managed_component_configs[template_file_path] = CAFEComponentConfig(self, template_file_path)
                    self.managed_component_configs[template_file_path].start()
                    self.managed_component_configs[template_file_path].schedule_config_update()
                except (IOError, OSError):
                    pass

        else:
            DEV_LOGGER.debug('Detail="Deleted component template file" '
                             'Template ="%s"' % template_file_path)

            # template deleted
            if template_file_path in self.managed_component_configs:
                self.managed_component_configs[template_file_path].stop()
                del self.managed_component_configs[template_file_path]

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

    def unregister_file_observer(self, filepath, callback):
        """
            Unregister for INotify's using the filepath & callback specified
        """
        DEV_LOGGER.debug('Detail="Unregistering for INotify " '
                         'File ="%s" '
                         'Callback = "%s"' % (filepath, callback))

        if self.filesystem_manager:
            if filepath in self.filesystem_manager.file_monitor.watched_files:
                self.filesystem_manager.file_monitor.watched_files[filepath].remove(callback)

    # -------------------------------------------------------------------------

    def _register_directory_observer(self, directorypath, callback):
        """
            Register for INotify's using the directory path & callback specified
        """
        DEV_LOGGER.debug('Detail="Registering for INotify " '
                         'Directory ="%s" '
                         'Callback = "%s"' % (directorypath, callback))

        if self.filesystem_manager:
            self.filesystem_manager.register_directory_observer(directorypath, callback)

    # -------------------------------------------------------------------------

    def _unregister_directory_observer(self, directorypath, callback):
        """
            Unregister for INotify's using the directory path & callback specified
        """
        DEV_LOGGER.debug('Detail="Unregistering for INotify " '
                         'Directory ="%s" '
                         'Callback = "%s"' % (directorypath, callback))

        if self.filesystem_manager:
            if directorypath in self.filesystem_manager.directory_monitor.watched_directories:
                self.filesystem_manager.directory_monitor.watched_directories[directorypath].remove(callback)

    # -------------------------------------------------------------------------

    def _deinitialise_filesystem(self):
        """
            Deinitialise the CAFE Manager filesystem requirements from full mode back to basic mode
        """
        DEV_LOGGER.debug('Detail="De-Initialising filesystem for CAFE Manager back to basic mode"')

        # Unregister inotify to template directory
        self._unregister_directory_observer(self.component_template_dir, self._on_template_change)

        self._destroy_config_staging_dir()
        self._destroy_config_status_dir()

    # -------------------------------------------------------------------------

    def _destroy_config_staging_dir(self):
        """
            Remove the component config staging directory where component config file will
            be initially created  by Cafe Manager
        """
        DEV_LOGGER.debug('Detail="Removing component configuration staging directory" '
                         'Staging directory="%s"' % self.component_config_staging_dir)
        try:
            if self.component_config_staging_dir:
                shutil.rmtree(self.component_config_staging_dir)
        except OSError as ex:
            # Ignore file or directory not found
            if ex.errno != errno.ENOENT:
                DEV_LOGGER.error(
                    'Detail="Failed to remove component configuration staging directory" '
                    'Staging directory="%s" '
                    'Reason="%r"' % (self.component_config_staging_dir, ex))
        finally:
            self.component_config_staging_dir = None

    # -------------------------------------------------------------------------

    def _destroy_config_status_dir(self):
        """
            Remove the component config status directory where Cafe Manager will report the status of whether
            a components config was successfully written or not
        """
        DEV_LOGGER.debug('Detail="Removing component config status directory" '
                         'Status directory="%s"' % self.component_config_status_dir)
        try:
            if self.component_config_status_dir:
                shutil.rmtree(self.component_config_status_dir)
        except OSError as ex:
            # Ignore file or directory not found
            if ex.errno != errno.ENOENT:
                DEV_LOGGER.debug(
                    'Detail="Failed to remove component config status directory" '
                    'Status directory="%s" '
                    'Reason="%r"' % (self.component_config_status_dir, ex))
        finally:
            self.component_config_status_dir = None
            self.cafe_status_manager = None

    # -------------------------------------------------------------------------

    def _destroy_components(self):
        """
            Destroy all components that we are currently managing
        """
        DEV_LOGGER.debug('Detail="Destroying all components which we are currently managing"')

        # destroy any CAFEComponentConfig objects.
        # Each objects destructor will in turn unregister inotifys for any CDB tables it was interested in
        for template_file_path in self.managed_component_configs.keys(): # pylint: disable=C0201
            self.managed_component_configs[template_file_path].stop()
            del self.managed_component_configs[template_file_path]


# =============================================================================
