"""
    Class to manage component config
"""

# Standard library imports
import time
import hashlib
import threading
import os
import shutil
import tarfile
import errno
import pyratemp

# Local application / library specific imports
from managementconnector.config.cafeproperties import CAFEProperties
from cafedynamic.cafeconvenience import CAFEConvenience
from cafedynamic.cafefilewriter import CAFEFileWriter
from cafedynamic.cafestatusmanager import CAFEStatusManager
from cafedynamic.cafexutil import CafeXUtils
from base_platform.expressway.cdb.webrestclient import HttpResponseError

DEV_LOGGER = CAFEProperties.get_dev_logger()
ADMIN_LOGGER = CAFEProperties.get_admin_logger()


# =============================================================================


class CAFEComponentConfig(threading.Thread):

    """
        Class to manage component config
    """

    def __init__(self, cafemanager, template_path):
        """
            Initialiser for CAFEComponentConfig
        """
        threading.Thread.__init__(self)
        self.perform_update_lock = threading.Condition(threading.RLock())
        self.perform_update = False
        self.kill_thread = False
        self.update_config_wait_time = CAFEProperties.get_update_config_wait_time()

        self.cafemanager = cafemanager
        self.template_path = template_path
        self.component_name, extension = os.path.split(template_path)[1].split('_template.')
        self.component_config_file = CAFEProperties.get_config_filepath_format() % (self.component_name, extension)
        self.component_staging_config_file = '%s/%s/%s.%s' % (cafemanager.component_config_staging_dir, self.component_name, self.component_name, extension)
        self.registered_cdb_notifications = list()

        try:
            self.component_staging_config_dir = os.path.dirname(self.component_staging_config_file)
            self._create_config_staging_dir(self.component_staging_config_dir)
        except OSError as ex:
            ADMIN_LOGGER.error(
                'Detail="Unable to create component specific configuration staging directory." '
                'Directory="%s" '
                'Component ="%s"' % (self.component_staging_config_dir, self.component_name))
            DEV_LOGGER.error(
                'Detail="Unable to create component specific configuration staging directory." '
                'Directory="%s" '
                'Component ="%s"'
                'Error ="%r %s"' % (self.component_staging_config_dir, self.component_name, ex, ex.__str__()))
            self.cafemanager.cafe_status_manager.set_status(self.component_name,
                                                            CAFEStatusManager.error(),
                                                            CAFEStatusManager.cafeconfigwriteerror())
            raise ex

        self.component_config_writer = CAFEFileWriter(self.component_staging_config_file)
        self.registered_cdb_tables = list()

        DEV_LOGGER.debug('Detail="Initialising CAFEComponentConfig object" '
                         'Component="%s" '
                         'Template="%s" '
                         'Config="%s"' % (self.component_name, self.template_path, self.component_config_file))

    # -------------------------------------------------------------------------

    def __del__(self):
        """
            Destructor for CAFEComponentConfig
        """
        try:
            DEV_LOGGER.debug('Detail="Destroying CAFEComponentConfig object" '
                             'Component="%s" '
                             'Template="%s" '
                             'Config="%s"' % (self.component_name, self.template_path, self.component_config_file))
        except AttributeError:
            pass
        self.stop()

    # -------------------------------------------------------------------------

    def start(self):
        """
            Start thread
        """
        DEV_LOGGER.debug('Detail="CAFEComponentConfig Thread: start()"'
                         'Component="%s" ' % (self.component_name))
        threading.Thread.start(self)

    # -------------------------------------------------------------------------

    def stop(self):
        """
            Stop thread
        """
        try:
            DEV_LOGGER.debug('Detail="CAFEComponentConfig Thread: stop()"'
                             'Component="%s" ' % (self.component_name))
        except AttributeError:
            pass
        self.kill_thread = True
        with self.perform_update_lock:
            self.perform_update = False
            self.perform_update_lock.notify()

    # -------------------------------------------------------------------------

    def schedule_config_update(self):
        """
            Schedule an update of this components configuration
        """
        DEV_LOGGER.debug('Detail="Scheduling a configuration update for CAFEComponentConfig object" '
                        'Component="%s" '
                        'Template="%s" '
                        'Config="%s"' % (self.component_name, self.template_path, self.component_config_file))

        # Validate that the template file has correct syntax and can be parsed
        # successfully
        try:
            CAFEFileWriter.validate_template_file_content(self.template_path)
        except pyratemp.TemplateParseError as ex:
            ADMIN_LOGGER.error(
                'Detail="Invalid syntax/content in component template file" '
                'Template="%s" '
                'Component ="%s"' % (self.template_path, self.component_name))
            DEV_LOGGER.error(
                'Detail="Invalid syntax/content in component template file" '
                'Template="%s" '
                'Component ="%s"'
                'Error ="%r %s"' % (self.template_path, self.component_name, ex, ex.__str__()))

            self.cafemanager.cafe_status_manager.set_status(self.component_name,
                                                            CAFEStatusManager.error(),
                                                            CAFEStatusManager.cafetemplatesyntaxerror())
            return
        except (IOError, ValueError, OSError) as ex:
            ADMIN_LOGGER.error(
                'Detail="Unexpected error when accessing template file" '
                'Template="%s" '
                'Component ="%s"' % (self.template_path, self.component_name))
            DEV_LOGGER.error(
                'Detail="Unexpected error when accessing template file" '
                'Template="%s" '
                'Component ="%s"'
                'Error ="%r %s"' % (self.template_path, self.component_name, ex, ex.__str__()))
            return

        with self.perform_update_lock:
            self.perform_update = True
            self.perform_update_lock.notify()

    # -------------------------------------------------------------------------

    def _get_and_reset_perform_update(self):
        """
            Get and reset to False the flag to indicate whether a update is required or not
        """

        perform_update = False
        with self.perform_update_lock:
            if self.perform_update:
                perform_update = self.perform_update
                self.perform_update = False

        DEV_LOGGER.debug('Detail="CAFEComponentConfig: _get_and_reset_perform_update=%s"'
                         'Component="%s" ' % (perform_update, self.component_name))
        return perform_update

    # -------------------------------------------------------------------------

    def run(self):

        while True:

            DEV_LOGGER.debug('Detail="CAFEComponentConfig: run(): check _update_config requests to start"'
                             'Component="%s" ' % (self.component_name))
            perform_update = False

            with self.perform_update_lock:
                perform_update = self._get_and_reset_perform_update()
                if not perform_update:
                    DEV_LOGGER.debug('Detail="CAFEComponentConfig: run(): acquire() and wait"'
                                     'Component="%s" ' % (self.component_name))
                    self.perform_update_lock.wait()  # releases perform_update_lock

                DEV_LOGGER.debug('Detail="CAFEComponentConfig: run(): Received signal"'
                                 'Component="%s" ' % (self.component_name))
                if self.kill_thread:
                    # need to unregister from cdb tables
                    self._unregister_all_cdb_tables()
                    self._destroy_config_staging_dir(self.component_staging_config_dir)

                    DEV_LOGGER.debug('Detail="CAFEComponentConfig: run(): Signalled to kill thread. exit 1"'
                                     'Component="%s" ' % (self.component_name))
                    return

            if perform_update and not self.kill_thread:
                # have been notified of update, wait a number of seconds in
                # case another request comes in

                DEV_LOGGER.debug('Detail="CAFEComponentConfig: run(): Signalled to perform update. Sleeping for %d seconds"'
                                 'Component="%s" ' % (self.update_config_wait_time, self.component_name))
                time.sleep(self.update_config_wait_time)

                DEV_LOGGER.debug('Detail="CAFEComponentConfig: run(): Performing update of components configuration"'
                                 'Component="%s" ' % (self.component_name))
                self._get_and_reset_perform_update()
                try:
                    self._update_config()
                except IOError as ioe:
                    if not self.kill_thread:
                        ADMIN_LOGGER.error(
                            'Detail="IO error while attempting to update component configuration file" '
                            'Configuration file="%s" '
                            'Component="%s"' % (self.component_staging_config_file, self.component_name))
                        DEV_LOGGER.error(
                            'Detail="IO error while attempting to update component configuration file" '
                            'Template="%s" '
                            'Component="%s" '
                            'Configuration file="%s" '
                            'Error ="%r - %s"' % (self.template_path, self.component_name, self.component_staging_config_file, ioe, ioe.__str__()))
                        self.cafemanager.cafe_status_manager.set_status(self.component_name,
                                                                        CAFEStatusManager.error(),
                                                                        CAFEStatusManager.cafeunknownerror())

            if self.kill_thread:
                # need to unregister from cdb tables
                self._unregister_all_cdb_tables()
                self._destroy_config_staging_dir(self.component_staging_config_dir)

                DEV_LOGGER.debug('Detail="CAFEComponentConfig: run(): Signalled to kill thread. exit 2"'
                                 'Component="%s" ' % (self.component_name))
                return

    # -------------------------------------------------------------------------

    def _update_config(self):
        """
            Update configuration file for component
        """
        DEV_LOGGER.debug('Detail="Updating configuration for CAFEComponentConfig object" '
                        'Component="%s" '
                        'Template="%s" '
                        'Config="%s"' % (self.component_name, self.template_path, self.component_config_file))
        component_template = ''
        component_template_dataset = dict()

        # Make a copy of the current list of register CDB tables.
        # Once the template is processed and any additional tables have been registered, this copy will be used to check
        # that we have no old registered tables that are no longer required
        previous_registered_cdb_tables = list(self.registered_cdb_tables)
        self.registered_cdb_tables = list()

        with open(self.template_path, 'r') as template:
            for line in template:
                try:
                    # scan line for CDB references
                    line, component_template_dataset = self._scan_and_update_cdb_refs(line, component_template_dataset)

                    # scan line for Expressway references
                    if line:
                        line, component_template_dataset = self._scan_and_update_conv_refs(line, component_template_dataset)
                except (LookupError, HttpResponseError):
                    return

                if line:
                    # add the modified line to the new template
                    component_template += line

        # unregister from any CDB tables that are no longer required by this
        # version of the template
        for old_cdb_table in list(set(previous_registered_cdb_tables) - set(self.registered_cdb_tables)):
            self._unregister_cdb_table(old_cdb_table)

        # write the components configuration file to the staging directory
        try:
            self._create_config_file(component_template_dataset, component_template)
        except (SyntaxError, OSError):
            return

        self._update_config_file()

    # -------------------------------------------------------------------------

    def _scan_and_update_cdb_refs(self, line, component_template_dataset):
        """
            Scans the input line string for CBD references, update the template dataset with the relevant CDB table data,
            and replace the raw CDB path reference in the line with a template keyword.
        """

        template_cdb_reference_matches = CAFEProperties.get_template_cdb_ref_regex().finditer(line)
        for template_cdb_reference_match in template_cdb_reference_matches:
            template_cdb_reference = template_cdb_reference_match.group(1)
            DEV_LOGGER.debug('Detail="Processing template CDB reference" '
                             'Component="%s" '
                             'Template="%s" '
                             'CDB Reference="%s" ' % (self.component_name, self.template_path, template_cdb_reference))

            cdb_table_match = CAFEProperties.get_template_cdb_table_regex().search(template_cdb_reference)
            if cdb_table_match:
                cdb_table = cdb_table_match.group(1)
                cdb_table_index = cdb_table_match.group(2)

                cdb_url = cdb_table
                if len(cdb_table_index):
                    # an index was specified so append this to the cdb url that
                    # we will be querying
                    cdb_url = cdb_table + '/' + cdb_table_index

                cdb_url_key = self._transform_cdb_url_to_key(cdb_url)

                DEV_LOGGER.debug('Detail="Translating CDB URL to template key" '
                                 'Component="%s" '
                                 'CDB URL="%s" '
                                 'Template Key="%s" ' % (self.component_name, cdb_url, cdb_url_key))

                if cdb_url_key not in component_template_dataset:
                    try:
                        component_template_dataset[cdb_url_key] = self.cafemanager.cafe_database.get_cdb_records(cdb_url)
                        self._register_cdb_table(cdb_table)
                    except HttpResponseError:
                        line = None
                        DEV_LOGGER.info(
                            'Detail="CDB URL in component template file did not exist" '
                            'Template="%s" '
                            'Component="%s" '
                            'CDB URL="%s" ' % (self.template_path, self.component_name, cdb_url))
                if line:
                    # replace the raw CDB path references with a template keyword
                    line = line.replace(template_cdb_reference, cdb_url_key)

        return line, component_template_dataset

    # -------------------------------------------------------------------------

    def _scan_and_update_conv_refs(self, line, component_template_dataset):
        """
            Scans the input line string for any convenience keyword references,
            update the template dataset with the relevant CDB data returned from the convenience method.
        """

        template_expressway_matches = CAFEProperties.get_template_expressway_regex().finditer(line)
        for template_expressway_match in template_expressway_matches:
            template_expressway_reference = template_expressway_match.group(1)
            DEV_LOGGER.debug('Detail="Processing template expressway convenience reference" '
                             'Component="%s" '
                             'Template="%s" '
                             'Expressway Convenience Reference="%s" ' % (self.component_name, self.template_path, template_expressway_reference))

            if template_expressway_reference not in component_template_dataset:
                try:
                    convenience = CAFEConvenience.get_convenience_method(template_expressway_reference)(self.cafemanager.cafe_database)
                    component_template_dataset[template_expressway_reference] = convenience['data']
                    for cdb_table in convenience['cdb_tables']:
                        self._register_cdb_table(cdb_table)
                except LookupError as ex:
                    ADMIN_LOGGER.error(
                        'Detail="Invalid Expressway Convenience keyword in component template file" '
                        'Template="%s" '
                        'Component="%s"' % (self.template_path, self.component_name))
                    DEV_LOGGER.error(
                        'Detail="Invalid Expressway Convenience keyword in component template file" '
                        'Template="%s" '
                        'Component="%s" '
                        'Expressway Convenience keyword="%s" '
                        'Error ="%r - %s"' % (self.template_path, self.component_name, template_expressway_reference, ex, ex.__str__()))
                    self.cafemanager.cafe_status_manager.set_status(self.component_name,
                                                                    CAFEStatusManager.error(),
                                                                    CAFEStatusManager.cafetemplatecontenterror())
                    raise ex

        return line, component_template_dataset

    # -------------------------------------------------------------------------

    def _create_config_file(self, component_template_dataset, component_template):
        """
            Create the components configuration file using the template and template dataset.
        """

        try:
            self.component_config_writer.config_file_write(component_template_dataset, component_template)
            self.component_config_writer.set_file_permissions()
        except SyntaxError as ex:
            ADMIN_LOGGER.error(
                'Detail="Error while attempting to write component configuration file" '
                'Configuration file="%s" '
                'Component="%s"' % (self.component_staging_config_file, self.component_name))
            DEV_LOGGER.error(
                'Detail="Error while attempting to write component configuration file" '
                'Configuration file="%s" '
                'Component="%s" '
                'Template="%s" '
                'Error ="%r - %s"' % (self.component_staging_config_file, self.component_name, self.template_path, ex, ex.__str__()))
            self.cafemanager.cafe_status_manager.set_status(self.component_name,
                                                            CAFEStatusManager.error(),
                                                            CAFEStatusManager.cafeconfiggenerationerror())
            raise ex
        except OSError as ex:
            ADMIN_LOGGER.error(
                'Detail="Error while updating component config file permissions" '
                'Configuration file="%s" '
                'Component="%s"' % (self.component_staging_config_file, self.component_name))
            DEV_LOGGER.error(
                'Detail="Error while updating component config file permissions" '
                'Configuration file="%s" '
                'Component="%s" '
                'Template="%s" '
                'Error ="%r - %s"' % (self.component_staging_config_file, self.component_name, self.template_path, ex, ex.__str__()))
            self.cafemanager.cafe_status_manager.set_status(self.component_name,
                                                            CAFEStatusManager.error(),
                                                            CAFEStatusManager.cafeconfigwriteerror())
            raise ex

    # -------------------------------------------------------------------------

    def _update_config_file(self):
        """
            Determines if the new configuration is different from the components current configuration, and if it is then
            it overwrites the components configuration file with the new config.
        """

        component_config_directory = os.path.dirname(self.component_config_file)

        if os.path.exists(component_config_directory):
            # Directory exists. Does the config file exist

            if os.path.exists(self.component_config_file):
                # component already has a config file, so we need to verify that the config file which we've just produced
                # in the staging directory, is different to that which the
                # component already has

                staging_config_checksum = self._generate_file_checksum(self.component_staging_config_file)
                current_config_checksum = self._generate_file_checksum(self.component_config_file)

                if staging_config_checksum == current_config_checksum:
                    DEV_LOGGER.debug('Detail="Generated config does not differ from components previous config" '
                                     'Component="%s" ' % (self.component_name))
                    os.remove(self.component_staging_config_file)
                    self.cafemanager.cafe_status_manager.set_status(self.component_name, CAFEStatusManager.success())
                    return

            # Config file didn't already exist, or checksums didn't match, so
            # copy the config file which we've just created.
            DEV_LOGGER.debug('Detail="Updating component with new configuration file" '
                             'Component="%s" ' % (self.component_name))

            archive_name = self.component_staging_config_file + '.tar'
            try:
                # Python cannot guarantee to keep file ownership using a simple copy.
                # So we need to create a tarball fo the config file, setting the ownership in the archive.
                # Then extract the tar ball into the components actual config
                # directory.
                self._create_tarfile(self.component_staging_config_file, archive_name)
                self._extract_tarfile(archive_name, component_config_directory)
                self.cafemanager.cafe_status_manager.set_status(self.component_name, CAFEStatusManager.success())
            except (tarfile.TarError, IOError, OSError) as ex:
                ADMIN_LOGGER.error(
                    'Detail="Error while attempting to move component configuration file from staging directory to configuration directory. '
                    'Configuration directory="%s" '
                    'Staging directory="%s" '
                    'Configuration file="%s" '
                    'Component="%s"' % (component_config_directory, self.component_staging_config_dir, self.component_staging_config_file, self.component_name))
                DEV_LOGGER.error(
                    'Detail="Error while attempting to move component configuration file from staging directory to configuration directory. '
                    'Configuration directory="%s" '
                    'Staging directory="%s" '
                    'Configuration file="%s" '
                    'Archive name="%s" '
                    'Component="%s" '
                    'Error ="%r - %s"' % (component_config_directory, self.component_staging_config_dir, self.component_staging_config_file, archive_name, self.component_name, ex, ex.__str__()))
                self.cafemanager.cafe_status_manager.set_status(self.component_name,
                                                                CAFEStatusManager.error(),
                                                                CAFEStatusManager.cafeconfigwriteerror())
            finally:
                try:
                    os.remove(self.component_staging_config_file)
                    os.remove(archive_name)
                except IOError:
                    # its not the end of the world if we can't clean up.
                    # It won't affect the next run, and shouldn't be a reason
                    # to mark this run as a failure.
                    pass
        else:
            # Component config directory does not exist. Either the component has been uninstalled or it didn't create the
            # directory in the first place when it was installed.
            ADMIN_LOGGER.error(
                'Detail="Error while attempting to write component configuration file. '
                'Components configuration directory does not exist" '
                'Configuration directory="%s" '
                'Configuration file="%s" '
                'Component="%s"' % (component_config_directory, self.component_staging_config_file, self.component_name))
            DEV_LOGGER.error(
                'Detail="Error while attempting to write component configuration file. '
                'Components configuration directory does not exist" '
                'Configuration directory="%s" '
                'Configuration file="%s" '
                'Component="%s" '
                'Template="%s"' % (component_config_directory, self.component_staging_config_file, self.component_name, self.template_path))
            self.cafemanager.cafe_status_manager.set_status(self.component_name, CAFEStatusManager.error(), CAFEStatusManager.cafeconfigwriteerror())

    # -------------------------------------------------------------------------

    @staticmethod
    def _generate_file_checksum(file_path):
        """
            Generate a md5 hash of a file
        """

        if not os.path.exists(file_path):
            return None

        md5hash = hashlib.md5()
        with open(file_path, 'r') as myfile:
            for line in myfile:
                md5hash.update(line)

        return md5hash.hexdigest()

    # -------------------------------------------------------------------------

    def _is_registered_cdb_table(self, cdb_path):
        """
           Check if cdb_path is in our list of registered tables. i.e we're interested in it
        """

        return cdb_path in self.registered_cdb_tables

    # -------------------------------------------------------------------------

    def _register_cdb_table(self, cdb_path):
        """
            Register for notifications from a CDB table
        """

        if not self._is_registered_cdb_table(cdb_path):
            self.registered_cdb_tables.append(cdb_path)
            self._register_for_db_notification(cdb_path)

    # -------------------------------------------------------------------------

    def _unregister_cdb_table(self, cdb_path):
        """
            Unregister for notifications from a CDB table
        """

        if self._is_registered_cdb_table(cdb_path):
            self.registered_cdb_tables.remove(cdb_path)

        self._unregister_for_db_notification(cdb_path)

    # -------------------------------------------------------------------------

    def _unregister_all_cdb_tables(self):
        """
            Unregister for notifications from a CDB table
        """

        # make a copy as we're modifying the original as we loop through
        # the list
        cdb_paths = list(self.registered_cdb_tables)
        for cdb_path in cdb_paths:
            self._unregister_cdb_table(cdb_path)

    # -------------------------------------------------------------------------

    def _create_config_staging_dir(self, dirpath):
        """
            Create the component config staging directory where component config file will
            be initially created  by Cafe Manager
        """
        DEV_LOGGER.debug('Detail="Creating component specific configuration staging directory" '
                         'Staging directory="%s" '
                         'Component="%s"' % (dirpath, self.component_name))
        try:
            if os.path.exists(dirpath):
                shutil.rmtree(dirpath)
            CafeXUtils.make_path(dirpath)
        except OSError as ex:
            DEV_LOGGER.error(
                'Detail="Failed to create component specific configuration staging directory" '
                'Staging directory="%s" '
                'Component="%s" '
                'Reason="%r %s"' % (dirpath, self.component_name, ex, ex.__str__()))
            raise ex

    # -------------------------------------------------------------------------

    def _destroy_config_staging_dir(self, dirpath):
        """
            Remove the component config staging directory where component config file will
            be initially created  by Cafe Manager
        """
        DEV_LOGGER.debug('Detail="Removing component specific configuration staging directory" '
                         'Staging directory="%s" '
                         'Component="%s"' % (dirpath, self.component_name))
        try:
            if dirpath:
                shutil.rmtree(dirpath)
        except OSError as ex:
            # Ignore file or directory not found
            if ex.errno != errno.ENOENT:
                DEV_LOGGER.error(
                    'Detail="Failed to remove component specific configuration staging directory" '
                    'Staging directory="%s" '
                    'Component="%s" '
                    'Reason="%r"' % (dirpath, self.component_name, ex))

    # -------------------------------------------------------------------------

    @staticmethod
    def _create_tarfile(filename, tarfilename):
        """
            Create a tarball of the file
        """

        DEV_LOGGER.debug('Detail="Creating tarball of file" '
                         'Tarball="%s" '
                         'File="%s" '
                         % (tarfilename, filename))

        archive_filename = os.path.split(filename)[1]

        with tarfile.open(tarfilename, 'w') as tar:
            tar.add(filename, arcname=archive_filename)

    # -------------------------------------------------------------------------

    @staticmethod
    def _extract_tarfile(tarfilename, extraction_dir):
        """
            Extract tarball into given directory
        """

        DEV_LOGGER.debug('Detail="Extracting tarball to directory" '
                         'Tarball="%s" '
                         'Directory="%s" ' % (tarfilename, extraction_dir))

        with tarfile.open(tarfilename, 'r') as tar:
            tar.extractall(extraction_dir)

    # -------------------------------------------------------------------------

    @staticmethod
    def _transform_cdb_url_to_key(cdb_url):
        """
            Transform a CDB url to a key to be used in a template dataset
            i.e replace any non-alphanumeric characters with a '_'
        """
        import re

        cdb_url_key = re.sub(r'[^\w]', '_', cdb_url)

        if cdb_url_key[0] == '_':
            # strip off any leading '_' character as otherwise it will be an
            # invalid key in the template
            cdb_url_key = cdb_url_key[1:]

        return cdb_url_key

    # -------------------------------------------------------------------------

    def _register_for_db_notification(self, cdb_path):
        """
            Register for notifications for the cdb table
        """

        if cdb_path in self.cafemanager.cdb_path_to_inotify_path:
            inotify_path = self.cafemanager.cdb_path_to_inotify_path[cdb_path]

            if inotify_path in self.registered_cdb_notifications:
                DEV_LOGGER.debug('Detail="CDB table is already register to for notifications" '
                                 'Component="%s" '
                                 'CDB Table ="%s" '
                                 'INotify path ="%s"' % (self.component_name, cdb_path, inotify_path))
            else:
                DEV_LOGGER.debug('Detail="Registering for CDB table notifications " '
                                 'Component="%s" '
                                 'CDB Table ="%s" '
                                 'INotify path ="%s"' % (self.component_name, cdb_path, inotify_path))

                self.cafemanager.register_file_observer(inotify_path, self._on_db_update)
                self.registered_cdb_notifications.append(inotify_path)

    # -------------------------------------------------------------------------

    def _unregister_for_db_notification(self, cdb_path):
        """
            Unregister for notifications for the cdb table
        """
        DEV_LOGGER.debug('Detail="Handling CDB notification unregister request" '
                         'Component="%s" '
                         'CDB Table ="%s"' % (self.component_name, cdb_path))

        if cdb_path in self.cafemanager.cdb_path_to_inotify_path:
            inotify_path = self.cafemanager.cdb_path_to_inotify_path[cdb_path]

            if inotify_path in self.registered_cdb_notifications:
                self.cafemanager.unregister_file_observer(inotify_path, self._on_db_update)
                self.registered_cdb_notifications.remove(inotify_path)

    # -------------------------------------------------------------------------

    def _on_db_update(self, cdb_inotify_path):
        """
            Handler for CDB inotify
        """

        if cdb_inotify_path not in self.registered_cdb_notifications:
            # unlikely to happen
            # if we're not interested then we shouldn't be registered for an inotify from it in the first place
            DEV_LOGGER.debug('Detail="No longer interested in updates from CDB table. Ignoring." '
                             'Component="%s" '
                             'CDB Table(s) ="%s" '
                             'INotify path ="%s"' % (self.component_name,
                                                     self.cafemanager.inotify_path_to_cdb_path[cdb_inotify_path],
                                                     cdb_inotify_path))

        for cdb_path in self.cafemanager.inotify_path_to_cdb_path[cdb_inotify_path]:
            if self._is_registered_cdb_table(cdb_path):
                DEV_LOGGER.debug('Detail="A component is interested in this CDB notification" '
                                 'Component ="%s" '
                                 'CDB table ="%s"' % (self.component_name,
                                                      cdb_path))
                self.schedule_config_update()

# =============================================================================
