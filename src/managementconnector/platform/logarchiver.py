""" Log Archiver """

import datetime
import subprocess  # nosec - usage validated
import glob
import time
import os
import os.path
import re
import traceback
import threading
from ssl import SSLError
from http.client import HTTPException
from urllib.error import URLError

import jsonschema

from managementconnector.platform.http import CertificateExceptionFusionCA, CertificateExceptionNameMatch, \
    CertificateExceptionInvalidCert
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config import jsonhandler
from managementconnector.cloud.atlaslogger import AtlasLogger
from managementconnector.config.config import Config
from managementconnector.service.eventsender import EventSender

from managementconnector.events.logpushevent import LogPushEvent

HYBRID_SERVICES_LOG_DIR = "/mnt/harddisk/log/"
HYBRID_SERVICES_LOG = HYBRID_SERVICES_LOG_DIR + "hybrid_services_log*"
PACKAGED_LOGS = HYBRID_SERVICES_LOG_DIR + "packagesd.log*"
CONNECTORS_TOP_CONFIG_DIR = "/opt/c_mgmt/etc/config/"
CONNECTORS_CONFIG = CONNECTORS_TOP_CONFIG_DIR + "*.json"
CONFIGURATION_FILES_DIR = "/tmp/config_files/"  # nosec - /tmp usage validated
FEDERATION_ORG_MIGRATION_LOG_DIR_NAME = "federation_org_migration/"
FEDERATION_ORG_MIGRATION_LOG_DIR = HYBRID_SERVICES_LOG_DIR + FEDERATION_ORG_MIGRATION_LOG_DIR_NAME
FEDERATION_ORG_MIGRATION_LOG_ARCHIVE = FEDERATION_ORG_MIGRATION_LOG_DIR + "hybrid_services_migration_archive_*"

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class LogArchiver(object):
    """Class for LogArchiver functionality"""

    lock = threading.Lock()

    @staticmethod
    def push_logs_async(config, oauth):
        """ Calls push_logs asynchronously """
        if config.read(ManagementConnectorProperties.FUSED) == "true":
            log_thread = threading.Thread(target=LogArchiver.push_logs, args=(config, AtlasLogger(oauth, config)))
            log_thread.start()

    @staticmethod
    def archive_logs_async(config):
        """ Calls archive_logs asynchronously """
        if config.read(ManagementConnectorProperties.FUSED) == "true":
            log_archive_thread = threading.Thread(target=LogArchiver.archive_logs, args=(config,))
            log_archive_thread.start()

    @staticmethod
    def push_logs(config, atlas_logger, log_request_id=''):
        """Build and push logs"""
        with LogArchiver.lock:
            is_valid, log_entry = LogArchiver.validate_request(config, log_request_id)
            if is_valid:
                DEV_LOGGER.debug('Detail="push_logs: Start archiving logs"')
                jsonhandler.write_json_file(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)

                # Backup default if template is broken
                conf_quantity = config.read(ManagementConnectorProperties.LOGGING_QUANTITY)
                quantity = int(conf_quantity) if conf_quantity \
                    else ManagementConnectorProperties.LOGGING_QUANTITY_DEFAULT
                serial_number = config.read(ManagementConnectorProperties.SERIAL_NUMBER)
                log_archive_res = LogArchiver.build_archive(quantity, serial_number)
                DEV_LOGGER.info('Detail="push_logs: Archive results %s"' % log_archive_res)

                # Return code 0 is fully successful. 1 is successful but logs have rolled underneath during
                if log_archive_res[0] in [0, 1]:
                    log_entry['status'] = 'archive complete'
                    jsonhandler.write_json_file(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)
                    tracking_info = {'serial_number': serial_number, 'tracking_id': log_entry['logsearchId']}
                    file_size = None
                    try:
                        file_size = os.path.getsize(log_archive_res[2])
                        post_result = atlas_logger.post_log(tracking_info, log_archive_res[2])
                        log_entry['status'] = 'complete'
                        jsonhandler.write_json_file(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)

                        log_push_event = LogPushEvent(ManagementConnectorProperties.EVENT_SUCCESS,
                                                      log_entry['logsearchId'],
                                                      log_archive_res[3],
                                                      post_result[1],
                                                      file_size,
                                                      quantity,
                                                      None,
                                                      None)

                        DEV_LOGGER.info('Detail="push_logs: Logs uploaded, generated search key %s, archive time %s '
                                        'put log time %s file size %s, filename %s"' % (log_entry['logsearchId'],
                                                                                        log_archive_res[3],
                                                                                        post_result[1],
                                                                                        file_size, log_archive_res[2]))
                    except (CertificateExceptionFusionCA,
                            CertificateExceptionNameMatch,
                            CertificateExceptionInvalidCert,
                            jsonschema.ValidationError,
                            URLError,
                            HTTPException,
                            SSLError,
                            ValueError) as error:
                        exc = traceback.format_exc()
                        DEV_LOGGER.error('Detail="push_logs: Error occurred posting Logs to Atlas:%s, stacktrace=%s"'
                                         % (repr(error), exc))
                        log_entry['status'] = 'error'
                        log_entry['cause'] = LogArchiver.translate_error(getattr(type(error), "__name__", "Unknown"))
                        jsonhandler.write_json_file(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)

                        log_push_event = LogPushEvent(ManagementConnectorProperties.EVENT_FAILURE,
                                                      log_entry['logsearchId'],
                                                      None,
                                                      None,
                                                      file_size,
                                                      quantity,
                                                      ManagementConnectorProperties.PUSH_FAILURE,
                                                      getattr(type(error), "__name__", "Unknown"))

                    LogArchiver.rm_archive(log_archive_res[2])
                    LogArchiver.rm_config_files()
                else:
                    log_entry['status'] = 'archive failed'
                    jsonhandler.write_json_file(ManagementConnectorProperties.LAST_KNOWN_LOG_ID, log_entry)
                    DEV_LOGGER.debug('Detail="push_logs: Log Creation Failed with %s"' % log_archive_res[1])

                    log_push_event = LogPushEvent(ManagementConnectorProperties.EVENT_FAILURE,
                                                  log_entry['logsearchId'],
                                                  None,
                                                  None,
                                                  None,
                                                  quantity,
                                                  ManagementConnectorProperties.ARCHIVE_FAILURE,
                                                  None)

                if log_push_event:
                    EventSender.post(atlas_logger.get_oauth(),
                                     config,
                                     EventSender.LOGPUSH,
                                     ManagementConnectorProperties.SERVICE_NAME,
                                     int(time.time()),
                                     log_push_event.get_detailed_info())

            return log_entry

    @staticmethod
    def validate_request(config, log_request_id):
        """ Validate a log push request """
        if not log_request_id:
            DEV_LOGGER.debug('Detail="push_logs: Retrieve the log request id from config"')
            log_request_details = config.read(ManagementConnectorProperties.LOGGING_IDENTIFIER)
            if log_request_details:
                log_request_id = log_request_details['uuid']

        log_entry = {'logsearchId': log_request_id, 'status': 'starting'}
        last_known_log_uuid = ''
        logged = jsonhandler.read_json_file(ManagementConnectorProperties.LAST_KNOWN_LOG_ID)
        if logged:
            try:
                last_known_log_uuid = logged['logsearchId']
            except KeyError:
                DEV_LOGGER.debug('Detail="push_logs: There is no logsearchId key, contents: %s"', logged)

        DEV_LOGGER.debug('Detail="push_logs: log_request_id=%s, last_known_log_uuid=%s"'
                         % (log_request_id, last_known_log_uuid))

        is_valid = False
        if not log_request_id:
            DEV_LOGGER.info('Detail="push_logs: No log request id to process"')
            log_entry['status'] = 'no_log_uuid'
        elif last_known_log_uuid == log_request_id:
            DEV_LOGGER.debug('Detail="push_logs: No change to log request id, nothing to do"')
            log_entry['status'] = 'log_uuid_unchanged'
        else:
            is_valid = True

        return is_valid, log_entry

    @staticmethod
    def archive_logs(config, migration_id=''):
        """Build and Archive logs"""
        with LogArchiver.lock:
            is_valid, log_entry = LogArchiver.validate_migration_log_request(config, migration_id)
            if is_valid:
                DEV_LOGGER.debug('Detail="archive_logs: Start archiving logs"')
                try:
                    migration_log_quantity = LogArchiver.get_migration_log_file_quantity(
                        log_entry["migration_start_timestamp"], log_entry['migrationId'])
                    DEV_LOGGER.info('Detail="archive_logs: Archive quantity=%s"' % migration_log_quantity)
                    log_archive_res = LogArchiver.build_archive(migration_log_quantity, None, log_entry['migrationId'])
                    # Return code 0 is fully successful. 1 is successful but logs have rolled underneath during
                    if log_archive_res[0] in [0, 1]:
                        log_entry['status'] = 'complete'
                        log_entry['expiry'] = LogArchiver.get_migration_log_expiry()
                        LogArchiver.rm_config_files()
                    else:
                        log_entry['status'] = 'archive failed'
                    log_entry['log_file'] = log_archive_res[2]
                    DEV_LOGGER.debug('Detail="archive_logs: Migration Log Archival Completed, status=%s"' % log_entry)
                except Exception as e:  # pylint: disable=W0703
                    log_entry['status'] = 'archive failed'
                    DEV_LOGGER.debug(
                        'Detail="archive_logs: Migration Log Archival Failed, status=%s, exc=%s, stacktrace=%s"' % (
                        log_entry, str(e), traceback.print_exc()))
                jsonhandler.write_json_file(ManagementConnectorProperties.LAST_KNOWN_MIGRATION_LOG_ID, log_entry)

            return log_entry

    @staticmethod
    def get_migration_log_file_quantity(timestamp, migration_id):
        """
            X = ManagementConnectorProperties.MIGRATION_LOGGING_QUANTITY_DEFAULT # configurable
            Get log file index based on search string presence
            Iterate through the log files upto max X
            until primary and secondary
            search strings are found
                return the log file index + 1 to archive
            else
                return 0 -> Archive default X log files sorted descending by time
        """
        log_file_quantity = 0
        try:
            primary_search_string = "FMC_FederationOrgMigration: migrate: Migration started, migrationId=%s" % \
                                    migration_id
            secondary_search_string = '\n' + timestamp[:15] if len(timestamp) > 15 else timestamp
            log_files = LogArchiver.get_sorted_files()
            primary_string_exists = False
            for log_file_path in log_files:
                log_file_content = LogArchiver.read_file_content(log_file_path)
                if primary_search_string in log_file_content:
                    log_file_quantity = LogArchiver.extract_index(log_file_path)
                    primary_string_exists = True
                if primary_string_exists:
                    if secondary_search_string in log_file_content:
                        log_file_quantity = LogArchiver.extract_index(log_file_path)
                        break
        except Exception as e:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="get_migration_log_file_quantity: Failed with exc=%s, stack_trace=%s"' % (
            e, traceback.format_exc()))
        # Failback to default quantity if search is unsuccessful
        return int(log_file_quantity) if log_file_quantity \
            else ManagementConnectorProperties.MIGRATION_LOGGING_QUANTITY_DEFAULT

    @staticmethod
    def get_sorted_files():
        max_files = ManagementConnectorProperties.MIGRATION_LOGGING_QUANTITY_DEFAULT
        return sorted(glob.iglob(HYBRID_SERVICES_LOG), key=os.path.getmtime, reverse=True)[:max_files]

    @staticmethod
    def read_file_content(file_path):
        file = open(file_path, 'r')
        file_content = file.read()
        # search_results = re.findall(search_string, file.read())
        file.close()
        return file_content

    @staticmethod
    def extract_index(file_path):
        file_index = re.findall("\d*?\d+", file_path)
        if len(file_index) > 0:
            return int(file_index[0]) + 1
        else:
            return 1

    @staticmethod
    def validate_migration_log_request(config, migration_id):
        """ Validate a Migration log Archive request """
        log_entry = {'migrationId': migration_id, 'status': 'starting'}
        if not migration_id:
            DEV_LOGGER.debug('Detail="archive_logs: Retrieve the migration log request id from config"')
            migration_log_request_details = config.read(ManagementConnectorProperties.MIGRATION_LOGGING_IDENTIFIER)
            if migration_log_request_details:
                migration_id = migration_log_request_details['migrationId']
                migration_log_request_details['status'] = 'starting'
                log_entry = migration_log_request_details

        last_known_migration_id = ''
        logged = jsonhandler.read_json_file(ManagementConnectorProperties.LAST_KNOWN_MIGRATION_LOG_ID)
        if logged:
            try:
                last_known_migration_id = logged['migrationId']
            except KeyError:
                DEV_LOGGER.debug('Detail="archive_logs: There is no migrationId key, contents: %s"', logged)

        DEV_LOGGER.debug('Detail="archive_logs: migration_id=%s, last_known_migration_id=%s"'
                         % (migration_id, last_known_migration_id))

        is_valid = False
        if not migration_id:
            DEV_LOGGER.info('Detail="archive_logs: No migration log request id to process"')
            log_entry['status'] = 'no_migration_id'
        elif last_known_migration_id == migration_id:
            DEV_LOGGER.debug('Detail="archive_logs: No change to migration log request id, nothing to do"')
            log_entry['status'] = 'migration_id_unchanged'
        else:
            is_valid = True

        return is_valid, log_entry

    @staticmethod
    def get_migration_log_expiry():
        """ Generate Migration Log Expiry TIme """
        expiry = datetime.datetime.now() + datetime.timedelta(ManagementConnectorProperties.MIGRATION_LOG_EXPIRY)
        return expiry.strftime('%Y-%m-%dT%H:%M:%S')

    @staticmethod
    def build_archive(quantity, serial_number, migration_id=''):
        """ Build an Archive with the hybrid service logs """

        cmd_response = 0
        cmd_output = None

        if migration_id:
            # create an empty log file to enable logrotate handler
            empty_log_file = FEDERATION_ORG_MIGRATION_LOG_DIR + "hybrid_services_migration_log"
            # create if file/directory doesn't exist - by default should be taken care by c_mgmt init
            os.makedirs(os.path.dirname(FEDERATION_ORG_MIGRATION_LOG_DIR), exist_ok=True)
            open(empty_log_file, mode='a').close()
            log_file = FEDERATION_ORG_MIGRATION_LOG_DIR + LogArchiver.generate_log_name(None, migration_id)
        else:
            log_file = "/tmp/" + LogArchiver.generate_log_name(serial_number, None)  # nosec - /tmp usage validated

        files = sorted(glob.iglob(HYBRID_SERVICES_LOG), key=os.path.getmtime, reverse=True)

        first_x_files = files[:quantity]

        LogArchiver.gather_status_files()

        LogArchiver.gather_config_files()

        matching_files = first_x_files + glob.glob(PACKAGED_LOGS) + glob.glob(HYBRID_SERVICES_LOG_DIR + "*.json")

        files_to_tar = [os.path.basename(entry) for entry in matching_files]

        files_to_tar += glob.glob(CONFIGURATION_FILES_DIR + "*.json")

        if not migration_id:
            migration_log_archives = LogArchiver.gather_migration_log_archives()
            files_to_tar += [FEDERATION_ORG_MIGRATION_LOG_DIR_NAME + os.path.basename(archive) for archive in
                             migration_log_archives]

        tar_command = ["tar", "-zcvf", log_file] + files_to_tar + ["--ignore-failed-read"]

        start_archive_timer = time.time()

        try:
            subprocess.check_output(tar_command, cwd=HYBRID_SERVICES_LOG_DIR)  # nosec - input is controlled
        except subprocess.CalledProcessError as tar_ex:
            # returned non-zero exit status, returning none object
            cmd_response = tar_ex.returncode
            cmd_output = tar_ex.output

        end_archive_timer = time.time()

        # Command Status, Command Output + File Name + time elapsed
        return [cmd_response, cmd_output, log_file, end_archive_timer - start_archive_timer]

    @staticmethod
    def generate_log_name(serial_number, migration_id=''):
        """ Build an Archive with the hybrid service logs """
        if not serial_number and migration_id:
            meta_file = "hybrid_services_migration_archive"  # Build an archive with migration id in place of serial no.
        else:
            meta_file = "hybrid_services_log"
        current_time = datetime.datetime.now().strftime('%d_%b_%Y_%H_%M_%S')
        meta_file += '_' + current_time
        meta_file += '_' + (serial_number if serial_number else migration_id)
        meta_file += ".tar.gz"

        return meta_file

    @staticmethod
    def rm_archive(archive_path):
        """ Remove the Archive """

        cmd_output = 0

        try:
            subprocess.check_output(["rm", archive_path])  # nosec - input is controlled
        except subprocess.CalledProcessError as rm_ex:
            cmd_output = rm_ex.returncode

        return cmd_output

    @staticmethod
    def rm_config_files():
        """ Remove the temporary config files """

        cmd_output = 0

        try:
            subprocess.check_output(["rm", "-rf", CONFIGURATION_FILES_DIR])  # nosec - input is controlled
        except subprocess.CalledProcessError as rm_ex:
            cmd_output = rm_ex.returncode

        return cmd_output

    @staticmethod
    def translate_error(exception):
        """
            Extract meaning from thrown exception to tell admin approximate cause of log push failure
        """

        if "Certificate" in exception:
            # add_certs can be 3 values:
            # "true"    - managing certs.
            # "false"   - not managing certs.
            # None      - never managed certs.
            add_certs = Config(inotify=False).read(ManagementConnectorProperties.ADD_FUSION_CERTS)

            cause = "unmanaged-certs"

            if add_certs:
                cause = "managed-certs"

        elif "URLError" in exception or "HTTPException" in exception:
            cause = "network"
        else:
            cause = "unspecified"

        return cause

    @staticmethod
    def strip_pii_from_file(in_file_path, out_file_path):
        """
            Obfuscate PII data from a file
        """
        with open(in_file_path) as pii_file:
            pii_string = pii_file.read()

        with open(out_file_path, "w") as pii_file:
            pii_file.write(LogArchiver.strip_pii_from_string(pii_string))

    @staticmethod
    def strip_pii_from_string(pii_string):
        """
            Obfuscate PII data from a string
        """

        replacement_string = '"####PII-EXPOSURE####"'
        pii_regex_values = {"emails": r'"[\w\.-]+@[\w\.-]+(\.[\w]+)+"', "passwords": r'"({cipher}.*?)"'}

        for pii_type, pii_regex in pii_regex_values.items():
            DEV_LOGGER.info('Detail="strip_pii_from_string: Replacing %s"' % pii_type)
            pii_string = re.sub(pii_regex, replacement_string, pii_string)

        return pii_string

    @staticmethod
    def gather_status_files():
        """
            Gather status files and store them in a temporary directory
        """
        connector_prefix = ManagementConnectorProperties.CONNECTOR_PREFIX
        generic_status = ManagementConnectorProperties.GENERIC_STATUS_FILE = '/var/run/%s/status.json'
        connector_name_regex = r"%s" % generic_status.replace("%s", r"(\S+)")
        DEV_LOGGER.info('Detail="gather_status_files: collect status files"')

        try:
            if not os.path.exists(CONFIGURATION_FILES_DIR):
                os.makedirs(CONFIGURATION_FILES_DIR)

            # loop through all status files, strip pii and create <connector_name>_status.json for each
            for status_file in glob.glob(generic_status % (connector_prefix + "*")):
                pii_free_status_file = re.search(connector_name_regex, status_file).group(1) + '_status.json'
                LogArchiver.strip_pii_from_file(status_file, CONFIGURATION_FILES_DIR + pii_free_status_file)
        except (OSError, IOError) as ex:
            DEV_LOGGER.debug('Detail="gather_status_files: failed to collect status files. Exception: %s, Stacktrace: '
                             '%s"' % (ex, traceback.print_exc()))

    @staticmethod
    def gather_config_files():
        """
            Gather configuration files and store them in a temporary directory
        """
        DEV_LOGGER.info('Detail="gather_config_files: collect configuration files"')
        try:
            if not os.path.exists(CONFIGURATION_FILES_DIR):
                os.makedirs(CONFIGURATION_FILES_DIR)

            # loop through all config files, strip pii and create <connector_name>.json for each
            for config_file in glob.glob(CONNECTORS_CONFIG):
                LogArchiver.strip_pii_from_file(config_file, CONFIGURATION_FILES_DIR + os.path.basename(config_file))
        except (OSError, IOError) as ex:
            DEV_LOGGER.debug('Detail="gather_config_files: failed to collect connector configuration files. '
                             'Exception: %s, Stacktrace: %s"' % (ex, traceback.print_exc()))

    @staticmethod
    def gather_migration_log_archives():
        """
            Gather migration log archive list
        """
        DEV_LOGGER.info('Detail="gather_migration_log_archives: collect the latest migration log archive"')
        try:
            if os.path.exists(FEDERATION_ORG_MIGRATION_LOG_DIR):
                # sort and pick the latest archive
                files = sorted(glob.iglob(FEDERATION_ORG_MIGRATION_LOG_ARCHIVE), key=os.path.getmtime, reverse=True)
                if len(files):
                    return files[:1]
                else:
                    return []
        except (OSError, IOError) as ex:
            DEV_LOGGER.debug('Detail="gather_migration_log_archives: failed to collect migration log archives. '
                             'Exception: %s, Stacktrace: %s"' % (ex, traceback.print_exc()))
