""" Core dump archiver """
import datetime
import os
import glob
import time
import subprocess
import urllib2
import ssl
import traceback
import threading
from pwd import getpwuid
import jsonschema

from ni.managementconnector.platform.http import CertificateExceptionFusionCA, CertificateExceptionNameMatch, \
    CertificateExceptionInvalidCert
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
CORE_DUMP_STORAGE = '/tmp/coredumps/'


class CoreArchiver(object):
    """ Class for packaging and uploading core dumps """

    lock = threading.Lock()

    @staticmethod
    def retrieve_and_archive_cores(config, atlas_logger, tracking_id):
        """ Create archive containing core dumps """
        with CoreArchiver.lock:
            output = {}
            serial_number = config.read(ManagementConnectorProperties.SERIAL_NUMBER)
            tar_file = CORE_DUMP_STORAGE + CoreArchiver.generate_filename(serial_number)
            file_paths = CoreArchiver.retrieve_core_paths()
            if not file_paths:
                output["status"] = "no core dumps found"
                os.system('touch /tmp/request/deletecoredumpdir')
                return output

            cmd_response = CoreArchiver.archive_core(tar_file, file_paths)

            if cmd_response == 0:
                output['status'] = 'archive successful'
                tracking_info = {'serial_number': serial_number, 'tracking_id': tracking_id}
                try:
                    post_result = atlas_logger.post_log(tracking_info, tar_file)
                    output['status'] = 'complete'
                    output['searchId'] = tracking_id
                    DEV_LOGGER.info(
                        'Detail="core_dump: Uploaded core dump, generated search key %s, upload time %s, '
                        'file size %s, filename %s"' % (tracking_info['tracking_id'],
                                                        post_result[1], os.path.getsize(tar_file), tar_file))
                    output['searchId'] = tracking_info['tracking_id']
                except (CertificateExceptionFusionCA,
                        CertificateExceptionNameMatch,
                        CertificateExceptionInvalidCert,
                        jsonschema.ValidationError,
                        urllib2.URLError,
                        ssl.SSLError,
                        ValueError) as error:
                    exc = traceback.format_exc()
                    DEV_LOGGER.error(
                        'Detail="core_dump: Error occurred uploading core dump to Atlas:%s, stacktrace=%s"'
                        % (repr(error), exc))
                    output['status'] = 'error uploading core dump'
                try:
                    os.remove(tar_file)
                except (IOError, OSError):
                    DEV_LOGGER.error('Detail=core_dump: Error removing file: %s' % tar_file)
            else:
                output['status'] = 'archive failed'
                DEV_LOGGER.error('Detail="core_dump: Core dump archival failed"')

            for file_path in file_paths:
                try:
                    os.remove(file_path)
                except IOError:
                    DEV_LOGGER.error('Detail=core_dump: Error removing file: %s' % file_path)
            os.system('touch /tmp/request/deletecoredumpdir')
            return output

    @staticmethod
    def generate_filename(serial_number):
        """ Create filename for core dump archive """
        meta_file = 'core_dump'
        current_time = datetime.datetime.now().strftime('%d_%b_%Y_%H_%M_%S')
        meta_file += '_' + current_time
        meta_file += '_' + serial_number
        meta_file += '.tar.gz'

        return meta_file

    @staticmethod
    def retrieve_core_paths():
        """ Retrieve system file paths for core dumps """
        core_file_paths = []
        core_file_timestamps = {}
        for file_path in ManagementConnectorProperties.CORE_DUMP_PATHS:
            try:
                if(glob.iglob(file_path)):
                    core_file = max(glob.iglob(file_path), key=os.path.getctime)
                    core_file_paths.append(core_file)
                    os.system("echo '%s' > /tmp/request/copycoredumps" % core_file)
                    timestamp = time.strftime("%d_%b_%Y_%H_%M_%S_", time.localtime(os.stat(core_file).st_mtime))
                    core_file_timestamps[os.path.basename(core_file)] = timestamp
            except ValueError:
                pass

        # Need to give time for copy script to execute
        if core_file_paths:
            i = 0
            while i < 10:
                if os.path.isfile(CORE_DUMP_STORAGE + core_file_paths[-1].split('/')[-1]) and \
                        getpwuid(os.stat(CORE_DUMP_STORAGE + core_file_paths[-1].split('/')[-1]).st_uid).pw_name == "_c_mgmt":
                    break
                i += 1
                time.sleep(1)
        file_paths = []
        for dirpath, _, filenames in os.walk(CORE_DUMP_STORAGE):
            for name in filenames:
                file_paths.append(os.path.join(dirpath, core_file_timestamps[name] + name))
                os.rename(os.path.join(dirpath, name), os.path.join(dirpath, core_file_timestamps[name] + name))
        return file_paths

    @staticmethod
    def archive_core(tar_file, file_paths):
        """ Create archive of core dumps """
        cmd_response = 0
        tar_command = ["tar", "--exclude=" + tar_file, "-zcvf", tar_file] + file_paths + ["--ignore-failed-read"]
        try:
            subprocess.check_output(tar_command, cwd=CORE_DUMP_STORAGE)
        except subprocess.CalledProcessError as tar_ex:
            cmd_response = tar_ex.returncode

        return cmd_response
