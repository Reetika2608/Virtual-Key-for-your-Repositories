""" Cert Handler """

from shutil import copyfileobj
import traceback
import re
import os

from base_platform.expressway.filesystemmanager import FilesystemManager
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class CertHandler(object):
    """ Cert Handler Class """

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Management Connector Cert Handler'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self, file_path, inotify=True, change_callback=None):
        self.filesystem_manager = None
        self.file_notify_path = file_path
        self._change_callback = change_callback

        if inotify:
            self.initialise_filesystem()

    # -------------------------------------------------------------------------

    def initialise_filesystem(self):
        """
            Initialise the filesystem requirements Cert Handler
        """
        DEV_LOGGER.debug('Detail="Initialising filesystem manager for Management Connector Cert Handler"')
        filesystem_manager = FilesystemManager("options", "_applicationManager")
        filesystem_manager.start()

        self.filesystem_manager = filesystem_manager

        self.register_file_observer(self.file_notify_path, self._on_cert_file_changed)

    # -------------------------------------------------------------------------

    def register_file_observer(self, filepath, callback):
        """
            Register for INotify's using the filepath & callback specified
        """
        DEV_LOGGER.debug('Detail="Registering for INotify" '
                         'File="%s" '
                         'Callback="%s"', filepath, callback)

        if self.filesystem_manager:
            self.filesystem_manager.register_file_observer(filepath, callback)

    # -------------------------------------------------------------------------

    def _on_cert_file_changed(self, filepath):
        """ Handle default cert file changes """
        DEV_LOGGER.debug('Detail="_on_cert_file_changed: Invoke callbacks on change notification"')
        DEV_LOGGER.debug('Detail="Certificate file at %s has changed"',filepath)

        # Regardless of whether we are managing certs or not, all_certs.pem should
        # contain the default expressway cert.
        existing_expressway_certs = ManagementConnectorProperties.DEFAULT_EXPRESSWAY_CA_FILE
        all_certs = ManagementConnectorProperties.COMBINED_CA_FILE
        merge_certs([existing_expressway_certs],all_certs)

        self._change_callback()


def merge_certs(filepaths,output):
    """ Management Connector Merge list of files in filepaths to create output """
    all_certs = ManagementConnectorProperties.COMBINED_CA_FILE
    all_certs_size_pre_repair = 0
    DEV_LOGGER.info('Detail="ManagementConnector CertHandler combining files"')
    with open(output,'wb') as outfile:
        for pem in filepaths:
            try:
                with open(pem,'rb') as infile:
                    copyfileobj(infile, outfile)
            except IOError as error:
                DEV_LOGGER.error('Detail="Management Connector Cert Handler merge failed with error: %s, stacktrace=%s"',
                                  error, traceback.format_exc())

    try:
        all_certs_size_pre_repair = os.path.getsize(all_certs)
    except OSError:
        all_certs_size_pre_repair = 0

    repair_certs()

    return all_certs_size_pre_repair


def repair_certs():
    """ Management Connector Cert Handler Repair new cert if necessary """
    DEV_LOGGER.info('Detail="ManagementConnector CertHandler repairing certs"')
    separator = "-----END"
    separator_wildcard = re.compile("(-----END.*-----)")
    name_start = "O="
    pem_start = "-----BEGIN"
    certs = []

    # read the certs file
    # split up each cert
    # strip any extra whitespace
    # append cert to new list
    # if cert data has changed write the certs to the cert file
    with open(ManagementConnectorProperties.COMBINED_CA_FILE, "rU") as cert_file:
        cert_data = cert_file.read()
        parsed = reduce(lambda acc, elem: acc[:-1] + [acc[-1] + elem] if separator in elem else acc + [elem],
                        re.split(separator_wildcard, cert_data), [])
        for parse in parsed:
            if name_start in parse:
                # remove extra text before O=
                finished_cert = re.sub(r".*%s" % name_start, "%s" % name_start, parse, flags=re.DOTALL)
                certs.append('\n' + finished_cert + '\n')
            elif pem_start in parse:
                # remove extra text before -----BEGIN
                finished_cert = re.sub(r".*%s" % pem_start, "%s" % pem_start, parse, flags=re.DOTALL)
                certs.append('\n' + finished_cert + '\n')

    if cert_data != ''.join(certs):
        DEV_LOGGER.info('Detail="ManagementConnector CertHandler certs need to be repaired"')
        with open(ManagementConnectorProperties.COMBINED_CA_FILE, "w") as cert_file:
            for cert in certs:
                cert_file.write(cert)
    else:
        DEV_LOGGER.info('Detail="ManagementConnector CertHandler certs do not need to be repaired"')
