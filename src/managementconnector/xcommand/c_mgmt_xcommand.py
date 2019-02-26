"""
    ManagementConnector xcommand
"""

# Sys Path needs to be in place before imports performed
import sys
sys.path.append('/opt/c_mgmt/src/')
from managementconnector.platform.libraryutils import LibraryUtils
LibraryUtils.append_library_path()
from managementconnector.platform.taacryptoappender import TaacryptoAppender
TaacryptoAppender.append_taacrypto_version()

from managementconnector.platform.hybridlogsetup import initialise_logging_hybrid_services
initialise_logging_hybrid_services("managementconnector")

import json
import urllib2
import traceback
from collections import OrderedDict
import time
import os
import shutil
import ssl
import jsonschema
from urlparse import urlsplit
from base64 import urlsafe_b64decode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from managementconnector.config.config import Config
from managementconnector.deploy import Deploy
from managementconnector.cloud.oauth import OAuth
from managementconnector.platform.serviceutils import ServiceUtils
from managementconnector.platform.http import Http, CertificateExceptionFusionCA, CertificateExceptionNameMatch, CertificateExceptionInvalidCert
from managementconnector.config import jsonhandler
from managementconnector.platform.system import System
from managementconnector.config.databasehandler import DatabaseHandler
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.service.eventsender import EventSender
from managementconnector.cloud.u2c import U2C


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


def run(command_name, parameters, callback, error_callback):
    """Main run method"""

    def mc_rollback():
        """Performs Rollback """
        parameters_list = parameters.split()
        connector_id = parameters_list[0].strip('"')

        # add to black list current version
        DEV_LOGGER.info('Detail="rollback: mc_rollback: Management Connector XCommand called with rollback: '
                        'connector_id=%s"', connector_id)

        try:

            config = Config(False)
            black_list = config.read(ManagementConnectorProperties.INSTALL_BLACK_LIST, default={})
            current_connector_versions = ServiceUtils.get_current_versions(config)
            previous_list = ServiceUtils.get_previous_versions(config)

            DEV_LOGGER.debug('Detail="rollback: mc_rollback:  black_list=%s, current_connector_versions=%s"',
                             black_list, current_connector_versions)

            if connector_id not in current_connector_versions:
                DEV_LOGGER.error('Detail="rollback: mc_rollback: Tried to rollback %s, but could not find current '
                                 'version in %s"', connector_id, current_connector_versions)
                error = {"label": "err.ROLLBACK_ERROR_NO_CURRENT_VERSION_%s", "params": OrderedDict([(connector_id, "")])}
                error_callback(error)
                return

            if connector_id not in previous_list:
                DEV_LOGGER.info('Detail="rollback: mc_rollback: Tried to rollback %s, but could not find previous '
                                'version in %s"', connector_id, previous_list)
                error = {"label": "err.ROLLBACK_ERROR_NO_PREVIOUS_VERSION_%s", "params": OrderedDict([(connector_id, "")])}
                error_callback(error)
                return

            if connector_id in black_list and black_list[connector_id]['version'] == current_connector_versions[connector_id]['version']:
                DEV_LOGGER.info('Detail="rollback: mc_rollback: Tried to rollback %s, but it is already rolled back '
                                '(%s)"', connector_id, black_list)
                error = {"label": "err.ROLLBACK_ERROR_AS_ALREADY_BLACK_LISTED_%s", "params": OrderedDict([(connector_id, "")])}
                error_callback(error)
                return

            black_list[connector_id] = current_connector_versions[connector_id]
            DEV_LOGGER.debug('Detail="rollback: mc_rollback: write updated blacklist to database=%s"' % black_list)
            config.write_blob(ManagementConnectorProperties.INSTALL_BLACK_LIST, black_list)

            if connector_id == ManagementConnectorProperties.SERVICE_NAME:
                fake_downloaded_tlp = "{}/{}{}".format(ManagementConnectorProperties.INSTALL_DOWNLOADS_DIR,
                                                       connector_id,
                                                       ManagementConnectorProperties.PACKAGE_EXTENSION)
                shutil.copy(System.get_previous_tlp_filepath(connector_id), fake_downloaded_tlp)
                shutil.copy(fake_downloaded_tlp, "/tmp/pkgs/new")  # nosec - /tmp usage validated

            # Reapply Cached Rollback CDB entries
            DEV_LOGGER.info('Detail="rollback: reapplying %s\'s cached cdb data"' % connector_id)
            reapply_cached_rollback_cdb(connector_id)

            DEV_LOGGER.debug('Detail="rollback: mc_rollback: rollback request complete"')

            send_rollback_event(connector_id, black_list[connector_id]["version"],
                                previous_list[connector_id]["version"])
            callback("Rollback Complete")

        except (OSError, IOError) as error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed rollback with error: %s, stacktrace=%s',
                             error, traceback.format_exc())

            error = {"label": "err.ROLLBACK_ERROR_%s_%s", "params": OrderedDict([(connector_id, ""), (error, "")])}
            error_callback(error)

    def mc_control():
        """Performs Connector Control like start/stop/restart """
        parameters_list = parameters.split()
        connector_id = parameters_list[0].strip('"')
        action_name = parameters_list[1].strip('"')

        DEV_LOGGER.info('Detail="control: mc_control: Management Connector XCommand called with control: '
                        'connector_name=%s, action=%s"', connector_id, action_name)

        if action_name != "start" and action_name != "stop" and action_name != "restart" and action_name != "set_configured":
            DEV_LOGGER.error('Detail="Management Connector XCommand failed control with error: wrong action name: %s"',
                             action_name)
        elif action_name == "set_configured":
            # create configured file to indicate configured
            # may have to use this on the short term if uc connector does not have configured code complete
            open(ManagementConnectorProperties.CONFIG_FILE_STATUS_LOCATION % connector_id, 'a').close()
        else:
            try:
                os.system("echo '%s %s' > %s"  # nosec - arguments have been validated
                          % (action_name, connector_id, ManagementConnectorProperties.SERVICE_CONTROL_REQUEST))
                callback("%s %s Complete" % (connector_id, action_name))
            except OSError:
                DEV_LOGGER.error('Detail="Exception happened when running action %s on %s"', action_name, connector_id)

    def reapply_cached_rollback_cdb(service_name):
        """ Reapply the cached cdb json file to the database on rollback """

        file_data = jsonhandler.read_json_file(ManagementConnectorProperties.SERVICE_CDB_CACHE_FILE % service_name)

        config = Config(False)
        if file_data:
            DEV_LOGGER.info('Detail="reapply_cached_rollback_cdb - applying cache for %s"', service_name)

            for table, entry in file_data.iteritems():
                for path, value in entry.iteritems():
                    full_path = table + "name/" + path
                    config.write(full_path, {"value": value})
                # Cleanup file after data has been reapplied.
                jsonhandler.delete_file(ManagementConnectorProperties.SERVICE_CDB_CACHE_FILE % service_name)
        else:
            DEV_LOGGER.info('Detail="reapply_cached_rollback_cdb - %s cache cdb data was empty."', service_name)

    def send_rollback_event(connector_type, from_version, to_version):
        """ Send the rollback event to FMS """
        config = Config(False)
        oauth = OAuth(config)
        oauth.init()

        detailed_info = {
            "connectorType": connector_type,
            "fromVersion": from_version,
            "toVersion": to_version
        }

        EventSender.post(oauth, config, EventSender.ROLLBACK, detailed_info=detailed_info)

    def ping_test(url, headers):
        """ Part of precheck test - verify connection to FMS"""

        status = "Unchecked"
        DEV_LOGGER.debug('Detail="precheck testing %s"', url)
        try:
            Http.get(url, headers)
            status = "Found_good_certs"
        except urllib2.HTTPError as http_error:
            DEV_LOGGER.error('Detail="precheck response, http failure: %s, reason: %s', http_error, http_error.reason)
            status = "Not_found"

        except CertificateExceptionFusionCA as cert_exception:
            DEV_LOGGER.error('Detail="precheck response, cert failure(1): %s', cert_exception)
            status = "Found_bad_certs"

        except CertificateExceptionNameMatch as cert_exception:
            DEV_LOGGER.error('Detail="precheck response, cert failure(2): %s', cert_exception)
            status = "Found_bad_certs"

        except CertificateExceptionInvalidCert as cert_exception:
            DEV_LOGGER.error('Detail="precheck response, cert failure(3): %s', cert_exception)
            status = "Found_bad_certs"

        except urllib2.URLError as url_error:
            DEV_LOGGER.error('Detail="precheck response, http failure(2): %s', url_error)
            status = "Not_found"

        return status

    # -------------------------------------------------------------------------
    def mc_precheck():
        """Reruns precheck command
        writes connection_status : Unchecked | Not_found | Found_bad_certs | Found_good_certs,
        and last_ping_time : timestamp to file"""

        DEV_LOGGER.info('Detail="Precheck rerun xcommand called"')
        ADMIN_LOGGER.info('Detail="Precheck rerun xcommand called"')

        status = "Unchecked"

        config = Config(False)
        idp_info = config.read(ManagementConnectorProperties.OAUTH_BASE)

        idp_url = idp_info["idpPingUrl"]
        atlas_url = idp_info["atlasPingUrl"]

        Http.init(config)

        headers = dict()
        headers['Content-Type'] = 'application/json'

        results = []
        for url in (idp_url, atlas_url):
            ping_result = ping_test(url, headers)
            DEV_LOGGER.info('Detail="ping url %s gets response %s"', url, ping_result)
            results.append(ping_result)

        for state in ("Unchecked", "Not_found", "Found_bad_certs", "Found_good_certs"):
            if state in results:
                status = state
                break

        callback(status)

    # -------------------------------------------------------------------------
    def mc_teardown():
        """Removes any installed connectors, Clear out Blobs"""
        DEV_LOGGER.info('Detail="Management Connector defuse xcommand called"')
        ADMIN_LOGGER.info('Detail="Management Connector defuse xcommand called"')

        config = Config(False)

        Deploy.trigger_deregister(config)

        callback("Defuse Complete")

    # -------------------------------------------------------------------------

    def mc_init():
        """Performs OAuth Initialisation and start the connector"""
        ADMIN_LOGGER.info('Detail="Management Connector UI invoked oauth"')
        DEV_LOGGER.info('Detail="Management Connector XCommand init called"')

        parameters_list = parameters.split()

        cluster_id = parameters_list[0]
        machine_account = parameters_list[1]

        try:
            reregister = True if parameters_list[2] == "reregister" else False
            DEV_LOGGER.debug('Detail="Management Connector: Xcommand reregister: %s c_mgmt restart"', reregister)
        except IndexError:
            reregister = False

        DEV_LOGGER.info('Detail="FMC_Lifecycle cluster ID %s fetched from FMS"', cluster_id)

        try:
            # Presume failed until Successful
            failure_occurred = True

            # Create config class without inotify for OAuth config
            config = Config(False)
            Http.init(config)

            config.write_blob(ManagementConnectorProperties.CLUSTER_ID, cluster_id)

            # Parse machine account details
            machine_account = json.loads(machine_account)

            # The following is to attempt to handle the case where we get a fuse that was initiated on a FMC that
            # started the fuse flow using V2 but then bootstraps to and lands here on a V3 build. In this case FMS
            # will have included URLs for idbroker & identity in th machine account payload. FMC should only need
            # the idbroker one which we save off to cdb. Then when we initiate the oauth object we should be talking to
            # the correct CI cluster when we get tokens.
            if "idBrokerUrl" in machine_account:
                idb_url = get_bare_url(machine_account["idBrokerUrl"])
                DEV_LOGGER.info('Detail="DEPRECATED: FMC_Lifecycle got an idbroker url from FMS in the machine account:'
                                ' %s"', idb_url)
                config.write_blob(ManagementConnectorProperties.U2C_IDB_HOST, idb_url)

            oauth = OAuth(config)

            oauth.create_machine_account(cluster_id, machine_account)
            oauth.init()

            # Populate service urls
            u2c = U2C(config, oauth)
            u2c.update_user_catalog()

            config.write_blob(ManagementConnectorProperties.FUSED, 'true')
            config.write_blob(ManagementConnectorProperties.ENABLED_SERVICES_STATE, {'c_mgmt': 'true'})

            if reregister:
                DEV_LOGGER.debug('Detail="Management Connector: Xcommand reregister: set reregister flag to false"')
                config.write_blob(ManagementConnectorProperties.REREGISTER, 'false')
            else:
                DatabaseHandler().delete_blob_entry(ManagementConnectorProperties.TEMP_TARGET_ORG_ID)

            DEV_LOGGER.info('Detail="Management Connector: Xcommand Success Full Startup"')

            # finally clause will handle the callback when everything is completely done
            failure_occurred = False

        except urllib2.HTTPError as http_error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with HTTPError error: %s, stacktrace=%s, '
                             'reason: %s', http_error, traceback.format_exc(), http_error.reason)

            # Params is an ordered dictionary with a list of tuples(text, link), to handle params and solution links
            # where a blank link implies no link is required.
            error = {"label": "err.HTTP_COMMUNICATION_ERROR_%s_%s_%s", "params": OrderedDict([(http_error.code, ""),
                                                                                              (http_error.url, ""),
                                                                                              (http_error.reason, "")])}
            error_callback(error)

        except CertificateExceptionFusionCA as cert_exception:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with CertificateExceptionFusionCA error: '
                             '%s, stacktrace=%s', cert_exception, traceback.format_exc())
            error = {"label": "err.CERT_FUSION_CA_ERROR_%s_%s", "params": OrderedDict([(Http.error_url, ""),
                                                                                       ("txt.TRUSTEDCACERTIFICATE",
                                                                                        "trustedcacertificate")])}
            error_callback(error)

        except CertificateExceptionNameMatch as cert_exception:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with CertificateExceptionNameMatch  '
                             'error: %s, stacktrace=%s', cert_exception, traceback.format_exc())
            error = {"label": "err.CERT_CONNECTION_NAME_ERROR_%s", "params": OrderedDict([(Http.error_url, "")])}
            error_callback(error)

        except CertificateExceptionInvalidCert as cert_exception:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with CertificateExceptionInvalidCert error: '
                             '%s, stacktrace=%s', cert_exception, traceback.format_exc())
            error = {"label": "err.CERT_CONNECTION_ERROR_%s_%s",
                     "params": OrderedDict([(Http.error_url, ""),
                                            ("txt.TRUSTEDCACERTIFICATE",
                                             "trustedcacertificate")])}

            error_callback(error)

        except urllib2.URLError as url_error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with URLError error: %s, stacktrace=%s',
                             url_error, traceback.format_exc())

            error = {"label": "err.URL_CONNECTION_ERROR_%s_%s_%s_%s",
                     "params": OrderedDict([(Http.error_url, ""),
                                            ("txt.PING", "ping"),
                                            ("txt.PROXY", "fusionproxy"),
                                            ("txt.DNS", "dns")])}

            error_callback(error)

        except ssl.SSLError as ssl_error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with SSLError error: %s, stacktrace=%s' %
                             (ssl_error, traceback.format_exc()))

            error = {"label": "err.SSL_ERROR_%s", "params": OrderedDict([(Http.error_url, "")])}
            error_callback(error)

        except (jsonschema.ValidationError, KeyError) as validation_exc:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with ValidationError error: %s, '
                             'stacktrace=%s', validation_exc, traceback.format_exc())
            error = {"label": "err.INVALID_RESPONSE_%s", "params": OrderedDict([(Http.error_url, "")])}
            error_callback(error)
        except ValueError as value_error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with ValueError error: %s, stacktrace=%s',
                             value_error, traceback.format_exc())
            error = {"label": "err.INVALID_RESPONSE_%s", "params": OrderedDict([(Http.error_url, "")])}
            error_callback(error)

        finally:
            if failure_occurred:
                DEV_LOGGER.debug('Detail="Management Connector XCommand failed: cleaning up certs if added."')
                # Remove certs if added
                config.write_static(ManagementConnectorProperties.ADD_FUSION_CERTS, "false")
                if not reregister:
                    DEV_LOGGER.debug('Detail="Management Connector XCommand failed: deleting blob."')
                    config.delete_blob()
            else:
                callback("Success Full Startup")

    # -------------------------------------------------------------------------

    def mc_deregistered_check():
        """
        Checks if we are deregistered and returns immediately if so.
        Otherwise times out after ~30 seconds and returns registration state
        """

        DEV_LOGGER.info('Detail="ManagementConnector deregistered check xcommand called"')

        database_handler = DatabaseHandler()
        for x in xrange(ManagementConnectorProperties.CDB_CLEAN_TIMEOUT):
            state = database_handler.read(ManagementConnectorProperties.FUSED)
            if not state:
                message = 'Management Connector is deregistered from the Cisco Collaboration Cloud'
                callback(message)
                return
            time.sleep(1)

        if state == 'false':
            message = 'Management Connector is deregistering from the Cisco Collaboration Cloud'
        else:
            message = 'Management Connector is registered to the Cisco Collaboration Cloud'

        callback(message)

    # -------------------------------------------------------------------------

    def mc_repair_certs():
        """Makes an attempt to repair a mis-aligned ca.pem"""

        DEV_LOGGER.info('Detail="ManagementConnector repair_certs xcommand called"')

        open('/tmp/request/fixfusioncerts', 'a').close()  # nosec - /tmp usage validated
        callback("Cert repair request complete")

    # -------------------------------------------------------------------------

    def mc_prefuse_install():
        """ Download current version of c_mgmt in stable prior to fusing """

        parameters_list = parameters.split()
        url = parameters_list[0].strip('"')
        version = parameters_list[1].strip('"')

        DEV_LOGGER.info('Detail="ManagementConnector Install before fuse: URL: %s Version: %s"', url, version)

        Http.init(Config(False))

        tlp_path_tmp = "{}/{}{}".format(ManagementConnectorProperties.INSTALL_DOWNLOADS_DIR,
                                        ManagementConnectorProperties.SERVICE_NAME,
                                        ManagementConnectorProperties.PACKAGE_EXTENSION)

        tlp_path_dest = "{}/{}{}".format(ManagementConnectorProperties.INSTALL_PACKAGE_DIR,
                                         ManagementConnectorProperties.SERVICE_NAME,
                                         ManagementConnectorProperties.PACKAGE_EXTENSION)

        Http.download(url, tlp_path_tmp)

        # Copy the bootstrap TLP to the install directory and leave it behind in the downloads directory.
        # The next time we start up Deploy::deploy_fusion will call ServiceUtils::save_tlps_for_rollback and
        # correctly stash away the TLP into currentversions.
        shutil.copy(tlp_path_tmp, tlp_path_dest)

        callback("c_mgmt configured")

    # -------------------------------------------------------------------------

    def mc_verify_signature():
        DEV_LOGGER.info('Detail="ManagementConnector verify_signature xcommand called"')

        parameters_list = parameters.split()

        bootstrap = parameters_list[0]
        signature = parameters_list[1]

        config = Config(False)
        test_mode = config.read(ManagementConnectorProperties.COMMANDS_TEST_MODE)
        public_key = None

        if test_mode == 'true':
            DEV_LOGGER.debug('Detail="verify_signature is in test mode."')
            public_key = load_der_public_key(
                b64decode(ManagementConnectorProperties.COMMANDS_TEST_PUB_KEY),
                default_backend())
        else:
            with open('/opt/c_mgmt/etc/hercules.pem') as pem:
                public_key = load_pem_public_key(
                    pem.read(),
                    default_backend())

        if public_key is None:
            DEV_LOGGER.error('Detail="verify_signature Public key could not be obtained."')
            return False

        try:
            public_key.verify(urlsafe_b64decode(signature),
                              str(urlsafe_b64decode(bootstrap)),
                              padding.PKCS1v15(),
                              hashes.SHA256())
            DEV_LOGGER.info('Detail="Successfully verified the standard signature."')
            write_bootstrap_data(config, json.loads(urlsafe_b64decode(bootstrap)))
            callback("Successfully verified signature")
        except InvalidSignature:
            try:
                public_key.verify(urlsafe_b64decode(urlsafe_b64decode(signature)),
                                  str(urlsafe_b64decode(bootstrap)),
                                  padding.PKCS1v15(),
                                  hashes.SHA256())
                DEV_LOGGER.info('Detail="Successfully verified the double wrapped signature"')
                write_bootstrap_data(config, json.loads(urlsafe_b64decode(bootstrap)))
                callback("Successfully verified signature")
            except InvalidSignature:
                DEV_LOGGER.info('Detail="Failed to verify both signature formats"')
                callback("Failed to verify signature")

    def write_bootstrap_data(config, bootstrap_json):
        """ write bootstrap data to the cafe blob """
        if "u2cUrl" in bootstrap_json:
            config.write_blob(ManagementConnectorProperties.U2C_HOST, bootstrap_json["u2cUrl"])
        if "targetOrgId" in bootstrap_json:
            config.write_blob(ManagementConnectorProperties.TEMP_TARGET_ORG_ID, bootstrap_json["targetOrgId"])
        if "idBrokerUrl" in bootstrap_json:
            config.write_blob(ManagementConnectorProperties.U2C_IDB_HOST, get_bare_url(bootstrap_json["idBrokerUrl"]))
        if "fmsUrl" in bootstrap_json:
            config.write_blob(ManagementConnectorProperties.FMS_HOST, get_bare_url(bootstrap_json["fmsUrl"]))
        if "teamsClusterId" in bootstrap_json:
            config.write_blob(ManagementConnectorProperties.TEAMS_CLUSTER_ID, bootstrap_json["teamsClusterId"])
        if "identityUrl" in bootstrap_json:
            config.write_blob(ManagementConnectorProperties.U2C_IDENTITY_HOST, bootstrap_json["identityUrl"])

    def get_bare_url(raw_url):
        """ get_bare_url """
        parsed_url = urlsplit(raw_url)
        return parsed_url.scheme + "://" + parsed_url.netloc

    def usage():
        """Output correct usage information"""
        message = "Incorrect Command supplied: %s - Current options: " % command_name + ", ".join(run_options.keys())
        callback(message)

    # -------------------------------------------------------------------------

    # xcommand cafe c_mgmt init "<oauth_access_token> <session_id>"
    # xcommand cafe c_mgmt precheck
    # xcommand cafe c_mgmt defuse
    # xcommand cafe c_mgmt rollback "<c_connector>"
    # xcommand cafe c_mgmt control "<c_connector> <action>" <action> can only be start, stop, or restart
    # xcommand cafe c_mgmt deregistered_check
    # xcommand cafe c_mgmt prefuse_install

    run_options = {"init":                  mc_init,
                   "precheck":              mc_precheck,
                   "defuse":                mc_teardown,
                   "rollback":              mc_rollback,
                   "control":               mc_control,
                   "deregistered_check":    mc_deregistered_check,
                   "repair_certs":          mc_repair_certs,
                   "verify_signature":      mc_verify_signature,
                   "prefuse_install":       mc_prefuse_install}

    if command_name not in run_options:
        usage()
        return

    if command_name == "init":
        DEV_LOGGER.info('Detail="Management Connector XCommand called with command init"')
    else:
        DEV_LOGGER.info('Detail="Management Connector XCommand called with command %s and parameters %s"',
                        command_name, parameters)

    run_options.get(command_name, usage)()


def error_handler(message):
    """ report error content back from xcommand """
    # print the error message to stdout so that the invoking script can pass along the content
    print json.dumps(message)
    sys.exit(ManagementConnectorProperties.SYS_ERROR_CODE)


def success_handler(message):
    """ report success content back from xcommand """
    # print the success message to stdout so that invoking script can pass along the content
    print message
    sys.exit(ManagementConnectorProperties.SYS_SUCCESS_CODE)


def main():
    """ xcommand invoked from shell script, or externally, parsing the command and parameters """
    command_name = None
    params = None

    if len(sys.argv) >= 2:
        command_name = sys.argv[1]
    if len(sys.argv) == 3:
        params = sys.argv[2]

    if command_name:
        run(command_name, params, success_handler, error_handler)
    else:
        DEV_LOGGER.error('Detail="Incorrect number of params supplied for xcommand"')


if __name__ == '__main__':
    main()
