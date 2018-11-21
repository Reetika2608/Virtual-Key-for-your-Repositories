"""
    ManagementConnector xcommand
"""

# Sys Path needs to be in place before imports performed

from ni.managementconnector.platform.libraryutils import LibraryUtils
LibraryUtils.append_library_path()

import json
import urllib2
import traceback
from collections import OrderedDict
import time
import os
import shutil
import ssl
import jsonschema

from ni.managementconnector.config.config import Config
from ni.managementconnector.deploy import Deploy
from ni.managementconnector.cloud.oauth import OAuth
from ni.managementconnector.platform.serviceutils import ServiceUtils
from ni.managementconnector.platform.http import Http, CertificateExceptionFusionCA, CertificateExceptionNameMatch, CertificateExceptionInvalidCert
from ni.managementconnector.config import jsonhandler
from ni.managementconnector.platform.system import System
from ni.managementconnector.config.databasehandler import DatabaseHandler
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.service.eventsender import EventSender
from ni.managementconnector.cloud.u2c import U2C


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


def run(command_name, parameters, rest_cdb_adaptor, callback, error_queue):  # pylint: disable=W0613
    """Main run method"""

    def mc_rollback():
        """Performs Rollback """
        parameters_list = parameters.split()
        connector_id = parameters_list[0].strip('"')

        # add to black list current version
        DEV_LOGGER.info('Detail="rollback: mc_rollback: Management Connector XCommand called with rollback: connector_id=%s"' % connector_id)

        try:

            config = Config(False)
            black_list = config.read(ManagementConnectorProperties.INSTALL_BLACK_LIST, default={})
            current_connector_versions = ServiceUtils.get_current_versions(config)
            previous_list = ServiceUtils.get_previous_versions(config)

            DEV_LOGGER.debug('Detail="rollback: mc_rollback:  black_list=%s, current_connector_versions=%s"' %
                             (black_list, current_connector_versions))

            if connector_id not in current_connector_versions:
                DEV_LOGGER.error('Detail="rollback: mc_rollback: Tried to rollback %s, but could not find current version in %s"' %
                                 (connector_id, current_connector_versions))
                error = {"label": "err.ROLLBACK_ERROR_NO_CURRENT_VERSION_%s", "params": OrderedDict([(connector_id, "")])}
                error_queue.put(json.dumps(error))
                return

            if connector_id not in previous_list:
                DEV_LOGGER.info('Detail="rollback: mc_rollback: Tried to rollback %s, but could not find previous version in %s"' %
                                (connector_id, previous_list))
                error = {"label": "err.ROLLBACK_ERROR_NO_PREVIOUS_VERSION_%s", "params": OrderedDict([(connector_id, "")])}
                error_queue.put(json.dumps(error))
                return

            if connector_id in black_list and black_list[connector_id]['version'] == current_connector_versions[connector_id]['version']:
                DEV_LOGGER.info('Detail="rollback: mc_rollback: Tried to rollback %s, but it is already rolled back (%s)"' %
                                (connector_id, black_list))
                error = {"label": "err.ROLLBACK_ERROR_AS_ALREADY_BLACK_LISTED_%s", "params": OrderedDict([(connector_id, "")])}
                error_queue.put(json.dumps(error))
                return

            black_list[connector_id] = current_connector_versions[connector_id]
            DEV_LOGGER.debug('Detail="rollback: mc_rollback: write updated blacklist to database=%s"' % black_list)
            config.write_blob(ManagementConnectorProperties.INSTALL_BLACK_LIST, black_list)

            if connector_id == ManagementConnectorProperties.SERVICE_NAME:
                fake_downloaded_tlp = "{}/{}{}".format(ManagementConnectorProperties.INSTALL_DOWNLOADS_DIR,
                                                       connector_id,
                                                       ManagementConnectorProperties.PACKAGE_EXTENSION)
                shutil.copy(System.get_previous_tlp_filepath(connector_id), fake_downloaded_tlp)
                shutil.copy(fake_downloaded_tlp, "/tmp/pkgs/new")

            # Reapply Cached Rollback CDB entries
            DEV_LOGGER.info('Detail="rollback: reapplying %s\'s cached cdb data"' % connector_id)
            reapply_cached_rollback_cdb(connector_id)

            DEV_LOGGER.debug('Detail="rollback: mc_rollback: rollback request complete"')

            send_rollback_event(connector_id, black_list[connector_id]["version"],
                                previous_list[connector_id]["version"])
            callback("Rollback Complete")

        except (OSError, IOError) as error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed rollback with error: %s, stacktrace=%s' %
                             (error, traceback.format_exc()))

            error = {"label": "err.ROLLBACK_ERROR_%s_%s", "params": OrderedDict([(connector_id, ""), (error, "")])}
            error_queue.put(json.dumps(error))

    def mc_control():
        """Performs Connector Control like start/stop/restart """
        parameters_list = parameters.split()
        connector_id = parameters_list[0].strip('"')
        action_name = parameters_list[1].strip('"')

        DEV_LOGGER.info('Detail="control: mc_control: Management Connector XCommand called with control: connector_name=%s, action=%s"' %
                        (connector_id, action_name))

        if action_name != "start" and action_name != "stop" and action_name != "restart" and action_name != "set_configured":
            DEV_LOGGER.error('Detail="Management Connector XCommand failed control with error: wrong action name: %s"' % action_name)
        elif action_name == "set_configured":
            # create configured file to indicate configured
            # may have to use this on the short term if uc connector does not have configured code complete
            open(ManagementConnectorProperties.CONFIG_FILE_STATUS_LOCATION % connector_id, 'a').close()
        else:
            try:
                os.system("echo '%s %s' > %s"
                          % (action_name, connector_id, ManagementConnectorProperties.SERVICE_CONTROL_REQUEST))
                callback("%s %s Complete" % (connector_id, action_name))
            except OSError:
                DEV_LOGGER.error('Detail="Exception happened when running action %s on %s"' % (action_name, connector_id))

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
            DEV_LOGGER.info('Detail="reapply_cached_rollback_cdb - %s cache cdb data was empty."' % service_name)

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
        DEV_LOGGER.debug('Detail="precheck testing %s"' % url)
        try:
            Http.get(url, headers)
            status = "Found_good_certs"
        except urllib2.HTTPError as http_error:
            DEV_LOGGER.error('Detail="precheck response, http failure: %s, reason: %s' %
                             (http_error, http_error.reason))
            status = "Not_found"

        except CertificateExceptionFusionCA as cert_exception:
            DEV_LOGGER.error('Detail="precheck response, cert failure(1): %s' %
                             (cert_exception))
            status = "Found_bad_certs"

        except CertificateExceptionNameMatch as cert_exception:
            DEV_LOGGER.error('Detail="precheck response, cert failure(2): %s' %
                             (cert_exception))
            status = "Found_bad_certs"

        except CertificateExceptionInvalidCert as cert_exception:
            DEV_LOGGER.error('Detail="precheck response, cert failure(3): %s' %
                             (cert_exception))
            status = "Found_bad_certs"

        except urllib2.URLError, url_error:
            DEV_LOGGER.error('Detail="precheck response, http failure(2): %s' %
                             (url_error))
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
            DEV_LOGGER.info('Detail="ping url %s gets response %s"' %
                            (url, ping_result))
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
            DEV_LOGGER.debug('Detail="Management Connector: Xcommand reregister: {} c_mgmt restart"'.format(reregister))
        except IndexError:
            reregister = False

        DEV_LOGGER.info('Detail="FMC_Lifecycle cluster ID {} fetched from FMS"'.format(cluster_id))

        try:
            # Presume failed until Successful
            failure_occurred = True

            # Create config class without inotify for OAuth config
            config = Config(False)
            Http.init(config)

            config.write_blob(ManagementConnectorProperties.CLUSTER_ID, cluster_id)

            # Parse machine account details
            machine_account = json.loads(machine_account)

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

            DEV_LOGGER.info('Detail="Management Connector: Xcommand Success Full Startup"')
            callback("Success Full Startup " + oauth.get_access_token())

        except urllib2.HTTPError as http_error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with HTTPError error: %s, stacktrace=%s, reason: %s' %
                             (http_error, traceback.format_exc(), http_error.reason))

            # Params is an ordered dictionary with a list of tuples(text, link), to handle params and solution links
            # where a blank link implies no link is required.
            error = {"label": "err.HTTP_COMMUNICATION_ERROR_%s_%s_%s", "params": OrderedDict([(http_error.code, ""),
                                                                                             (http_error.url, ""),
                                                                                             (http_error.reason, "")])}
            error_queue.put(json.dumps(error))

        except CertificateExceptionFusionCA as cert_exception:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with CertificateExceptionFusionCA error: %s, stacktrace=%s' %
                             (cert_exception, traceback.format_exc()))
            error = {"label": "err.CERT_FUSION_CA_ERROR_%s_%s", "params": OrderedDict([(Http.error_url, ""),
                                                                                      ("txt.TRUSTEDCACERTIFICATE", "trustedcacertificate")])}
            error_queue.put(json.dumps(error))

        except CertificateExceptionNameMatch as cert_exception:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with CertificateExceptionNameMatch  error: %s, stacktrace=%s' %
                             (cert_exception, traceback.format_exc()))
            error = {"label": "err.CERT_CONNECTION_NAME_ERROR_%s", "params": OrderedDict([(Http.error_url, "")])}
            error_queue.put(json.dumps(error))

        except CertificateExceptionInvalidCert as cert_exception:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with CertificateExceptionInvalidCert error: %s, stacktrace=%s' %
                             (cert_exception, traceback.format_exc()))
            error = {"label": "err.CERT_CONNECTION_ERROR_%s_%s", "params": OrderedDict([(Http.error_url, ""),
                                                                                        ("txt.TRUSTEDCACERTIFICATE", "trustedcacertificate")])}
            error_queue.put(json.dumps(error))

        except urllib2.URLError, url_error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with URLError error: %s, stacktrace=%s' %
                             (url_error, traceback.format_exc()))

            error = {"label": "err.URL_CONNECTION_ERROR_%s_%s_%s_%s", "params": OrderedDict([(Http.error_url, ""),
                                                                                            ("txt.PING", "ping"),
                                                                                            ("txt.PROXY", "fusionproxy"),
                                                                                            ("txt.DNS", "dns")])}
            error_queue.put(json.dumps(error))

        except ssl.SSLError, ssl_error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with SSLError error: %s, stacktrace=%s' %
                             (ssl_error, traceback.format_exc()))

            error = {"label": "err.SSL_ERROR_%s", "params": OrderedDict([(Http.error_url, "")])}
            error_queue.put(json.dumps(error))

        except (jsonschema.ValidationError, KeyError) as validation_exc:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with ValidationError error: %s, stacktrace=%s' %
                             (validation_exc, traceback.format_exc()))
            error = {"label": "err.INVALID_RESPONSE_%s", "params": OrderedDict([(Http.error_url, "")])}
            error_queue.put(json.dumps(error))
        except (ValueError) as value_error:
            DEV_LOGGER.error('Detail="Management Connector XCommand failed with ValueError error: %s, stacktrace=%s' %
                             (value_error, traceback.format_exc()))
            error = {"label": "err.INVALID_RESPONSE_%s", "params": OrderedDict([(Http.error_url, "")])}
            error_queue.put(json.dumps(error))

        else:
            failure_occurred = False
        finally:
            if failure_occurred:
                DEV_LOGGER.debug('Detail="Management Connector XCommand failed: cleaning up certs if added."')
                # Remove certs if added
                config.write_static(ManagementConnectorProperties.ADD_FUSION_CERTS, "false")
                if not reregister:
                    DEV_LOGGER.debug('Detail="Management Connector XCommand failed: deleting blob."')
                    config.delete_blob()

    # -------------------------------------------------------------------------

    def mc_deregistered_check():
        """ Checks if we are deregistered and returns immediately if so. Otherwise times out after ~30 seconds and returns registration state """

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

        open('/tmp/request/fixfusioncerts', 'a').close()
        callback("Cert repair request complete")

    # -------------------------------------------------------------------------

    def mc_prefuse_install():
        """ Download current version of c_mgmt in stable prior to fusing """

        parameters_list = parameters.split()
        url = parameters_list[0].strip('"')
        version = parameters_list[1].strip('"')

        DEV_LOGGER.info('Detail="ManagementConnector Install before fuse: URL: {} Version: {}"'.format(url, version))

        Http.init(Config(False))

        tlp_path_tmp = "{}/{}{}".format(ManagementConnectorProperties.INSTALL_DOWNLOADS_DIR,
                                        ManagementConnectorProperties.SERVICE_NAME,
                                        ManagementConnectorProperties.PACKAGE_EXTENSION)

        tlp_path_dest = "{}/{}{}".format(ManagementConnectorProperties.INSTALL_PACKAGE_DIR,
                                         ManagementConnectorProperties.SERVICE_NAME,
                                         ManagementConnectorProperties.PACKAGE_EXTENSION)

        Http.download(url, tlp_path_tmp)

        shutil.move(tlp_path_tmp, tlp_path_dest)

        callback("c_mgmt configured")

    # -------------------------------------------------------------------------

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
                   "prefuse_install":       mc_prefuse_install}

    if command_name not in run_options:
        usage()
        return

    if command_name == "init":
        DEV_LOGGER.info('Detail="Management Connector XCommand called with command init"')
    else:
        DEV_LOGGER.info('Detail="Management Connector XCommand called with command %s and parameters %s"' % (command_name, parameters))

    run_options.get(command_name, usage)()
