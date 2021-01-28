""" Class that handles commands coming from remote-dispatcher/mercury """

import os
import json
from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from managementconnector.config import jsonhandler
from managementconnector.platform.http import Http
from managementconnector.platform.serviceutils import ServiceUtils
from managementconnector.service.servicemanager import ServiceManager
from managementconnector.platform.system import System
from cafedynamic.cafexutil import CafeXUtils
from managementconnector.config.config import Config
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud import schema
from managementconnector.platform.logarchiver import LogArchiver
from managementconnector.platform.corearchiver import CoreArchiver
from managementconnector.cloud.atlaslogger import AtlasLogger
from managementconnector.platform.connectivitycheck import ConnectivityCheck

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()
TARGET_TYPE = Config(inotify=False).read(ManagementConnectorProperties.TARGET_TYPE)

class RemoteDispatcher(object):
    """ RemoteDispatcher class """

    @staticmethod
    def get_connector():
        """Get connector name@serialNumber"""
        return RemoteDispatcher.TARGET_TYPE + "@" \
            + RemoteDispatcher.config.read(ManagementConnectorProperties.SERIAL_NUMBER)

    @staticmethod
    def get_org_id():
        """Get org id"""
        return ServiceUtils.get_org_id(RemoteDispatcher.config)

    @staticmethod
    def get_mercury_config():
        """Get mercury config"""
        return jsonhandler.read_json_file(ManagementConnectorProperties.MERCURY_FILE % (RemoteDispatcher.TARGET_TYPE, RemoteDispatcher.TARGET_TYPE))

    @staticmethod
    def get_remotedispatcher_url():
        """ Build the remotedispatcher end-point """
        host = RemoteDispatcher.config.read(ManagementConnectorProperties.REMOTE_DISPATCHER_HOST)
        url = RemoteDispatcher.config.read(ManagementConnectorProperties.REMOTE_DISPATCHER_URL)
        return host + url

    @staticmethod
    def get_command_url():
        """ Build the remotedispatcher command url """
        return RemoteDispatcher.get_remotedispatcher_url() + "/commands/" + RemoteDispatcher.get_org_id() + "/connectors/" + RemoteDispatcher.get_connector() + "/command"

    @staticmethod
    def register(oauth, config):
        """ Register with RemoteDispatcher """
        RemoteDispatcher.config = config
        RemoteDispatcher.oauth = oauth
        RemoteDispatcher.TARGET_TYPE = config.read(ManagementConnectorProperties.TARGET_TYPE)

        mercury_config = RemoteDispatcher.get_mercury_config()
        if mercury_config:
            post_data = {
                "orgId": RemoteDispatcher.get_org_id(),
                "connectorId": RemoteDispatcher.get_connector(),
                "connectorType": RemoteDispatcher.TARGET_TYPE,
                "deviceId": mercury_config['route'],
                "hostname": config.read(ManagementConnectorProperties.HOSTNAME),
                "clusterName": config.read(ManagementConnectorProperties.CLUSTER_NAME),
                "clusterId": config.read(ManagementConnectorProperties.CLUSTER_ID)
            }

            DEV_LOGGER.debug('Detail="Register with remotedispatcher data= %s"' % (json.dumps(post_data)))
            registration_url = RemoteDispatcher.get_remotedispatcher_url() + "/connectors/register?probe=true"
            response = Http.post(registration_url, oauth.get_header(), json.dumps(post_data),
                                 schema=schema.REMOTE_DISPATCHER_RESPONSE)
            RemoteDispatcher.write_config_to_disk(response)
        else:
            DEV_LOGGER.error('Detail="No mercury configuration was found"')
            RemoteDispatcher.delete_config_from_disk(config)

    @staticmethod
    def write_config_to_disk(config):
        """ Write Remote Dispatcher registration information to disk """
        remote_dispatcher_config = {"orgId": config["orgId"], "connectorId": config["connectorId"],
                                    "deviceId": config["deviceId"], "hostname": config["hostname"],
                                    "clusterName": config["clusterName"], "clusterId": config["clusterId"]}

        jsonhandler.write_json_file(ManagementConnectorProperties.REMOTE_DISPATCHER_FILE
                                    % (RemoteDispatcher.TARGET_TYPE, RemoteDispatcher.TARGET_TYPE), remote_dispatcher_config)

    @staticmethod
    def delete_config_from_disk(config):
        """ Remove Remote Dispatcher registration information from disk """
        jsonhandler.delete_file(ManagementConnectorProperties.REMOTE_DISPATCHER_FILE
                                % (config.read(ManagementConnectorProperties.TARGET_TYPE), config.read(ManagementConnectorProperties.TARGET_TYPE)))


    @staticmethod
    def verify_signature(message):
        """ Verify Signature """
        test_mode = RemoteDispatcher.config.read(ManagementConnectorProperties.COMMANDS_TEST_MODE)
        public_key = None

        if test_mode == 'true':
            DEV_LOGGER.debug('Detail="FMC_Websocket It is test mode."')

            public_key = load_der_public_key(
                b64decode(ManagementConnectorProperties.COMMANDS_TEST_PUB_KEY),
                default_backend())
        else:
            with open('/opt/c_mgmt/etc/hercules.pem') as pem:
                public_key = load_pem_public_key(
                    pem.read(),
                    default_backend())

        if public_key is None:
            DEV_LOGGER.error('Detail="FMC_Websocket Public key could not be obtained."')
            return False

        try:
            public_key.verify(b64decode(message['data']['signature']),
                              str(message['data']['command']['action']),
                              padding.PKCS1v15(),
                              hashes.SHA256())
            return True
        except InvalidSignature:
            DEV_LOGGER.error('Detail="FMC_Websocket The signature is not authentic."')
            return False

    @staticmethod
    def handle_command(command):
        """ command Handler """
        if not RemoteDispatcher.verify_signature(command):
            DEV_LOGGER.error('Detail="FMC_Websocket Not continuing processing this command"')
            return

        command_id = command['data']['command']['commandId']
        action = command['data']['command']['action']
        command_output = dict()
        status = "complete"

        params = None
        # assign params if present
        if "parameters" in command['data']['command']:
            params = command['data']['command']['parameters']
            if params and not isinstance(params, list):
                params = [params]

        if command_id:
            if action in ['stop', 'start', 'restart']:
                audit_error = RemoteDispatcher.audit_connectors(params)
                if not audit_error:
                    process_error = RemoteDispatcher.process_start_stop(action, params)
                    if process_error:
                        command_output[ManagementConnectorProperties.SERVICE_NAME] = process_error
                else:
                    # Audit of connectors failed
                    command_output[ManagementConnectorProperties.SERVICE_NAME] = audit_error

            elif action in ["enable", "disable"]:
                if System.am_i_master():
                    audit_error = RemoteDispatcher.audit_connectors(params)
                    if not audit_error:
                        process_error = RemoteDispatcher.process_enable_disable(action, params)
                        if process_error:
                            command_output[ManagementConnectorProperties.SERVICE_NAME] = process_error
                    else:
                        # Audit of connectors failed
                        command_output[ManagementConnectorProperties.SERVICE_NAME] = audit_error
                else:
                    not_master_response = "Enable/Disable will be handled by master node in cluster"
                    DEV_LOGGER.info('Detail="FMC_Websocket handle_command {}"'.format(not_master_response))
                    command_output[ManagementConnectorProperties.SERVICE_NAME] = not_master_response

            elif action == 'ping':
                command_output[ManagementConnectorProperties.SERVICE_NAME] = RemoteDispatcher.process_ping()
            elif action == 'push_logs':
                command_output, status = RemoteDispatcher.process_push_logs(params[0] if params else None)
            elif action == 'core_dump':
                command_output, status = RemoteDispatcher.process_core_dump(params[0] if params else None)
            elif action == 'check_connection':
                command_output, status = RemoteDispatcher.process_connectivity_check(params[0] if params else None)
            else:
                DEV_LOGGER.error('Detail="FMC_Websocket handle_command not handling unrecognized command: %s"', action)
                status = "unrecognized_command"

            RemoteDispatcher.send_result_to_remotedispatcher(status, command_id, command_output)
        else:
            DEV_LOGGER.error('Detail="No command id"')

    @staticmethod
    def process_push_logs(log_request_id):
        """ Process the push_logs command """
        status = 'error'
        command_output = {ManagementConnectorProperties.SERVICE_NAME: {}}
        if log_request_id:
            atlas_logger = AtlasLogger(RemoteDispatcher.oauth, RemoteDispatcher.config)
            command_output[ManagementConnectorProperties.SERVICE_NAME] = LogArchiver.push_logs(RemoteDispatcher.config, atlas_logger, log_request_id)
            if command_output[ManagementConnectorProperties.SERVICE_NAME]['status'] is 'complete':
                status = 'complete'
        else:
            command_output[ManagementConnectorProperties.SERVICE_NAME]['logsearchId'] = 'Not provided'
        return command_output, status

    @staticmethod
    def process_core_dump(search_id):
        """ Process the core_dump command """
        status = 'error'
        command_output = {ManagementConnectorProperties.SERVICE_NAME: {}}
        if search_id:
            atlas_logger = AtlasLogger(RemoteDispatcher.oauth, RemoteDispatcher.config)
            command_output[ManagementConnectorProperties.SERVICE_NAME] = CoreArchiver.retrieve_and_archive_cores(
                RemoteDispatcher.config, atlas_logger, search_id)
            if command_output[ManagementConnectorProperties.SERVICE_NAME]['status'] is 'complete':
                status = 'complete'
        else:
            command_output[ManagementConnectorProperties.SERVICE_NAME]['searchId'] = 'Not provided'
        return command_output, status

    @staticmethod
    def process_connectivity_check(url):
        """ Check if we can connect to a given URL """
        status = "error"
        command_output = {ManagementConnectorProperties.SERVICE_NAME: {}}
        if url:
            if url.startswith("http://"):
                command_output[ManagementConnectorProperties.SERVICE_NAME]["url"] = "HTTP not supported"
            else:
                command_output[ManagementConnectorProperties.SERVICE_NAME] = ConnectivityCheck.check_connectivity_to_url(
                    RemoteDispatcher.oauth, RemoteDispatcher.config, url)
                status = "complete"
        else:
            command_output[ManagementConnectorProperties.SERVICE_NAME]["url"] = "Not provided"
        return command_output, status

    @staticmethod
    def process_ping():
        """ Process the ping command """
        status = {}

        installed_connectors = CafeXUtils.get_installed_connectors(ManagementConnectorProperties.CONNECTOR_PREFIX)
        service_manager = ServiceManager(RemoteDispatcher.config, RemoteDispatcher.oauth)

        for connector_name in installed_connectors:

            service = service_manager.get(connector_name)
            connector_status = ''
            start_time = ''

            if service.get_composed_status() == 'running':

                connector_status = ServiceUtils.get_connector_status_by_name(connector_name)

                start_time = ServiceUtils.get_service_start_time(connector_name)

            total_status = {
                "state": service.get_composed_status(),
                "status": connector_status,
                "startTime": start_time
            }
            status[connector_name] = total_status

        return status

    @staticmethod
    def process_start_stop(action, connectors):
        """ Process start stop and restart commands """
        err_str = None

        command_allowed = True
        if connectors and ManagementConnectorProperties.SERVICE_NAME in connectors and action == "stop":
            command_allowed = False
            # Don't allow Management Connector to be stopped.
            not_c_mgmt = "Stopping %s is not permitted." % ManagementConnectorProperties.SERVICE_NAME
            err_str = not_c_mgmt
            DEV_LOGGER.error('Detail="FMC_Websocket handle_command %s"', not_c_mgmt)

        if command_allowed:
            DEV_LOGGER.info('Detail="FMC_Websocket handle_command '
                            'process_start_stop sending action: %s to connector: %s"'
                            % (action, connectors))
            # Join the list of connector names into a string for bash request
            request_str = "%s %s" % (action, " ".join(connectors))
            DEV_LOGGER.info('Detail="FMC_Websocket handle_command writing command: %s"', request_str)
            os.system("echo '%s' > %s" % (request_str, ManagementConnectorProperties.SERVICE_CONTROL_REQUEST))  # nosec - input has been validated

        return err_str

    @staticmethod
    def process_enable_disable(action, connectors):
        """ process and enable or disable command """
        DEV_LOGGER.info('Detail="FMC_Websocket process_enable_disable: action {} params: {}"'.format(action, connectors))
        status = None
        # convert action from enable/disable to true/false
        state = None

        if action == "enable":
            state = "true"
        elif action == "disable":
            state = "false"

        if state and connectors:
            if not ManagementConnectorProperties.SERVICE_NAME in connectors:
                RemoteDispatcher.config.update_blob_entries(ManagementConnectorProperties.ENABLED_SERVICES_STATE, connectors, state)
            else:
                error_str = "Enable/Disable on {} not permitted".format(ManagementConnectorProperties.SERVICE_NAME)
                DEV_LOGGER.error('Detail="FMC_Websocket process_enable_disable {}"'.format(error_str))
                status = error_str
        else:
            error_str = "Invalid enable disable command processed. Action: {} and Params: {}".format(action, connectors)

            DEV_LOGGER.error('Detail="FMC_Websocket process_enable_disable {}"'.format(error_str))
            status = error_str

        return status

    @staticmethod
    def audit_connectors(connectors):
        """ Ensure all connectors are entitled connectors """
        error_str = None
        entitled_names = []
        entitled_services = RemoteDispatcher.config.read(ManagementConnectorProperties.ENTITLED_SERVICES)

        for service in entitled_services:
            entitled_names.append(service['name'])

        if connectors:
            for connector in connectors:
                if connector not in entitled_names:
                    error_str = "audit_connectors - not entitled for {}".format(connector)
                    DEV_LOGGER.error('Detail="FMC_Websocket {} - full list: {}"'.format(error_str, entitled_names))
                    break
        else:
            error_str = "Invalid command - parameters were expected"

        return error_str

    @staticmethod
    def send_result_to_remotedispatcher(status, command_id, command_output):
        """ Send result to remotedispatcher """
        output = ""
        if command_output:
            output = json.dumps(command_output)

        post_data = {
            "commandId": command_id,
            "status": status,
            "commandOutput": output
        }

        DEV_LOGGER.info('Detail="Send result to remotedispatcher url= %s,  data= %s"'
                        % (RemoteDispatcher.get_command_url(), json.dumps(post_data)))
        Http.patch(RemoteDispatcher.get_command_url(), RemoteDispatcher.oauth.get_header(), json.dumps(post_data))
