""" Atlas """

import json

from managementconnector.platform.http import Http
from managementconnector.platform.system import System
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config.versionchecker import get_expressway_full_version
from managementconnector.platform.serviceutils import ServiceUtils
from managementconnector.cloud import schema
from managementconnector.config import jsonhandler

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class Atlas(object):
    """ Management Connector Atlas Class """

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Management Connector Atlas Class'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self, config_handler):
        """ Atlas __init__  """

        self._config = config_handler
        self._full_version = get_expressway_full_version()

    @staticmethod
    def parse_dependency_config(register_response):
        """
            Reads any config for dependency TLPs
        """

        dependency_config = []

        if 'dependencies' in register_response:
            for dependency in register_response['dependencies']:

                version = dependency['version']
                name = dependency['dependencyType']
                url = dependency['tlpUrl']
                packages_exist = url is not None and len(url.strip()) > 0

                # Added Display Name for Alarm Handling, Dependency is just to distinguish for connector config
                dependency_config.append({'version': version, 'name': name, 'display_name': name, 'url': url,
                                          'dependency': 'true', 'allow_upgrade': packages_exist})

        DEV_LOGGER.debug('Detail="parse_dependency_config: dependency_config=%s"', dependency_config)

        return dependency_config
    # -------------------------------------------------------------------------

    @staticmethod
    def parse_mc_config(register_response):
        """
            parse Atlas formatted config into ManagementConnector format
            This method extracts the latest version and name from the tlp_url
            input format = {u'connectors': [{u'connector_type': u'expressway_csi', u'version': u'8.5-1.0',
            u'packages':[{u'tlp_url': u'ftp://10.53.63.198/Edge/CSI/master/demo/csi.tlp'}], u'enabled': False}]}
        """

        connectors_config = []
        entitled_config = []

        if 'connectors' in register_response:
            for connector in register_response['connectors']:

                display_name = connector['display_name']

                latest = None
                version = -1

                if connector['version'] > version:
                    version = connector['version']
                    latest = connector
                if(connector['connector_type'] in ManagementConnectorProperties.SERVICE_LIST):
                    connector['connector_type'] = ManagementConnectorProperties.SERVICE_NAME

                name = connector['connector_type']
                packages_exist = len(connector['packages']) > 0
                if packages_exist:
                    url = latest['packages'][0]['tlp_url']
                else:
                    # Case where there was no package included with connector
                    DEV_LOGGER.info('Detail="_parse_mc_config: package not entitled to upgrade as no package info '
                                    'for %s"', connector['connector_type'])
                    url = ''

                # Server enable flag removed, and set to false
                # This is left to support future enhancement of enablement from cloud.
                connectors_config.append({'connector_type': connector['connector_type'],
                                          'version': version, 'display_name': display_name,
                                          'name': name, 'url': url, 'enabled': 'false',
                                          'allow_upgrade': packages_exist 
                                          })

                entitled_config.append({'name': name, 'display_name': display_name})

        DEV_LOGGER.debug('Detail="_parse_mc_config: ret = %s, entitled_config=%s"' %
                         (connectors_config, entitled_config))

        Atlas._order_connectors(connectors_config)

        return connectors_config, entitled_config

    # -------------------------------------------------------------------------

    @staticmethod
    def _order_connectors(connectors_config):
        """ Order the connectors appropriately """
        # Management Connector should be first in the download sequence.
        try:
            c_mgmt_index = next(index for (index, item) in enumerate(connectors_config) if item["name"] ==
                                ManagementConnectorProperties.SERVICE_NAME)
            if c_mgmt_index != 0:
                c_mgmt = connectors_config.pop(c_mgmt_index)
                connectors_config.insert(0, c_mgmt)
        except StopIteration:
            DEV_LOGGER.info('Detail="%s did not exist in the connectors config."',
                            ManagementConnectorProperties.SERVICE_NAME)


    def _get_post_request_data(self, service):
        """ used by Register a connector, returns json which will be posted to FMS per connector """
        service_name = service.get_name()

        device_type = self._config.read(ManagementConnectorProperties.TARGET_TYPE)
        serial_number = self._config.read(ManagementConnectorProperties.SERIAL_NUMBER)
        cluster_name = self._config.read(ManagementConnectorProperties.CLUSTER_NAME)
        cluster_id = self._config.read(ManagementConnectorProperties.CLUSTER_ID)
        ip_v4 = self._config.read(ManagementConnectorProperties.IPV4_ADDRESS)
        ip_v6 = self._config.read(ManagementConnectorProperties.IPV6_ADDRESS)
        domain_name = self._config.read(ManagementConnectorProperties.DOMAINNAME)
        host_name = self._config.read(ManagementConnectorProperties.HOSTNAME)
        if service.get_name() in ManagementConnectorProperties.SERVICE_LIST:
            heartbeat_contents = jsonhandler.read_json_file(
                ManagementConnectorProperties.UPGRADE_HEARTBEAT_FILE % (device_type, device_type))
        else:
            heartbeat_contents = jsonhandler.read_json_file(
                ManagementConnectorProperties.UPGRADE_HEARTBEAT_FILE % (device_type, service_name))
        sys_mem = System.get_system_mem()
        sys_disk = System.get_system_disk()
        platform_type = System.get_platform_type()
        cpus = System.get_cpu_cores()

        connector_status = {}
        if service.get_composed_status() == 'running':
            # Update the Metrics
            service.update_service_metrics()
            connector_status = ServiceUtils.get_connector_status(service)
            if service_name is ManagementConnectorProperties.SERVICE_NAME and System.am_i_master():
                connector_status["clusterSerials"] = self._config.read(ManagementConnectorProperties.CLUSTER_SERIALS)

            if service_name is ManagementConnectorProperties.SERVICE_NAME:
                if heartbeat_contents:
                    try:
                        connector_status["maintenanceMode"] = heartbeat_contents['provisioning']['maintenanceMode']
                    except KeyError:
                        connector_status["maintenanceMode"] = "off"
                else:
                    connector_status["maintenanceMode"] = "off"

            start_time = ServiceUtils.get_service_start_time(service_name)
        else:
            DEV_LOGGER.debug('Detail="post_status: service %s is not running"', service.get_name())
            start_time = ''

        if host_name is not None and host_name != '' and domain_name is not None and domain_name != '':
            host_name = host_name + '.' + domain_name

        status = {"state": service.get_composed_status(),
                  "alarms": ServiceUtils.get_alarms(service, ServiceUtils.get_alarm_url_prefix(self._config),
                                                    include_suppressed=False),
                  "connectorStatus": connector_status,
                  "startTimestamp": start_time
                  }

        host_hardware = {"cpus": cpus,
                        "totalMemory": str(long(sys_mem['total_kb']) * 1024),
                        "totalDisk": str(long(sys_disk['total_kb']) * 1024),
                        "hostType": platform_type

                       }

        if (device_type != ManagementConnectorProperties.SERVICE_NAME and service_name == ManagementConnectorProperties.SERVICE_NAME):
            device_type = device_type
        else:
            device_type = service_name

        version = ServiceUtils.get_version(service_name)
        if version is None:
            version = 'None'

        post_data = {"id": device_type + "@" + serial_number,
                     "cluster_id": cluster_id,
                     "cluster_name": cluster_name,
                     "host_name": host_name,
                     "ip4_ip_address": ip_v4,
                     "ip6_ip_address": ip_v6,
                     "serial": serial_number,
                     "connector_type":  device_type,
                     "version": version,
                     "platform": "expressway",
                     "platform_version": self._full_version,
                     "status": status,
                     "hostHardware": host_hardware}

        DEV_LOGGER.debug('Detail="_get_post_request_data: %s"', post_data)

        return post_data

    def register_connector(self, header, service):
        """ Register a connector, returns provisioning data """
        register_url = self._config.read(ManagementConnectorProperties.REGISTER_URL)
        atlas_url_prefix = self._config.read(ManagementConnectorProperties.ATLAS_URL_PREFIX)
        device_type = self._config.read(ManagementConnectorProperties.TARGET_TYPE)
        full_url = atlas_url_prefix + register_url

        response = Http.post(full_url, header, json.dumps(self._get_post_request_data(service)),
                             schema=schema.MANAGEMENT_CONNECTOR_REGISTER_RESPONSE)

        Atlas._write_heatbeat_to_disk(device_type, service, response)

        try:
            # Only the Mgmt. Connector has Provisioning Info
            if service.get_name() in ManagementConnectorProperties.SERVICE_LIST:
                self._configure_heartbeat(response['provisioning']['heartbeatInterval'])
        except KeyError, error:
            DEV_LOGGER.debug('Detail="register_connector: No heartbeat interval information, missing key: %s"', error)

        return response

    # -------------------------------------------------------------------------

    @staticmethod
    def _write_heatbeat_to_disk(device_type, service, heartbeat):
        """ Write connector heartbeat response out to disk """
        service_name = service.get_name()

        if service.get_name() in ManagementConnectorProperties.SERVICE_LIST:
            jsonhandler.write_json_file(
                ManagementConnectorProperties.UPGRADE_HEARTBEAT_FILE % (device_type, device_type),
                heartbeat)
        else:
            jsonhandler.write_json_file(
                ManagementConnectorProperties.UPGRADE_HEARTBEAT_FILE % (device_type, service_name),
                heartbeat)

    # -------------------------------------------------------------------------

    def _configure_heartbeat(self, heartbeat_interval):
        """Configure the heartbeat interval"""
        DEV_LOGGER.debug('Detail="_configure_heartbeat:  %s"', heartbeat_interval)
        if int(self._config.read(ManagementConnectorProperties.POLL_TIME)) != heartbeat_interval:
            DEV_LOGGER.info('Detail="_configure_heartbeat update db with new value: %s"', heartbeat_interval)
            self._config.write_blob(ManagementConnectorProperties.POLL_TIME, heartbeat_interval)
        else:
            DEV_LOGGER.debug('Detail="_configure_heartbeat value is same, no need for db update"')
