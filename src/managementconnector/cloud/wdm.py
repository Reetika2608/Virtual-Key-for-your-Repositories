""" Device Manager """

import json
import os
import traceback
import time

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.config import jsonhandler
from managementconnector.platform.http import Http

from managementconnector.cloud import schema

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class DeviceManager(object):
    """ Management Connector DeviceManager """

    @staticmethod
    #---------------------------------------------------
    def register(header, config, force_create):
        """ Register FMC with WDM - Based on Calendar Connector  """

        try:

            if force_create:
                # Full Registration
                DeviceManager.deregister_from_wdm(header)

                device_details = DeviceManager.register_with_wdm(header, config)

            else:
                # Registration Refresh
                device_details = DeviceManager.refresh_with_wdm(header, config)

            return device_details

        except Exception as error: # pylint: disable=W0703
            DEV_LOGGER.error('Detail="FMC_Websocket Registration Exception occurred:%s, stacktrace=%s"' % (repr(error), traceback.format_exc()))

            DeviceManager.remove_mercury_config_from_disk()

            raise error

    @staticmethod
    #---------------------------------------------------
    def register_with_wdm(header, config):
        """ Register FMC with WDM """

        wdm_data = DeviceManager.get_registration_data(config)

        DEV_LOGGER.debug('Detail="FMC_Websocket WDM Registration"')

        wdm_url = DeviceManager.get_wdm_url(config)

        response = Http.post(wdm_url, header, json.dumps(wdm_data), schema=schema.WDM_RESPONSE)

        wdm_device = response['url']
        web_socket_url = response['webSocketUrl']

        time_refreshed = int(round(time.time()))

        # Useful to write out connection details for End-End Testing
        DeviceManager.write_mercury_config_to_disk(wdm_device.split('/')[-1], wdm_device, time_refreshed)

        DEV_LOGGER.info('Detail="FMC_Websocket WDM Device Info - WebSocketURL: %s. DeviceID: %s"' % (web_socket_url, wdm_device))

        return {"device_url": wdm_device, "ws_url": web_socket_url,  "last_refreshed" : time_refreshed}


    #---------------------------------------------------
    @staticmethod
    def refresh_with_wdm(header, config):
        """ Refresh FMC with WDM """

        json_content = jsonhandler.read_json_file(ManagementConnectorProperties.MERCURY_FILE % ManagementConnectorProperties.SERVICE_NAME)

        wdm_data = DeviceManager.get_registration_data(config)

        if json_content:

            DEV_LOGGER.info('Detail="FMC_Websocket WDM Re-Registration"')

            device_id = json_content["route"]

            wdm_url = DeviceManager.get_wdm_url(config) + "/" + device_id

            response = Http.put(wdm_url, header, json.dumps(wdm_data), schema=schema.WDM_RESPONSE)

            wdm_device = response['url']
            web_socket_url = response['webSocketUrl']

            # TIme of refresh - used for testing
            time_refreshed = int(round(time.time()))

            DeviceManager.write_mercury_config_to_disk(wdm_device.split('/')[-1], wdm_device, time_refreshed)

            DEV_LOGGER.info('Detail="FMC_Websocket Refreshed WDM Device Info - WebSocketURL: %s. DeviceID: %s"' % (web_socket_url, wdm_device))

            return {"device_url": wdm_device, "ws_url": web_socket_url,  "last_refreshed": time_refreshed}
        else:
            raise Exception("Empty or Missing Mercury File, path: %s" % ManagementConnectorProperties.MERCURY_FILE
                            % ManagementConnectorProperties.SERVICE_NAME)

    # -------------------------------------------------------------------------
    @staticmethod
    def get_registration_data(config):
        """ Data Needed to Register with WDM """

        ip_v4 = config.read(ManagementConnectorProperties.IPV4_ADDRESS)
        host_name = config.read(ManagementConnectorProperties.HOSTNAME)
        domain_name = config.read(ManagementConnectorProperties.DOMAINNAME)

        if host_name and domain_name:
            identity = host_name + "." + domain_name
        else:
            identity = ip_v4

        wdm_data = {
            "deviceType": ManagementConnectorProperties.DEVICE_TYPE,
            "name": ManagementConnectorProperties.SERVICE_NAME + "." + config.read(ManagementConnectorProperties.SERIAL_NUMBER),
            "model": identity,
            "localizedModel": identity,
            "systemName": identity,
            "systemVersion": config.read(ManagementConnectorProperties.VERSION),
            "isDeviceManaged": False
        }

        return wdm_data


    # -------------------------------------------------------------------------
    @staticmethod
    def deregister_from_wdm(header):
        """ Unregister FMC from WDM """
        # If check should prevent deregistatration from happending more than once
        if os.path.isfile(ManagementConnectorProperties.MERCURY_FILE % ManagementConnectorProperties.SERVICE_NAME):

            DEV_LOGGER.info('Detail="FMC_Websocket DeRegistering with WDM"')

            try:

                wdm_device = jsonhandler.read_json_file(ManagementConnectorProperties.MERCURY_FILE % ManagementConnectorProperties.SERVICE_NAME)['device_url']

                Http.delete(wdm_device, header)

            finally:
                DeviceManager.remove_mercury_config_from_disk()

        else:
            DEV_LOGGER.debug('Detail="FMC_Websocket DeRegistered Previously"')

    # -------------------------------------------------------------------------
    @staticmethod
    def write_mercury_config_to_disk(device_id, device_url, time_refreshed):
        """ Write Mercury Information out to disk """

        mercury_data = {"route": device_id, "device_url" : device_url, "last_refreshed": time_refreshed }

        jsonhandler.write_json_file(ManagementConnectorProperties.MERCURY_FILE % ManagementConnectorProperties.SERVICE_NAME,
                                    mercury_data)

    # -------------------------------------------------------------------------
    @staticmethod
    def remove_mercury_config_from_disk():
        """ Remove Mercury Information from disk """
        jsonhandler.delete_file(ManagementConnectorProperties.MERCURY_FILE % ManagementConnectorProperties.SERVICE_NAME)

    # -------------------------------------------------------------------------
    @staticmethod
    def is_registered():
        """ Read Mercury Information from disk """

        rtn_value = False

        if os.path.isfile(ManagementConnectorProperties.MERCURY_FILE % ManagementConnectorProperties.SERVICE_NAME):
            rtn_value = True

        return rtn_value

    @staticmethod
    def get_wdm_url(config):
        """ build the device end-point """
        host = config.read(ManagementConnectorProperties.WDM_HOST)
        url = config.read(ManagementConnectorProperties.WDM_URL)
        return host + url