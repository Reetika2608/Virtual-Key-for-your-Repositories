""" Class to Manage U2C Retrieval """
import json
from urlparse import urlsplit
from managementconnector.cloud import schema
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.platform.http import Http
DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class U2C(object):
    """ U2C Class """

    # Map service name to cdb entry
    service_map = {"atlas": ManagementConnectorProperties.U2C_ATLAS,
                   "wdm": ManagementConnectorProperties.U2C_WDM,
                   "metrics": ManagementConnectorProperties.U2C_METRICS,
                   "remoteDispatcher": ManagementConnectorProperties.U2C_RD,
                   "feature": ManagementConnectorProperties.U2C_FEATURE,
                   "idbroker": ManagementConnectorProperties.U2C_IDBROKER,
                   "identity": ManagementConnectorProperties.U2C_IDENTITY,
                   "fms": ManagementConnectorProperties.U2C_FMS,
                   "atlasFusionAdminPortal": ManagementConnectorProperties.U2C_ADMIN_PORTAL}

    def __init__(self, config, oauth):
        """ Constructor """
        self._config = config
        self._oauth = oauth

    def update_user_catalog(self):
        """ Update any service in the U2C User URL List"""
        DEV_LOGGER.debug('Detail="FMC_U2C update_user_catalog: updating user catalog"')
        host = self._config.read(ManagementConnectorProperties.U2C_HOST)
        user_url = self._config.read(ManagementConnectorProperties.U2C_USER_SERVICE_URL)
        service_catalogs = Http.get(host + user_url, headers=self._oauth.get_header(), schema=schema.U2C_SERVICES_RESPONSE)
        U2C.process_catalog(self._config, service_catalogs["services"])

    @staticmethod
    def process_catalog(config, catalog):
        """ Process the catalog returned and update the config with the value"""
        DEV_LOGGER.debug('Detail="FMC_U2C process_catalog: processing response from U2C"')

        for service_entry in catalog:
            if service_entry["serviceName"] in U2C.service_map:
                url = service_entry["logicalNames"][0]

                # if the url is fms then the path needs to be stripped                
                if service_entry["serviceName"] == "fms":
                    parsed_url = urlsplit(url)
                    url = parsed_url.scheme + "://" + parsed_url.netloc

                config.write(U2C.service_map[service_entry["serviceName"]], {"value": json.dumps(url)})
