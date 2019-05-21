""" Class to Manage U2C Retrieval """
import json
from urlparse import urlsplit

from managementconnector.cloud import schema
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

SERVICE_PREFIX = "&services="

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class U2C(object):
    """ U2C Class """

    # Map service name to cdb entry
    service_map = {"atlas": ManagementConnectorProperties.U2C_ATLAS,
                   "wdm": ManagementConnectorProperties.U2C_WDM,
                   "metrics": ManagementConnectorProperties.U2C_METRICS,
                   "remoteDispatcher": ManagementConnectorProperties.U2C_RD,
                   "feature": ManagementConnectorProperties.U2C_FEATURE,
                   "fms": ManagementConnectorProperties.U2C_FMS,
                   "atlasFusionAdminPortal": ManagementConnectorProperties.U2C_ADMIN_PORTAL}

    def __init__(self, config, oauth, http, database):
        self._http = http
        self._config = config
        self._oauth = oauth
        self._database_handler = database
        self._identity_and_u2c_host_check = False

    def update_user_catalog(self):
        """ Update any service in the U2C User URL List"""
        DEV_LOGGER.debug('Detail="FMC_U2C update_user_catalog: updating user catalog"')
        host = self._config.read(ManagementConnectorProperties.U2C_HOST)
        user_service_url = self._config.read(ManagementConnectorProperties.U2C_USER_SERVICE_URL)
        service_catalogs = self._http.get(
            host + user_service_url + SERVICE_PREFIX + self.build_services_list(self.service_map),
            headers=self._oauth.get_header(),
            schema=schema.U2C_SERVICES_RESPONSE)
        U2C.process_catalog(self._config, service_catalogs["services"])

        if not self._identity_and_u2c_host_check:
            self._check_identity_url(service_catalogs["services"])
            self._check_u2c_host_url(host)
            self._identity_and_u2c_host_check = True

    def build_services_list(self, map):
        return ",".join(sorted(map.keys()))

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

    def _check_identity_url(self, catalog):
        """ Audit the identity URL directly in CDB. Populate it from U2C if it is missing """
        identity_url = self._database_handler.read(ManagementConnectorProperties.U2C_IDENTITY_HOST)
        if not identity_url or identity_url == "":
            DEV_LOGGER.info('Detail="FMC_U2C populate_identity_url: getting identity URL from U2C"')
            for service_entry in catalog:
                if service_entry["serviceName"] == "identity":
                    url = service_entry["logicalNames"][0]
                    self._config.write(ManagementConnectorProperties.U2C_IDENTITY, {"value": json.dumps(url)})

    def _check_u2c_host_url(self, host):
        """ Read the U2C URL directly from CDB. Populate it with the default from the template, if it is missing """
        u2c_host_url = self._database_handler.read(ManagementConnectorProperties.U2C_HOST)
        if not u2c_host_url or u2c_host_url == "":
            DEV_LOGGER.info(
                'Detail="FMC_U2C populate U2C host URL: Setting U2C host to default value from template: %s"' % host)
            self._config.write_blob(ManagementConnectorProperties.U2C_HOST, {"value": json.dumps(host)})
