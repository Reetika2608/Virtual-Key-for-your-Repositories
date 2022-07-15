""" Class to Manage U2C Retrieval """
import json
from urllib.parse import urlsplit

from managementconnector.cloud import schema
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

SERVICE_PREFIX = "&services="

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class U2C(object):
    """ U2C Class """

    # Map service name to cdb entry
    service_map = {"clientLogs": ManagementConnectorProperties.U2C_CLIENT_LOGS,
                   "wdm": ManagementConnectorProperties.U2C_WDM,
                   "metrics": ManagementConnectorProperties.U2C_METRICS,
                   "remoteDispatcher": ManagementConnectorProperties.U2C_RD,
                   "feature": ManagementConnectorProperties.U2C_FEATURE,
                   "fms": ManagementConnectorProperties.U2C_FMS,
                   "atlasFusionAdminPortal": ManagementConnectorProperties.U2C_ADMIN_PORTAL,
                   "ucmgmt-controller":ManagementConnectorProperties.U2C_UCMGMT_CONTROLLER_HOST,
                   "ucmgmt-gateway": ManagementConnectorProperties.U2C_UCMGMT_GATEWAY_HOST,
                   "ucmgmt-licensing": ManagementConnectorProperties.U2C_UCMGMT_LICENSING_HOST,
                   "ucmgmt-migration": ManagementConnectorProperties.U2C_UCMGMT_MIGRATION_HOST,
                   "ucmgmt-telemetry-mgmt": ManagementConnectorProperties.U2C_UCMGMT_TELEMETRY_MGMT_HOST,
                   "ucmgmt-upgrade": ManagementConnectorProperties.U2C_UCMGMT_UPGRADE_HOST,
                   "ucmgmt-web": ManagementConnectorProperties.U2C_UCMGMT_WEB_HOST,
                   "idbroker": ManagementConnectorProperties.U2C_IDBROKER,
                   "identity": ManagementConnectorProperties.U2C_IDENTITY}

    def __init__(self, config, oauth, http, database):
        self._http = http
        self._config = config
        self._oauth = oauth
        self._database_handler = database
        self._identity_and_u2c_host_check = False

    def update_user_catalog(self, header=None, check_config=False):
        """ Update any service in the U2C User URL List"""
        DEV_LOGGER.info('Detail="FMC_U2C update_user_catalog: updating user catalog"')
        host = self._config.read(ManagementConnectorProperties.U2C_HOST)
        if isinstance(host, dict):  # Workaround for SPARK-91437: If the u2c url was NOT set, we wrote the wrong value to the DB
            host = host["value"].replace('"', '').replace('\\', '')

        try:
            if header is None:
                header = self._oauth.get_header()
            # fetch complete service catalog
            user_service_url = self._config.read(ManagementConnectorProperties.U2C_USER_SERVICE_URL)
            u2c_url = host + user_service_url + SERVICE_PREFIX + self.build_services_list(self.service_map)
            service_catalogs = self._http.get(u2c_url, headers=header, schema=schema.U2C_SERVICES_RESPONSE)
        except:  # pylint: disable=W0703
            # an edge scenario if the tokens are invalid during restart
            # todo: refactor for better code reuse
            # fetch limited service catalog without auth
            DEV_LOGGER.info('Detail="FMC_U2C update_user_catalog: Fetching limited service catalog without auth"')
            user_service_url = self._config.read(ManagementConnectorProperties.U2C_LIMITED_SERVICE_URL)
            org_id = self._config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)['organization_id']
            u2c_url = host + user_service_url + org_id
            header = dict()
            header['Content-Type'] = 'application/json'
            service_catalogs = self._http.get(u2c_url, headers=header, schema=schema.U2C_SERVICES_RESPONSE)

        self.process_catalog(self._config, service_catalogs["services"])

        if not self._identity_and_u2c_host_check:
            self._check_identity_url(service_catalogs["services"])
            self._check_u2c_host_url(host)
            self._identity_and_u2c_host_check = True

        # post u2c refresh, ensure config file is updated to avoid stale data
        is_config_updated = self._config.check_config_update(ManagementConnectorProperties.IDP_HOST,
                                                             ManagementConnectorProperties.U2C_IDB_HOST)
        if check_config:
            return is_config_updated

    @staticmethod
    def build_services_list(map):
        return ",".join(sorted(map.keys()))

    def process_catalog(self, config, catalog):
        """ Process the catalog returned and update the config with the value"""
        DEV_LOGGER.debug('Detail="FMC_U2C process_catalog: processing response from U2C"')

        for service_entry in catalog:
            if service_entry["serviceName"] in U2C.service_map:
                url = service_entry["logicalNames"][0]

                # if the url is fms then the path needs to be stripped                
                if service_entry["serviceName"] == "fms":
                    parsed_url = urlsplit(url)
                    url = parsed_url.scheme + "://" + parsed_url.netloc

                # if the url is identity then update machine account identity url
                if service_entry["serviceName"] == "identity":
                    self._update_oauth_identity_url(identity_url=url)

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
        if not u2c_host_url or u2c_host_url == "" or "value" in u2c_host_url:
            DEV_LOGGER.info(
                'Detail="FMC_U2C populate U2C host URL: Setting U2C host to default value from template: %s"' % host)
            self._config.write_blob(ManagementConnectorProperties.U2C_HOST, host)

    def _update_oauth_identity_url(self, identity_url):
        """ Update Oauth Machine Account Identity URL """
        DEV_LOGGER.info('Detail="FMC_U2C _update_oauth_identity_url: Updating Oauth Machine Account Identity URL"')

        # Fetch Oauth Machine Account Details from DB
        machine_response = self._config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)
        machine_response_copy = machine_response.copy()

        # Parse and update the identity url
        parsed_identity_url = urlsplit(identity_url)
        parsed_oauth_identity_url = urlsplit(machine_response_copy["location"])
        if parsed_identity_url.scheme and parsed_identity_url.hostname:
            machine_response_copy["location"] = "{0}://{1}{2}".format(parsed_identity_url.scheme,
                                                                      parsed_identity_url.hostname,
                                                                      parsed_oauth_identity_url.path)
            self._config.write_blob(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS,
                                    machine_response_copy)
            DEV_LOGGER.info(
                'Detail="FMC_U2C _update_oauth_identity_url: URL = %s."' % machine_response_copy["location"])
        else:
            DEV_LOGGER.error(
                'Detail="FMC_U2C _update_oauth_identity_url: Cannot Parse Identity URL = %s."' % identity_url)
