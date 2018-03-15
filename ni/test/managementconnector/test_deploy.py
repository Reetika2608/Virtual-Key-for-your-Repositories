
import sys

import unittest
import logging
import time
import threading
import mock

import json
import urllib2

sys.path.append("/opt/c_mgmt/bin/")
# Append all required paths to the syspath for library imports.
from ni.managementconnector.platform.libraryutils import LibraryUtils
LibraryUtils.append_library_path()

from ni.managementconnector.platform import http

from ni.managementconnector.config import jsonhandler
from ni.managementconnector.config.config import Config
from ni.managementconnector.deploy import Deploy
from ni.managementconnector.cloud.mercury import Mercury

from ni.managementconnector.deployrunner import DeployRunner

from ni.managementconnector.platform.alarms import MCAlarm
import time

EMPTY_CONFIG = False

# 1) Get bearer toeken from machine account: _get_bearer_token_for_machine_account
#   type=POST,
#   url=https://idbroker.webex.com/idb/token/4214d345-7caf-4e32-b015-34de878d1158/v1/actions/GetBearerToken/invoke,
#   headers={'Content-Type': 'application/json'},
#   data={"password": "aaBB12$9aa826c9-3d80-4b73-9c4b-d3d9a857df09", "name": "fusion-mgmnt-253508ed-e23b-4e08-a9ec-ce9f1263b3e6", "adminUser": false},
#   response = {u'BearerToken': u'BRTOKEN++'}"
# 2) Get bearer response from IDP: _get_bearer_oauth_response_from_idp
#   type=POST,
#   url=https://hercules.hitest.huron-dev.com/v1/machine_accounts,
#   headers={'Content-Type': 'application/json', 'Authorization': 'Bearer NDA1YTFiZTgtZWY5Ny00M2EyLTk1MDEtY2ZhNTViNDI4OTA0ODM4MTY0MTctM2U1'},
#   data={"session_id" : "57v6W32fVCm5cvNwOerTgJvcGYYWy9sp5d8aOpoT" },
#   response = {u'username': u'fusion-mgmnt-253508ed-e23b-4e08-a9ec-ce9f1263b3e6', u'organization_id': u'4214d345-7caf-4e32-b015-34de878d1158', u'password': u'aaBB12$9aa826c9-3d80-4b73-9c4b-d3d9a857df09', u'location': u'https://identity.webex.com/organization/4214d345-7caf-4e32-b015-34de878d1158/v1/Machines/ed643b38-076f-4447-8583-5a1ef82b13e0'}"
# 3) Get access token
#   type=POST,
#   url=https://idbroker.webex.com/idb/oauth2/v1/access_token,
#   headers={'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic QzBjZDI4M2RjNWI3ZDhiZDU5MjlhODI1MzI0Yzc0YjRkMjc1NWQxNGNmNTJlYjRiMjU2ZjlhNjNiZWMxNWZjZTg6OTE0ZjkxNjFiNTBiZjNlYjNlYzAyOTIwNjcyMzg3YjVkMmQxMTgwMzRmNDgyOGIzODExZGM5ZTUzZmVhZWE2MA=='},
#   data=grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type:saml2-bearer&assertion=BRTOKEN++&scope=Identity%3ASCIM%20Identity%3AOrganization%20squared-fusion-mgmt%3Amanagement%20%20spark%3Alogs_write,
#   response = {u'token_type': u'Bearer', u'refresh_token_expires_in': 5183999, u'access_token': u'OThmOTgyMzctZDBhMi00ZmY1LWE3ZmItMDQxNzk4NDNkOTVmOTdlYjJmY2MtZTlk', u'expires_in': 43199, u'refresh_token': u'N2NiM2I1ZjAtZDlmYi00NzRlLWFmOGMtN2YwNmJiZGNjMTkyOTlmMmMyYjUtNjk1'}"
# 4) Management Connector: Register
#   type=POST
#   url=https://hercules.hitest.huron-dev.com/v1/connectors,
#   headers={'Content-Type': 'application/json', 'Authorization': u'Bearer OThmOTgyMzctZDBhMi00ZmY1LWE3ZmItMDQxNzk4NDNkOTVmOTdlYjJmY2MtZTlk'},
#   data={"serial": "0974F8FD", "version": "X8.6PreAlpha0 (Test SW)", "cluster_id": "GUID", "cluster_name" : "cluster_name", "ip4_ip_address" : "ip_v4", "ip6_ip_address" : "ip_v6", "connector_type": "c_mgmt", "host_name": "gwydlvm1186"},
#   response = {u'status': None, u'display_name': u'Fusion Management', u'registered_by': u'14a2a40a-8f38-4866-8f1a-e6226baf42c3', u'created_at': u'2014-11-14T09:43:49.744Z', u'updated_at': u'2014-11-14T09:43:49.744Z', u'status_url': u'https://hercules.hitest.huron-dev.com/v1/connector_statuses/18', u'organization_id': u'4214d345-7caf-4e32-b015-34de878d1158', u'connector_type': u'c_mgmt', u'version': u'X8.6PreAlpha0 (Test SW)', u'cluster_id': u'', u'host_name': u'gwydlvm1186', u'provisioning_url': u'https://hercules.hitest.huron-dev.com/v1/management_connectors/3', u'serial': u'0974F8FD', u'id': 18}"

h_type = []
h_url = []
h_headers = []
h_data = []
h_response = []

# 1) Get bearer toeken from machine account: _get_bearer_token_for_machine_account
h_type.append("POST")
h_url.append("https://idbroker.webex.com/idb/token/4214d345-7caf-4e32-b015-34de878d1158/v1/actions/GetBearerToken/invoke")
h_headers.append("{'Content-Type': 'application/json'}")
h_data.append('{"password": "aaBB12$9aa826c9-3d80-4b73-9c4b-d3d9a857df09", "name": "fusion-mgmnt-253508ed-e23b-4e08-a9ec-ce9f1263b3e6", "adminUser": false}')
h_response.append({u'BearerToken': u'BRTOKEN++'})

# 2) Get bearer response from IDP: _get_bearer_oauth_response_from_idp
h_type.append("POST" )
h_url.append("https://hercules.hitest.huron-dev.com/v1/machine_accounts" )
h_headers.append("{'Content-Type': 'application/json', 'Authorization': 'Bearer NDA1YTFiZTgtZWY5Ny00M2EyLTk1MDEtY2ZhNTViNDI4OTA0ODM4MTY0MTctM2U1'}")
h_data.append('{"session_id" : "57v6W32fVCm5cvNwOerTgJvcGYYWy9sp5d8aOpoT" }')
h_response.append({u'username': u'fusion-mgmnt-253508ed-e23b-4e08-a9ec-ce9f1263b3e6', u'organization_id': u'4214d345-7caf-4e32-b015-34de878d1158', u'password': u'aaBB12$9aa826c9-3d80-4b73-9c4b-d3d9a857df09', u'location': u'https://identity.webex.com/organization/4214d345-7caf-4e32-b015-34de878d1158/v1/Machines/ed643b38-076f-4447-8583-5a1ef82b13e0'})
# 3) Get access token
h_type.append("POST" )
h_url.append("https://idbroker.webex.com/idb/oauth2/v1/access_token")
h_headers.append("{'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic QzBjZDI4M2RjNWI3ZDhiZDU5MjlhODI1MzI0Yzc0YjRkMjc1NWQxNGNmNTJlYjRiMjU2ZjlhNjNiZWMxNWZjZTg6OTE0ZjkxNjFiNTBiZjNlYjNlYzAyOTIwNjcyMzg3YjVkMmQxMTgwMzRmNDgyOGIzODExZGM5ZTUzZmVhZWE2MA=='}")
h_data.append('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type:saml2-bearer&assertion=BRTOKEN++&scope=Identity%3ASCIM%20Identity%3AOrganization%20squared-fusion-mgmt%3Amanagement%20spark%3Alogs_write')
h_response.append({u'token_type': u'Bearer', u'refresh_token_expires_in': 51839, u'access_token': u'OThmOTgyMzctZDBhMi00ZmY1LWE3ZmItMDQxNzk4NDNkOTVmOTdlYjJmY2MtZTlk', u'expires_in': 4319999, u'refresh_token': u'N2NiM2I1ZjAtZDlmYi00NzRlLWFmOGMtN2YwNmJiZGNjMTkyOTlmMmMyYjUtNjk1'})
# 4) Management Connector: Register
h_type.append("POST")
h_url.append("https://hercules.hitest.huron-dev.com/v1/connectors")
h_headers.append("{'Content-Type': 'application/json', 'Authorization': u'Bearer OThmOTgyMzctZDBhMi00ZmY1LWE3ZmItMDQxNzk4NDNkOTVmOTdlYjJmY2MtZTlk'}")
h_data.append('')
h_response.append({u'status': None, u'display_name': u'Fusion Management', u'registered_by': u'14a2a40a-8f38-4866-8f1a-e6226baf42c3', u'created_at': u'2014-11-14T09:43:49.744Z', u'updated_at': u'2014-11-14T09:43:49.744Z', u'status_url': u'https://hercules.hitest.huron-dev.com/v1/connector_statuses/18', u'organization_id': u'4214d345-7caf-4e32-b015-34de878d1158', u'connector_type': u'c_mgmt', u'version': u'X8.6PreAlpha0 (Test SW)', u'cluster_id': u'', u'host_name': u'gwydlvm1186', u'provisioning_url': u'https://hercules.hitest.huron-dev.com/v1/management_connectors/3', u'serial': u'0974F8FD', u'id': 18, u'provisioning': {u'connectors': [{u'connector_type': u'c_cal', u'version': u'8.6-1.0.521', u'display_name': u'Calendar Service', u'packages': []}]}})
# 5) Management Connector: Register (Bad Packages)
h_type.append("POST")
h_url.append("https://hercules.hitest.huron-dev.com/wrongpackages")
h_headers.append("{'Content-Type': 'application/json', 'Authorization': u'Bearer OThmOTgyMzctZDBhMi00ZmY1LWE3ZmItMDQxNzk4NDNkOTVmOTdlYjJmY2MtZTlk'}")
h_data.append('')
h_response.append({u'status': None, u'display_name': u'Fusion Management', u'registered_by': u'14a2a40a-8f38-4866-8f1a-e6226baf42c3', u'created_at': u'2014-11-14T09:43:49.744Z', u'updated_at': u'2014-11-14T09:43:49.744Z', u'status_url': u'https://hercules.hitest.huron-dev.com/v1/connector_statuses/18', u'organization_id': u'4214d345-7caf-4e32-b015-34de878d1158', u'connector_type': u'c_mgmt', u'version': u'X8.6PreAlpha0 (Test SW)', u'cluster_id': u'', u'host_name': u'gwydlvm1186', u'provisioning_url': u'https://hercules.hitest.huron-dev.com/v1/management_connectors/3', u'serial': u'0974F8FD', u'id': 18, u'provisioning': {u'connectors': [{u'connector_type': u'c_cal', u'version': u'8.6-1.0.521', u'display_name': u'Calendar Service', u'packages': [{u'tlp_url': u'https://aaa.bbb.ccc'}]}]}})

EXPECTED_NUMBER_OF_UPDATES = 5
number_of_status_updates = 0
install_executing = False
stop_install = False
install_semaphore = threading.Semaphore(1)
deploy_global = None

def _http_request(url, headers, data, request_type, silent=False, schema=None, load_validate_json=True):
    ''' used for mock test intercept'''
    http.DEV_LOGGER.info('***TEST _http_request: url=%s, data=%s, request_type=%s' % (url, data, request_type))
    # urllib2.urlopen(req)
    for i in range(len(h_type)):
        #http.DEV_LOGGER.info('***TEST _http_request: i=%s, url=%s, data=%s, request_type=%s' % (i, h_url[i], h_data[i], h_type[i]))
        if "/v1/connectors" in url:
            indata = json.loads(data)
            if indata["status"] is not None:
                global number_of_status_updates
                number_of_status_updates = number_of_status_updates  + 1
                return h_response[3]
            if indata["connector_type"] == "c_mgmt" :
                return h_response[3]
            if indata["connector_type"] == "c_xyz":
                return h_response[3]
        elif url == h_url[i] and data == h_data[i] and request_type == h_type[i]:
            # ignore hreaders and headers == h_headers[i]
            http.DEV_LOGGER.info('***TEST _http_request: h_response[i]=%s***' % (h_response[i]))
            return h_response[i]
    http.DEV_LOGGER.info('***TEST Error, could not find url %s in h_urls =%s***' % (url, h_url))
    #http.DEV_LOGGER.info('***TEST Error, could not find h_data=%s***' % h_data)


class MockAlarm():
    def __init__(self):
        self._alarms = []
        self.alarm_lock = threading.Lock()

    def clear_alarm(self, guid):
        if self.is_raised(guid):
            self._alarms.remove(guid)

    def is_raised(self, guid):
        return guid in self._alarms

    def raise_alarm(self, guid, params=None):
        if not self.is_raised(guid):
            self._alarms.append(guid)


def get_wrong_server_packages(self):
    """Return a TLP Config with an invalid URL """

    http.DEV_LOGGER.info('get_wrong_server_packages')

    connectors_config = []


    connectors_config.append({'connector_type': "c_xyz",
                            'version': "version",
                            'display_name' : 'xyz_display_name',
                            'name': "c_xyz", 'url': 'http://www.dsdsadsaudvs_bad_address.com', 'enabled': 'false'
                            })

    return connectors_config


def get_wrong_tlp_path_packages(self):
    """Return a TLP Config with an invalid URL """

    http.DEV_LOGGER.info('get_wrong_tlp_path_packages')


    connectors_config = []


    connectors_config.append({'connector_type': "c_xyz",
                            'version': "version",
                            'display_name' : 'xyz_display_name',
                            'name': "c_xyz", 'url': 'http://www.google.com/Edge/CAFE/Upgrade/hello_8-6-1.1234a.tlp', 'enabled': 'false'
                            })

    return connectors_config


def mock_get_config(self):
    """ Get config from JSON file """
    return { "config": {
        "errorPollTime": "60",
        "pollTime": "30",
        "registerUrl": "/v1/connectors" },
        "certs": {
           "ca" :"/mnt/harddisk/current/fusion/certs/fusion_ca.pem"
        },
        "system": {
            "ipv4Address": "10.53.56.182",
            "ipv6Address": "",
            "hostname" : "gwydlvm340",
            "clusterName" : "clustername",
            "clusterId" : "guid",
            "serialNumber" : "0E4D1FA5",
            "version" : "X8.6PreAlpha0 (Test SW)"
        },
        "alarms":{"raised" : []},
        "oauth": {
        "idpHost": "idbroker.webex.com",
        "atlasUrlPrefix" : "https://hercules.hitest.huron-dev.com",
        "clientId": "C0cd283dc5b7d8bd5929a825324c74b4d2755d14cf52eb4b256f9a63bec15fce8",
        "clientSecret": "914f9161b50bf3eb3ec02920672387b5d2d118034f4828b3811dc9e53feaea60"},        
        "oauthMachineAccountDetails" : {"username": "fusion-mgmnt-cbe0b5de-afb7-4a10-8fed-b57f3e0d5941", "organization_id": "4214d345-7caf-4e32-b015-34de878d1158", "password": "{cipher}oVrpg5PojgkbTkeo/zZven4unYXuAySG1maxmy63quZFWhx/zo/1c9p0ZuoYu4xMVhfuOZc/XTSSOKcwGodATw==", "location": "https://identity.webex.com/organization/4214d345-7caf-4e32-b015-34de878d1158/v1/Machines/5ddfa042-7c46-481b-a4d4-192c1866b119"},
         }

def mock_deploy_fusion(self):
    http.DEV_LOGGER.info('+++++ mock_deploy_fusion')

    global deploy_global
    mc_type = 'c_mgmt'

    for _ in xrange(EXPECTED_NUMBER_OF_UPDATES):
        http.DEV_LOGGER.info('+++++ call _do_register_config_status')
        try:
            deploy_global._do_register_config_status(mc_type)
        finally:
            poll_time = 0.5
            http.DEV_LOGGER.debug('Detail="sleep for %.1f seconds"' % poll_time)
            time.sleep(poll_time)
    
    http.DEV_LOGGER.info('+++++ completed mock_deploy_fusion')

def mock_upgrade_worker(config):
    with install_semaphore:
        if not stop_install:
            global install_executing
            install_executing = True
            long_install_duration = 4
            http.DEV_LOGGER.debug('Detail="sleep %d seconds - as if updating/installing takes long"' % long_install_duration)
            time.sleep(long_install_duration)

def join_install_thread():
    for thread in threading.enumerate():
        if thread.getName() == 'InstallThread':
            http.DEV_LOGGER.info('joining %s', thread.getName())
            thread.join()
            break

class DeployTest(unittest.TestCase):
    """ Deploy HTTP Test Class """

    def setUp(self):
        """ Deploy Test Setup """
        http.DEV_LOGGER.info('***TEST Setup***')
        self._oauth = mock.MagicMock()
        token = {
            "time_read": int(round(time.time())),
            "access_token": "{cipher}QWwtf67eHcrF2QCHbpk3BlLAyBagodUwQhJni7uLQ417BI+FHp7L0oyE9qwPaJ5MhY6iyzhW9f2Ov0EyPMGSoccXcQeoynJMy3KN2D3Iwew=",
            "expires_in": 51839, "refresh_token_expires_in": 4319999, "token_type": "Bearer", "refresh_time_read": 1416391399,
            "refresh_token": "{cipher}bpp50WRjhWge0kHEDRNI4A3PpZ6p2cpjaLcevyxwIGaaOPSQcYLztX1CsSNDtEoYArlAkyq7g583kQrgFrutxSe4Zlsk4FmrGWDI2ss2V+4="
        }
        self._oauth._get_oauth_resp_from_idp.return_value = token
        self._oauth.get_access_token.return_value = token['access_token']


    def test_long_install_and_status_update(self):
        http.DEV_LOGGER.info('+++++ test_long_install_and_status_update')
        global number_of_status_updates
        number_of_status_updates = 0
        global install_executing
        global deploy_global
        install_executing = False

        _orig_http_request = http._http_request
        http._http_request = _http_request

        _orig__get_config = jsonhandler._get_config
        jsonhandler._get_config = mock_get_config

        config = Config()
        deploy_global = Deploy(config)
        deploy_global._alarms = MockAlarm()
        deploy_global._oauth = self._oauth
        deploy_global._mercury_connection = Mercury(config, deploy_global._oauth)
        deploy_global._service_manager._alarms = MockAlarm()

        _orig_deploy_get_config = deploy_global._get_config
        deploy_global._get_config = get_wrong_tlp_path_packages

        orig_deploy_fusion = deploy_global.deploy_fusion
        deploy_global.deploy_fusion = mock_deploy_fusion

        _orig_upgrade_worker = deploy_global._service_manager.upgrade_worker
        deploy_global._service_manager.upgrade_worker = mock_upgrade_worker

        deploy_global._oauth_init = False

        deploy_global.deploy_fusion(deploy_global)

        self.assertTrue(install_executing)
        # The test sets up two connectors (c_mgmt & c_xyz) and loops to EXPECTED_NUMBER_OF_UPDATES(5)
        # each time posting a status update for each connector.
        self.assertEquals(number_of_status_updates, EXPECTED_NUMBER_OF_UPDATES * 2)

        global stop_install
        stop_install = True

        http._http_request  = _orig_http_request
        deploy_global.deploy_fusion = orig_deploy_fusion
        deploy_global._get_config = _orig_deploy_get_config
        deploy_global._service_manager.upgrade_worker = _orig_upgrade_worker
        http.DEV_LOGGER.info('+++++ completed test_deploy_fusion')


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
