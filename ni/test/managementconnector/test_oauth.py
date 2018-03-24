""" OAuth Test """
import unittest
import sys
import logging
import mock
import io
import urllib2

sys.path.append("/opt/c_mgmt/bin/")

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.cloud.oauth import OAuth
from ni.managementconnector.config.config import Config


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()

ACCESS_TOKEN = "Access Token"
REFRESH_TOKEN = "Refresh Token"
REFRESHED_TOKEN = "Refreshed Access Token"


def config_read_side_effect(*args, **kwargs):
    """ Config Side Effect """
    if args[0] == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return {"username" : "username", "organization_id" : "org_id", "location": "somewhere", "password": "{cipher}LT4V5Hr02ejy326BWD+3TgmyS2GK6TPm6UyxxgmxgzOe96Zr52c9HOk7hKBtDeI1iob1OTTFom+bzvFXKMgPwQ==", "id": "id"}

    if args[0] == ManagementConnectorProperties.OAUTH_BASE:
        return {"idpHost" : "idpHost" , "clientId" : "clientId", "clientSecret" : "clientSecret"}

def config_read_side_effect_none(*args, **kwargs):
    """ Config Side Effect """
    if args[0] == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return None

def config_read_side_effect_exception(*args, **kwargs):
    """ Config Side Effect """
    if args[0] == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        raise

def post(url, headers, data, silent=False, schema=None):
    """ Post Side Effect """
    DEV_LOGGER.info("Post Side Effect")

    curr_time = OAuth.get_current_time()

    if "grant_type" in data:

       oauth_response = {'access_token' : REFRESHED_TOKEN, 'expires_in' : 100, 'accountExpiration' : 272,
                            'time_read' : curr_time, 'refresh_token_expires_in' : 865000,
                            'refresh_token' : REFRESH_TOKEN,
                            'refresh_time_read' : curr_time}

    elif "GetBearerToken" in url:
        oauth_response = {'BearerToken' : 'bearertoken'}

    return oauth_response

class OAuthTest(unittest.TestCase):
    """ Management Connector OAuth Test Class """

    def setUp(self):
        ''' Test Setup'''

        self.oauth = OAuth(Config())

    def tearDown(self):
        ''' Test tearDown '''

    @mock.patch('ni.managementconnector.cloud.oauth.taacrypto.decrypt_with_system_key')
    @mock.patch('ni.managementconnector.platform.http.Http.post', side_effect=post)
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_init(self, mock_config, mock_http, mock_decrypt):
        """ Test Init OAuth """

        DEV_LOGGER.info("****** test_init ******")

        mock_decrypt.return_value = "test"

        mock_config.read.side_effect = config_read_side_effect

        oauth = OAuth(mock_config)

        oauth.init()

        token = oauth.get_access_token()

        self.assertEqual(token, REFRESHED_TOKEN)

    @mock.patch('ni.managementconnector.cloud.oauth.OAuth._get_machine_details_from_json')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth._is_machine_account_cache_stale')
    def test_get_access_token(self, mock_is_machine_acc_cache_stale, mock_json_config):
        """ Get Access Token Tests """

        DEV_LOGGER.info("****** test_get_access_token ******")

        mock_is_machine_acc_cache_stale.return_value = False

        mock_json_config.return_value = {'password': 'password'}


        #Valid Token

        curr_time = OAuth.get_current_time()

        self.oauth.oauth_response = {'access_token' : ACCESS_TOKEN, 'expires_in' : 400, 'accountExpiration' : 272,
                            'time_read' : curr_time, 'refresh_token_expires_in' : 865000,
                            'refresh_time_read' : curr_time,
                            'refresh_token' : REFRESH_TOKEN}

        self.oauth.machine_response = {}

        token = self.oauth.get_access_token()

        self.assertTrue(token == ACCESS_TOKEN)

    @mock.patch('ni.managementconnector.config.config.Config.read')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth._get_machine_details_from_json')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth._is_machine_account_cache_stale')
    @mock.patch('ni.managementconnector.cloud.oauth.Http')
    def test_get_access_token_expired(self, mock_http, mock_is_machine_acc_cache_stale, mock_json_config, mock_config_read):
        """ Get Access Token Tests """

        DEV_LOGGER.info("****** test_get_access_token_expired ******")

        mock_config_read.return_value = {"clientId": "test", "clientSecret": "test", "idpHost": "test"}

        curr_time = OAuth.get_current_time()

        mock_is_machine_acc_cache_stale.return_value = False

        mock_json_config.return_value = {'password': 'password'}

        mock_http.post.return_value = {'access_token' : REFRESHED_TOKEN, 'expires_in' : 100, 'accountExpiration' : 272,
                            'time_read' : curr_time, 'refresh_token_expires_in' : 865000,
                            'refresh_token' : REFRESH_TOKEN,
                            'refresh_time_read' : curr_time}

        self.oauth.http = mock_http

        #Expired Token

        curr_time = OAuth.get_current_time()

        self.oauth.oauth_response = {'access_token' : ACCESS_TOKEN, 'expires_in' : 10, 'accountExpiration' : 272,
                            'time_read' : curr_time, 'refresh_token_expires_in' : 865000,
                            'refresh_time_read' : curr_time, 'refresh_token' : REFRESH_TOKEN}

        token = self.oauth.get_access_token()

        DEV_LOGGER.info("token = %s" %(token))

        self.assertTrue(token == REFRESHED_TOKEN)

    @mock.patch('ni.managementconnector.cloud.oauth.taacrypto.decrypt_with_system_key')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth._is_machine_account_cache_stale')
    @mock.patch('ni.managementconnector.config.config.Config')
    @mock.patch('ni.managementconnector.platform.http.Http.post', side_effect=post)
    def test_get_access_token_refresh_expired(self, mock_http, mock_config, mock_is_machine_acc_cache_stale, mock_decrypt):
        """ Get Access Token Tests """

        DEV_LOGGER.info("****** test_get_access_token_refresh_expired ******")

        mock_decrypt.return_value = "test"

        mock_config.read.side_effect = config_read_side_effect
        test_oauth = OAuth(mock_config)

        #Expired Refresh Token

        curr_time = OAuth.get_current_time()

        mock_is_machine_acc_cache_stale.return_value = False

        test_oauth.oauth_response = {'access_token' : ACCESS_TOKEN, 'expires_in' : 10, 'accountExpiration' : 272,
                            'time_read' : curr_time, 'refresh_token_expires_in' : 10,
                            'refresh_time_read' : curr_time, 'refresh_token' : REFRESH_TOKEN}

        test_oauth.machine_response = {'location' : 'some_location', 'username' : 'username', 'password' : 'password',
                                         'adminUser' : False, 'organization_id' : 'organization_id'}


        token = test_oauth.get_access_token()

        self.assertTrue(token == REFRESHED_TOKEN)

        token = test_oauth.get_access_token()
        self.assertTrue(token == REFRESHED_TOKEN)



    @mock.patch('ni.managementconnector.cloud.oauth.Http')
    def test_refresh_oauth_resp_with_idp(self, mock_http, mock_config):
        """ Get Refresh Token Tests """

        DEV_LOGGER.info("****** test_refresh_oauth_resp_with_idp ******")

        time_in_past = OAuth.get_current_time() - 100

        test_oauth = OAuth(mock_config)
        mock_config.read.side_effect = config_read_side_effect

        test_oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        test_oauth.machine_response = {'location': "location", 'password': "password"}

        test_oauth.http = mock_http

        mock_http.post.return_value = {'access_token': REFRESHED_TOKEN, 'expires_in': 100, 'accountExpiration': 100}

        oauth_info = test_oauth._refresh_oauth_resp_with_idp()
        self.assertTrue(oauth_info['refresh_time_read'] > time_in_past)
        self.assertTrue(oauth_info['access_token'] == REFRESHED_TOKEN)

    @mock.patch('ni.managementconnector.config.config.Config.read')
    @mock.patch('ni.managementconnector.cloud.oauth.Http')
    def test_refresh_oauth_resp_with_idp(self, mock_http, mock_config_read):
        """ Get Refresh Token Tests """

        DEV_LOGGER.info("****** test_refresh_oauth_resp_with_idp ******")

        mock_config_read.return_value = {"clientId": "test", "clientSecret": "test", "idpHost": "test"}

        time_in_past = OAuth.get_current_time() - 100

        self.oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        self.oauth.machine_response = {'location': "location", 'password': "password"}

        self.oauth.http = mock_http

        mock_http.post.return_value = {'access_token': REFRESHED_TOKEN, 'expires_in': 100, 'accountExpiration': 100}
        
        oauth_info = self.oauth._refresh_oauth_resp_with_idp()
        self.assertTrue(oauth_info['refresh_time_read'] > time_in_past)
        self.assertTrue(oauth_info['access_token'] == REFRESHED_TOKEN)

    @mock.patch('ni.managementconnector.cloud.oauth.Http')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_is_cached_machine_account_stale(self, mock_config, mock_http):
        """ Get Access Token Tests """

        DEV_LOGGER.info("****** test_is_cached_machine_account_stale ******")

        test_oauth = OAuth(mock_config)
        exception = Exception()

        #JSON
        mock_config.read.side_effect = config_read_side_effect

        ### Stale cache
        test_oauth.machine_response = {'location': 'some_location', 'username': 'username', 'password': 'password',
                                       'adminUser': False, 'organization_id': 'organization_id', "id": "id"}

        stale_state = test_oauth._is_machine_account_cache_stale()

        DEV_LOGGER.info("state = %s" % (stale_state))

        self.assertTrue(stale_state)

        ### Fresh cache
        test_oauth.machine_response = {'location': 'somewhere', 'username': 'username', 'password': 'password',
                                       'adminUser': False, 'organization_id': 'organization_id', "id": "id"}

        stale_state = test_oauth._is_machine_account_cache_stale()

        DEV_LOGGER.info("state = %s" % (stale_state))

        self.assertFalse(stale_state)

        ### No JSON read
        mock_config.read.side_effect = config_read_side_effect_none

        test_oauth.machine_response = {'location': 'somewhere', 'username': 'username', 'password': 'password',
                                       'adminUser': False, 'organization_id': 'organization_id', "id": "id"}

        stale_state = test_oauth._is_machine_account_cache_stale()

        DEV_LOGGER.info("state = %s" % (stale_state))

        self.assertFalse(stale_state)

        ### Exception
        mock_config.read.side_effect = config_read_side_effect_exception

        test_oauth.machine_response = {'location': 'somewhere', 'username': 'username', 'password': 'password',
                                       'adminUser': False, 'organization_id': 'organization_id', "id": "id"}

        stale_state = test_oauth._is_machine_account_cache_stale()

        DEV_LOGGER.info("state = %s" % (stale_state))

        self.assertFalse(stale_state)

    @mock.patch('ni.managementconnector.cloud.oauth.OAuth._get_idp_headers')
    @mock.patch('ni.managementconnector.config.config.Config')
    @mock.patch('ni.managementconnector.cloud.oauth.Http')
    def test_refresh_oauth_resp_with_idp_http_error_400(self, mock_http, mock_config, mock_idp_headers):
        """ Get Refresh Token Tests """

        DEV_LOGGER.info("****** test_refresh_oauth_resp_with_idp_http_error_400 ******")

        time_in_past = OAuth.get_current_time() - 100

        test_oauth = OAuth(mock_config)

        headers = {'Content-Type': 'application/json', 'TrackingID': ''}
        stream = io.TextIOWrapper(io.BytesIO(''))
        url = "https://idbroker.webex.com/idb/oauth2/v1/access_token"

        test_oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        mock_http.post.side_effect = urllib2.HTTPError(url, 400, "invalid", headers, stream)

        # REREGISTER, 'true'
        try:
            test_oauth._refresh_oauth_resp_with_idp()
        except urllib2.HTTPError:
            DEV_LOGGER.info("***OK exception***")

        test_oauth._config.write_blob.assert_called_with(ManagementConnectorProperties.REREGISTER, 'true')

        #REREGISTER, 'false'
        mock_http.post.side_effect = None
        mock_http.post.return_value = {'access_token': REFRESHED_TOKEN, 'expires_in': 100, 'accountExpiration': 100}
        test_oauth._refresh_oauth_resp_with_idp()
        test_oauth._config.write_blob.assert_called_with(ManagementConnectorProperties.REREGISTER, 'false')

    @mock.patch('ni.managementconnector.cloud.oauth.OAuth._get_machine_details_from_json')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth._get_idp_headers')
    @mock.patch('ni.managementconnector.config.config.Config')
    @mock.patch('ni.managementconnector.cloud.oauth.Http')
    def test_token_for_machine_account_http_error_401(self, mock_http, mock_config, mock_idp_headers, mock_json_config):
        """ Get Refresh Token Tests """

        DEV_LOGGER.info("****** test_token_for_machine_account_http_error_401 ******")

        time_in_past = OAuth.get_current_time() - 100

        test_oauth = OAuth(mock_config)

        mock_json_config.return_value = {'username': 'username', 'password': 'password', 'organization_id': 'organization_id'}

        headers = {'Content-Type': 'application/json', 'TrackingID': ''}
        stream = io.TextIOWrapper(io.BytesIO(''))
        url = "https://idbroker.webex.com/idb/token/org_id/v1/actions/GetBearerToken/invoke"

        #test_oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        mock_http.post.side_effect = urllib2.HTTPError(url, 401, "invalid", headers, stream)

        # REREGISTER, 'true'
        try:
            test_oauth._get_token_for_machine_account()
        except urllib2.HTTPError:
            DEV_LOGGER.info("***OK exception***")

        test_oauth._config.write_blob.assert_called_with(ManagementConnectorProperties.REREGISTER, 'true')

        # REREGISTER, 'false'
        mock_http.post.side_effect = None
        mock_http.post.return_value = {'BearerToken': 'BearerToken'}
        test_oauth._get_token_for_machine_account()
        test_oauth._config.write_blob.assert_called_with(ManagementConnectorProperties.REREGISTER, 'false')


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
