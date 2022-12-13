""" OAuth Test """
import unittest
import sys
import logging
import mock
import io
import urllib.request, urllib.error, urllib.parse
from .constants import SYS_LOG_HANDLER

# Pre-import a mocked pyinotify
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud.oauth import OAuth, ConfigFileUpdateFailedException
from managementconnector.config.config import Config

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()

ACCESS_TOKEN = "Access Token"
REFRESH_TOKEN = "Refresh Token"
REFRESHED_TOKEN = "Refreshed Access Token"

MAX_POLL_TEST_TIMEOUT = 150
CURRENT_TIME = OAuth.get_current_time()
MUST_END_POLL = CURRENT_TIME + MAX_POLL_TEST_TIMEOUT

SLEEP_MAX_WAIT = 10


def config_read_side_effect(*args, **kwargs):
    """ Config Side Effect """
    if args[0] == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return {"username": "username", "organization_id": "org_id", "location": "somewhere",
                "password": "{cipher}LT4V5Hr02ejy326BWD+3TgmyS2GK6TPm6UyxxgmxgzOe96Zr52c9HOk7hKBtDeI1iob1OTTFom+bzvFXKMgPwQ==",
                "id": "id"}

    if args[0] == ManagementConnectorProperties.OAUTH_BASE:
        return {"idpHost": "idpHost", "clientId": "clientId", "clientSecret": "clientSecret"}


def config_read_side_effect_none(*args, **kwargs):
    """ Config Side Effect """
    if args[0] == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        return None


def config_read_side_effect_exception(*args, **kwargs):
    """ Config Side Effect """
    if args[0] == ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS:
        raise Exception("Random error")


def post(url, headers, data, silent=False, schema=None):
    """ Post Side Effect """
    DEV_LOGGER.info("Post Side Effect")

    curr_time = OAuth.get_current_time()
    oauth_response = None

    if "grant_type" in data:
        oauth_response = {'access_token': REFRESHED_TOKEN, 'expires_in': 100, 'accountExpiration': 272,
                          'time_read': curr_time, 'refresh_token_expires_in': 865000,
                          'refresh_token': REFRESH_TOKEN,
                          'refresh_time_read': curr_time}

    elif "GetBearerToken" in url:
        oauth_response = {'BearerToken': 'bearertoken'}

    return oauth_response


def poll_side_effect(url, headers, data, silent=False, schema=None):
    """ CI Polling Side Effect """
    global MUST_END_POLL
    if OAuth.get_current_time() < MUST_END_POLL:
        headers = {'Content-Type': 'application/json', 'TrackingID': ''}
        stream = io.TextIOWrapper(io.BytesIO(b''))
        url = "https://idbroker.webex.com/idb/oauth2/v1/access_token"

        raise urllib.error.HTTPError(url, 401, "invalid", headers, stream)
    else:
        return {'access_token': REFRESHED_TOKEN, 'refresh_token': REFRESHED_TOKEN,
                'expires_in': 100, 'accountExpiration': 100}


def sleep_side_effect(seconds):
    """ Sleep Side Effect """
    if seconds > SLEEP_MAX_WAIT:
        DEV_LOGGER.debug(
            'Detail="test_oauth: sleep_side_effect: '
            'Bypassing %s second wait by SLEEP_MAX_WAIT of %s seconds"' % (seconds, SLEEP_MAX_WAIT))
        seconds = SLEEP_MAX_WAIT

    end_time = OAuth.get_current_time() + seconds
    while True:
        if OAuth.get_current_time() > end_time:
            return


class OAuthTest(unittest.TestCase):
    """ Management Connector OAuth Test Class """

    def setUp(self):
        """ Test Setup"""

        self.oauth = OAuth(Config(inotify=False))

    def tearDown(self):
        """ Test tearDown """

    @mock.patch('managementconnector.cloud.oauth.U2C.update_user_catalog')
    @mock.patch('managementconnector.cloud.oauth.decrypt_with_system_key')
    @mock.patch('managementconnector.platform.http.Http.post', side_effect=post)
    @mock.patch('managementconnector.config.config.Config')
    def test_init(self, mock_config, mock_http, mock_decrypt, mock_u2c):
        """ Test Init OAuth """

        DEV_LOGGER.info("****** test_init ******")

        mock_decrypt.return_value = "test"

        mock_config.read.side_effect = config_read_side_effect

        mock_u2c.update_user_catalog.return_value = None

        oauth = OAuth(mock_config)

        oauth.init()

        token = oauth.get_access_token()

        self.assertEqual(token, REFRESHED_TOKEN)

    @mock.patch('managementconnector.cloud.oauth.OAuth._get_machine_details_from_json')
    @mock.patch('managementconnector.cloud.oauth.OAuth._is_machine_account_cache_stale')
    def test_get_access_token(self, mock_is_machine_acc_cache_stale, mock_json_config):
        """ Get Access Token Tests """

        DEV_LOGGER.info("****** test_get_access_token ******")

        mock_is_machine_acc_cache_stale.return_value = False

        mock_json_config.return_value = {'password': 'password'}

        # Valid Token

        curr_time = OAuth.get_current_time()

        self.oauth.oauth_response = {'access_token': ACCESS_TOKEN, 'expires_in': 400, 'accountExpiration': 272,
                                     'time_read': curr_time, 'refresh_token_expires_in': 865000,
                                     'refresh_time_read': curr_time,
                                     'refresh_token': REFRESH_TOKEN}

        self.oauth.machine_response = {}

        token = self.oauth.get_access_token()

        self.assertTrue(token == ACCESS_TOKEN)

    @mock.patch('managementconnector.cloud.oauth.U2C.update_user_catalog')
    @mock.patch('managementconnector.config.config.Config.read')
    @mock.patch('managementconnector.cloud.oauth.OAuth._get_machine_details_from_json')
    @mock.patch('managementconnector.cloud.oauth.OAuth._is_machine_account_cache_stale')
    @mock.patch('managementconnector.cloud.oauth.Http')
    def test_get_access_token_expired(self, mock_http, mock_is_machine_acc_cache_stale, mock_json_config,
                                      mock_config_read, mock_u2c):
        """ Get Access Token Tests """

        DEV_LOGGER.info("****** test_get_access_token_expired ******")

        mock_config_read.return_value = {"clientId": "test", "clientSecret": "test", "idpHost": "test"}

        curr_time = OAuth.get_current_time()

        mock_is_machine_acc_cache_stale.return_value = False

        mock_json_config.return_value = {'password': 'password'}

        mock_http.post.return_value = {'access_token': REFRESHED_TOKEN, 'expires_in': 100, 'accountExpiration': 272,
                                       'time_read': curr_time, 'refresh_token_expires_in': 865000,
                                       'refresh_token': REFRESH_TOKEN,
                                       'refresh_time_read': curr_time}

        self.oauth.http = mock_http

        # Expired Token

        curr_time = OAuth.get_current_time()

        self.oauth.oauth_response = {'access_token': ACCESS_TOKEN, 'expires_in': 10, 'accountExpiration': 272,
                                     'time_read': curr_time, 'refresh_token_expires_in': 865000,
                                     'refresh_time_read': curr_time, 'refresh_token': REFRESH_TOKEN}

        mock_u2c.update_user_catalog.return_value = None

        token = self.oauth.get_access_token()

        DEV_LOGGER.info("token = %s" % (token))

        self.assertTrue(token == REFRESHED_TOKEN)

    @mock.patch('managementconnector.cloud.oauth.U2C.update_user_catalog')
    @mock.patch('managementconnector.cloud.oauth.decrypt_with_system_key')
    @mock.patch('managementconnector.cloud.oauth.OAuth._is_machine_account_cache_stale')
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.platform.http.Http.post', side_effect=post)
    def test_get_access_token_refresh_expired(self, mock_http, mock_config, mock_is_machine_acc_cache_stale,
                                              mock_decrypt, mock_u2c):
        """ Get Access Token Tests """

        DEV_LOGGER.info("****** test_get_access_token_refresh_expired ******")

        mock_decrypt.return_value = "test"

        mock_config.read.side_effect = config_read_side_effect
        test_oauth = OAuth(mock_config)

        # Expired Refresh Token

        curr_time = OAuth.get_current_time()

        mock_is_machine_acc_cache_stale.return_value = False

        test_oauth.oauth_response = {'access_token': ACCESS_TOKEN, 'expires_in': 10, 'accountExpiration': 272,
                                     'time_read': curr_time, 'refresh_token_expires_in': 10,
                                     'refresh_time_read': curr_time, 'refresh_token': REFRESH_TOKEN}

        test_oauth.machine_response = {'location': 'some_location', 'username': 'username', 'password': 'password',
                                       'adminUser': False, 'organization_id': 'organization_id'}

        mock_u2c.update_user_catalog.return_value = None

        token = test_oauth.get_access_token()

        self.assertTrue(token == REFRESHED_TOKEN)

        token = test_oauth.get_access_token()
        self.assertTrue(token == REFRESHED_TOKEN)

    @mock.patch('managementconnector.cloud.oauth.U2C.update_user_catalog')
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.cloud.oauth.Http')
    def test_refresh_oauth_resp_with_idp(self, mock_http, mock_config, mock_u2c):
        """ Get Refresh Token Tests """

        DEV_LOGGER.info("****** test_refresh_oauth_resp_with_idp ******")

        time_in_past = OAuth.get_current_time() - 100

        test_oauth = OAuth(mock_config)
        mock_config.read.side_effect = config_read_side_effect

        test_oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        test_oauth.machine_response = {'location': "location", 'password': "password"}

        test_oauth.http = mock_http

        mock_http.post.return_value = {'access_token': REFRESHED_TOKEN, 'refresh_token': REFRESHED_TOKEN,
                                       'expires_in': 100, 'accountExpiration': 100}

        mock_u2c.update_user_catalog.return_value = None

        oauth_info = test_oauth.refresh_oauth_resp_with_idp()
        self.assertTrue(oauth_info['refresh_time_read'] > time_in_past)
        self.assertTrue(oauth_info['access_token'] == REFRESHED_TOKEN)

    @mock.patch('managementconnector.cloud.oauth.time.sleep')
    @mock.patch('managementconnector.cloud.oauth.DEV_LOGGER.info')
    @mock.patch('managementconnector.cloud.oauth.U2C.update_user_catalog')
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.cloud.oauth.Http')
    def test_migration_polling(self, mock_http, mock_config, mock_u2c, mock_logger_info, mock_sleep):
        """ Test Get Refresh Token with CI Polling """

        DEV_LOGGER.info("****** test_migration_polling ******")

        # custom sleep method
        mock_sleep.side_effect = sleep_side_effect

        time_in_past = OAuth.get_current_time() - 100

        test_oauth = OAuth(mock_config)
        mock_config.read.side_effect = config_read_side_effect

        test_oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        test_oauth.machine_response = {'location': "location", 'password': "password"}

        test_oauth.http = mock_http

        mock_http.post.side_effect = poll_side_effect

        mock_u2c.update_user_catalog.return_value = None

        oauth_info = test_oauth.refresh_oauth_resp_with_idp(
            wait_before_polling=ManagementConnectorProperties.ORG_MIGRATION_CI_POLL_PRE_WAIT)

        mock_sleep.assert_any_call(ManagementConnectorProperties.ORG_MIGRATION_CI_POLL_PRE_WAIT_TIME)
        mock_logger_info.assert_any_call('Detail="FMC_OAuth: exponential_backoff_retry"')

        # assert token refresh
        self.assertTrue(oauth_info['refresh_time_read'] > time_in_past)
        self.assertTrue(oauth_info['access_token'] == REFRESHED_TOKEN)

    @mock.patch('managementconnector.cloud.oauth.DEV_LOGGER.info')
    @mock.patch('managementconnector.cloud.oauth.U2C.update_user_catalog')
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.cloud.oauth.Http')
    def test_config_update_failure_exception(self, mock_http, mock_config, mock_u2c, mock_logger_info):
        """ Test ConfigFileUpdateFailedException """

        DEV_LOGGER.info("****** test_config_update_failure_exception ******")

        time_in_past = OAuth.get_current_time() - 100

        test_oauth = OAuth(mock_config)
        mock_config.read.side_effect = config_read_side_effect

        test_oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        test_oauth.machine_response = {'location': "location", 'password': "password"}

        test_oauth.http = mock_http

        mock_http.post.side_effect = None

        # return False to simulate ConfigFileUpdateFailedException
        mock_u2c.update_user_catalog.return_value = False

        oauth_info = test_oauth.refresh_oauth_resp_with_idp()

        # assert ConfigFileUpdateFailedException is raised
        self.assertRaises(ConfigFileUpdateFailedException)

    @mock.patch('managementconnector.cloud.oauth.U2C.update_user_catalog')
    @mock.patch('managementconnector.config.config.Config.read')
    @mock.patch('managementconnector.cloud.oauth.Http')
    def test_refresh_oauth_resp_with_idp(self, mock_http, mock_config_read, mock_u2c):
        """ Get Refresh Token Tests """

        DEV_LOGGER.info("****** test_refresh_oauth_resp_with_idp ******")

        mock_config_read.return_value = {"clientId": "test", "clientSecret": "test", "idpHost": "test"}

        time_in_past = OAuth.get_current_time() - 100

        self.oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        self.oauth.machine_response = {'location': "location", 'password': "password"}

        self.oauth.http = mock_http

        mock_http.post.return_value = {'access_token': REFRESHED_TOKEN, 'refresh_token': REFRESHED_TOKEN,
                                       'expires_in': 100, 'accountExpiration': 100}

        mock_u2c.update_user_catalog.return_value = None

        oauth_info = self.oauth.refresh_oauth_resp_with_idp()
        self.assertTrue(oauth_info['refresh_time_read'] > time_in_past)
        self.assertTrue(oauth_info['access_token'] == REFRESHED_TOKEN)

    @mock.patch('managementconnector.cloud.oauth.Http')
    @mock.patch('managementconnector.config.config.Config')
    def test_is_cached_machine_account_stale(self, mock_config, mock_http):
        """ Get Access Token Tests """

        DEV_LOGGER.info("****** test_is_cached_machine_account_stale ******")

        test_oauth = OAuth(mock_config)
        exception = Exception()

        # JSON
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

        DEV_LOGGER.info("state = %s" % stale_state)

        self.assertFalse(stale_state)

    @mock.patch('managementconnector.cloud.oauth.U2C.update_user_catalog')
    @mock.patch('managementconnector.cloud.oauth.OAuth._get_idp_headers')
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.cloud.oauth.Http')
    def test_refresh_oauth_resp_with_idp_http_error_400(self, mock_http, mock_config, mock_idp_headers, mock_u2c):
        """ Get Refresh Token Tests """

        DEV_LOGGER.info("****** test_refresh_oauth_resp_with_idp_http_error_400 ******")

        time_in_past = OAuth.get_current_time() - 100

        test_oauth = OAuth(mock_config)

        headers = {'Content-Type': 'application/json', 'TrackingID': ''}
        stream = io.TextIOWrapper(io.BytesIO(b''))
        url = "https://idbroker.webex.com/idb/oauth2/v1/access_token"

        test_oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        mock_http.post.side_effect = urllib.error.HTTPError(url, 400, "invalid", headers, stream)

        mock_u2c.update_user_catalog.return_value = None

        # REREGISTER, 'true'
        try:
            test_oauth.refresh_oauth_resp_with_idp()
        except urllib.error.HTTPError:
            DEV_LOGGER.info("***OK exception***")

        test_oauth._config.write_blob.assert_called_with(ManagementConnectorProperties.REREGISTER, 'true')

        # REREGISTER, 'false'
        mock_http.post.side_effect = None
        mock_http.post.return_value = {'access_token': REFRESHED_TOKEN, 'refresh_token': REFRESHED_TOKEN,
                                       'expires_in': 100, 'accountExpiration': 100}
        test_oauth.refresh_oauth_resp_with_idp()
        test_oauth._config.write_blob.assert_called_with(ManagementConnectorProperties.REREGISTER, 'false')

    @mock.patch('managementconnector.cloud.oauth.OAuth._get_machine_details_from_json')
    @mock.patch('managementconnector.cloud.oauth.OAuth._get_idp_headers')
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.cloud.oauth.Http')
    def test_token_for_machine_account_http_error_401(self, mock_http, mock_config, mock_idp_headers, mock_json_config):
        """ Get Refresh Token Tests """

        DEV_LOGGER.info("****** test_token_for_machine_account_http_error_401 ******")

        time_in_past = OAuth.get_current_time() - 100

        test_oauth = OAuth(mock_config)

        mock_json_config.return_value = {'username': 'username', 'password': 'password',
                                         'organization_id': 'organization_id'}

        headers = {'Content-Type': 'application/json', 'TrackingID': ''}
        stream = io.TextIOWrapper(io.BytesIO(b''))
        url = "https://idbroker.webex.com/idb/token/org_id/v1/actions/GetBearerToken/invoke"

        # test_oauth.oauth_response = {'refresh_token': REFRESH_TOKEN, 'refresh_time_read': time_in_past}
        mock_http.post.side_effect = urllib.error.HTTPError(url, 401, "invalid", headers, stream)
        
        # REREGISTER, 'true'
        try:
            test_oauth._get_token_for_machine_account()
        except urllib.error.HTTPError:
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
