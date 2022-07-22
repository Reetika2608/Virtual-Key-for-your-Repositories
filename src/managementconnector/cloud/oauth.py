""" This module starts ManagementConnector """

import time
import base64
import json
import traceback
from urllib import error as urllib_error
from urllib.parse import quote as urllib_quote
from random import SystemRandom as RandomGenerator

from base_platform.expressway.taacrypto.taacrypto import encrypt_with_system_key, decrypt_with_system_key
from managementconnector.platform.http import Http
from managementconnector.cloud import schema
from managementconnector.cloud.u2c import U2C
from managementconnector.config.databasehandler import DatabaseHandler

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class UnableToReachCIException(Exception):
    """ Raised when Unable to reach CI """
    def __init__(self, message):
        super().__init__(message)

        # custom object to access error message
        self.error = message


class ConfigFileUpdateFailedException(Exception):
    """ Raised when 'c_mgmt.json' Config file is not updated """

    def __init__(self, message):
        super().__init__(message)

        # custom object to access error message
        self.error = message


class OAuth(object):
    """Class for OAuth functionality"""

    def __init__(self, config):
        """ Constructor """
        self.oauth_response = None
        self.machine_response = None

        Http.init(config)

        self._config = config

        self._http_error_raised = False

        self._u2c = U2C(self._config, None, Http, DatabaseHandler())

    # -------------------------------------------------------------------------

    def init(self):
        """OAuth Init Method, anything calling this method will have to handle
        urllib2.HTTPError errors, where the OAuth Component has problems calling out
        to the IDP."""

        rtn_value = True

        DEV_LOGGER.debug('Detail="FMC_OAuth init "')
        ADMIN_LOGGER.info('Detail="FMC_OAuth init"')

        self.machine_response = self._get_machine_details_from_json()
        if self.machine_response is None:
            DEV_LOGGER.error('Detail="FMC_OAuth Machine Account Info missing from DB"')
            rtn_value = False
        else:
            # Get an access token based on machine account
            bearer_token = self._get_token_for_machine_account()
            self.oauth_response = self._get_oauth_resp_from_idp(bearer_token['BearerToken'])
            DEV_LOGGER.debug('Detail="FMC_OAuth Init Complete "')
            ADMIN_LOGGER.info('Detail="FMC_OAuth Init Complete"')

        return rtn_value

    # -------------------------------------------------------------------------

    def get_access_token(self):
        """Returns the Access Token, this method is not thread-safe, if concurrency
        an issue - code will need to be refactored. Anything calling this method will have to handle
        urllib2.HTTPError errors, where the OAuth Component has problems calling out
        to the IDP"""

        if self.oauth_response is not None:
            # Check to see if the Access Token is still valid. If expired make refresh request to IDP
            # Need to break out further for refresh token expiry
            if self._is_access_expired():
                stale = self._is_machine_account_cache_stale()

                self.machine_response = self._get_machine_details_from_json()

                if self._is_refresh_token_expired() or stale:
                    bearer_token = self._get_token_for_machine_account()
                    self.oauth_response = self._get_oauth_resp_from_idp(bearer_token['BearerToken'])
                else:
                    self.oauth_response = self.refresh_oauth_resp_with_idp()

            return self.oauth_response["access_token"]
        else:
            DEV_LOGGER.error('Detail="FMC_OAuth The OAuth Object has not been initialized correctly"')
            return ""

    # -------------------------------------------------------------------------

    def get_account_expiration(self):
        """ get_account_expiration """

        account_expiration = None

        # Make sure oauth response is up to date
        self.get_access_token()

        if "accountExpiration" in self.oauth_response:
            account_expiration = self.oauth_response["accountExpiration"]

        return account_expiration

    # -------------------------------------------------------------------------

    def get_header(self, access_token=None, no_auth=False):
        """ return header with Access Token """
        headers = dict()
        headers['Content-Type'] = 'application/json'
        if no_auth:
            return headers
        elif access_token is not None:
            headers['Authorization'] = "Bearer " + access_token
        else:
            headers['Authorization'] = "Bearer " + self.get_access_token()
        return headers

    # -------------------------------------------------------------------------

    def _get_token_for_machine_account(self):
        """Authentication for per organization based machine account"""

        DEV_LOGGER.info('Detail="FMC_OAuth _get_token_for_machine_account:"')

        machine_response = self._get_machine_details_from_json()

        headers = {'Content-Type': 'application/json'}
        data = {'name': machine_response["username"], 'password': machine_response["password"], 'adminUser': False}

        body = json.dumps(data)

        idp_info = self._config.read(ManagementConnectorProperties.OAUTH_BASE)

        bearer_url = '{}/idb/token/{}/v1/actions/GetBearerToken/invoke'.format(idp_info["idpHost"],
                                                                               machine_response["organization_id"])

        bearer_response = {}

        try:
            bearer_response = Http.post(bearer_url, headers, body, silent=True, schema=schema.BEARER_TOKEN_RESPONSE)
        except urllib_error.HTTPError as error:
            DEV_LOGGER.error(
                'Detail="RAW: FMC_OAuth _get_token_for_machine_account: '
                'error: code=%s, url=%s"' % (error.code, error.url))
            if error.code == 401:
                self._revive_on_http_error(error)

        self._update_revive_status()

        return bearer_response

    # -------------------------------------------------------------------------

    def _get_oauth_resp_from_idp(self, bearer_token):
        """Authentication for organization - based machine account"""

        DEV_LOGGER.info('Detail="FMC_OAuth _get_oauth_resp_from_idp:"')

        grant_type = 'urn:ietf:params:oauth:grant-type:saml2-bearer'
        encoded_grant_type = urllib_quote(grant_type)
        scopes = 'Identity:SCIM Identity:Organization squared-fusion-mgmt:management spark:logs_write'
        encoded_scopes = urllib_quote(scopes)
        body = "grant_type={}&assertion={}&scope={}".format(encoded_grant_type, bearer_token, encoded_scopes)

        headers = self._get_idp_headers()

        idp_info = self._config.read(ManagementConnectorProperties.OAUTH_BASE)

        idp_url = idp_info["idpHost"] + "/" + ManagementConnectorProperties.IDP_URL

        self.oauth_response = Http.post(idp_url, headers, body, silent=True, schema=schema.ACCESS_TOKEN_RESPONSE)

        self.oauth_response["time_read"] = self.get_current_time()
        self.oauth_response["refresh_time_read"] = self.get_current_time()

        DEV_LOGGER.info('Detail="FMC_OAuth _get_oauth_resp_from_idp: refresh_time_read %s "' %
                        (self.oauth_response["refresh_time_read"]))

        return self.oauth_response

    # -------------------------------------------------------------------------

    def create_machine_account(self, cluster_id, machine_account):
        """Create a Machine Account based on FMS response details"""

        DEV_LOGGER.info('Detail="FMC_OAuth create_machine_account:"')

        self.machine_response = {'cluster_id': cluster_id,
                                 'id': machine_account['id'],
                                 'location': machine_account['url'],
                                 'organization_id': machine_account['organizationId'],
                                 'password': machine_account['password'],
                                 'username': machine_account['username']}

        self._store_machine_response_in_db()

        return self.machine_response

    # -------------------------------------------------------------------------

    def refresh_oauth_resp_with_idp(self, wait_before_polling=False):
        """refresh the OAuth Response, by sending a refresh request to the IDP"""

        DEV_LOGGER.info('Detail="FMC_OAuth refresh_oauth_response_with_idp:"')

        # user catalog refresh
        self.refresh_u2c(check_config=True)

        # ensure config cache clearance
        if not self._config.is_cache_cleared():
            DEV_LOGGER.warn(
                'Detail="FMC_OAuth: refresh_oauth_resp_with_idp: Config cache was not cleared, clearing it now"')
            self._config.clear_cache()

        body = 'grant_type=refresh_token&refresh_token=' + self.oauth_response["refresh_token"]
        headers = self._get_idp_headers()

        idp_info = self._config.read(ManagementConnectorProperties.OAUTH_BASE)

        idp_url = idp_info["idpHost"] + "/" + ManagementConnectorProperties.IDP_URL

        response = {}
        try:
            if wait_before_polling:
                wait_time_before_poll = ManagementConnectorProperties.ORG_MIGRATION_CI_POLL_PRE_WAIT_TIME
                DEV_LOGGER.info('Detail="FMC_Utility refresh_oauth_resp_with_idp: waiting %s seconds"' %
                                wait_time_before_poll)
                time.sleep(wait_time_before_poll)
            response = Http.post(idp_url, headers, body, silent=True, schema=schema.REFRESH_ACCESS_TOKEN_RESPONSE)
        except urllib_error.HTTPError as error:
            DEV_LOGGER.error('Detail="RAW: FMC_OAuth refresh_oauth_resp_with_idp: error: code=%s, url=%s"' % (
                error.code, error.url))
            MIGRATION_STATE = self._config.read(ManagementConnectorProperties.FMS_MIGRATION_STATE)
            DEV_LOGGER.debug('Detail="FMC_Utility refresh_oauth_resp_with_idp: MIGRATION_STATE: %s"' % MIGRATION_STATE)
            if MIGRATION_STATE != ManagementConnectorProperties.FMS_MIGRATION_STARTED and error.code == 400:
                self._revive_on_http_error(error)
            else:
                try:
                    response = self.exponential_backoff_retry(
                        Http.post,
                        ManagementConnectorProperties.ORG_MIGRATION_CI_POLL_TIMEOUT,
                        ManagementConnectorProperties.ORG_MIGRATION_CI_POLL_BACKOFF,
                        ManagementConnectorProperties.ORG_MIGRATION_CI_POLL_BACKOFF_REFRESH_INTERVAL,
                        *(idp_url, headers, body, True, schema.REFRESH_ACCESS_TOKEN_RESPONSE))
                except UnableToReachCIException as e:
                    DEV_LOGGER.error('Detail="RAW: FMC_OAuth refresh_oauth_resp_with_idp: error: msg=%s, url=%s"' % (
                        e.error, idp_url))
                    raise

        self._update_revive_status()

        # Update some the OAuth Fields
        self.oauth_response["refresh_token"] = response["refresh_token"]

        self.oauth_response["access_token"] = response["access_token"]

        if "accountExpiration" in response:
            self.oauth_response["accountExpiration"] = response["accountExpiration"]

        self.oauth_response["expires_in"] = response["expires_in"]

        self.oauth_response["time_read"] = self.get_current_time()

        # Mark the last time the refresh token was used
        self.oauth_response["refresh_time_read"] = self.get_current_time()

        DEV_LOGGER.info('Detail="FMC_OAuth refresh_oauth_resp_with_idp: refresh_time_read %s; expires_in %s "' %
                        (self.oauth_response["refresh_time_read"], self.oauth_response["expires_in"]))

        return self.oauth_response

    # -------------------------------------------------------------------------

    @staticmethod
    def exponential_backoff_retry(predicate, timeout, backoff=2, refresh_interval=30, *args):
        """ Calls the predicate function with an increasing delay between successive retries """
        backoff_time = RandomGenerator().random()
        must_end = OAuth.get_current_time() + timeout
        refresh_time = OAuth.get_current_time() + refresh_interval
        DEV_LOGGER.info('Detail="FMC_OAuth: exponential_backoff_retry"')
        while OAuth.get_current_time() < must_end:
            try:
                response = predicate(*args)
                return response
            except urllib_error.HTTPError as error:
                DEV_LOGGER.error(
                    'Detail="FMC_OAuth: exponential_backoff_retry: RAW: FMC_OAuth  exponential_backoff_retry('
                    'refresh_oauth_resp_with_idp): '
                    'error: code=%s, url=%s"' % (error.code, error.url))
            except Exception as unhandled_exception:  # catch unseen exceptions
                DEV_LOGGER.error(
                    'Detail="FMC_OAuth: exponential_backoff_retry: RAW: FMC_OAuth  exponential_backoff_retry('
                    'refresh_oauth_resp_with_idp): '
                    'error=%s"' % unhandled_exception)
            # refresh the backoff once refresh interval is reached
            if OAuth.get_current_time() >= refresh_time:
                DEV_LOGGER.debug('Detail="FMC_OAuth: exponential_backoff_retry: Refresh interval reached.."')
                backoff_time = RandomGenerator().random()
                refresh_time = OAuth.get_current_time() + refresh_interval
            # retry delay increases by a factor of backoff (example: backoff=2seconds) everytime
            backoff_time = (backoff_time + backoff) + RandomGenerator().random()
            DEV_LOGGER.debug(
                'Detail="FMC_OAuth: exponential_backoff_retry: Will call CI after %0.2f seconds"' % backoff_time)
            time.sleep(backoff_time)  # sleep
        DEV_LOGGER.debug(
            'Detail="FMC_OAuth: exponential_backoff_retry: Failed to fetch response even after %s seconds"' % timeout)
        raise UnableToReachCIException('Timed Out, Unable to reach CI.')

    # -------------------------------------------------------------------------

    def refresh_u2c(self, check_config):
        """ Refresh u2c """
        # update user catalog - after every token refresh
        # if u2c refresh fails with auth, retry without auth as fallback
        DEV_LOGGER.info('Detail="FMC_OAuth refresh_u2c"')
        try:
            u2c_status = self._u2c.update_user_catalog(
                header=self.get_header(access_token=self.oauth_response["access_token"]),
                check_config=check_config)
        except:
            u2c_status = self._u2c.update_user_catalog(
                header=self.get_header(no_auth=True),
                check_config=check_config)

        if not u2c_status:
            raise ConfigFileUpdateFailedException({"message": "Config File did not update after U2C refresh"})

    # -------------------------------------------------------------------------

    def _get_machine_details_from_json(self):
        """Retrieve OAuth Detail from the DB"""

        # MACHINE_ACCOUNT_CDB_POSTFIX = 'oauth_machine_account_details'
        rtn_value = self._config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)

        if rtn_value is None:
            DEV_LOGGER.error('Detail="FMC_OAuth _get_machine_details_from_json Failed to read a record."')
            return None

        rtn_value_copy = rtn_value.copy()
        rtn_value_copy['password'] = decrypt_with_system_key(rtn_value_copy['password'])

        return rtn_value_copy

    # -------------------------------------------------------------------------

    def _store_machine_response_in_db(self):
        """Store Machine Details in the DB"""
        # Convert to JSON Dict and write to DB
        machine_response_copy = self.machine_response.copy()
        machine_response_copy['password'] = encrypt_with_system_key(machine_response_copy['password'])

        self._config.write_blob(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS, machine_response_copy)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_current_time():
        """returns current time"""
        return int(round(time.time()))

    # -------------------------------------------------------------------------

    def _get_idp_headers(self):
        """returns headers for IDP Calls"""

        idp_info = self._config.read(ManagementConnectorProperties.OAUTH_BASE)
        basic = base64.b64encode((idp_info["clientId"] + ':' + idp_info["clientSecret"]).encode('ascii'))
        basic = basic.decode('ascii')
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + basic}

        return headers

    # -------------------------------------------------------------------------

    def _is_access_expired(self):
        """ is_access_expired """
        expires_in = self.oauth_response['expires_in']
        current_time = self.get_current_time()
        # Adding 300 seconds, so as to refresh the token a little earlier than necessary.
        # Avoiding a situation where token is returned as valid, but a few second elapses
        # before the token is used. The elapse time might invalidate the token.
        expired = expires_in < (current_time - self.oauth_response[
            'time_read'] + ManagementConnectorProperties.ACCESS_TOKEN_REFRESH)
        if expired:
            DEV_LOGGER.debug(
                'Detail="FMC_OAuth is_access_expired: expired=%s = expires_in=%s > current_time=%s-token_get_time=%s"' %
                (expired, expires_in, current_time, self.oauth_response['time_read']))

        return expired

    # -------------------------------------------------------------------------

    def _is_refresh_token_expired(self):
        """ is_refresh_token_expired """
        expires_in = self.oauth_response['refresh_token_expires_in']
        current_time = self.get_current_time()
        # Adding 1 (86400 secs) days, so as to refresh the token a little earlier than necessary.
        expired = expires_in < (current_time - self.oauth_response[
            'refresh_time_read'] + ManagementConnectorProperties.REFRESH_TOKEN_REFRESH)
        DEV_LOGGER.debug(
            'Detail="FMC_OAuth _is_refresh_token_expired: expired=%s = expires_in=%s > current_time=%s-token_get_time=%s"' %
            (expired, expires_in, current_time, self.oauth_response['refresh_time_read']))

        return expired

    # -------------------------------------------------------------------------

    def _is_machine_account_cache_stale(self):
        """Check if machine account cache is out of sync with cdb"""
        stale = False

        try:
            rtn_value = self._config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)

            if not rtn_value:
                DEV_LOGGER.error('Detail="FMC_OAuth _is_machine_account_cache_stale: Failed to read a record."')
                return False

            DEV_LOGGER.debug('Detail="FMC_OAuth _is_machine_account_cache_stale: cached value=%s = JSON value=%s "' %
                             (self.machine_response['location'], rtn_value['location']))
            if rtn_value['location'] != self.machine_response['location']:
                DEV_LOGGER.debug('Detail="FMC_OAuth _is_machine_account_cache_stale: True"')
                stale = True

        except Exception as error:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="FMC_OAuth _is_machine_account_cache_stale Error =%s, stacktrace=%s"' % (
            error, traceback.format_exc()))
            return False

        return stale

    # -------------------------------------------------------------------------

    def _update_revive_status(self):
        """Update revive status"""

        if self._http_error_raised:
            self._http_error_raised = False
            DEV_LOGGER.debug(
                'Detail="RAW: FMC_OAuth _update_revive_status: setting _http_error_raised to: {} "'.format(
                    self._http_error_raised))
            self._config.write_blob(ManagementConnectorProperties.REREGISTER, 'false')

    # -------------------------------------------------------------------------

    def _revive_on_http_error(self, error):
        """Handle specific erors that set revive flag"""
        DEV_LOGGER.error('Detail="RAW: FMC_OAuth Init: error: code=%s, url=%s"' % (error.code, error.url))
        self._config.write_blob(ManagementConnectorProperties.REREGISTER, 'true')
        self._http_error_raised = True
        raise  # pylint: disable=E0704

    # -------------------------------------------------------------------------
