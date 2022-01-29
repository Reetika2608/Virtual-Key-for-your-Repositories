""" This module starts ManagementConnector """

import time
import base64
import json
import traceback
from urllib import error as urllib_error
import taacrypto
from random import SystemRandom as RandomGenerator

from managementconnector.platform.http import Http
from managementconnector.cloud import schema

from managementconnector.cloud.u2c import U2C
from managementconnector.config.databasehandler import DatabaseHandler

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


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

    def get_header(self, access_token=None):
        """ return header with Access Token """
        headers = dict()
        headers['Content-Type'] = 'application/json'
        if access_token is not None:
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

        try:
            bearer_response = Http.post(bearer_url, headers, body, silent=True, schema=schema.BEARER_TOKEN_RESPONSE)
        except urllib_error.HTTPError as error:
            DEV_LOGGER.error('Detail="RAW: FMC_OAuth _get_token_for_machine_account: error: code=%s, url=%s"' % (
            error.code, error.url))
            if error.code == 401:
                self._revive_on_http_error(error)

        self._update_revive_status()

        return bearer_response

    # -------------------------------------------------------------------------

    def _get_oauth_resp_from_idp(self, bearer_token):
        """Authentication for organization - based machine account"""

        DEV_LOGGER.info('Detail="FMC_OAuth _get_oauth_resp_from_idp:"')

        body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type:saml2-bearer&assertion=" + \
               bearer_token + "&scope=Identity%3ASCIM%20Identity%3AOrganization%20squared-fusion-mgmt%3Amanagement%20spark%3Alogs_write"

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

    def refresh_oauth_resp_with_idp(self, migration=False):
        """refresh the OAuth Response, by sending a refresh request to the IDP"""

        DEV_LOGGER.info('Detail="FMC_OAuth refresh_oauth_response_with_idp:"')

        body = 'grant_type=refresh_token&refresh_token=' + self.oauth_response["refresh_token"]
        headers = self._get_idp_headers()

        idp_info = self._config.read(ManagementConnectorProperties.OAUTH_BASE)

        idp_url = idp_info["idpHost"] + "/" + ManagementConnectorProperties.IDP_URL

        """
        if migration is in progress
            Enter into polling CI for new token with exponential backoff retry algorithm
            if response received
                resume operations
            else
                retry till timeout
        else
            normal refresh token call
        """
        try:
            if migration:
                response = self.exponential_backoff_retry(Http.post, ManagementConnectorProperties.CI_POLL_TIMEOUT,
                                                          ManagementConnectorProperties.CI_POLL_BACKOFF,
                                                          ManagementConnectorProperties.CI_POLL_REFRESH_INTERVAL,
                                                          *(idp_url, headers,
                                                            body, True, schema.REFRESH_ACCESS_TOKEN_RESPONSE))
            else:
                response = Http.post(idp_url, headers, body, silent=True, schema=schema.REFRESH_ACCESS_TOKEN_RESPONSE)
        except urllib_error.HTTPError as error:
            DEV_LOGGER.error('Detail="RAW: FMC_OAuth refresh_oauth_resp_with_idp: error: code=%s, url=%s"' % (
                error.code, error.url))
            if error.code == 400:
                self._revive_on_http_error(error)
        except Exception as e:
            DEV_LOGGER.error('Detail="RAW: FMC_OAuth refresh_oauth_resp_with_idp: error: msg=%s, url=%s"' % (
                e, idp_url))

        self._update_revive_status()

        # Update some the OAuth Fields
        self.oauth_response["access_token"] = response["access_token"]

        if "accountExpiration" in response:
            self.oauth_response["accountExpiration"] = response["accountExpiration"]

        self.oauth_response["expires_in"] = response["expires_in"]

        self.oauth_response["time_read"] = self.get_current_time()

        # Mark the last time the refresh token was used
        self.oauth_response["refresh_time_read"] = self.get_current_time()

        DEV_LOGGER.info('Detail="FMC_OAuth refresh_oauth_resp_with_idp: refresh_time_read %s; expires_in %s "' %
                        (self.oauth_response["refresh_time_read"], self.oauth_response["expires_in"]))

        # user catalog refresh
        self.refresh_u2c()

        return self.oauth_response

    # -------------------------------------------------------------------------

    @staticmethod
    def exponential_backoff_retry(predicate, timeout, backoff=2, refresh_interval=30, *args):
        """ Calls the predicate function with an increasing delay between successive retries """
        backoff_time = RandomGenerator().random()
        must_end = time.time() + timeout
        refresh_time = time.time() + refresh_interval
        DEV_LOGGER.info('Detail="Org Migration: Polling CI"')
        while time.time() < must_end:
            try:
                response = predicate(*args)
                return response
            except urllib_error.HTTPError as error:
                DEV_LOGGER.error('Detail="Org Migration: RAW: FMC_OAuth  exponential_backoff_retry('
                                 'refresh_oauth_resp_with_idp): '
                                 'error: code=%s, url=%s"' % (error.code, error.url))
                pass
            # refresh the backoff once refresh interval is reached
            if time.time() >= refresh_time:
                DEV_LOGGER.debug('Detail="Org Migration: Refresh interval reached.."')
                backoff_time = RandomGenerator().random()
                refresh_time = time.time() + refresh_interval
            # retry delay increases by a factor of backoff (example: backoff=2seconds) everytime
            backoff_time = (backoff_time + backoff) + RandomGenerator().random()
            DEV_LOGGER.debug(f'Detail="Org Migration: Will call CI after {backoff_time} seconds"')
            time.sleep(backoff_time)  # sleep
        DEV_LOGGER.debug(f'Detail="Org Migration: Failed to fetch response even after {timeout} seconds"')
        raise Exception('Unable to reach CI')

    # -------------------------------------------------------------------------

    def refresh_u2c(self):
        # update user catalog - after every token refresh
        DEV_LOGGER.debug('Detail="FMC_OAuth refresh_u2c: Refresh user catalog"')
        self._u2c.update_user_catalog(header=self.get_header(access_token=self.oauth_response["access_token"]))
        DEV_LOGGER.debug('Detail="FMC_OAuth refresh_u2c: User Catalog refresh done"')
        return

    # -------------------------------------------------------------------------

    def refresh_oauth_resp_with_idp_old(self):
        """refresh the OAuth Response, by sending a refresh request to the IDP"""

        DEV_LOGGER.info('Detail="FMC_OAuth refresh_oauth_response_with_idp:"')

        body = 'grant_type=refresh_token&refresh_token=' + self.oauth_response["refresh_token"]
        headers = self._get_idp_headers()

        idp_info = self._config.read(ManagementConnectorProperties.OAUTH_BASE)

        idp_url = idp_info["idpHost"] + "/" + ManagementConnectorProperties.IDP_URL

        try:
            response = Http.post(idp_url, headers, body, silent=True, schema=schema.REFRESH_ACCESS_TOKEN_RESPONSE)
        except urllib_error.HTTPError as error:
            DEV_LOGGER.error('Detail="RAW: FMC_OAuth _refresh_oauth_resp_with_idp: error: code=%s, url=%s"' % (
                error.code, error.url))
            if error.code == 400:
                self._revive_on_http_error(error)

        self._update_revive_status()

        # Update some the OAuth Fields
        self.oauth_response["access_token"] = response["access_token"]

        if "accountExpiration" in response:
            self.oauth_response["accountExpiration"] = response["accountExpiration"]

        self.oauth_response["expires_in"] = response["expires_in"]

        self.oauth_response["time_read"] = self.get_current_time()

        # Mark the last time the refresh token was used
        self.oauth_response["refresh_time_read"] = self.get_current_time()

        DEV_LOGGER.info('Detail="FMC_OAuth _refresh_oauth_resp_with_idp: refresh_time_read %s; expires_in %s "' %
                        (self.oauth_response["refresh_time_read"], self.oauth_response["expires_in"]))

        return self.oauth_response

    # -------------------------------------------------------------------------

    def _get_machine_details_from_json(self):
        """Retrieve OAuth Detail from the DB"""

        # MACHINE_ACCOUNT_CDB_POSTFIX = 'oauth_machine_account_details'
        rtn_value = self._config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)

        if rtn_value is None:
            DEV_LOGGER.error('Detail="FMC_OAuth _get_machine_details_from_json Failed to read a record."')
            return None

        rtn_value_copy = rtn_value.copy()
        rtn_value_copy['password'] = taacrypto.decrypt_with_system_key(rtn_value_copy['password'])

        return rtn_value_copy

    # -------------------------------------------------------------------------

    def _store_machine_response_in_db(self):
        """Store Machine Details in the DB"""
        # Convert to JSON Dict and write to DB
        machine_response_copy = self.machine_response.copy()
        machine_response_copy['password'] = taacrypto.encrypt_with_system_key(machine_response_copy['password'])

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
