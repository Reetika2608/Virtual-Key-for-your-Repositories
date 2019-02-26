""" Module for dealing with anything CI related """
import json
import logging
import re
import requests

from random import randint
from tests_integration.utils.config import Config

LOG = logging.getLogger(__name__)

CONFIG = Config()
ID_BROKER_HOST = 'https://' + CONFIG.ci_broker_server() + '/idb/'

# Generate a random ID for this run, so that we can prefix new CI users with it.
SESSION_ID = str(randint(0, 999))  # Inclusive

# when logging in to atlas on a web browser
CI_DEFAULT_ADMIN_SCOPES = ("Identity:SCIM "
                           "Identity:Config "
                           "Identity:Organization "
                           "webexsquare:admin "
                           "webexsquare:get_conversation "
                           "ciscouc:admin "
                           "cloudMeetings:login "
                           "webex-messenger:get_webextoken "
                           "ccc_config:admin")


def get_new_access_token(user, password):
    """
    Generate and return an Access Token
    """

    org = CONFIG.org_id()
    client_id = CONFIG.client_id()
    client_sec = CONFIG.client_secret()

    LOG.info("get_new_access_token: %s %s %s %s %s", org, user, password, client_id, client_sec)
    return get_new_access_token_with_client(org, user, password, client_id, client_sec)


def get_new_access_token_with_client(org, user, password, client_id, client_secret, scopes=None):
    """
    :param org: realm that the end user is defined in
    :param user: admin user email address
    :param password: admin password
    :param client_id:
    :param client_secret:
    :param scopes: the scopes being requested from the resource
    :return: access_token
    """

    # Get Authentication Code
    auth_code, session = get_cis_auth_code(org, user, password, CONFIG.ci_broker_server(), client_id, scopes)

    # Get Access &  Refresh\ Token
    access, refresh = get_cis_access_token(auth_code, CONFIG.ci_broker_server(), client_id, client_secret)

    return access, refresh, session


def get_cis_auth_code(org, user, passwd, cis_url, client_id, scopes=None):
    """
    For a specific user or admin user in an organization
    retrieve a authentication code. Input parameters

    - org: realm that the end user is defined in
    - user: user id
    - passwd: user password
    - cis_url: URL of CIS identity broker
    - client_id: end user client id

    Return the retrieved Authentication code

    """
    default_scopes = CI_DEFAULT_ADMIN_SCOPES

    if scopes:
        # Override default scopes
        default_scopes = scopes

    # Log a user in to Identity broker and retain resulting cookies
    # which are used in following URL requests
    sess = requests.Session()

    # Log the user on
    ci_login_url = "https://" + cis_url + "/idb/UI/Login?org=" + org
    ci_login_data = {"IDToken1": user, "IDToken2": passwd}

    LOG.info("LOGIN---------------")
    LOG.info("ci_login_url: %s", ci_login_url)
    LOG.info("token_post_data: %s", ci_login_data)

    req = sess.post(ci_login_url, ci_login_data)

    assert 'success' in req.text, "Can not find success message in request answer %s" % req.text

    # log.info("login response: %s", req.text)
    LOG.info("END LOGIN---------------")

    # Fetch an authentication code
    ci_auth_url = "https://" + cis_url + "/idb/oauth2/v1/authorize"
    ci_auth_body = {"response_type": "code",
                    "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
                    "client_id": client_id, "scope": default_scopes,
                    "realm": org,
                    "state": SESSION_ID}

    LOG.info("ci_auth_url: %s", ci_auth_url)
    LOG.info("ci_auth_body: %s", ci_auth_body)
    req_code = sess.post(ci_auth_url, ci_auth_body, timeout=None)

    assert 'code=' in req_code.text, "Can not find Authentication Code in request answer %s" % req_code.text

    LOG.info("reqCode.text: %s", req_code.text)

    match = re.search('code=(.+?)</body>', req_code.text)
    LOG.info("Authentication Code: %s", match.group(1))
    return match.group(1), sess


def get_cis_access_token(auth_code, cis_url, client_id, client_secret):
    """
    When passed an authentication code return a Access
    Token. Input parameters

    - auth_code: authentication code
    - cis_url: URL of CIS identity broken
    - client_id: client id
    - client_secret: client secret

    Returns an Access Token

    """
    # Generate an access token
    access_token_url = ("https://" + cis_url + "/idb/oauth2/v1/access_token")
    access_token_body = {"code": auth_code, "redirect_uri": "urn:ietf:wg:oauth:2.0:oob", "grant_type": "authorization_code"}

    LOG.info("reqTokenUrl: %s", access_token_url)
    LOG.info("inputData: %s", access_token_body)
    req = requests.post(access_token_url, access_token_body, auth=(client_id, client_secret))

    # If it was a success, store off SAML Token.
    if req.status_code == 200:
        LOG.info(">>> 200 ok received. ")

        assert ('access_token' in req.text), "Can not find Access Token in request answer %s" % req.text
        response_json = json.loads(req.text)
        LOG.info("Access Token: %s", response_json['access_token'])
        LOG.info("Refresh Token: %s", response_json['refresh_token'])

        return str(response_json['access_token']), str(response_json['refresh_token'])
    else:
        LOG.error("ERROR >>> Failed to get Token, response code: %d", req.status_code)
        LOG.info("ERROR >>> RESPONSE:")
        LOG.info(req.text)
        return None


def delete_ci_access_token(ci_access_token):
    """ Delete Access Token """
    delete_ci_token(ci_access_token, token_type_hint="access_token")


def delete_ci_refresh_token(ci_refresh_token):
    """ Delete Refresh Token """
    delete_ci_token(ci_refresh_token, token_type_hint="refresh_token")


def delete_ci_token(ci_token, token_type_hint="access_token"):
    """
    Delete a specific Access Token. Input parameters
    - access_token: Access token to be deleted

    Returns the status code of delete action
    - 200 indicates successfull token deletion
    """
    # Create necessary headers dict.
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    # Token Data to delete.
    input_data = {
        "token": ci_token,
        "token_type_hint": token_type_hint}

    # DELETE request to ID Broker.
    url = ID_BROKER_HOST + "oauth2/v1/revoke"
    LOG.info(">>> POST Request URL: '%s'", url)
    LOG.info(">>> DELETING Token(%s): '%s'", token_type_hint, ci_token)
    resp = requests.api.post(
        url=url,
        auth=(CONFIG.client_id(), CONFIG.client_secret()),
        headers=headers,
        data=json.dumps(input_data),
        verify=True)

    if resp.status_code == 200:
        LOG.info(">>> 200 OK received. ")
        LOG.info(">>> Token Revoked (" + token_type_hint + "): " + ci_token)
        return True
    else:
        LOG.info("ERROR >>> JSON RESPONSE:")
        LOG.info(json.dumps(resp.json(), indent=4))
        LOG.error("ERROR >>> Failed to revoke Token(%s): %s, response code: %d", token_type_hint, ci_token,
                  resp.status_code)
        return False
