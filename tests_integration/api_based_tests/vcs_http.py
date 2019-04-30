"""
Helper that maintains a logged in HTTP session to a VCS and allows testers
to perform certain scenarios over the web interface without the use of a
browser.
"""

import logging
import re
from urlparse import urlparse, parse_qs

import requests

log = logging.getLogger(name="vcs_http")

# Regex search strings to look for in HTML
POST_FORM_SESSIONID = (
    '<input type="hidden" name="sessionid" id="sessionid" value="(\S+)"/>'
)

FUSE_VCS_ALREADY_REGISTERED = (
    '<span>This Expressway cluster is registered with'
    ' the Cisco Collaboration Cloud.</span>'
)

FUSE_VCS_SUCCESS = (
    '<td.*><b>Success</b>: Registered.*</td>'
)

FUSE_VCS_FAILURE = (
    '<td.*><b>Failed</b>:(.*)</td>'
)

SET_PROXY_SUCCESS = (
    '<td.*><b>Success</b>: Saved</td>'
)


class VCSHttpError(Exception):
    pass


def log_and_exit(response, error_msg):
    print(error_msg)
    print(response)
    print(response.url)
    assert False


class VCSHttpSession(object):
    """Maintains a logged in HTTP session to a VCS"""

    def __init__(self, hostname, username, password, trust_env=False):
        self.hostname = hostname
        self.username = username
        self.password = password
        # trust_env is a bool value passed on to the requests.Session
        # It tells requests whether to use the os env variables or not. Default
        # to "False" so that http_proxy env variables are ignored.
        self.trust_env = trust_env
        self.session = None
        self._reset_session()

    def set_session(self, session):
        """Manually change the requests session in use"""
        self.session = session
        self.session.trust_env = self.trust_env

    def _reset_session(self):
        """Erase & reset the requests session being used"""
        self.session = requests.Session()
        self.session.trust_env = self.trust_env

    def _login(self):
        """Authenticate to the VCS using HTTP. Cookies from the auth'd session
           are stored in self.session
        """
        log.info("Logging in to VCS web interface")
        login_data = {
            'submitbutton': 'Login',
            'username': self.username,
            'password': self.password,
            'formbutton': 'Login'
        }
        url = "https://" + self.hostname + "/login"
        r = self.session.post(
            url=url,
            data=login_data,
            verify=False,
            allow_redirects=False
        )
        ck = self.session.cookies.keys()
        log.info("Cookies obtained: %s" % str(ck))
        if 'SHARPID' not in ck or 'tandberg_login' not in ck:
            msg = "VCS login failed."
            log_and_exit(r, msg)

    def verify_login(fn):
        """Decorator to ensure user is logged in on HTTP session"""

        def _verify_login_decorator(self, *args, **kwargs):
            url = "https://" + self.hostname + "/overview"
            r = self.session.get(url, verify=False)
            ck = self.session.cookies.keys()
            if 'SHARPID' not in ck or 'tandberg_login' not in ck:
                self._login()
            fn(self, *args, **kwargs)

        return _verify_login_decorator

    def _get_sessionid(self, response):
        """Given an HTTP response, check the page and search for a
            session ID to use in a POST

            Returns session id (str) or None
        """
        re_search = POST_FORM_SESSIONID
        m = re.search(re_search, response.text)
        if not m:
            return None
        return m.groups()[0]

    @verify_login
    def enable_hybrid_services(self, bootstrap_data):
        """Enable hybrid services. You should call set_session() first to set
        the http requests.Session to one with cookies from a logged in Teams
        admin
        """
        s = self.session
        # GET fusionregistration page
        log.info("HTTP GET to /fusionregistration to get sessionid")
        url = "https://" + self.hostname + "/fusionregistration?" + bootstrap_data
        r = s.get(url, verify=False)
        # Check to see if the VCS is already registered.
        re_search = FUSE_VCS_ALREADY_REGISTERED
        m = re.search(re_search, r.text)
        if m:
            msg = "The VCS is already registered!"
            log_and_exit(r, msg)
        # Otherwise, search for session id to use in POST
        sess_id = self._get_sessionid(r)
        if not sess_id:
            msg = "Unable to get sessionid from /fusionregistration page"
            log_and_exit(r, msg)

        # POST to fusionregistration
        # (click the "Update software & verify connection" button)
        # Note that box to allow VCS to download hybrid services certs is
        # checked.
        log.info("HTTP POST to /fusionregistration to initiate register")
        url = "https://" + self.hostname + "/fusionregistration"
        data = {
            'submitbutton': "Update software & verify connection",
            'formbutton': "Update software & verify connection",
            'sessionid': sess_id,
            'use_fusion_ca': 'use'
        }
        r = s.post(url=url, data=data, verify=False)

        # POST to fusionregistration (click the "Register" button)
        data = {
            'submitbutton': "Register",
            'formbutton': "Register",
            'sessionid': sess_id,
            'use_fusion_ca': 'use'
        }
        r = s.post(url=url, data=data, verify=False)

        # This POST should redirect 3 times.
        # 1) Initial POST, HTTP 303 response (response[0])
        # 2) GET to idbroker for auth API, HTTP 302 response (response[1])
        # 3) GET to hercules /fuse_redirect, HTTP 302 response
        # 4) GET to hercules /html/fuse_redirect.html       
        if not r.history:
            msg = "Expected HTTP redirects after POST to /fusionregistration"
            log_and_exit(r, msg)
        if 'fuse_redirect' not in r.url:
            log.error("Final url in HTTP flow is '%s', expecting"
                      " fuse_redirect" % r.url)
            msg = "POST to /fusionregistration not redirected properly"
            log_and_exit(r, msg)

        # Pull out the access token from the URL received in response to HTTP
        # request #2 (this is r.history[1])
        try:
            redirect_url = r.history[1].headers['Location']
        except IndexError:
            log.error("Could not find location header in response to GET"
                      " to idbroker authorize API")
            msg = "POST to /fusionregistration not redirected properly"
            log_and_exit(r, msg)
        log.debug("Redirect URL: %s" % redirect_url)
        parsed_url = urlparse(redirect_url)
        log.debug("Parsed URL: %s" % str(parsed_url))
        url_params = parse_qs(parsed_url.fragment)

        # Pull out the hercules hostname used in this request (e.g.
        # hercules-a.wbx2.com or hercules-intb.ciscospark.com)
        url_host = '{uri.scheme}://{uri.netloc}'.format(uri=parsed_url)
        try:
            token = url_params['access_token'][0]
        except (KeyError, IndexError):
            msg = "Failed to find access token in register attempt"
            log_and_exit(r, msg)
        try:
            state = url_params['state'][0]
        except (KeyError, IndexError):
            msg = "Failed to find state in register attempt"
            log_and_exit(r, msg)
        log.debug("Token used for CI register: %s" % token)
        log.debug("State used for CI register: %s" % state)

        # Send a POST to FMS redirect_data to see the result of the
        # fuse attempt
        log.info("HTTP POST to /redirect_data to see registration result")
        url = url_host + "/redirect_data"
        data = {
            'access_token': token,
            'state': state
        }
        r = s.post(url=url, json=data)
        if r.status_code != 200:
            msg = "VCS registration failed, expected 200OK response"
            log_and_exit(r, msg)

        # 200OK response was received, now do the equivalent of pressing
        # "Allow" button.
        log.info("200OK response received")
        try:
            r_json = r.json()
            url = r_json['redirect_uri_with_token']
        except (KeyError, ValueError):
            msg = "Unexpected data in redirect_data response"
            log_and_exit(r, msg)

        # Send a GET to the 'redirect_uri_with_token' (back to the VCS)
        # This will HTTP 303 redirect us back to the fusionregistration page
        log.info("HTTP GET back to VCS with registration token")
        r = s.get(url=url, verify=False)
        if r.status_code != 200:
            msg = ("Registration error, expected 200OK response")
            log_and_exit(r, msg)
        log.info("200OK response received, verifying result on VCS web page")

        # Check to see if there is a failure message in the HTML content
        re_search = FUSE_VCS_FAILURE
        m = re.search(re_search, r.text)
        if m:
            reason = m.groups()[0]
            log.error("Reason: %s" % reason)
            msg = ("VCS register confirmation page contains failure message: %s"
                   % reason)
            log_and_exit(r, msg)

        # Verify the success message is on the page
        re_search = FUSE_VCS_SUCCESS
        m = re.search(re_search, r.text)
        if not m:
            msg = "Registration success message not found on VCS web page"
            log_and_exit(r, msg)
        else:
            log.info("VCS registration succeeded!")

    @verify_login
    def revive_expressway(self):
        """Enable hybrid services. You should call set_session() first to set
        the http requests.Session to one with cookies from a logged in Teams
        admin
        """
        s = self.session
        # GET fusionregistration page
        log.info("HTTP GET to /fusionregistration to get sessionid")
        url = "https://" + self.hostname + "/fusionregistration"
        r = s.get(url, verify=False)
        sess_id = self._get_sessionid(r)
        if not sess_id:
            msg = "Unable to get sessionid from /fusionregistration page"
            log_and_exit(r, msg)

        # POST to fusionregistration (click the "Register" button)
        data = {
            'submitbutton': "Re-Register",
            'formbutton': "Re-Register",
            'sessionid': sess_id
        }
        r = s.post(url=url, data=data, verify=False)

        # This POST should redirect 3 times.
        # 1) Initial POST, HTTP 303 response (response[0])
        # 2) GET to idbroker for auth API, HTTP 302 response (response[1])
        # 3) GET to hercules /fuse_redirect, HTTP 302 response
        # 4) GET to hercules /html/fuse_redirect.html
        if not r.history:
            msg = "Expected HTTP redirects after POST to /fusionregistration"
            log_and_exit(r, msg)
        if 'fuse_redirect' not in r.url:
            log.error("Final url in HTTP flow is '%s', expecting"
                      " fuse_redirect" % r.url)
            msg = "POST to /fusionregistration not redirected properly"
            log_and_exit(r, msg)

        # Pull out the access token from the URL received in response to HTTP
        # request #2 (this is r.history[1])
        try:
            redirect_url = r.history[1].headers['Location']
        except IndexError:
            log.error("Could not find location header in response to GET"
                      " to idbroker authorize API")
            msg = "POST to /fusionregistration not redirected properly"
            log_and_exit(r, msg)
        log.debug("Redirect URL: %s" % redirect_url)
        parsed_url = urlparse(redirect_url)
        log.debug("Parsed URL: %s" % str(parsed_url))
        url_params = parse_qs(parsed_url.fragment)

        # Pull out the hercules hostname used in this request (e.g.
        # hercules-a.wbx2.com or hercules-intb.ciscospark.com)
        url_host = '{uri.scheme}://{uri.netloc}'.format(uri=parsed_url)
        try:
            token = url_params['access_token'][0]
        except (KeyError, IndexError):
            msg = "Failed to find access token in register attempt"
            log_and_exit(r, msg)
        try:
            state = url_params['state'][0]
        except (KeyError, IndexError):
            msg = "Failed to find state in register attempt"
            log_and_exit(r, msg)
        log.debug("Token used for CI register: %s" % token)
        log.debug("State used for CI register: %s" % state)

        # Send a POST to FMS redirect_data to see the result of the
        # fuse attempt
        log.info("HTTP POST to /redirect_data to see registration result")
        url = url_host + "/redirect_data"
        data = {
            'access_token': token,
            'state': state
        }
        r = s.post(url=url, json=data)
        if r.status_code != 200:
            msg = "VCS registration failed, expected 200OK response"
            log_and_exit(r, msg)

        # 200OK response was received, now do the equivalent of pressing
        # "Allow" button.
        log.info("200OK response received")
        try:
            r_json = r.json()
            url = r_json['redirect_uri_with_token']
        except (KeyError, ValueError):
            msg = "Unexpected data in redirect_data response"
            log_and_exit(r, msg)

        # Send a GET to the 'redirect_uri_with_token' (back to the VCS)
        # This will HTTP 303 redirect us back to the fusionregistration page
        log.info("HTTP GET back to VCS with registration token")
        r = s.get(url=url, verify=False)
        if r.status_code != 200:
            msg = ("Registration error, expected 200OK response")
            log_and_exit(r, msg)
        log.info("200OK response received, verifying result on VCS web page")

        # Check to see if there is a failure message in the HTML content
        re_search = FUSE_VCS_FAILURE
        m = re.search(re_search, r.text)
        if m:
            reason = m.groups()[0]
            log.error("Reason: %s" % reason)
            msg = ("VCS register confirmation page contains failure message: %s"
                   % reason)
            log_and_exit(r, msg)

        # Verify the success message is on the page
        re_search = FUSE_VCS_SUCCESS
        m = re.search(re_search, r.text)
        if not m:
            msg = "Registration success message not found on VCS web page"
            log_and_exit(r, msg)
        else:
            log.info("VCS registration succeeded!")

    @verify_login
    def set_hybrid_services_proxy(self, address, port,
                                  username=None, password=None):
        """Set proxy on VCS for hybrid services"""
        log.info("Setting proxy on VCS %s:%s user: %s pw: %s"
                 % (address, port, username, password))
        s = self.session
        url = "https://" + self.hostname + "/fusionproxy"
        r = s.get(url=url, verify=False, allow_redirects=False)
        sess_id = self._get_sessionid(r)
        if not sess_id:
            msg = "Unable to get sessionid from /fusionproxy page"
            log_and_exit(r, msg)
        data = {
            'sessionid': sess_id,
            'submitbutton': "Save",
            'pwd_is_changed': "1",
            'enabled': "true",
            'address': address,
            'port': port,
            'username': username if username else "",
            'password': password if password else "",
        }
        r = s.post(url=url, data=data, verify=False)
        re_search = SET_PROXY_SUCCESS
        m = re.search(re_search, r.text)
        if not m:
            msg = "Failed to set proxy on VCS"
            log_and_exit(r, msg)
        else:
            log.info("Proxy set on VCS successfully")

    def unset_hybrid_services_proxy(self):
        """Unset proxy on VCS for hybrid services"""
        log.info("Clearing proxy settings on VCS")
        s = self.session
        url = "https://" + self.hostname + "/fusionproxy"
        r = s.get(url=url, verify=False, allow_redirects=False)
        sess_id = self._get_sessionid(r)
        if not sess_id:
            msg = "Unable to get sessionid from /fusionproxy page"
            log_and_exit(r, msg)
        data = {
            'sessionid': sess_id,
            'submitbutton': "Save",
            'pwd_is_changed': "1",
            'enabled': "false",
            'address': "",
            'port': "",
            'username': "",
            'password': "",
        }
        r = s.post(url=url, data=data, verify=False)
        re_search = SET_PROXY_SUCCESS
        m = re.search(re_search, r.text)
        if not m:
            msg = "Failed to unset proxy on VCS"
            log_and_exit(r, msg)
        else:
            log.info("Proxy unset on VCS successfully")
