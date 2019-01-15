import unittest
import sys
import logging
import mock
import json
import jsonschema
from StringIO import StringIO
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
logging.getLogger().addHandler(SYS_LOG_HANDLER)

import managementconnector.platform.http as http
import managementconnector.config.config as config
from managementconnector.cloud import schema

class HTTPTest(unittest.TestCase):
    """ Management Connector HTTP Test Class """
        
    def setUp(self):
        """ Manamgent Connector Test Setup """
        http.Http.init(config.Config())
        http._http_request = _http_request # mock out http request
        
        http.DEV_LOGGER.debug('***TEST Setup***')

    def test_requests(self):
        """ Test Management Connector Started """
        
        http.DEV_LOGGER.debug('***TEST*** test_requests')

        url = "http://www.cisco_foo.com/request"
        headers = {'Content-Type': 'application/json'}

        response = http.Http.get(url, headers)
        self.assertTrue(response['foo'], "GET")

        data = "data 1"
        response = http.Http.post(url, headers, data)
        self.assertTrue(response['foo'], "POST")

        data = "data 1"
        response = http.Http.put(url, headers, data)
        self.assertTrue(response['foo'], "PUT")

        response = http.Http.delete(url, headers)
        self.assertTrue(response['foo'], "DELETE")

    @mock.patch('managementconnector.platform.http.Http._config.read')
    @mock.patch('managementconnector.platform.http.uuid.uuid4')
    def test_create_tracking_id(self, mock_uuid4, mock_config_read):
        """ Test create_tracking_id"""
        
        mock_uuid4.return_value = 'd15ca292-e38c-11e4-a85e-180373e48c59'
        mock_config_read.return_value = '52A00618'
        expected_tracking_id = 'EXP_' + 'd15ca292-e38c-11e4-a85e-180352A00618'
        self.assertEqual(http.Http.create_tracking_id(), expected_tracking_id)

        mock_uuid4.return_value = 'd15ca292-e38c-11e4-a85e-180373e48c59'
        mock_config_read.return_value = None
        expected_tracking_id = 'EXP_' + mock_uuid4.return_value
        self.assertEqual(http.Http.create_tracking_id(), expected_tracking_id)

    @mock.patch('managementconnector.platform.http.ManagementConnectorProperties')
    @mock.patch('managementconnector.platform.http.taacrypto.decrypt_with_system_key')
    @mock.patch('managementconnector.platform.http.Http._config.read')
    def test_get_proxy(self, mock_config_read, mock_decrypt, mock_properties):
        """ Test get_proxy """
        http.DEV_LOGGER.debug('***TEST*** test_get_proxy')

        mock_properties.PROXY_ADDRESS = 'address'
        mock_properties.PROXY_PORT = 'port'
        mock_properties.PROXY_USERNAME = 'username'
        mock_properties.PROXY_ENABLED = 'enabled'
        mock_properties.PROXY_PASSWORD = 'password'

        proxy_config = {
            'address': '1.2.3.4',
            'port': '3128',
            'username': 'cafe',
            'password': 'cafe',
            'enabled' : 'true'
        }        

        def proxy_config_read(key):
            try:
                return proxy_config[key]
            except KeyError:
                return None

        mock_config_read.side_effect = proxy_config_read
        mock_decrypt.return_value = proxy_config['password']        
    
        self.assertDictEqual(proxy_config, http.Http.get_proxy())

        # If there is no address or port configured, get_proxy should return None
        proxy_config.pop('address')
        self.assertEqual(None, http.Http.get_proxy())

        proxy_config.pop('port')
        self.assertEqual(None, http.Http.get_proxy())

    @mock.patch('managementconnector.platform.http.Http.get_proxy')
    def test_install_urllib_opener(self, mock_get_proxy):
        """ Test proxy is configured """
        http.DEV_LOGGER.debug('***TEST*** test_install_urllib_opener')

        config = {
            'address': '1.2.3.4',
            'port': '3128',
            'username': 'cafe',
            'password': 'cafe',
            'enabled' : 'true'
        }

        mock_get_proxy.return_value = config

        http.Http.install_urllib_opener()
        # There must be a proxy handler
        self.assertTrue(any(isinstance(handler, http.urllib2.ProxyHandler) for handler in http.urllib2._opener.handlers))

        # Proxy handler must have the correct config as defined above
        for handler in http.urllib2._opener.handlers:
            if isinstance(handler, http.urllib2.ProxyHandler):
                self.assertEqual(handler.proxies, {'https': 'cafe:cafe@1.2.3.4:3128'})

    @mock.patch('managementconnector.platform.http.Http.get_proxy')
    def test_enable_disable_proxy(self, mock_get_proxy):
        """ Test proxy is enabled and disabled """
        http.DEV_LOGGER.debug('***TEST*** test_enable_disable_proxy')
        config = {
            'address': u'1.2.3.4',
            'port': u'3128',
            'username': u'cafe',
            'password': 'cafe',
            'enabled' : u'true'
        }

        mock_get_proxy.return_value = config
        http.Http.install_urllib_opener()
        # There must be a proxy handler
        self.assertTrue(any(isinstance(handler, http.urllib2.ProxyHandler) for handler in http.urllib2._opener.handlers))

        config['enabled'] = u'false'
        http.Http.install_urllib_opener()
        # There must be no proxy handler
        self.assertFalse(any(isinstance(handler, http.urllib2.ProxyHandler) for handler in http.urllib2._opener.handlers))

    def test_validate_json_response(self):
        """ Test validating json response """
        http.DEV_LOGGER.debug('***TEST*** test_validate_json_response')

        url = "http://www.cisco_foo.com/request"
        headers = {'Content-Type': 'application/json'}

        good_bearer_token_response = {
            u'BearerToken': u'YjcyMDliN2UtNGUyOC00YzM5LThmMDUtNmQ4YjdlY2YxNmQ1YzJjYTBhNTQtMTU3'
        }

        bad_bearer_token_response = {
            u'BearerToken': 456
        }

        good_access_token_response = {
            u'token_type': u'Bearer', 
            u'refresh_token_expires_in': 5183999, 
            u'access_token': u'OThmOTgyMzctZDBhMi00ZmY1LWE3ZmItMDQxNzk4NDNkOTVmOTdlYjJmY2MtZTlk', 
            u'expires_in': 43199, 
            u'refresh_token': u'N2NiM2I1ZjAtZDlmYi00NzRlLWFmOGMtN2YwNmJiZGNjMTkyOTlmMmMyYjUtNjk1'
        }

        bad_access_token_response = {
            u'token_type': u'Bearer', 
            u'refresh_token_expires_in': 5183999, 
            u'access_token': 5183999, 
            u'expires_in': 43199, 
            u'refresh_token': u'N2NiM2I1ZjAtZDlmYi00NzRlLWFmOGMtN2YwNmJiZGNjMTkyOTlmMmMyYjUtNjk1'
        }

        good_refresh_access_token_response = {
            u'expires_in': 43199, 
            u'token_type': u'Bearer', 
            u'access_token': u'OThmOTgyMzctZDBhMi00ZmY1LWE3ZmItMDQxNzk4NDNkOTVmOTdlYjJmY2MtZTlk', 
            u'refresh_token_expires_in': 5183999
        }

        bad_refresh_access_token_response = {
            # u'expires_in': 43199, 
            u'token_type': u'Bearer', 
            u'access_token': u'OThmOTgyMzctZDBhMi00ZmY1LWE3ZmItMDQxNzk4NDNkOTVmOTdlYjJmY2MtZTlk', 
            u'refresh_token_expires_in': 5183999
        }

        good_register_response = {
        u'display_name': u'Fusion Management', 
        u'connector_type': u'c_mgmt', 
        u'version': u'X8.6PreAlpha0 (Test SW)', 
        u'provisioning': {u'connectors': [{u'connector_type': u'c_cal', 
                                           u'display_name': u'Calendar Service', 
                                           u'packages': [{u'tlp_url': u'https://7f3b835a2983943a12b7-f3ec652549fc8fa11516a139bfb29b79.ssl.cf5.rackcdn.com/OpenJDK/20150430231431/d_openj.tlp'}] 
                                          }],
                         u'dependencies': [{u'tlpUrl': u'https://7f3b835a2983943a12b7-f3ec652549fc8fa11516a139bfb29b79.ssl.cf5.rackcdn.com/OpenJDK/20150430231431/d_openj.tlp', 
                                           u'dependencyType': u'd_dependency', 
                                           u'version': u'testVersion'
                                          }],
                         u'heartbeatInterval': 20
                         }
        }

        bad_register_response = {
        u'display_name': 5183999, 
        u'connector_type': u'c_mgmt', 
        u'version': u'X8.6PreAlpha0 (Test SW)', 
        u'provisioning': {u'connectors': [{u'connector_type': u'c_cal', 
                                           u'display_name': u'Calendar Service', 
                                           u'packages': [{u'tlp_url': u'https://7f3b835a2983943a12b7-f3ec652549fc8fa11516a139bfb29b79.ssl.cf5.rackcdn.com/OpenJDK/20150430231431/d_openj.tlp'}] 
                                          }],
                         u'dependencies': [{u'tlpUrl': u'https://7f3b835a2983943a12b7-f3ec652549fc8fa11516a139bfb29b79.ssl.cf5.rackcdn.com/OpenJDK/20150430231431/d_openj.tlp', 
                                           u'dependencyType': u'd_dependency', 
                                           u'version': u'testVersion'
                                          }],
                         u'heartbeatInterval': 20
                         }
        }

        good_bearer_token_response_raw = StringIO(json.dumps(good_bearer_token_response))
        bad_bearer_token_response_raw = StringIO(json.dumps(bad_bearer_token_response))
        good_access_token_response_raw = StringIO(json.dumps(good_access_token_response))
        bad_access_token_response_raw = StringIO(json.dumps(bad_access_token_response))
        good_register_response_raw = StringIO(json.dumps(good_register_response))
        bad_register_response_raw = StringIO(json.dumps(bad_register_response))
        good_refresh_access_token_response_raw = StringIO(json.dumps(good_refresh_access_token_response))
        bad_refresh_access_token_response_raw = StringIO(json.dumps(bad_refresh_access_token_response))

        try:
            http.Http.post(url, headers, good_bearer_token_response_raw, silent=True, schema=schema.BEARER_TOKEN_RESPONSE)
        except jsonschema.ValidationError:
            self.fail('good_bearer_token_response test failed')

        try:
            http.Http.post(url, headers, good_access_token_response_raw, silent=True, schema=schema.ACCESS_TOKEN_RESPONSE)
        except jsonschema.ValidationError:
            self.fail('good_access_token_response test failed')

        try:
            http.Http.post(url, headers, good_register_response_raw, schema=schema.MANAGEMENT_CONNECTOR_REGISTER_RESPONSE)
        except jsonschema.ValidationError:
            self.fail('good_register_response test failed')

        try:
            http.Http.post(url, headers, good_refresh_access_token_response_raw, schema=schema.REFRESH_ACCESS_TOKEN_RESPONSE)
        except jsonschema.ValidationError:
            self.fail('good_refresh_access_token_response test failed')


        with self.assertRaises(jsonschema.ValidationError):
            http.Http.post(url, headers, bad_bearer_token_response_raw, silent=True, schema=schema.BEARER_TOKEN_RESPONSE)

        with self.assertRaises(jsonschema.ValidationError):
            http.Http.post(url, headers, bad_access_token_response_raw, silent=True, schema=schema.ACCESS_TOKEN_RESPONSE)

        with self.assertRaises(jsonschema.ValidationError):
            http.Http.post(url, headers, bad_register_response_raw, schema=schema.MANAGEMENT_CONNECTOR_REGISTER_RESPONSE)

        with self.assertRaises(jsonschema.ValidationError):
            http.Http.post(url, headers, bad_refresh_access_token_response_raw, schema=schema.REFRESH_ACCESS_TOKEN_RESPONSE)


def _http_request(url, headers, data, request_type, silent=False, schema=None, load_validate_json=True):
    ''' used for mock test intercept'''

    if schema is not None:
        http._validate_json_response(data, schema)

    if request_type == 'GET':
        return {'foo': "GET"}
    elif  request_type == 'POST':
        return {'foo': "POST"}
    elif  request_type == 'PUT':
        return {'foo': "PUT"}
    elif  request_type == 'DELETE':
        return {'foo': "DELETE"}
    else:
        raise Exception("bad error")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()