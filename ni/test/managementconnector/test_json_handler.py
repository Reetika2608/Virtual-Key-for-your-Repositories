""" Test JSON Handler """

import logging
import json
import unittest
import mock
from mock import mock_open, patch

from ni.managementconnector.config.jsonhandler import JsonHandler
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.config import jsonhandler

from sys import version_info
if version_info.major == 2:
    import __builtin__ as builtins
else:
    import builtins

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


SAMPLE_CONFIG = '''\
{\
    "config": '{\"error_poll_time\": 60, \"poll_time\": 30, \"register_url\": \"www.somewhere.com\" }',\
    "oauth":\
    {\
        "idp_host": "idbroker.webex.com",\
        "client_id": "Cb34745f09072748be251803ca89227b443949ef9710f3ce317311d6d394b619b",\
        "client_secret": "4c01a69c1abd780fd8f4da808d68c52d74ffc13869d75fa8c6076813c6ca4c11"\
    }\
}\
'''


def get_config(path):
    """
    Return predefined config as json
    Strip out Single quotes to allow json to parse string
    """
    DEV_LOGGER.info('get_config: Mocking out file read')
    js_clean = SAMPLE_CONFIG.replace("'", "")
    return json.loads(js_clean)



class JsonHandlerTest(unittest.TestCase):
    """ Management Connector Config Handler Test Class """

    def setUp(self):
        """ setUp """

        self.set_mock_config()

        self.json_handler = JsonHandler(ManagementConnectorProperties.CONFIG_FILE_LOCATION, False)
      

        # Create JsonHandler object with no inotify
        # If template and or json config exists don't set mock

    def tearDown(self):
        jsonhandler._get_config = self.orig_json_handler_get_config 

    def set_mock_config(self):
        """ Sets Mock requests for get, post and delete. """

        # Can't cleanly intercept first get config as it's in __init__
        # So change method and call for update
        self.orig_json_handler_get_config = jsonhandler._get_config
        jsonhandler._get_config = get_config


        #self.config_handler.file_notify_path = "managementconnector.json"

    def test_ouath_config(self):
        """ Test getting OAuth config from Config file """

        outh_config = self.json_handler.get_oauth_config()
        idp_host = "idbroker.webex.com"
        client_id = "Cb34745f09072748be251803ca89227b443949ef9710f3ce317311d6d394b619b"
        client_secret = "4c01a69c1abd780fd8f4da808d68c52d74ffc13869d75fa8c6076813c6ca4c11"

        self.assertTrue(outh_config['idp_host'] == idp_host,
                        msg="idp_host did not match: Expected %s, Actual: %s" % (idp_host, outh_config['idp_host']))

        self.assertTrue(outh_config['client_id'] == client_id,
                        msg="client_id did not match: Expected %s, Actual: %s" % (client_id, outh_config['client_id']))

        self.assertTrue(outh_config['client_secret'] == client_secret,
                        msg="client_secret did not match: Expected %s, Actual: %s" % (client_secret,
                                                                                      outh_config['client_secret']))

    def test_get_register_url(self):
        """ Test get register url """
        DEV_LOGGER.info('test_get_register_url')
        expected_url = u"www.somewhere.com"

        register_url = self.json_handler.get_register_url()
        self.assertTrue(register_url == expected_url, msg="Register URL didn't match. Expected: %s - value: %s" %
                                                          (expected_url, register_url))

    def test_get_poll_time(self):
        """ Test get register url """
        DEV_LOGGER.info('test_get_poll_time')
        expected_time = 30

        poll_time = self.json_handler.get_poll_time()
        self.assertTrue(poll_time == expected_time, msg="Poll time didn't match: Expected %s Actual: %s" %
                                                        (expected_time, poll_time))

    def test_get_error_poll_time(self):
        """ Test get register url """
        DEV_LOGGER.info('test_get_error_poll_time')
        expected_error_time = 60

        error_poll_time = self.json_handler.get_error_poll_time()
        self.assertTrue(error_poll_time == expected_error_time, msg="Error Poll time didn't match: Expected %s Actual: "
                                                                    "%s" % (expected_error_time, error_poll_time))

    def test_get(self):
        """ Test generic get method """
        DEV_LOGGER.info('test_get_error_poll_time')

        DEV_LOGGER.info('Checking not there level 1')
        parts = ["not-there"]
        not_there = self.json_handler.get(parts)
        self.assertTrue(not_there is None, msg="Not there is not None")

        DEV_LOGGER.info('Checking not there level 2')
        parts = ["config", "not-there"]
        not_there = self.json_handler.get(parts)
        self.assertTrue(not_there is None, msg="Not there is not None")

        expected = "www.somewhere.com"

        parts = ["config", "register_url"]

        text_register_url = self.json_handler.get(parts)

        self.assertTrue(text_register_url == expected, msg="Error Poll time didn't match: Expected %s Actual: %s, actual_type=%s"
                                                         % (expected, text_register_url, type(text_register_url)))

    def test_get_int(self):
        """ Test generic get_int method """
        expected = 60

        parts = ["config", "error_poll_time"]

        error_poll_time = self.json_handler.get_int(parts)

        self.assertTrue(error_poll_time == expected, msg="Error Poll time didn't match: Expected %s Actual: %s, actual_type=%s"
                                                         % (expected, error_poll_time, type(error_poll_time)))

    @mock.patch('json.load')
    def test_json_value_error_get_config(self, j_load):
        """ Test JSON get_config with json value error"""
        DEV_LOGGER.info('test_json_value_error - raise ValueError - invalid json')
        j_load.return_value = ValueError()

        parts = ["doesn't matter"]
        value = self.json_handler.get(parts)

        DEV_LOGGER.info('test_json_value_error - parts: %s, value: %s' % (parts, value))
        self.assertIsNone(value)

    @mock.patch('json.load')
    def test_json_io_error(self, j_load):
        """ Test JSON get_config with io error"""
        DEV_LOGGER.info('test_json_io_error - raise IOError - config does not exist')
        j_load.return_value = IOError()

        parts = ["doesn't matter"]
        value = self.json_handler.get(parts)

        DEV_LOGGER.info('test_json_io_error - parts: %s, value: %s' % (parts, value))
        self.assertIsNone(value)

    def test_json_value_error_read_json_file(self):
        """ Test JSON read_json_file with json value error"""
        DEV_LOGGER.info('test_json_value_error_read_json_file - raise ValueError - invalid json')
        
        with patch.object(builtins, 'open', mock_open(read_data='')):
            value = jsonhandler.read_json_file("foobar.txt")
        self.assertIsNone(value)
        

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
