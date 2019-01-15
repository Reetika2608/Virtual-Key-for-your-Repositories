"""
    Test MercuryThread
"""

import io
import logging
import mock
import sys
import unittest

from urllib2 import HTTPError
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
logging.getLogger().addHandler(SYS_LOG_HANDLER)

# Append all required paths to the syspath for library imports.
from managementconnector.platform.libraryutils import LibraryUtils
LibraryUtils.append_library_path()

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud.mercury import Mercury
from managementconnector.lifecycle.mercurythread import MercuryThread

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class MercuryThreadTest(unittest.TestCase):
    """ Unit test class for MercuryThread """

    @mock.patch('threading.Event')
    @mock.patch('managementconnector.lifecycle.mercurythread.Mercury')
    @mock.patch('managementconnector.config.config.Config')
    def test_mercury_registration_exception(self, mock_config, mock_merc, mock_event):
        """
            User Story: US11651 FMC Hardening of WDM/Mercury Integration
            Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                        in order to create multiple objects in other threads.
        """
        DEV_LOGGER.info("***TEST*** test_mercury_registration_exception")

        exception = Exception()

        mercury_thread = MercuryThread(mock_config, mock_event)
        mercury_thread._oauth_init = True
        mercury_thread._mercury_connection = mock_merc
        mock_merc.heartbeat.side_effect = exception

        mercury_thread._do_heartbeat()

        mock_merc.handle_mercury_exception.assert_called_with(exception)
        self.assertTrue(mock_event.wait.called, msg="Event wait was not called as expected, called: %s" % mock_event.wait.called)

    @mock.patch('threading.Event')
    @mock.patch('managementconnector.platform.http.Http.get_proxy')
    @mock.patch('managementconnector.cloud.mercury.websocket.WebSocketApp')
    @mock.patch('managementconnector.cloud.oauth.OAuth')
    @mock.patch('managementconnector.config.config.Config')
    def test_on_config_update_proxy(self, mock_config, mock_oauth, mock_web, mock_proxy, mock_event):
        """
            User Story: US11651 FMC Hardening of WDM/Mercury Integration
            Notes:      Moved machine account refresh to separate thread to decouple from the OAuth object,
                        in order to create multiple objects in other threads.
        """

        config = {
            'address': '1.2.3.4',
            'port': '3128',
            'username': 'cafe',
            'password': 'cafe',
            'enabled': 'true'
        }

        mock_proxy.return_value = config
        merc = Mercury(mock_config, mock_oauth)
        merc._ws = mock_web

        mercury_thread = MercuryThread(mock_config, mock_event)
        mercury_thread._mercury_connection = merc

        mercury_thread.on_config_update()

        self.assertTrue(mock_web.close.called, "Websocket close not called as expected: %s" % mock_web.close.called)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()