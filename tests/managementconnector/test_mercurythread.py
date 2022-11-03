"""
    Test MercuryThread
"""

import logging
import mock
import sys
import unittest

from .constants import SYS_LOG_HANDLER

# Pre-import a mocked pyinotify
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

# Append all required paths to the syspath for library imports.
from managementconnector.platform.libraryutils import LibraryUtils
LibraryUtils.append_library_path()

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud.mercury import Mercury
from managementconnector.lifecycle.mercurythread import MercuryThread

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
MIGRATION_STATUS_STARTED = False

def migration_status_side_effect():
    return False

class MercuryThreadTest(unittest.TestCase):
    """ Unit test class for MercuryThread """

    @mock.patch('threading.Event')
    @mock.patch('managementconnector.lifecycle.mercurythread.Mercury')
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.check_migration_status')
    def test_mercury_registration_exception(self, mock_migration_check, mock_config, mock_merc, mock_event):
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
        mock_migration_check.return_value = False
        mercury_thread._do_heartbeat()
        mock_merc.handle_mercury_exception.assert_called_with(exception)
        self.assertTrue(mock_event.wait.called, msg="Event wait was not called as expected, called: %s" % mock_event.wait.called)

    @mock.patch('threading.Event')
    @mock.patch('managementconnector.lifecycle.mercurythread.Mercury')
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.check_migration_status')
    def test_mercury_heartbeat_with_migration(self, mock_migration_check, mock_config, mock_merc, mock_event):
        """ Test mercury doesn't heartbeat during migration"""
        DEV_LOGGER.info("***TEST*** test_migration_stops_mercury_heartbeat")

        mercury_thread = MercuryThread(mock_config, mock_event)
        mercury_thread._oauth_init = True
        mercury_thread._mercury_connection = mock_merc
        mock_migration_check.return_value = True
        mercury_thread._do_heartbeat()
        self.assertFalse(mock_merc.heartbeat.called, 'failed')

    @mock.patch('threading.Event')
    @mock.patch('managementconnector.lifecycle.mercurythread.Mercury')
    @mock.patch('managementconnector.config.config.Config')
    @mock.patch('managementconnector.cloud.federationorgmigration.FederationOrgMigration.check_migration_status')
    def test_mercury_heartbeat_without_migration(self, mock_migration_check, mock_config, mock_merc, mock_event):
        """ Test mercury doesn't heartbeat during migration"""
        DEV_LOGGER.info("***TEST*** test_no_migration_mercury_heartbeat")

        mercury_thread = MercuryThread(mock_config, mock_event)
        mercury_thread._oauth_init = True
        mercury_thread._mercury_connection = mock_merc
        mock_migration_check.return_value = False
        mercury_thread._do_heartbeat()
       
        mock_merc.heartbeat.assert_called_once()

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