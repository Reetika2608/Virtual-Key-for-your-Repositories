import unittest
import sys
import logging
import mock

sys.path.append("/opt/c_mgmt/bin/")

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.service.service import Service, DisableException
from ni.managementconnector.config.config import Config

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class ServiceTest(unittest.TestCase):
    """ Service Test Class """

    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch('ni.managementconnector.service.service.CafeXUtils')
    def test_requires_refresh(self, mock_cafeutils, mock_get_system_mem):

        mock_cafeutils.is_package_installed.return_value = True
        mock_cafeutils.get_package_version.return_value = "version"
        config = Config()
        service = Service('some_name', config, None)

        version = 'version'

        service.set_install_details("url", version)

        self.assertFalse(service.requires_refresh(version))
        self.assertTrue(service.requires_refresh("new_version"))

        mock_cafeutils.is_package_installed.return_value = True
        self.assertFalse(service.requires_refresh(version))

     # -------------------------------------------------------------------------

    @mock.patch('ni.managementconnector.service.service.register_default_loggers')
    @mock.patch('ni.managementconnector.service.service.ServiceUtils.cache_service_cdb_schema')
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch('ni.managementconnector.service.service.ServiceUtils.is_supported_extension')
    @mock.patch('ni.managementconnector.service.service.ManagementConnectorProperties.EXPRESSWAY_FULL_VERSION')
    @mock.patch('ni.managementconnector.service.service.time')
    @mock.patch('ni.managementconnector.service.service.EventSender.post')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.service.service.Service._download')
    @mock.patch('ni.managementconnector.service.service.Service._install')
    @mock.patch('ni.managementconnector.service.service.Service.uninstall')
    @mock.patch('ni.managementconnector.service.service.Service.disable')
    @mock.patch('ni.managementconnector.service.service.CafeXUtils')
    def test_configure(self, mock_cafeutils, mock_disable, mock_uninstall, mock_install, mock_download, mock_oauth, mock_sender, mock_time, mock_platform, mock_serviceutils, mock_get_system_mem, mock_cache_service_cdb_schema, mock_register_default_loggers):
        config = Config(False)
        service = Service('c_xyz', config, mock_oauth)

        mock_cafeutils.get_package_version.return_value = '2.0'
        mock_cafeutils.is_package_installed.return_value = True
        mock_cafeutils.is_backup_restore_occurring.return_value = False
        mock_install.return_value = 98765
        mock_uninstall.return_value = True
        mock_disable.return_value = True
        mock_download.return_value = "path", 54321, 12345
        mock_serviceutils.return_value = True

        upgrade_disabled_from_fms = False

        service.configure("some_url", "2.0", upgrade_disabled_from_fms)
        self.assertFalse(mock_install.called, "Install should not have been called.")
        self.assertTrue(mock_cafeutils.is_backup_restore_occurring.called, "Backup occurring should have been called.")
        self.assertFalse(mock_sender.called, "Event Post should not have been called")

        service.configure("some_url", "3.0", upgrade_disabled_from_fms)
        self.assertTrue(mock_install.called, "Install should have been called.")
        self.assertTrue(mock_cafeutils.is_backup_restore_occurring.called, "Backup occurring should have been called.")

        details = {"fields": {"downloadDuration": 12345, "fileSize": 54321, "url": "some_url", "installDuration": 98765,
                              "platformVersion": mock_platform, "connectorVersion": "3.0"},
                   "measurementName": 'connectorUpgradeEvent', "tags": {"state": 'success', "connectorType": "c_xyz"}}
        mock_sender.assert_called_with(mock_oauth, config, "connectorUpgrade", "c_mgmt", 1, details)

    @mock.patch('ni.managementconnector.service.service.DatabaseHandler')
    @mock.patch('ni.managementconnector.service.service.register_default_loggers')
    @mock.patch('ni.managementconnector.service.service.ServiceUtils.cache_service_cdb_schema')
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch('ni.managementconnector.service.service.CafeXUtils')
    def test_disable(self, mock_cafeutils, mock_get_system_mem, mock_cache_service_cdb_schema, mock_register_default_loggers, mock_delete_enabled_service_blob):

        service = Service('c_xyz', Config(), None)

        mock_cafeutils.is_connector_running.return_value = True
        mock_cafeutils.get_package_version.return_value = "2.0"

        try:
            service.disable(1)
        except DisableException as e:

            details = e.args[0]

            d = {'message': 'Could not disable service', 'version': "2.0", 'name': 'c_xyz'}
            self.assertEqual(d, details)

    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch('ni.managementconnector.service.service.ServiceUtils')
    @mock.patch('ni.managementconnector.service.service.CafeXUtils')
    @mock.patch('ni.managementconnector.config.config.Config')
    def test_get_composed_status(self, mock_config, mock_cafeutils, mock_serviceutils, mock_get_system_mem):

        DEV_LOGGER.info("***TEST*** test_get_composed_status")

        service = Service('c_xyz',  mock_config, None)

        mock_serviceutils.is_configured_status.return_value = True
        mock_serviceutils.get_version.return_value = "1.0"

        mock_cafeutils.is_package_installed.return_value = False
        mock_cafeutils.is_connector_running.return_value = True
        mock_cafeutils.get_operation_status.return_value = "True"
        mock_cafeutils.is_connector_enabled.return_value = True

        mock_config.read.return_value = None
        mock_cafeutils.is_connector_enabled.return_value = False

        mock_serviceutils.is_installing.return_value = "installing"
        self.assertTrue(service.get_composed_status(False) == 'installing')

        mock_serviceutils.is_installing.return_value = None
        mock_cafeutils.is_package_installed.return_value = False
        self.assertTrue(service.get_composed_status(False) == 'not_installed')

        mock_cafeutils.is_package_installed.return_value = True
        mock_serviceutils.is_configured_status.return_value = False
        self.assertTrue(service.get_composed_status(False) == 'not_configured')

        mock_serviceutils.is_configured_status.return_value = True
        self.assertTrue(service.get_composed_status(False) == 'disabled')

        mock_cafeutils.is_connector_enabled.return_value = True
        self.assertTrue(service.get_composed_status(False) == 'running')

        mock_cafeutils.is_connector_running.return_value = False
        self.assertTrue(service.get_composed_status(False) == 'stopped')

    def test_get_composed_status_running_and_not_configured_displays_not_configured(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure composed state displays not configured when not configured and stopped
        Notes:
        """
        status = {'version': "12345",
                  'enabled': True,
                  'installing': None,
                  'installed': True,
                  'running': True,
                  'operational_status': True,
                  'configured': False}

        self.assertEquals(Service._get_composed_state(status), "not_configured")

    def test_get_composed_status_stopped_and_not_configured_displays_not_configured(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure composed state displays not configured when not configured and stopped
        Notes:
        """
        status = {'version': "12345",
                  'enabled': True,
                  'installing': None,
                  'installed': True,
                  'running': False,
                  'operational_status': True,
                  'configured': False}

        self.assertEquals(Service._get_composed_state(status), "not_configured")

    def test_get_composed_status_stopped_and_configured_displays_stopped(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure composed state displays stopped when not running and configured
        Notes:
        """
        status = {'version': "12345",
                  'enabled': True,
                  'installing': None,
                  'installed': True,
                  'running': False,
                  'operational_status': True,
                  'configured': True}

        self.assertEquals(Service._get_composed_state(status), "stopped")

    def test_legacy_get_composed_status_stopped_and_not_configured_displays_stopped(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure composed state displays stopped for legacy and ignores configured state
        Notes:
        """
        status = {'version': "12345",
                  'enabled': True,
                  'installing': None,
                  'installed': True,
                  'running': False,
                  'operational_status': True,
                  'configured': False}

        self.assertEquals(Service._handle_legacy_composed_state(status), "stopped")

    def test_legacy_get_composed_status_stopped_and_configured_displays_stopped(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure composed state displays stopped for legacy and ignores configured state
        Notes:
        """
        status = {'version': "12345",
                  'enabled': True,
                  'installing': None,
                  'installed': True,
                  'running': False,
                  'operational_status': True,
                  'configured': True}

        self.assertEquals(Service._handle_legacy_composed_state(status), "stopped")

    @mock.patch('ni.managementconnector.config.config.Config')
    def test_related_external_alarm(self, mock_config):
        mock_config.read.return_value = [{'display_name': u'c_mgmt', 'name': u'c_mgmt'},
                                         {'display_name': u'c_Cal', 'name': u'c_cal'},
                                         {'display_name': u'c_ucmc', 'name': u'c_ucmc'}]

        alarm = {"parameters": [u"/path/to/c_ucmc", 1234]}
        self.assertTrue(Service.is_related_external_alarm(alarm, mock_config), "This is a related external alarm.")

        alarm = {"parameters": [u"something_happened_to_some_other_process", 1234]}
        self.assertFalse(Service.is_related_external_alarm(alarm, mock_config), "This is a not related external alarm.")

        alarm = {"parameters": [u"something happened to c_cal"]}
        self.assertTrue(Service.is_related_external_alarm(alarm, mock_config), "This is a related external alarm.")

        alarm = {"parameters": []}
        self.assertFalse(Service.is_related_external_alarm(alarm, mock_config), "This is a not related external alarm.")

    @mock.patch('ni.managementconnector.service.service.register_default_loggers')
    @mock.patch('ni.managementconnector.service.service.ServiceUtils.cache_service_cdb_schema')
    @mock.patch("ni.managementconnector.platform.system.System.get_system_mem")
    @mock.patch('ni.managementconnector.service.service.ManagementConnectorProperties.EXPRESSWAY_VERSION')
    @mock.patch('ni.managementconnector.service.service.EventSender')
    @mock.patch('ni.managementconnector.cloud.oauth.OAuth')
    @mock.patch('ni.managementconnector.service.service.Service._handle_legacy_uninstall',)
    @mock.patch('ni.managementconnector.service.service.ServiceUtils')
    @mock.patch('ni.managementconnector.config.config.Config.read')
    @mock.patch('ni.managementconnector.service.service.Service._download')
    @mock.patch('ni.managementconnector.service.service.Service._install')
    @mock.patch('ni.managementconnector.service.service.Service.uninstall')
    @mock.patch('ni.managementconnector.service.service.Service.disable')
    @mock.patch('ni.managementconnector.service.service.CafeXUtils')
    def test_configure_prevent_connector(self, mock_cafeutils, mock_disable, mock_uninstall, mock_install, mock_download, mock_config, mock_serviceutils, mock_leg, mock_oath, mock_sender, mock_platform, mock_get_system_mem, mock_cache_service_cdb_schema, mock_register_default_loggers):
        service = Service('c_xyz', Config(), mock_oath)

        mock_cafeutils.get_package_version.return_value = '2.0'
        mock_cafeutils.is_package_installed.return_value = True
        mock_cafeutils.is_backup_restore_occurring.return_value = False
        mock_install.return_value = True
        mock_uninstall.return_value = True
        mock_disable.return_value = True
        mock_download.return_value = "path", "fileSize", "downloadDuration"
        mock_config.return_value = ['c_xyz','c_ucmc']
        mock_serviceutils.is_supported_extension.return_value = True

        upgrade_disabled_from_fms = False

        # Connector upgrade prevented
        service.configure("some_url", "2.0", upgrade_disabled_from_fms)
        self.assertFalse(mock_install.called, "Install should not have been called.")
        self.assertFalse(mock_cafeutils.is_backup_restore_occurring.called, "Backup occurring should have been called.")

        # Connector upgrade prevented
        mock_config.return_value = 'c_xyz'
        service.configure("some_url", "2.0", upgrade_disabled_from_fms)
        self.assertFalse(mock_install.called, "Install should not have been called.")
        self.assertFalse(mock_cafeutils.is_backup_restore_occurring.called, "Backup occurring should have been called.")

        # Connector upgrade prevented
        mock_serviceutils.is_supported_extension.return_value = False
        service.configure("some_url", "2.0", upgrade_disabled_from_fms)
        self.assertFalse(mock_install.called, "Install should not have been called.")
        self.assertFalse(mock_cafeutils.is_backup_restore_occurring.called, "Backup occurring should have been called.")
        mock_serviceutils.is_supported_extension.return_value = True

        # Connectors prevented list not empty but current connector not in list
        mock_config.return_value = 'c_ucmc'
        service.configure("some_url", "3.0", upgrade_disabled_from_fms)
        self.assertTrue(mock_install.called, "Install should have been called.")
        self.assertTrue(mock_cafeutils.is_backup_restore_occurring.called, "Backup occurring should have been called.")
        self.assertTrue(mock_serviceutils.request_service_change.called, "Backup occurring should have been called.")

        # Connectors prevented list not empty but current connector not in list
        mock_config.return_value = ['c_ucmc']
        service.configure("some_url", "3.0", upgrade_disabled_from_fms)
        self.assertTrue(mock_install.called, "Install should have been called.")
        self.assertTrue(mock_cafeutils.is_backup_restore_occurring.called, "Backup occurring should have been called.")
        self.assertTrue(mock_serviceutils.request_service_change.called, "Backup occurring should have been called.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
