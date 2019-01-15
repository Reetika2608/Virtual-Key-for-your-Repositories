
import sys

import unittest
import logging
import mock
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.platform.libraryutils import LibraryUtils
LibraryUtils.append_library_path()

from managementconnector.mgmtconnector import ManagementConnector
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
CERT_ADD_RUN = 0
CERT_CHANGED = 0

class MockConfig():
    """ Mock Config Class """

    def __init__(self):
        self.config = {}

    def write(self, path, content):
        """ Write config to database """
        self.config[path] = content

    def read(self, path):
        """ Read config from """
        return self.config[path]


def mock_deploy_fusion():
    """ Mock Deploy to prevent loop """
    pass

def mock_undeploy_fusion():
    """ Mock UnDeploy """
    pass


def get_file_size_side_effect(*args, **kwargs):
    DEV_LOGGER.info("TEST: get_file_size_side_effect: Entering with args: %s" % args)
    global CERT_CHANGED

    if args[0] == ManagementConnectorProperties.COMBINED_CA_FILE:
        if CERT_CHANGED == 0:
            DEV_LOGGER.info("TEST: RETURNING size = 10")
            return 10

        else:
            DEV_LOGGER.info("TEST: RETURNING size = 20")
            return 20
        DEV_LOGGER.info("TEST: RETURNING size = 10")
        return 10
    else:
        DEV_LOGGER.info("TEST: RETURNING size = 10")
        return 10


def config_read_certs_side_effect(*args, **kwargs):
    DEV_LOGGER.info("TEST: config_read_certs_side_effect: Entering with args: %s" % args)
    global CERT_ADD_RUN

    if args[0] == ManagementConnectorProperties.ADD_FUSION_CERTS:
        if CERT_ADD_RUN == 0:
            DEV_LOGGER.info("TEST: RETURNING true")
            CERT_ADD_RUN = 1
            return "true"
        elif CERT_ADD_RUN == 1:
            DEV_LOGGER.info("TEST: RETURNING false")
            CERT_ADD_RUN = 0
            return "false"
    elif args[0] == ManagementConnectorProperties.ENABLED_SERVICES:
        DEV_LOGGER.info("TEST: RETURNING [\"c_mgmt\"]")
        return ["c_mgmt"]
    elif args[0] == ManagementConnectorProperties.ENABLED_SERVICES_STATE:
        DEV_LOGGER.info("TEST: RETURNING {\"c_mgmt\": \"true\"}")
        return {"c_mgmt": "true"}


class ManagementConnectorTest(unittest.TestCase):
    """ Management Connector Test Class """

    @mock.patch('managementconnector.platform.logarchiver.LogArchiver.push_logs_async')
    @mock.patch('managementconnector.mgmtconnector.WatchdogThread')
    @mock.patch('managementconnector.mgmtconnector.FeatureThread')
    @mock.patch('managementconnector.mgmtconnector.ManagementConnector.toggle_features')
    @mock.patch('managementconnector.mgmtconnector.U2CThread')
    @mock.patch('managementconnector.mgmtconnector.MercuryRunner')
    @mock.patch('managementconnector.mgmtconnector.MachineAccountRunner')
    @mock.patch('managementconnector.platform.serviceutils.CafeXUtils.is_package_installing')
    @mock.patch('managementconnector.mgmtconnector.ServiceUtils.request_service_change')
    @mock.patch('managementconnector.mgmtconnector.CAFEManager')
    @mock.patch('managementconnector.mgmtconnector.Deploy')
    @mock.patch('managementconnector.mgmtconnector.Config')
    def test_on_config_update_c_mgmt(self, mock_config, mock_deploy, mock_manager, mock_request, mock_installing, mock_machine, mock_mercury, mock_u2c,  mock_toggle, mock_thread, mock_watchdog, mock_push_logs_async):
        """ Test ManagementConnector on_config_update for c_mgmt"""

        # Set Mocks
        mock_installing.return_value = False
        mc = ManagementConnector()
        mc._config = MockConfig()
        mc._deploy.deploy_fusion = mock_deploy_fusion
        mc._deploy.un_deploy_fusion = mock_undeploy_fusion
        mc._machine_runner = mock_machine
        mc._mercury_runner = mock_mercury

        mc._config.write(ManagementConnectorProperties.ADD_FUSION_CERTS, None)
        mc._config.write(ManagementConnectorProperties.ENABLED_SERVICES, ["c_mgmt"])
        mc._config.write(ManagementConnectorProperties.ENABLED_SERVICES_STATE, {"c_mgmt": "true"})
        mc.on_config_update()
        self.assertTrue(mc.deployed, msg="mc.deployed: %s" % mc.deployed)

        self.assertTrue(mock_mercury.start.called, "mercury_runner start was not called when expected, called: %s" % mock_mercury.start.called)
        self.assertTrue(mock_machine.start.called, "machine_runner start was not called when expected, called: %s" % mock_machine.start.called)

        mc._config.write(ManagementConnectorProperties.ENABLED_SERVICES_STATE, {"c_mgmt": "false"})
        mc.on_config_update()
        self.assertFalse(mc.deployed)
        mock_push_logs_async.assert_called()

    @mock.patch('managementconnector.platform.logarchiver.LogArchiver.push_logs_async')
    @mock.patch('managementconnector.platform.serviceutils.CafeXUtils.is_package_installing')
    @mock.patch('managementconnector.mgmtconnector.ServiceUtils.request_service_change')
    @mock.patch('managementconnector.mgmtconnector.CAFEManager')
    @mock.patch('managementconnector.mgmtconnector.Deploy')
    @mock.patch('managementconnector.mgmtconnector.Config')
    def test_on_config_update_c_cal(self, mock_config, mock_deploy, mock_manager, mock_request, mock_installing, mock_push_logs_async):
        """ Test ManagementConnector on_config_update for Exchange Calendar """
        service_path = "/configuration/service/name/c_cal"

        # Set Mocks
        mock_installing.return_value = False
        mc = ManagementConnector()
        mc._config = MockConfig()

        mc._config.write(ManagementConnectorProperties.ADD_FUSION_CERTS, None)
        mc._config.write(ManagementConnectorProperties.ENABLED_SERVICES, [])
        # Check Mode is set to on
        mc._config.write(ManagementConnectorProperties.ENABLED_SERVICES_STATE, {"c_cal": "true"})
        mc.on_config_update()
        mode = mc._config.read(service_path)
        self.assertTrue(mode['mode'] == "on")

        # Check Mode is set to off
        mc._config.write(ManagementConnectorProperties.ENABLED_SERVICES, ["c_cal"])
        mc._config.write(ManagementConnectorProperties.ENABLED_SERVICES_STATE, {"c_cal": "false"})
        mc.on_config_update()
        mode = mc._config.read(service_path)
        self.assertTrue(mode['mode'] == "off")
        mock_push_logs_async.assert_called()

    @mock.patch('managementconnector.platform.logarchiver.LogArchiver.push_logs_async')
    @mock.patch('managementconnector.mgmtconnector.WatchdogThread')
    @mock.patch('managementconnector.mgmtconnector.FeatureThread')
    @mock.patch('managementconnector.mgmtconnector.U2CThread')
    @mock.patch('managementconnector.mgmtconnector.ManagementConnector.toggle_features')
    @mock.patch('managementconnector.mgmtconnector.MercuryRunner')
    @mock.patch('managementconnector.mgmtconnector.MachineAccountRunner')
    @mock.patch('managementconnector.platform.serviceutils.CafeXUtils.is_package_installing')
    @mock.patch('managementconnector.mgmtconnector.ServiceUtils.request_service_change')
    @mock.patch('managementconnector.mgmtconnector.CAFEManager')
    @mock.patch('managementconnector.mgmtconnector.Deploy')
    @mock.patch('managementconnector.mgmtconnector.Config')
    def test_on_config_update_both_connectors(self, mock_config, mock_deploy, mock_manager, mock_request, mock_installing, mock_machine, mock_mercury, mock_toggle, mock_u2c_thread,  mock_feature_thread, mock_watchdog, mock_push_logs_async):
        """ Test ManagementConnector on_config_update for c_mgmt and c_cal"""
        service_path = "/configuration/service/name/c_cal"

        # Set Mocks
        mock_installing.return_value = False
        mc = ManagementConnector()
        mc._config = MockConfig()
        mc._deploy.deploy_fusion = mock_deploy_fusion
        mc._machine_runner = mock_machine
        mc._mercury_runner = mock_mercury

        mc._config.write(ManagementConnectorProperties.ADD_FUSION_CERTS, None)
        mc._config.write(ManagementConnectorProperties.ENABLED_SERVICES, [])
        mc._config.write(ManagementConnectorProperties.ENABLED_SERVICES_STATE, {"c_mgmt": "true", "c_cal": "true"})
        mc.on_config_update()
        self.assertTrue(mc.deployed)
        self.assertTrue(mock_mercury.start.called, "mercury_runner start was not called when expected, called: %s" % mock_mercury.start.called)
        self.assertTrue(mock_machine.start.called, "machine_runner start was not called when expected, called: %s" % mock_machine.start.called)
        mock_push_logs_async.assert_called()

        mode = mc._config.read(service_path)
        self.assertTrue(mode['mode'] == "on")

    @mock.patch('managementconnector.mgmtconnector.os.listdir')
    @mock.patch('managementconnector.mgmtconnector.os.path.getsize')
    @mock.patch('managementconnector.mgmtconnector.ManagementConnectorProperties.is_fusion_certs_added')
    @mock.patch('managementconnector.mgmtconnector.CAFEManager')
    @mock.patch('managementconnector.mgmtconnector.Deploy')
    @mock.patch('managementconnector.mgmtconnector.Config')
    @mock.patch('managementconnector.mgmtconnector.jsonhandler')
    @mock.patch('managementconnector.mgmtconnector.merge_certs')
    @mock.patch('managementconnector.mgmtconnector.CertHandler')
    def test_check_for_certs(self, mock_cert, mock_merge, mock_json, mock_config, mock_deploy, mock_manager, mock_cert_added, mock_getsize, mock_listdir):
        """ Check for different certs scenarios """

        global CERT_CHANGED
        # Set up Side Effects and Return Values
        global CERT_ADD_RUN
        # Managed certs
        CERT_ADD_RUN = 0
        mock_config.read.side_effect = config_read_certs_side_effect
        mock_cert_added.return_value = False
        mock_getsize.side_effect = get_file_size_side_effect

        # Create ManagementConnector and Check Defaults
        mc = ManagementConnector()
        mc._config = mock_config

        CERT_CHANGED = 0
        DEV_LOGGER.info("TEST: Checking Defaults before function call.")
        self.assertTrue(not mock_json.write_json_file.called)
        self.assertTrue(not mock_config.read.called, "mock config unexpected read, calls: %s" % mock_config.read.called)

        # Check Certs get added
        DEV_LOGGER.info("TEST: Adding Certs. CERT_ADD_RUN: %s " % CERT_ADD_RUN)
        mc.check_for_certs()

        DEV_LOGGER.info("TEST: After Add - CERT_ADD_RUN: %s " % CERT_ADD_RUN)
        mock_config.read.assert_called_with(ManagementConnectorProperties.ADD_FUSION_CERTS)
        mock_json.write_json_file.assert_called_with(ManagementConnectorProperties.FUSION_CERTS_DIR_ADD_REQUEST, "")
        mock_merge.assert_called_with([ManagementConnectorProperties.DEFAULT_EXPRESSWAY_CA_FILE,ManagementConnectorProperties.FUSION_CA_FILE],ManagementConnectorProperties.COMBINED_CA_FILE)

        # Check Certs get removed
        DEV_LOGGER.info("TEST: Removing Certs.")
        mock_cert_added.return_value = True
        mock_listdir.return_value = []
        CERT_CHANGED = 1

        mc.check_for_certs()
        DEV_LOGGER.info('TEST: After Remove - CERT_ADD_RUN: %s ' % CERT_ADD_RUN)
        mock_config.read.assert_called_with(ManagementConnectorProperties.ADD_FUSION_CERTS)
        mock_json.write_json_file.assert_called_with(ManagementConnectorProperties.FUSION_CERTS_DIR_DEL_REQUEST, "")
        mock_merge.assert_called_with([ManagementConnectorProperties.DEFAULT_EXPRESSWAY_CA_FILE],ManagementConnectorProperties.COMBINED_CA_FILE)

        # Check Same Value Case and reset mock called to False
        mock_cert_added.return_value = True
        mock_json.write_json_file.reset_mock()
        mc.all_certs_size_pre_repair = 20
        DEV_LOGGER.info("TEST: Not applying changes to Certs.")
        mc.check_for_certs()
        self.assertTrue(not mock_json.write_json_file.called)

    @mock.patch('managementconnector.mgmtconnector.U2CThread')
    @mock.patch('managementconnector.mgmtconnector.WatchdogThread')
    @mock.patch('managementconnector.mgmtconnector.FeatureThread')
    @mock.patch('managementconnector.mgmtconnector.MercuryRunner')
    @mock.patch('managementconnector.mgmtconnector.MachineAccountRunner')
    @mock.patch('managementconnector.mgmtconnector.os.listdir')
    @mock.patch('managementconnector.mgmtconnector.os.path.getsize')
    @mock.patch('managementconnector.mgmtconnector.ManagementConnectorProperties.is_fusion_certs_added')
    @mock.patch('managementconnector.mgmtconnector.CAFEManager')
    @mock.patch('managementconnector.mgmtconnector.Deploy')
    @mock.patch('managementconnector.mgmtconnector.Config')
    @mock.patch('managementconnector.mgmtconnector.jsonhandler')
    @mock.patch('managementconnector.mgmtconnector.merge_certs')
    @mock.patch('managementconnector.mgmtconnector.CertHandler')
    def _test_on_config_update_doesnt_trigger_merge_certs(self, mock_cert, mock_merge, mock_json, mock_config, mock_deploy, mock_manager,
                               mock_cert_added, mock_getsize, mock_listdir, machine_runner, mercury_runner, mock_feature, mock_watchdog, mock_u2c):
        """ Verifies that on config updates does not trigger merge certs if it is already merged - currently failing """
        DEV_LOGGER.info("TEST: test_on_config_update_doesnt_trigger_merge_certs.")
        global CERT_ADD_RUN
        # Managed certs
        CERT_ADD_RUN = 0
        mock_config.read.side_effect = config_read_certs_side_effect
        mock_cert_added.return_value = False
        mock_getsize.side_effect = get_file_size_side_effect

        # Create ManagementConnector and Check Defaults
        mc = ManagementConnector()
        mc._config = mock_config

        self.assertTrue(not mock_json.write_json_file.called)
        self.assertTrue(not mock_config.read.called, "mock config unexpected read, calls: %s" % mock_config.read.called)

        mc.check_for_certs()

        # verify we attempt to read db
        mock_config.read.assert_called_with(ManagementConnectorProperties.ADD_FUSION_CERTS)
        # verify we attempt to create folder
        mock_json.write_json_file.assert_not_called_with(ManagementConnectorProperties.FUSION_CERTS_DIR_ADD_REQUEST, "")
        mock_config.read.assert_called_with(ManagementConnectorProperties.ADD_FUSION_CERTS)
        mock_merge.assert_called_with(
            [ManagementConnectorProperties.DEFAULT_EXPRESSWAY_CA_FILE, ManagementConnectorProperties.FUSION_CA_FILE],
            ManagementConnectorProperties.COMBINED_CA_FILE)

        self.assertTrue(mock_json.write_json_file.called)

        mc.on_config_update()

        mock_merge.assert_not_called_with(
            [ManagementConnectorProperties.DEFAULT_EXPRESSWAY_CA_FILE, ManagementConnectorProperties.FUSION_CA_FILE],
            ManagementConnectorProperties.COMBINED_CA_FILE)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
