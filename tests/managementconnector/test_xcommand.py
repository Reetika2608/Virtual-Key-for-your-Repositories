"""CMgmtXCommand Test"""
import sys
import unittest
import mock
import logging
import json
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

import managementconnector.xcommand.c_mgmt_xcommand as c_mgmt


def error_queue(message):
    pass


class CMgmtXCommandTest(unittest.TestCase):
    """CMgmtXCommand Test class"""
    
    def setUp(self):
        # reload c_mgmt as xstatus and xcommand share the same module name
        # sys.path.insert(0, "/opt/c_mgmt/xcommand/")
        # reload(c_mgmt)
        pass

    def test_usage_run_invalid_option(self):
        """Test running with invalid options"""
        mock_callback = mock.MagicMock()
        c_mgmt.run("invalid_run_option", 'qwe qwe', mock_callback, None)
        expected_callback = 'Incorrect Command supplied: invalid_run_option - Current options: control, precheck, init, rollback, repair_certs, verify_signature, deregistered_check, prefuse_install, defuse'
        mock_callback.assert_called_with(expected_callback)

    @mock.patch('__builtin__.open')
    def test_mc_init(self, mock_open):
        """Test running init"""
        def mc_init():
            mock_callback = mock.MagicMock()

            cluster_id = "cluster_id"
            machine_account = '{"id":"id","url":"url","organizationId":"organizationId","password":"password","username":"username"}'
            c_mgmt.run("init", cluster_id + " " + machine_account, mock_callback, None)
            mock_oauth.return_value.create_machine_account.assert_called_with('cluster_id',json.loads(machine_account))

            with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.U2C'):
                with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.Http'):
                    with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.Config'):
                        with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.DatabaseHandler'):
                            with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.OAuth') as mock_oauth:
                                mc_init()

    def test_mc_precheck(self):
        """Test running precheck"""
        def mc_precheck():
            mock_callback = mock.MagicMock()
            c_mgmt.run("precheck", 'x', mock_callback, None)
            mock_callback.assert_called_with('Found_good_certs')

        with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.Http'):
            with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.Config'):
                mc_precheck()

    def test_mc_teardown(self):
        """Test running defuse"""
        def mc_teardown():
            mock_callback = mock.MagicMock()
            c_mgmt.run("defuse", 'abc 123', mock_callback, None)
            mock_callback.assert_called_with('Defuse Complete')

        with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.time.sleep'):
            with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.Config'):
                mc_teardown()

    def test_mc_rollback(self):
        """Test running rollback"""
        def mc_rollback():
            mock_callback = mock.MagicMock()
            c_mgmt.run("rollback", 'c_cal', mock_callback, error_queue)

        with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.time.sleep'):
            with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.Config'):
                mc_rollback()

    def test_mc_control(self):
        """Test running control command"""
        def mc_control():
            mock_callback = mock.MagicMock()
            c_mgmt.run("control", 'c_cal restart', mock_callback, error_queue)
            mock_callback.assert_called_with('c_cal restart Complete')

        with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.time.sleep'):
            with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.Config'):
                mc_control()

    @mock.patch('os.system')
    @mock.patch('managementconnector.platform.alarms.MCAlarm.clear_alarm')
    @mock.patch('managementconnector.config.config.Config.write_blob')
    def test_init_reregister(self, mock_config_write_blob, mock_clear_alarm, mock_os_system):
        """Test running init reregister"""
        def init_register():
            mock_callback = mock.MagicMock()
            cluster_id = "cluster_id"
            machine_account = '{"id":"id","url":"url","organizationId":"organizationId","password":"password","username":"username"}'

            c_mgmt.run("init", cluster_id + " " + machine_account + " " + "reregister", mock_callback, None)
            mock_config_write_blob.assert_called_with(ManagementConnectorProperties.REREGISTER, 'false')

        with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.OAuth'):
            with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.U2C'):
                with mock.patch('managementconnector.xcommand.c_mgmt_xcommand.Http'):
                    init_register()

    @mock.patch('managementconnector.config.config.Config.read')
    def test_verify_signature(self, mock_config_read):
        """Test running init reregister"""
        bootstrap_data = "eyJ1cmwiOiAidXJsIn0="  # {"url": "url"}
        bootstrap_signature = "b_ifNuBqcKtQEtNgd8m7EZWNk_LHTRdutycda_EzOM0JjNyYn6nNYt8mTUGt2LdrnGOdTbY5tuXkCpFHBFW6IAyY7Vca4JUYc1B13w-xfs2CfbKES6d7BhHze9a6Fo-hyW1hHVMfrz34CVc-voZKW_x8OhQry1kDa_M5aOecBbblAW7EHwL3GoPkAXZyn4iIux6gnECeuB_oNhsgXdxogdSzZeDH4BJ0FduxW4FiHRL-PUregAwYy6iFbHpHJByhiecOCKrto5c6zor0z35JY2bwxrU4rRlDcjr5bcmo2tWjGUJ2hmYTGhL6mkTJDv5UIogge6D2i8Hq_skG-1pdNQ=="
        mock_config_read.return_value = "true"
        mock_callback = mock.MagicMock()
        c_mgmt.run("verify_signature", bootstrap_data + " " + bootstrap_signature, mock_callback, None)
        mock_callback.assert_called_with('Successfully verified signature')


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
