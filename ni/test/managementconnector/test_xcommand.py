"""CMgmtXCommand Test"""
import sys
import unittest
import mock
import logging
import json

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

# sys.path.append("/opt/c_mgmt/xcommand/")
# import c_mgmt
import ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand as c_mgmt

class ErrorQueue():
    def __init__(self):
        _error = None

    def put(self, arg):
        _error = arg

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
        c_mgmt.run("invalid_run_option", 'qwe qwe', None, mock_callback, None)
        expected_callback = 'Incorrect Command supplied: invalid_run_option - Current options: control, precheck, init, rollback, repair_certs, deregistered_check, prefuse_install, defuse'
        mock_callback.assert_called_with(expected_callback)

    @mock.patch('__builtin__.open')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.U2C')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Http')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.OAuth')
    def test_mc_init(self, mock_oauth, mock_config, mock_http, mock_u2c, mock_open):
        """Test running init"""
        mock_callback = mock.MagicMock()

        cluster_id = "cluster_id"
        machine_account = '{"id":"id","url":"url","organizationId":"organizationId","password":"password","username":"username"}'
        c_mgmt.run("init", cluster_id + " " + machine_account, None, mock_callback, None)
        mock_oauth.return_value.create_machine_account.assert_called_with('cluster_id',json.loads(machine_account))

    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Http')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config')
    def test_mc_precheck(self, mock_config, mock_http):
        """Test running precheck"""
        mock_callback = mock.MagicMock()
        c_mgmt.run("precheck", 'x', None, mock_callback, None)
        mock_callback.assert_called_with('Found_good_certs')

    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.time.sleep')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config')
    def test_mc_teardown(self, mock_config, mock_sleep):
        """Test running defuse"""
        mock_rest_cdb_adaptor = mock.MagicMock()
        mock_callback = mock.MagicMock()
        c_mgmt.run("defuse", 'abc 123', mock_rest_cdb_adaptor, mock_callback, None)
        mock_callback.assert_called_with('Defuse Complete')

    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.time.sleep')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config')
    def test_mc_rollback(self, mock_config, mock_sleep):
        """Test running rollback"""
        mock_rest_cdb_adaptor = mock.MagicMock()
        mock_callback = mock.MagicMock()
        error_queue = ErrorQueue()
        c_mgmt.run("rollback", 'c_cal', mock_rest_cdb_adaptor, mock_callback, error_queue)
        #mock_callback.assert_called_with('Rollback Complete')

    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.time.sleep')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config')
    def test_mc_control(self, mock_config, mock_sleep):
        """Test running control command"""
        mock_rest_cdb_adaptor = mock.MagicMock()
        mock_callback = mock.MagicMock()
        error_queue = ErrorQueue()
        c_mgmt.run("control", 'c_cal restart', mock_rest_cdb_adaptor, mock_callback, error_queue)
        mock_callback.assert_called_with('c_cal restart Complete')

    @mock.patch('os.system')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.U2C')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Http')
    @mock.patch('ni.managementconnector.platform.alarms.MCAlarm.clear_alarm')
    @mock.patch('ni.managementconnector.config.config.Config.write_blob')
    @mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.OAuth')
    def test_init_reregister(self, mock_oauth, mock_config_write_blob, mock_clear_alarm, mock_http, mock_u2c, mock_os_system):
        """Test running init reregister"""
        mock_callback = mock.MagicMock()
        cluster_id = "cluster_id"
        machine_account = '{"id":"id","url":"url","organizationId":"organizationId","password":"password","username":"username"}'

        c_mgmt.run("init", cluster_id + " " + machine_account + " " + "reregister", None, mock_callback, None)
        mock_config_write_blob.assert_called_with(ManagementConnectorProperties.REREGISTER, 'false')

if __name__ == "__main__":
   logging.basicConfig(level=logging.DEBUG)
   unittest.main()
