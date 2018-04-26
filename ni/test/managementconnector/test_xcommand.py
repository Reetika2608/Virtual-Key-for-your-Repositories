"""CMgmtXCommand Test"""
import sys
import unittest
import mock
import logging
import json

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

try:
    sys.path.append("/opt/c_mgmt/xcommand/")
    import c_mgmt
except ImportError:
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
    def test_mc_init(self, mock_open):
        """Test running init"""
        def mc_init():
            mock_callback = mock.MagicMock()

            cluster_id = "cluster_id"
            machine_account = '{"id":"id","url":"url","organizationId":"organizationId","password":"password","username":"username"}'
            c_mgmt.run("init", cluster_id + " " + machine_account, None, mock_callback, None)
            mock_oauth.return_value.create_machine_account.assert_called_with('cluster_id',json.loads(machine_account))

        try:
            with mock.patch('c_mgmt.U2C'):
                with mock.patch('c_mgmt.Http'):
                    with mock.patch('c_mgmt.Config'):
                        with mock.patch('c_mgmt.OAuth') as mock_oauth:
                            mc_init()
        except ImportError:
            with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.U2C'):
                with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Http'):
                    with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config'):
                        with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.OAuth') as mock_oauth:
                            mc_init()

    def test_mc_precheck(self):
        """Test running precheck"""
        def mc_precheck():
            mock_callback = mock.MagicMock()
            c_mgmt.run("precheck", 'x', None, mock_callback, None)
            mock_callback.assert_called_with('Found_good_certs')

        try:
            with mock.patch('c_mgmt.Http'):
                with mock.patch('c_mgmt.Config'):
                    mc_precheck()
        except ImportError:
            with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Http'):
                with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config'):
                    mc_precheck()

    def test_mc_teardown(self):
        """Test running defuse"""
        def mc_teardown():
            mock_rest_cdb_adaptor = mock.MagicMock()
            mock_callback = mock.MagicMock()
            c_mgmt.run("defuse", 'abc 123', mock_rest_cdb_adaptor, mock_callback, None)
            mock_callback.assert_called_with('Defuse Complete')

        try:
            with mock.patch('c_mgmt.time.sleep'):
                with mock.patch('c_mgmt.Config'):
                    mc_teardown()
        except ImportError:
            with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.time.sleep'):
                with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config'):
                    mc_teardown()

    def test_mc_rollback(self):
        """Test running rollback"""
        def mc_rollback():
            mock_rest_cdb_adaptor = mock.MagicMock()
            mock_callback = mock.MagicMock()
            error_queue = ErrorQueue()
            c_mgmt.run("rollback", 'c_cal', mock_rest_cdb_adaptor, mock_callback, error_queue)
            #mock_callback.assert_called_with('Rollback Complete')

        try:
            with mock.patch('c_mgmt.time.sleep'):
                with mock.patch('c_mgmt.Config'):
                    mc_rollback()
        except ImportError:
            with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.time.sleep'):
                with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config'):
                    mc_rollback()


    def test_mc_control(self):
        """Test running control command"""
        def mc_control():
            mock_rest_cdb_adaptor = mock.MagicMock()
            mock_callback = mock.MagicMock()
            error_queue = ErrorQueue()
            c_mgmt.run("control", 'c_cal restart', mock_rest_cdb_adaptor, mock_callback, error_queue)
            mock_callback.assert_called_with('c_cal restart Complete')

        try:
            with mock.patch('c_mgmt.time.sleep'):
                with mock.patch('c_mgmt.Config'):
                    mc_control()
        except ImportError:
            with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.time.sleep'):
                with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Config'):
                    mc_control()

    @mock.patch('os.system')
    @mock.patch('ni.managementconnector.platform.alarms.MCAlarm.clear_alarm')
    @mock.patch('ni.managementconnector.config.config.Config.write_blob')
    def test_init_reregister(self, mock_config_write_blob, mock_clear_alarm, mock_os_system):
        """Test running init reregister"""
        def init_register():
            mock_callback = mock.MagicMock()
            cluster_id = "cluster_id"
            machine_account = '{"id":"id","url":"url","organizationId":"organizationId","password":"password","username":"username"}'

            c_mgmt.run("init", cluster_id + " " + machine_account + " " + "reregister", None, mock_callback, None)
            mock_config_write_blob.assert_called_with(ManagementConnectorProperties.REREGISTER, 'false')

        try:
            with mock.patch('c_mgmt.OAuth'):
                with mock.patch('c_mgmt.U2C'):
                    with mock.patch('c_mgmt.Http'):
                        init_register()
        except ImportError:
            with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.OAuth'):
                with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.U2C'):
                    with mock.patch('ni.files.opt.c_mgmt.xcommand.c_mgmt_xcommand.Http'):
                        init_register()


if __name__ == "__main__":
   logging.basicConfig(level=logging.DEBUG)
   unittest.main()
