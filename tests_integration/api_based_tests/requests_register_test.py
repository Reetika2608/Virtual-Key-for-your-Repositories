""" Hybrid Services Registration tests via requests library """
import datetime
import logging
import re
import unittest

from tests_integration.utils import ci
from tests_integration.utils.cdb_methods import configure_connectors, enable_expressway_connector, get_serialno, \
    set_poll_time, get_current_machine_account_password, set_machine_account_expiry
from tests_integration.utils.common_methods import wait_until, run_full_management_connector_restart, \
    wait_for_connectors_to_install
from tests_integration.utils.config import Config
from tests_integration.utils.fms import enable_cloud_fusion, deregister_cluster
from tests_integration.utils.predicates import is_blob_empty, has_machine_password_changed, are_connectors_entitled, \
    is_connector_installed, is_command_complete, is_alarm_raised
from tests_integration.utils.remote_dispatcher import dispatch_command_to_rd
from tests_integration.utils.ssh_methods import run_ssh_command, get_device_time, file_exists

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


class RequestsRegisterTest(unittest.TestCase):
    """ Hybrid Services Registration tests via requests library """
    config = None
    ci = None
    cluster_id = None
    access_token = None
    refresh_token = None
    session = None

    @classmethod
    def setUpClass(cls):
        LOG.info("Running: setUpClass")

        cls.config = Config()
        cls.access_token, cls.refresh_token, cls.session = ci.get_new_access_token(cls.config.org_admin_user(),
                                                                                   cls.config.org_admin_password())

        set_poll_time(cls.config.exp_hostname_primary(), cls.config.exp_admin_user(), cls.config.exp_admin_pass(), 9)
        cls.connector_id = "c_mgmt@" + \
                           get_serialno(
                               cls.config.exp_hostname_primary(),
                               cls.config.exp_admin_user(),
                               cls.config.exp_admin_pass())

        cls.cluster_id = enable_cloud_fusion(
            cls.config.org_id(),
            cls.config.cluster_name(),
            cls.config.fms_server(),
            cls.config.exp_hostname_primary(),
            cls.config.exp_admin_user(),
            cls.config.exp_admin_pass(),
            cls.config.expected_connectors(),
            cls.access_token,
            cls.session)

        wait_for_connectors_to_install(
            cls.config.exp_hostname_primary(),
            cls.config.exp_root_user(),
            cls.config.exp_root_pass(),
            cls.config.expected_connectors())

    @classmethod
    def tearDownClass(cls):
        LOG.info("Running: tearDownClass")
        if cls.config and cls.access_token:
            deregister_cluster(cls.config.org_id(),
                               cls.cluster_id,
                               cls.config.fms_server(),
                               cls.access_token)

        # Clean up any tokens we got at the start
        if cls.access_token:
            ci.delete_ci_access_token(cls.access_token)
        if cls.refresh_token:
            ci.delete_ci_refresh_token(cls.refresh_token)

        LOG.info("Cluster has been de-registered. Wait for cleanup to complete on %s" % cls.config.exp_hostname_primary())
        wait_until(is_blob_empty, 60, 5, *(
            cls.config.exp_hostname_primary(),
            cls.config.exp_admin_user(),
            cls.config.exp_admin_pass()))

    def test_connectors_can_be_enabled_with_correct_process_count(self):
        """
        Purpose: Verify that connectors when enabled, have the correct number of running processes
        Steps:
        1. Verify connectors are entitled
        2. Verify connectors have been installed
        3. Configure, and Enable connectors
        4. Verify that connectors are running with correct number of processes
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_connectors_can_be_enabled_with_correct_process_count.__doc__)

        self.assertTrue(wait_until(are_connectors_entitled, 60, 5, *(self.config.exp_hostname_primary(),
                                                                     self.config.exp_admin_user(),
                                                                     self.config.exp_admin_pass(),
                                                                     self.config.expected_connectors())),
                        "%s does not have the full list of entitled connectors (%s)."
                        % (self.config.exp_hostname_primary(), str(self.config.expected_connectors())))

        for connector in self.config.expected_connectors():
            self.assertTrue(wait_until(is_connector_installed, 180, 10,
                                       *(self.config.exp_hostname_primary(),
                                         self.config.exp_root_user(),
                                         self.config.exp_root_pass(),
                                         connector)),
                            "%s does not have the connector %s installed." % (self.config.exp_hostname_primary(), connector))

        configure_connectors(
            self.config.exp_hostname_primary(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass(),
            self.config.exp_root_user(),
            self.config.exp_root_pass())

        # Enable all other connectors
        for connector in self.config.expected_connectors():
            if connector != "c_mgmt":
                self.assertTrue(
                    enable_expressway_connector(
                        self.config.exp_hostname_primary(),
                        self.config.exp_admin_user(),
                        self.config.exp_admin_pass(),
                        connector),
                    "Connector %s is not enabled on %s." % (connector, self.config.exp_hostname_primary()))

            # Verify that all connectors have the correct number of running processes
            process_dict = {'c_cal': 'java',
                            'c_ucmc': 'CSI',
                            'c_mgmt': 'managementconnectormain',
                            'c_imp': 'java'}

            connector_binary = None
            if connector in process_dict:
                connector_binary = process_dict[connector]
            self.assertIsNotNone(connector_binary, "No binary defined for " + connector)

            cmd = "ps aux | grep %s | grep %s | grep -v grep | wc -l" % (connector, connector_binary)
            result = run_ssh_command(
                self.config.exp_hostname_primary(),
                self.config.exp_root_user(),
                self.config.exp_root_pass(),
                cmd)
            count = int(result.strip())
            LOG.info("%s output from %s: %d", cmd, self.config.exp_hostname_primary(), count)
            self.assertLessEqual(
                count,
                1,
                "The number of processes for connector %s on %s is %s. It should be not be greater than 1"
                % (connector, self.config.exp_hostname_primary(), count))

    def test_heartbeat_file_write(self):
        """
        Purpose:
        This test ensures that management connector writes out connector's heartbeat response to file and the
        connector user can read the file.
        Note:
            This test makes an assumption that the connectors are installed and have previously
            heartbeated at least once
        Steps:
        1. Ensure File exists
        2. Ensure file can be read
        3. Ensure file is up to date

        Notes:
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_heartbeat_file_write.__doc__)

        connector = "c_cal"
        heartbeat_file = "/var/run/c_mgmt/{}.heartbeat".format(connector)

        LOG.info("Step 1: Ensure Connectors Heartbeat file exists, connector=%s", connector)
        self.assertTrue(file_exists(
            self.config.exp_hostname_primary(),
            self.config.exp_root_user(),
            self.config.exp_root_pass(),
            heartbeat_file))

        LOG.info("Step 2: Ensure Connectors user can read heartbeat file")

        cat_heartbeat = "su _{} -s /bin/bash -c 'cat {}'".format(connector, heartbeat_file)

        results = run_ssh_command(
            self.config.exp_hostname_primary(),
            self.config.exp_root_user(),
            self.config.exp_root_pass(),
            cat_heartbeat)
        self.assertTrue(results, msg="No Content found in the .heartbeat file: {}".format(heartbeat_file))

        LOG.info("Step 3: Ensure Connectors heartbeat file is up to date")
        current_utc = get_device_time(self.config.exp_hostname_primary(), self.config.exp_root_user(),
                                      self.config.exp_root_pass())
        heartbeat_epoch = run_ssh_command(
            self.config.exp_hostname_primary(),
            self.config.exp_root_user(),
            self.config.exp_root_pass(),
            'stat -c %Y ' + heartbeat_file)

        heartbeat_time = datetime.datetime.utcfromtimestamp(float(heartbeat_epoch))
        self.assertTrue((heartbeat_time - current_utc) < datetime.timedelta(seconds=40),
                        'Server utc is %s but heartbeat file was written at %s' % (
                            str(current_utc), str(heartbeat_time)))

    def test_alarm_post(self):
        """
        Purpose:
        This test ensures that management connector alarms are sent in the heartbeat to FMS when they are raised
         on the expressway.
        Note:
            In the test alarm 60073 is raised and lowered because this is only checked by FMC once on start up
            and thus they will not interfere with one another
        Steps:
        1. Raise alarm
        2. Verify alarm is raised in FMS
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_alarm_post.__doc__)

        alarm_to_raise = "60073"

        try:
            run_ssh_command(
                self.config.exp_hostname_primary(),
                self.config.exp_root_user(),
                self.config.exp_root_pass(),
                "/sbin/alarm raise " + alarm_to_raise)

            LOG.info("Checking for alarm %s from connector %s on expressway %s", alarm_to_raise, self.connector_id,
                     self.config.exp_hostname_primary())

            def is_alarm_raised_on_exp(alarm):
                """ exp alarm raised predicate """
                alarm_list = run_ssh_command(self.config.exp_hostname_primary(),
                                             self.config.exp_root_user(),
                                             self.config.exp_root_pass(),
                                             "/sbin/alarm list")
                LOG.info("alarm raised: %s", alarm_to_raise in alarm_list)
                return alarm in alarm_list

            self.assertTrue(wait_until(is_alarm_raised_on_exp, 5, 1, alarm_to_raise),
                            "Alarm {} was not raised in time on the Expressway.".format(alarm_to_raise))

            self.assertTrue(wait_until(is_alarm_raised, 30, 1, *(self.config.org_id(),
                                                                 self.cluster_id,
                                                                 self.config.fms_server(),
                                                                 self.connector_id,
                                                                 alarm_to_raise,
                                                                 self.access_token)),
                            "Alarm {} was not raised in time.".format(alarm_to_raise))
        finally:
            run_ssh_command(
                self.config.exp_hostname_primary(),
                self.config.exp_root_user(),
                self.config.exp_root_pass(),
                "/sbin/alarm lower " + alarm_to_raise)

    def test_check_file_permissions(self):
        """
        Purpose: Check connectors file permissions.
        Steps:
        1. For each Expressway in the cluster verify that all feature connectors files have correct permissions.
        Notes:
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_check_file_permissions.__doc__)

        for connector in self.config.expected_connectors():
            if connector != 'c_mgmt':
                opt_conn_perms = {'.': 'drwxr--r--',
                                  'bin': 'drwxr--r--',
                                  'etc': 'drwxr--r--',
                                  'install': 'drwxr--r--'}

                opt_root_perms = {'..': 'drwxr-xr-x'}

                etc_conn_perms = {'/etc/init.d/%s' % connector: '-rwxr--r--'}

                LOG.info('Check init.d script permissions')

                results = run_ssh_command(
                    self.config.exp_hostname_primary(),
                    self.config.exp_root_user(),
                    self.config.exp_root_pass(),
                    'ls -lah /etc/init.d/%s' % connector)

                LOG.info('Check init.d script permissions')
                etc_user = "_%s" % connector

                for path, perm in etc_conn_perms.items():
                    LOG.info("Check user and permissions of '%s'", path)
                    pattern = '(%s).*?(%s).*?(%s).*?(%s)' % (perm, etc_user, etc_user, path)
                    regex = re.compile(pattern)
                    match = regex.search(results)
                    self.assertIsNotNone(match, "User or permissions of %s are not correct. The actual values are %s."
                                         % (path, results))

                LOG.info("Check opt user permissions")

                results = run_ssh_command(
                    self.config.exp_hostname_primary(),
                    self.config.exp_root_user(),
                    self.config.exp_root_pass(),
                    'ls -lah /mnt/harddisk/current/opt/%s' % connector)

                for path, perm in opt_conn_perms.items():
                    LOG.info("Check user and permissions of '%s'.", path)
                    pattern = '(%s).*?(%s).*?(%s).*?(%s)' % (perm, etc_user, etc_user, path)
                    regex = re.compile(pattern)
                    match = regex.search(results)

                    self.assertIsNotNone(match, "User or permissions of %s are not correct. The actual values are %s."
                                         % (path, results))

                LOG.info("Check opt root permissions")
                root_user = "root"
                for path, perm in opt_root_perms.items():
                    LOG.info("Check user and permissions of '%s'.", path)
                    pattern = '(%s).*?(%s).*?(%s).*?(%s)' % (perm, root_user, root_user, path)
                    regex = re.compile(pattern)
                    match = regex.search(results)

                    self.assertIsNotNone(match, "User or permissions of %s are not correct. The actual values are %s."
                                         % (path, results))

    def test_remote_dispatcher_ping_command(self):
        """
        Purpose: Verify that a connector can process a ping command from RemoteDispatcher
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_remote_dispatcher_ping_command.__doc__)

        command_id = dispatch_command_to_rd(
            self.config.org_id(),
            self.connector_id,
            self.config.rd_server(),
            {"action": "ping"},
            self.access_token)

        self.assertTrue(wait_until(is_command_complete, 20, 1, *(
            self.config.org_id(),
            self.connector_id,
            self.config.rd_server(),
            command_id,
            self.access_token)),
                        "Command {} was not completed in time.".format(command_id))

    def test_machine_password_rotation(self):
        """
        Purpose: Verify that management connector can rotate its machine account password
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_machine_password_rotation.__doc__)
        try:
            current_password = get_current_machine_account_password(
                self.config.exp_hostname_primary(),
                self.config.exp_admin_user(),
                self.config.exp_admin_pass())
            LOG.info("Current machine account password: %s" % current_password)

            # By default management connector will rotate its password when there are 45 days left until expiry. This
            # number of days can be configured in the DB. Set it to something ludicrously high like 500 and restart
            # the connector. The rotation logic should be triggered
            LOG.info("Set the password rotation to 500 days and restart the connector")
            set_machine_account_expiry(
                self.config.exp_hostname_primary(),
                self.config.exp_admin_user(),
                self.config.exp_admin_pass(),
                500)
            run_full_management_connector_restart(
                self.config.exp_hostname_primary(),
                self.config.exp_root_user(),
                self.config.exp_root_pass())

            self.assertTrue(wait_until(has_machine_password_changed, 30, 1, *(
                self.config.exp_hostname_primary(),
                self.config.exp_admin_user(),
                self.config.exp_admin_pass(),
                current_password)),
                            "Password {} was not changed in time.".format(current_password))

            LOG.info("Password was successfully changed to %s" % get_current_machine_account_password(
                self.config.exp_hostname_primary(),
                self.config.exp_admin_user(),
                self.config.exp_admin_pass()))
        finally:
            LOG.info("Set the password rotation back to 45 days")
            set_machine_account_expiry(
                self.config.exp_hostname_primary(),
                self.config.exp_admin_user(),
                self.config.exp_admin_pass(),
                45)
