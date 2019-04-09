import datetime
import re
import unittest
import uuid

from tests_integration.utils import ci
from tests_integration.utils.cdb_methods import clear_rollback_blacklist, get_serialno, get_logging_host_url, \
    set_logging_entry_to_blob, set_machine_account_expiry, get_current_machine_account_password, get_cluster_id
from tests_integration.utils.common_methods import wait_until_true, get_log_data_from_atlas, \
    run_full_management_connector_restart
from tests_integration.utils.config import Config
from tests_integration.utils.integration_test_logger import get_logger
from tests_integration.utils.predicates import is_connector_installed, can_connector_be_rolled_back, \
    has_version_changed, is_blob_empty, has_connector_pid_changed, is_blacklist_empty, is_alarm_raised, \
    is_command_complete, has_machine_password_changed
from tests_integration.utils.remote_dispatcher import dispatch_command_to_rd
from tests_integration.utils.ssh_methods import rollback_connector, get_installed_connector_version, \
    get_connector_pid, run_ssh_command, get_device_time, file_exists

LOG = get_logger()


class RegisteredTest(unittest.TestCase):
    """ Hybrid Services tests on a registered system """
    config = None
    access_token = None
    refresh_token = None
    session = None
    cluster_id = None

    @classmethod
    def setUpClass(cls):
        LOG.info("Running: setUpClass")
        cls.config = Config()
        cls.access_token, cls.refresh_token, cls.session = ci.get_new_access_token(cls.config.org_admin_user(),
                                                                                   cls.config.org_admin_password())
        cls.connector_id = "c_mgmt@" + get_serialno(cls.config.exp_hostname_primary(),
                                                    cls.config.exp_admin_user(),
                                                    cls.config.exp_admin_pass())
        cls.cluster_id = get_cluster_id(cls.config.exp_hostname_primary(),
                                        cls.config.exp_admin_user(),
                                        cls.config.exp_admin_pass())

    @classmethod
    def tearDownClass(cls):
        LOG.info("Running: tearDownClass")
        # Clean up any tokens we got at the start
        if cls.access_token:
            ci.delete_ci_access_token(cls.access_token)
        if cls.refresh_token:
            ci.delete_ci_refresh_token(cls.refresh_token)

    def test_rollback_and_upgrade_of_management_connector(self):
        """
        Rollback and re-upgrade management connector
        Steps:
        1. Check that we are fused, the expected connectors are installed and that we can rollback c_mgmt
        2. Get the current installed version and PID and then initiate the rollback xcommand
        3. Wait and assert that:
            a. The installed version changes
            b. The connector reaches a fully installed state
            c. The PID changes
        4. Get the new installed version and PID and clear the rollback blacklist to allow the connector to upgrade
        5. Wait and assert that:
            a. The installed version changes
            b. The connector reaches a fully installed state
            c. The PID changes
        6. Assert that the rollback TLPs are recycled back to to current & previous directories and that
           it is possible to rollback again if we need to
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_rollback_and_upgrade_of_management_connector.__doc__)

        # 1. Check that we are fused, the expected connectors are installed and that we can rollback c_mgmt
        self.assertFalse(is_blob_empty(self.config.exp_hostname_primary(),
                                       self.config.exp_admin_user(),
                                       self.config.exp_admin_pass()),
                         "cafeblobconfiguration is empty in CDB. Is %s fused?" % self.config.exp_hostname_primary())
        for connector in self.config.expected_connectors():
            self.assertTrue(wait_until_true(is_connector_installed, 10, 1,
                                            *(self.config.exp_hostname_primary(),
                                              self.config.exp_root_user(),
                                              self.config.exp_root_pass(),
                                              connector)),
                            "%s does not have the connector %s installed." %
                            (self.config.exp_hostname_primary(), connector))
        self.assertTrue(can_connector_be_rolled_back(self.config.exp_hostname_primary(),
                                                     self.config.exp_root_user(),
                                                     self.config.exp_root_pass(),
                                                     "c_mgmt"),
                        "c_mgmt does not have candidate TLPs in previousversions & currentversions directories")

        # 2. Get the current installed version and PID and then initiate the rollback xcommand
        current_version = get_installed_connector_version(self.config.exp_hostname_primary(),
                                                          self.config.exp_root_user(),
                                                          self.config.exp_root_pass(),
                                                          "c_mgmt")
        current_pid = get_connector_pid(self.config.exp_hostname_primary(),
                                        self.config.exp_root_user(),
                                        self.config.exp_root_pass(),
                                        "c_mgmt")
        self.assertIsNotNone(current_version, "Could not get the version management connector installed on %s"
                             % self.config.exp_hostname_primary())
        self.assertIsNotNone(current_pid, "Could not get the PID of management connector on %s"
                             % self.config.exp_hostname_primary())
        LOG.info("Current installed FMC version is %s and current PID is %s", current_version, current_pid)
        try:
            self.assertTrue(rollback_connector(self.config.exp_hostname_primary(),
                                               self.config.exp_root_user(),
                                               self.config.exp_root_pass(),
                                               "c_mgmt"),
                            "c_mgmt did not rollback successfully")

            # 3. Wait and assert that:
            #     a. The installed version changes
            #     b. The connector reaches a fully installed state
            #     c. The PID changes
            self.assertTrue(wait_until_true(has_version_changed, 30, 1, *(self.config.exp_hostname_primary(),
                                                                          self.config.exp_root_user(),
                                                                          self.config.exp_root_pass(),
                                                                          "c_mgmt",
                                                                          current_version)),
                            "c_mgmt did not roll back in time and is still running version %s" % current_version)
            self.assertTrue(wait_until_true(is_connector_installed, 45, 1, *(self.config.exp_hostname_primary(),
                                                                             self.config.exp_root_user(),
                                                                             self.config.exp_root_pass(),
                                                                             "c_mgmt")),
                            "c_mgmt did not install in time and is still not ready")
            self.assertTrue(wait_until_true(has_connector_pid_changed, 30, 1, *(self.config.exp_hostname_primary(),
                                                                                self.config.exp_root_user(),
                                                                                self.config.exp_root_pass(),
                                                                                "c_mgmt",
                                                                                current_pid)),
                            "c_mgmt PID did not change in time and is still %s" % current_pid)

            # 4. Get the new installed version and PID and clear the rollback blacklist to let the connector upgrade
            rollback_version = get_installed_connector_version(self.config.exp_hostname_primary(),
                                                               self.config.exp_root_user(),
                                                               self.config.exp_root_pass(),
                                                               "c_mgmt")
            rollback_pid = get_connector_pid(self.config.exp_hostname_primary(),
                                             self.config.exp_root_user(),
                                             self.config.exp_root_pass(),
                                             "c_mgmt")
            self.assertIsNotNone(rollback_version, "Could not get the version management connector installed on %s"
                                 % self.config.exp_hostname_primary())
            self.assertIsNotNone(rollback_pid, "Could not get the PID of management connector on %s"
                                 % self.config.exp_hostname_primary())
            LOG.info("Rolled back FMC version to %s and the new PID is %s", rollback_version, rollback_pid)

            LOG.info("Clearing the rollback blacklist and allowing c_mgmt to upgrade to %s", current_version)
            clear_rollback_blacklist(self.config.exp_hostname_primary(),
                                     self.config.exp_admin_user(),
                                     self.config.exp_admin_pass())

            # 5. Wait and assert that:
            #     a. The installed version changes
            #     b. The connector reaches a fully installed state
            #     c. The PID changes
            self.assertTrue(wait_until_true(has_version_changed, 60, 1, *(self.config.exp_hostname_primary(),
                                                                          self.config.exp_root_user(),
                                                                          self.config.exp_root_pass(),
                                                                          "c_mgmt",
                                                                          rollback_version)),
                            "c_mgmt did not upgrade in time and is still running version %s" % rollback_version)
            self.assertTrue(wait_until_true(is_connector_installed, 45, 1, *((self.config.exp_hostname_primary(),
                                                                              self.config.exp_root_user(),
                                                                              self.config.exp_root_pass(),
                                                                              "c_mgmt"))),
                            "c_mgmt upgrade did not install in time and is still not ready")
            self.assertTrue(wait_until_true(has_connector_pid_changed, 90, 1, *(self.config.exp_hostname_primary(),
                                                                                self.config.exp_root_user(),
                                                                                self.config.exp_root_pass(),
                                                                                "c_mgmt",
                                                                                rollback_pid)),
                            "c_mgmt upgrade PID did not change in time and is still %s" % rollback_pid)
            upgraded_version = get_installed_connector_version(self.config.exp_hostname_primary(),
                                                               self.config.exp_root_user(),
                                                               self.config.exp_root_pass(),
                                                               "c_mgmt")
            upgraded_pid = get_connector_pid(self.config.exp_hostname_primary(),
                                             self.config.exp_root_user(),
                                             self.config.exp_root_pass(),
                                             "c_mgmt")
            self.assertIsNotNone(upgraded_version,
                                 "Could not get the version of new management connector installed on %s"
                                 % self.config.exp_hostname_primary())
            self.assertIsNotNone(upgraded_pid, "Could not get the PID of the new management connector on %s"
                                 % self.config.exp_hostname_primary())
            LOG.info("Upgraded FMC version to %s and the new PID is %s", upgraded_version, upgraded_pid)
        finally:
            if not is_blacklist_empty(self.config.exp_hostname_primary(),
                                      self.config.exp_admin_user(),
                                      self.config.exp_admin_pass()):
                # Disaster recovery. If we hit this code that means that the test has failed after the rollback but
                # before we delete the rollback blacklist. This is here to always ensure that it gets deleted and that
                # once we exit this test the expressway should be in the same state that we found it in
                LOG.info("The test has failed but there is still a rollback blacklist in CDB. Attempt to recover...")
                clear_rollback_blacklist(self.config.exp_hostname_primary(),
                                         self.config.exp_admin_user(),
                                         self.config.exp_admin_pass())

            # 6. Assert that the rollback TLPs are recycled back to to current & previous directories and that
            #    it is possible to rollback again if we need to

            # Note the absurdly long wait time in this assertion. This is to handle the failure case disaster
            # recovery mentioned just above. In the happy path this should take a few seconds.
            self.assertTrue(wait_until_true(can_connector_be_rolled_back, 300, 1, *(self.config.exp_hostname_primary(),
                                                                                    self.config.exp_root_user(),
                                                                                    self.config.exp_root_pass(),
                                                                                    "c_mgmt")),
                            "Upgrade did not repopulate the rollback TLPs")

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

            self.assertTrue(wait_until_true(is_alarm_raised_on_exp, 5, 1, alarm_to_raise),
                            "Alarm {} was not raised in time on the Expressway.".format(alarm_to_raise))

            self.assertTrue(wait_until_true(is_alarm_raised, 30, 1, *(self.config.org_id(),
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

        self.assertTrue(wait_until_true(is_command_complete, 20, 1, *(
            self.config.org_id(),
            self.connector_id,
            self.config.rd_server(),
            command_id,
            self.access_token)),
                        "Command {} was not completed in time.".format(command_id))

    def test_log_push(self):
        """
        Purpose: Verify that management connector can archive and push logs to the cloud
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_log_push.__doc__)

        search_uuid = str(uuid.uuid4())
        serial_number = get_serialno(self.config.exp_hostname_primary(),
                                     self.config.exp_admin_user(),
                                     self.config.exp_admin_pass())
        atlas_logging_url = get_logging_host_url(self.config.exp_hostname_primary(),
                                                 self.config.exp_admin_user(),
                                                 self.config.exp_root_pass())

        # Trigger log push by injecting a UUID in the CDB
        set_logging_entry_to_blob(self.config.exp_hostname_primary(),
                                  self.config.exp_admin_user(),
                                  self.config.exp_admin_pass(),
                                  search_uuid)

        def logging_metadata_available(logging_url):
            """
                Wait for atlas logs to be available.
            """
            log_resp = get_log_data_from_atlas(logging_url, search_uuid, self.access_token)
            LOG.info("get_log_data_from_atlas resp: %s", log_resp)
            LOG.info("get_log_data_from_atlas text: %s", log_resp.text)
            updated = True if 'metadataList' in log_resp.json() and log_resp.json()['metadataList'] else False

            return updated

        wait_until_true(logging_metadata_available, 120, 5, atlas_logging_url)

        response = get_log_data_from_atlas(atlas_logging_url, search_uuid, self.access_token)
        log_meta_list = response.json()['metadataList'][0]

        self.assertEquals(search_uuid, log_meta_list['meta']['fusion'])
        self.assertEquals(serial_number, log_meta_list['meta']['locusid'])

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

    def test_feature_connector_file_permissions(self):
        """
        Purpose: Check connectors file permissions.
        Steps:
        1. For each Expressway in the cluster verify that all feature connectors files have correct permissions.
        Notes:
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_feature_connector_file_permissions.__doc__)

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

            self.assertTrue(wait_until_true(has_machine_password_changed, 30, 1, *(
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
