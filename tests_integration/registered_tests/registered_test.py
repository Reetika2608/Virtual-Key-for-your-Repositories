import datetime
import re
import unittest
import uuid

import requests

from tests_integration.api_based_tests.vcs_http import VCSHttpSession
from tests_integration.utils import ci
from tests_integration.utils.cdb_methods import get_serialno, get_logging_host_url, \
    set_logging_entry_to_blob, set_machine_account_expiry, get_current_machine_account_password, get_cluster_id, \
    get_machine_account_url, enable_expressway_connector, disable_expressway_connector, disable_fmc_upgrades, \
    set_poll_time
from tests_integration.utils.common_methods import wait_until_true, get_log_data_from_atlas, \
    run_full_management_connector_restart, wait_until_false
from tests_integration.utils.config import Config
from tests_integration.utils.fms import get_connector
from tests_integration.utils.integration_test_logger import get_logger
from tests_integration.utils.predicates import is_alarm_raised, \
    is_command_complete, has_machine_password_changed, is_text_on_page, is_connector_running, \
    is_connector_in_composed_status, is_connector_in_fms_state
from tests_integration.utils.remote_dispatcher import dispatch_command_to_rd
from tests_integration.utils.ssh_methods import run_ssh_command, get_device_time, file_exists, restart_connector, \
    stop_connector, start_connector, run_xcommand

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
        cls.serial = get_serialno(cls.config.exp_hostname_primary(),
                                  cls.config.exp_admin_user(),
                                  cls.config.exp_admin_pass())
        cls.connector_id = "c_mgmt@" + cls.serial
        cls.cluster_id = get_cluster_id(cls.config.exp_hostname_primary(),
                                        cls.config.exp_admin_user(),
                                        cls.config.exp_admin_pass())

        disable_fmc_upgrades(cls.config.exp_hostname_primary(),
                             cls.config.exp_admin_user(),
                             cls.config.exp_admin_pass())

        set_poll_time(cls.config.exp_hostname_primary(), cls.config.exp_admin_user(), cls.config.exp_admin_pass(), 9)

    @classmethod
    def tearDownClass(cls):
        LOG.info("Running: tearDownClass")
        # Clean up any tokens we got at the start
        if cls.access_token:
            ci.delete_ci_access_token(cls.access_token)
        if cls.refresh_token:
            ci.delete_ci_refresh_token(cls.refresh_token)

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

            self.assertTrue(wait_until_true(is_alarm_raised_on_exp, 25, 1, alarm_to_raise),
                            "Alarm {} was not raised in time on the Expressway.".format(alarm_to_raise))

            self.assertTrue(wait_until_true(is_alarm_raised, 90, 1, *(self.config.org_id(),
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

        self.assertTrue(wait_until_true(is_command_complete, 40, 1, *(
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

        self.assertTrue(wait_until_true(logging_metadata_available, 360, 10, atlas_logging_url),
                        "Did not get logging metadata in time")

        response = get_log_data_from_atlas(atlas_logging_url, search_uuid, self.access_token)
        try:
            log_meta_list = response.json()['metadataList'][0]
        except IndexError:
            LOG.error("IndexError while reading log resonse. Got {}".format(response.json()))
            raise

        self.assertEqual(search_uuid, log_meta_list['meta']['fusion'])
        self.assertEqual(serial_number, log_meta_list['meta']['locusid'])

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

        def check_for_file(hostname, root_user, root_pass, file):
            LOG.info("Checking for {} at {}...".format(heartbeat_file, hostname))
            return file_exists(hostname, root_user, root_pass, file)

        LOG.info("Step 1: Ensure Connectors Heartbeat file exists, connector=%s", connector)
        self.assertTrue(wait_until_true(check_for_file, 40, 3,
                                        *(self.config.exp_hostname_primary(),
                                          self.config.exp_root_user(),
                                          self.config.exp_root_pass(),
                                          heartbeat_file)),
                        "Did not find heartbeat file for {} ({}) in time".format(connector, heartbeat_file))

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

    def test_revive_on_broken_machine_account(self):
        """
        Purpose: Verify Revive functionality
        Steps:
        1. Delete CI machine account (get machine account url from blob).
        2. Re-start FMC.
        3. Confirm revive message and button are available on fusion page.
        4. Verify that no c_mgmt.heartbeat file exists on-box.
        5. Using requests emulate clicking the button to revive the connection.
        6. After revive is complete, confirm that the revive button is no longer visible.
        7. Verify that a new c_mgmt.heartbeat file has been written on-box.
        8. Verify that the machine account URL changed during the revive process.
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_revive_on_broken_machine_account.__doc__)

        # 1. Delete CI machine account (get machine account url from blob).
        starting_machine_url = get_machine_account_url(self.config.exp_hostname_primary(),
                                                       self.config.exp_admin_user(),
                                                       self.config.exp_admin_pass())

        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        LOG.info("Deleting the machine account %s found on %s",
                 starting_machine_url, self.config.exp_hostname_primary())
        response = requests.delete(starting_machine_url, headers=headers, verify=False)
        self.assertTrue(response.ok, "Failed to delete machine account in CI: {}".format(starting_machine_url))

        # 2. Re-start FMC.
        # Do a "dumb" connector restart. Because we are deleting the machine account some of the criteria
        # that the smart restart method waits on will never be satisfied
        restart_connector(self.config.exp_hostname_primary(),
                          self.config.exp_root_user(),
                          self.config.exp_root_pass(),
                          "c_mgmt")

        # 3. Confirm revive message and button are available on fusion page.
        self.assertTrue(wait_until_true(is_text_on_page, 120, 10, *(self.config.exp_hostname_primary(),
                                                                   self.config.exp_admin_user(),
                                                                   self.config.exp_admin_pass(),
                                                                   "fusionregistration",
                                                                   "There is an error in your connection")),
                        "{} is not showing the revive error message".format(self.config.exp_hostname_primary()))
        self.assertTrue(wait_until_true(is_text_on_page, 90, 5, *(self.config.exp_hostname_primary(),
                                                                  self.config.exp_admin_user(),
                                                                  self.config.exp_admin_pass(),
                                                                  "fusionregistration",
                                                                  "Re-Register")),
                        "{} is not showing the revive button".format(self.config.exp_hostname_primary()))

        # 4. Verify that no c_mgmt.heartbeat file exists on-box.
        # When FMC restarted it would have deleted all on-box .heartbeat files. Now that the machine account has
        # been deleted it should not be possible for a heartbeat file to exist on-box.
        self.assertFalse(file_exists(self.config.exp_hostname_primary(),
                                     self.config.exp_root_user(),
                                     self.config.exp_root_pass(),
                                     "/var/run/c_mgmt/c_mgmt.heartbeat"),
                         "Heartbeat file still exists on {}".format(self.config.exp_hostname_primary()))

        # 5. Using requests emulate clicking the button to revive the connection.
        exp_session = VCSHttpSession(
            hostname=self.config.exp_hostname_primary(),
            username=self.config.exp_admin_user(),
            password=self.config.exp_admin_pass()
        )
        exp_session.set_session(self.session)
        exp_session.revive_expressway()

        # 6. After revive is complete, confirm on both nodes that the revive button is no longer visible.
        self.assertFalse(wait_until_false(is_text_on_page, 60, 10, *(self.config.exp_hostname_primary(),
                                                                     self.config.exp_admin_user(),
                                                                     self.config.exp_admin_pass(),
                                                                     "fusionregistration",
                                                                     "There is an error in your connection")),
                         "{} is still showing the revive error message".format(self.config.exp_hostname_primary()))
        self.assertFalse(wait_until_false(is_text_on_page, 60, 5, *(self.config.exp_hostname_primary(),
                                                                    self.config.exp_admin_user(),
                                                                    self.config.exp_admin_pass(),
                                                                    "fusionregistration",
                                                                    "Re-Register")),
                         "{} is still showing the revive button".format(self.config.exp_hostname_primary()))

        # 7. Verify that a new c_mgmt.heartbeat file has been written on-box.
        # FMC only writes a heartbeat file to disk after a successful POST to FMS. Once this file exists then
        # we have posted a heartbeat using the new machine account.
        self.assertTrue(wait_until_true(file_exists, 60, 5, *(self.config.exp_hostname_primary(),
                                                              self.config.exp_root_user(),
                                                              self.config.exp_root_pass(),
                                                              "/var/run/c_mgmt/c_mgmt.heartbeat")),
                        "{} has no heartbeat file on-box. Are we still broken?"
                        .format(self.config.exp_hostname_primary()))

        # 8. Verify that the machine account URL changed during the revive process.
        revived_machine_url = get_machine_account_url(self.config.exp_hostname_primary(),
                                                      self.config.exp_admin_user(),
                                                      self.config.exp_admin_pass())
        self.assertNotEqual(starting_machine_url, revived_machine_url,
                             "The machine account URL did not change during revive: {}".format(starting_machine_url))

    def test_management_connector_xstatus(self):
        """
        To verify that management connector's status is displayed correctly.
        Steps:
        1. Run xstatus and validate values.
        2. Disable management connector, run xstatus and validate values.
        """

        states = [True]

        for state in states:
            # set the expected result from xstatus
            try:
                if state:
                    enable_expressway_connector(self.config.exp_hostname_primary(), self.config.exp_admin_user(),
                                                self.config.exp_admin_pass(), "c_mgmt")
                    self.assertTrue(wait_until_true(is_connector_running, 10, 1,
                                                    *(self.config.exp_hostname_primary(),
                                                      self.config.exp_root_user(),
                                                      self.config.exp_root_pass(),
                                                      "c_mgmt")),
                                    "Timed out waiting for c_mgmt to be running")
                    expected = (True, True, '"operational"')

                xcommand_result = run_xcommand(
                    self.config.exp_hostname_primary(),
                    self.config.exp_root_user(),
                    self.config.exp_root_pass(),
                    "xstat cafe")

                # Clean the result
                xstatus = xcommand_result[xcommand_result.find("*s Cafe: /") + 10:xcommand_result.find("*s/end")]

                enabled = running = False
                operational_status = 'notset'
                for level, name, parent in self.parse_xstatus(xstatus.split('\n')):
                    # print('{0}name={1} ( {2} )'.format(' ' * (4 * level), name, parent or 'root'))
                    if (parent == 'c_mgmt:' and
                            name.split(':')[0] == 'enabled' and
                            name.split(':')[1].strip() == '"True"'):
                        enabled = True
                    elif (parent == 'c_mgmt:' and
                          name.split(':')[0] == 'running' and
                          name.split(':')[1].strip() == '"True"'):
                        running = True
                    elif (parent == 'c_mgmt:' and
                          name.split(':')[0] == 'operational_status'):
                        operational_status = name.split(':')[1].strip()

                result = (enabled, running, operational_status)
                self.assertEqual(expected, result)
            finally:
                enable_expressway_connector(self.config.exp_hostname_primary(), self.config.exp_admin_user(),
                                            self.config.exp_admin_pass(), "c_mgmt")
                if not wait_until_true(is_connector_running, 10, 1,
                                       *(self.config.exp_hostname_primary(),
                                         self.config.exp_root_user(),
                                         self.config.exp_root_pass(),
                                         "c_mgmt")):
                    LOG.warn("c_mgmt did not start in time during cleanup")

    def parse_xstatus(self, lines):
        """
        Parse an indented xstatus into (level, name, parent) tuples.  Each level
        of indentation is 2 spaces.
        """
        indent = 2
        regex = re.compile(r'^(?P<indent>(?: {2})*)(?P<name>\S.*)')
        stack = []
        for line in lines:
            if line.strip():  # Keep empty lines
                # remove the first 5 indents
                line = ' ' * (len(line) - len(line.lstrip(' ')) - 5) + line.lstrip()
                match = regex.match(line)
                if not match:
                    raise ValueError(
                        'Indentation not a multiple of {0} spaces: "{1}"'.format(indent, line)
                    )
                level = len(match.group('indent')) // indent
                if level > len(stack):
                    raise ValueError('Indentation too deep: "{0}"'.format(line))
                stack[level:] = [match.group('name')]
                yield level, match.group('name'), (stack[level - 1] if level else None)

    def test_management_connector_white_box_status(self):
        """
        Purpose: Verify that management connector sends whitebox status (in heartbeat)

        Steps:
        1. Get Calendar Status, checking for internal connector status
        """

        connector = get_connector(self.config.org_id(), self.cluster_id, self.config.fms_server(),
                                  '%s@%s' % ("c_cal", self.serial), self.access_token)
        connector_status = connector["connectorStatus"]
        # Since we are not testing the actual values in the connector_status (whether the connector
        # is operational or not just assert that the elements in fact are there, and don't test for values.
        self.assertTrue('initialized' in connector_status,
                        "initialized not in connector status: {}".format(connector_status))
        self.assertTrue('operational' in connector_status,
                        "operational not in connector status: {}".format(connector_status))

    def test_post_status_of_connector(self):
        """
        Purpose:
        To verify correct connector status is being sent by management
        connector to management service.
        Note:
        This test does not verify the UI because it does not use the selenium runner,
        but verifies xstatus which is used by the UI.
        Steps:
        1. Disable calendar connector
        2. Verify that Xstatus and FMS reflects the new state
        3. Re-enable calendar connector
        4. Stop calendar connector
        5. Verify that Xstatus and FMS reflects the new state
        """
        test_connector = 'c_cal'
        connector_id = test_connector + '@' + get_serialno(self.config.exp_hostname_primary(),
                                                           self.config.exp_admin_user(),
                                                           self.config.exp_admin_pass())

        def verify_connector_in_state(connector, state):
            # Verify XStatus state
            LOG.info("Waiting for {} to reach the {} composed status".format(connector, state))
            self.assertTrue(
                wait_until_true(is_connector_in_composed_status, 40, 2, *(self.config.exp_hostname_primary(),
                                                                          self.config.exp_root_user(),
                                                                          self.config.exp_root_pass(),
                                                                          connector,
                                                                          state)))

            # Verify FMS state
            LOG.info("Waiting for {} to reach the {} state in FMS".format(connector, state))
            self.assertTrue(wait_until_true(is_connector_in_fms_state, 80, 2, *(self.config.org_id(),
                                                                                self.cluster_id,
                                                                                self.config.fms_server(),
                                                                                connector_id,
                                                                                self.access_token,
                                                                                state)))
        try:  # Test disabling connector
            LOG.info("Disabling {}...".format(test_connector))
            disable_expressway_connector(self.config.exp_hostname_primary(),
                                         self.config.exp_admin_user(),
                                         self.config.exp_admin_pass(),
                                         test_connector)

            verify_connector_in_state(test_connector, 'disabled')
        finally:
            enable_expressway_connector(self.config.exp_hostname_primary(),
                                        self.config.exp_admin_user(),
                                        self.config.exp_admin_pass(),
                                        test_connector)

        # Wait for connector to get enabled to make sure that re-enabling doesn't interfere with stopping
        self.assertTrue(
            wait_until_true(is_connector_in_composed_status, 40, 2, *(self.config.exp_hostname_primary(),
                                                                      self.config.exp_root_user(),
                                                                      self.config.exp_root_pass(),
                                                                      test_connector,
                                                                      'running')))

        try:  # Test stopping connector
            LOG.info("Stopping {}".format(test_connector))
            stop_connector(self.config.exp_hostname_primary(),
                           self.config.exp_root_user(),
                           self.config.exp_root_pass(),
                           test_connector)
            verify_connector_in_state(test_connector, 'stopped')
        finally:
            start_connector(self.config.exp_hostname_primary(),
                            self.config.exp_root_user(),
                            self.config.exp_root_pass(),
                            test_connector)
