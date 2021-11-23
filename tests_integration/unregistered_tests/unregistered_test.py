""" Management Connector Tests not requiring Registration """
import re
import unittest

import requests

from tests_integration.utils.cdb_methods import delete_cdb_entry
from tests_integration.utils.common_methods import wait_until_true
from tests_integration.utils.config import Config
from tests_integration.utils.integration_test_logger import get_logger
from tests_integration.utils.predicates import has_log_configuration_updated
from tests_integration.utils.ssh_methods import get_file_data, run_ssh_command

LOG = get_logger()


class UnregisteredTest(unittest.TestCase):
    """ UnregisteredTest: tests that can be run against an expressway that has not been registered to the cloud """
    cluster_id = None

    @classmethod
    def setUpClass(cls):
        LOG.info("Running: setUpClass")
        cls.config = Config()

    def test_management_connector_file_permissions(self):
        """
        Purpose: Verify management connector is created with correct permissions/owner
        Steps:
        1. Validate owner and permissions of /etc/init.d script.
        2. Validate owner and permissions folder and files in /opt/c_mgmt.
        Notes:
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_management_connector_file_permissions.__doc__)

        checkpoints = [
            {
                "location": "/etc/init.d/c_mgmt",
                "perms": [("/etc/init.d/c_mgmt", "-rwxr-xr-x")]
            },
            {
                "location": "/opt/c_mgmt",
                "perms": [
                    (".", "drwxr-xr-x"),
                    ("bin", "lrwxrwxrwx"),
                    ("etc", "drwxr-xr-x"),
                    ("lib", "drwxr-xr-x"),
                    ("lib64", "drwxr-xr-x"),
                    ("plugins", "drwxr-xr-x"),
                    ("python", "drwxr-xr-x"),
                    ("src", "drwxr-xr-x"),
                    ("usr", "drwxr-xr-x"),
                    ("xcommand", "drwxr-xr-x"),
                    ("xstatus", "drwxr-xr-x")
                ]
            },
            {
                "location": "/usr",
                "perms": [("bin", "drwxr-xr-x")]
            },
        ]
        user = "root"
        for checkpoint in checkpoints:
            result = run_ssh_command(
                self.config.exp_hostname_primary(),
                self.config.exp_root_user(),
                self.config.exp_root_pass(),
                "ls -lah " + checkpoint["location"])
            for path, perm in checkpoint["perms"]:
                pattern = "(%s).*?(%s).*?(%s).*?(%s)" % (perm, user, user, path)
                regex = re.compile(pattern)
                self.assertIsNotNone(regex.search(result), "User or permissions of %s are not correct. "
                                                           "The actual values are %s." % (path, result))

    def test_hybrid_service_log_level(self):
        """
        Purpose: Verify Hybrid services log levels are propagated to ttlog.conf
        Steps:
        1. Write to hybrid services log level table.
        2. Validate entry has propagated to ttlog.conf.
        3. Cleanup
        Notes:
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_hybrid_service_log_level.__doc__)

        hybrid_log_level_path = "/api/management/configuration/hybridserviceslogger/"
        name = "hybridservices.cafe.test"
        full_path = hybrid_log_level_path + "name/" + name

        try:
            # Step. 1
            requests.post('https://' + self.config.exp_hostname_primary() + full_path, data='level=DEBUG',
                          auth=(self.config.exp_admin_user(), self.config.exp_admin_pass()), verify=False)

            self.assertTrue(wait_until_true(has_log_configuration_updated, 5, 1, *(
                self.config.exp_hostname_primary(),
                self.config.exp_root_user(),
                self.config.exp_root_pass())),
                            "Log configuration did not propagate from CDB to config file")
        finally:
            # Step. 3
            delete_cdb_entry(self.config.exp_hostname_primary(),
                             self.config.exp_admin_user(),
                             self.config.exp_admin_pass(),
                             hybrid_log_level_path + "name" + "/" + name)

    def test_alarm_onboarding(self):
        """
        Purpose: Test Alarm onboarding either through tlp install or vcs install.
        Steps:
        1. Ensure select set of Alarms are onboarded.
        2. Check the full c_mgmt alarm range(60050-60099) for any alarms unknown
           to this script. If one exists it is likely newly added - log errors to the
           user telling them where to add the alarm details to source control then fail.
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_alarm_onboarding.__doc__)

        alarm_id_limit = 60073

        LOG.debug('***TEST Start***')
        c_mgmt_alarm_range = list(range(60050, 60099 + 1))
        known_alarm_ids = list(range(60050, alarm_id_limit + 1))
        onboard_alarms = []

        for alarm in known_alarm_ids:
            result = run_ssh_command(
                self.config.exp_hostname_primary(),
                self.config.exp_root_user(),
                self.config.exp_root_pass(),
                "alarm query %s" % alarm)
            LOG.info("Checking Alarm ID: %s is registered", alarm)

            self.assertTrue(str(alarm) in result and result != "Alarm '{}' not found".format(alarm),
                            msg="Alarm: {} not found in content: {}".format(alarm, result))

        LOG.info("Checking full c_mgmt alarm range(60050-60099) for unknown alarms")
        for alarm in c_mgmt_alarm_range:
            result = run_ssh_command(
                self.config.exp_hostname_primary(),
                self.config.exp_root_user(),
                self.config.exp_root_pass(),
                "alarm query %s" % alarm)

            if str(alarm) in result and result != "Alarm '{}' not found".format(alarm):
                onboard_alarms.append(alarm)
                if alarm not in known_alarm_ids:
                    LOG.error("Alarm ID %s is registered on the server but is not in the known alarm list", alarm)
                    LOG.error(
                        "New alarms must be added to xlib GIT: example: https://bitbucket-eng-gpk1.cisco.com"
                        "/bitbucket/projects/XLIB/repos/xlib/pull-requests/114/overview")
                    LOG.error("New alarms must be added to management-connector GIT: debian/controlpostinst")
                    LOG.error("New alarms must be added to management-connector GIT: debian/control/prerm")

        self.assertEqual(known_alarm_ids, onboard_alarms, "Alarms on the server did not match the expected list")

    def test_certificate_format(self):
        """
        Purpose: Verify all real certs being added in FMC are a valid format
        Steps:
                1. Loop through all certs in FMC
                2. Assert the files have Organisation and CommonName information
                3. Assert the files do not have dos newline
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_certificate_format.__doc__)

        LOG.info("test_2_actual_cert_format: looping through certs checking format")
        certs_path = "/opt/c_mgmt/etc/certs/"
        dos_newline = "\r\n"
        org = "O="
        common_name = "CN="
        fail_message = "\n***\n*** If you're adding a new cert ensure the following criteria are met.\n" \
                       "*** Description Info is present\n" \
                       "*** DOS newline chars are not present\n" \
                       "*** TTM Default Certs have been updated\n" \
                       "*** Documentation is updated with new cert info\n" \
                       "*** For more information see wiki below\n" \
                       "*** https://wiki.cisco.com/display/WX2/Adding+New+Certificates+to+FMC"

        files_str = run_ssh_command(
            self.config.exp_hostname_primary(),
            self.config.exp_root_user(),
            self.config.exp_root_pass(),
            "ls {}".format(certs_path))

        # Split each line for each file and remove last newline char
        files = files_str.split("\n")[:-1]
        paths = [certs_path + path for path in files if path]

        for path in paths:
            contents = get_file_data(
                self.config.exp_hostname_primary(),
                self.config.exp_root_user(),
                self.config.exp_root_pass(),
                path)

            self.assertTrue(org in contents or common_name in contents,
                            "Description Info not in {}\n{}\n{}".format(path, fail_message, contents))
            self.assertTrue(dos_newline not in contents,
                            "DOS newline in {}\n{}\n{}".format(path, fail_message, contents))
