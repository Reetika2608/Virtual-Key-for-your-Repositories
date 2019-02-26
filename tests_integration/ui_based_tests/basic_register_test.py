""" Basic UI Based Registration Test """
import unittest
import sys
import logging
import re

from tests_integration.utils.config import Config
from tests_integration.utils.common_methods import configure_connectors, run_ssh_command, is_connector_installed, \
    create_log_directory, wait_until, is_connector_entitled
from tests_integration.utils.web_methods import register_expressway, deregister_expressway, create_web_driver, \
    is_in_page_source, is_visible, login_expressway, navigate_expressway_menus, enable_expressway_connector

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


class BasicRegisterTest(unittest.TestCase):
    """ BasicRegisterTest """
    config = None

    @classmethod
    def setUpClass(cls):
        LOG.info("Running: setUpClass")
        cls.config = Config()
        register_expressway(
            cls.config.exp_hostname1(),
            cls.config.exp_admin_user(),
            cls.config.exp_admin_pass(),
            cls.config.org_admin_user(),
            cls.config.org_admin_password())
        cls.log_directory = create_log_directory()

    @classmethod
    def tearDownClass(cls):
        LOG.info("Running: tearDownClass")

    def setUp(self):
        self.web_driver = create_web_driver()

    def tearDown(self):
        LOG.info("Running: tearDown")
        if sys.exc_info()[0]:
            class_name = self.__class__.__name__
            LOG.info("Log directory: %s/%s_%s.png", self.log_directory, class_name, self._testMethodName)
            self.web_driver.save_screenshot('%s/%s_%s.png' % (self.log_directory, class_name, self._testMethodName))
        self.web_driver.quit()

    def test_01_check_fusion(self):
        """
        User Story: US6888: Alpha and Integration build pipeline - Part II
        Purpose: Verify that all VCSes in the cluster are fused.
        Steps:
        1. For each VCS in the cluster verify the status of fusion.
        Notes:
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_01_check_fusion.__doc__)

        self.assertTrue(wait_until(is_connector_entitled, 60, 5, *(self.config.exp_hostname1(),
                                                                   self.config.exp_admin_user(),
                                                                   self.config.exp_admin_pass(),
                                                                   ["c_mgmt"])),
                        "Failed to register. c_mgmt not in list of entitled connectors")

    def test_02_check_entitled_connectors(self):
        """
        User Story: US6888: Alpha and Integration build pipeline - Part II
        Purpose: Verify that all VCSes have a list of entitled connectors.
        Steps:
        1. For each VCS in the cluster get the list of entitled blends.
        2. Verify that each VCS has a list of entitled connectors.
        Notes:
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_02_check_entitled_connectors.__doc__)

        self.assertTrue(wait_until(is_connector_entitled, 60, 5, *(self.config.exp_hostname1(),
                                                                   self.config.exp_admin_user(),
                                                                   self.config.exp_admin_pass(),
                                                                   self.config.expected_connectors())),
                        "%s does not have the full list of entitled connectors (%s)."
                        % (self.config.exp_hostname1(), str(self.config.expected_connectors())))

    def test_03_check_entitled_connectors_ui(self):
        """
        User Story: US6888: Alpha and Integration build pipeline - Part II
        Purpose: Verify that all entitled connectors are displayed on in the table
                 on the fusion page.
        Steps:
        1. Get the list of entitled blends.
        2. For each VCS in the cluster verify that all the entitled connectors are
           displayed on the fusion page of the VCS.
        Notes:
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_03_check_entitled_connectors_ui.__doc__)

        login_expressway(
            self.web_driver,
            self.config.exp_hostname1(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass())
        navigate_expressway_menus(self.web_driver, ["Applications", "Hybrid Services", "Connector Management"])

        for expected_display in self.config.expected_connectors().values():
            self.assertTrue(self.web_driver.find_element_by_partial_link_text(expected_display),
                            "%s is not displaying on the UI of %s." % (expected_display, self.config.exp_hostname1()))

    def test_04_check_installed_connectors(self):
        """
        User Story: US6888: Alpha and Integration build pipeline - Part II
        Purpose: Verify that all entitled connectors are installed.
        Steps:
        1. Get the list of entitled blends.
        2. For each VCS in the cluster verify that all the entitled connectors are
           displayed on the upgrade page of the VCS.
        Notes:
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_04_check_installed_connectors.__doc__)

        for connector in self.config.expected_connectors():
            self.assertTrue(wait_until(is_connector_installed, 180, 10,
                                       *(self.config.exp_hostname1(),
                                         self.config.exp_root_user(),
                                         self.config.exp_root_pass(),
                                         connector)),
                            "%s does not have the connector %s installed." % (self.config.exp_hostname1(), connector))

        login_expressway(
            self.web_driver,
            self.config.exp_hostname1(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass())
        navigate_expressway_menus(self.web_driver, ["Maintenance", "Upgrade"])

        for expected_display in self.config.expected_connectors().values():
            self.assertTrue(self.web_driver.find_element_by_xpath(("//*[contains(text(), '%s')]" % expected_display)),
                            "%s does not show the connector %s on the UI." % (
                                self.config.exp_hostname1(), expected_display))

    def test_05_check_enabling_connectors(self):
        """
        User Story: DE1685: 2 instances of c_cal running on mgmt conn startup.
        Purpose: Verify that we do not have multiple connector instances after
        MC upgrade.
        Steps:
        1. Get the list of entitled blends.
        2. For each VCS in the cluster verify that all the entitled connectors
        have the correct no. of processes.
        Notes:
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_05_check_enabling_connectors.__doc__)

        configure_connectors(
            self.config.exp_hostname1(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass(),
            self.config.exp_root_user(),
            self.config.exp_root_pass())

        for expected_display in self.config.expected_connectors().values():
            if expected_display != "Management Connector":
                self.assertTrue(
                    enable_expressway_connector(
                        self.web_driver,
                        self.config.exp_hostname1(),
                        self.config.exp_admin_user(),
                        self.config.exp_admin_pass(),
                        expected_display),
                    "Connector %s is not enabled on %s." % (expected_display, self.config.exp_hostname1()))

    def test_06_check_connector_instances(self):
        """
        User Story: DE1685: 2 instances of c_cal running on mgmt conn startup.
        Purpose: Verify that we do not have multiple connector instances after
        MC upgrade.
        Steps:
        1. Get the list of entitled blends.
        2. For each VCS in the cluster verify that all the entitled connectors
        have the correct process.
        Notes:
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_06_check_connector_instances.__doc__)

        # Mapping of Connector to binary. If the binary associated with a Connector changes this
        # dict will need updating
        process_dict = {'c_cal': 'java',
                        'c_ucmc': 'CSI',
                        'c_mgmt': 'managementconnectormain',
                        'c_imp': 'java'}

        for connector in self.config.expected_connectors():
            connector_binary = None
            if connector in process_dict:
                connector_binary = process_dict[connector]
            self.assertIsNotNone(connector_binary, "No binary defined for " + connector)

            cmd = "ps aux | grep %s | grep %s | grep -v grep | wc -l" % (connector, connector_binary)
            results = run_ssh_command(
                self.config.exp_hostname1(),
                self.config.exp_root_user(),
                self.config.exp_root_pass(),
                cmd)
            count = int(results[0])
            LOG.info("%s output from %s: %d", cmd, self.config.exp_hostname1(), count)
            self.assertLessEqual(
                count,
                1,
                "The number of processes for connector %s on %s is %s. It should be not be greater than 1"
                % (connector, self.config.exp_hostname1(), count))

    def test_07_check_file_permissions(self):
        """
        User Story: .
        Purpose: Check blend file permissions.
        Steps:
        1. Get the list of entitled blends.
        2. For each VCS in the cluster verify that all blend files have correct root/user permissions.
        Notes:
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_07_check_file_permissions.__doc__)

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
                    self.config.exp_hostname1(),
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
                    self.config.exp_hostname1(),
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

    def test_08_check_defuse(self):
        """
        User Story: .
        Purpose: Check defuse.
        Steps:
        1. Check defuse status.
        2. Check that blends have uninstalled.
        Notes:
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_08_check_defuse.__doc__)

        deregister_expressway(self.config.exp_hostname1(), self.config.exp_admin_user(), self.config.exp_admin_pass(),
                              self.config.org_admin_user(), self.config.org_admin_password())

        login_expressway(
            self.web_driver,
            self.config.exp_hostname1(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass())
        navigate_expressway_menus(self.web_driver, ["Applications", "Hybrid Services", "Connector Management"])
        self.assertTrue(wait_until(is_in_page_source, 120, 5,
                                   *(self.web_driver, " is not yet registered with the Cisco Webex Cloud.")),
                        "%s did not defuse successfully." % self.config.exp_hostname1())

        navigate_expressway_menus(self.web_driver, ["Maintenance", "Upgrade"])

        for expected_display in self.config.expected_connectors().values():
            if expected_display != "Management Connector":
                self.assertFalse(is_visible(self.web_driver, "//*[contains(text(), '%s')]" % expected_display),
                                 "Connector %s was not successfully uninstalled from %s."
                                 % (expected_display, self.config.exp_hostname1()))
