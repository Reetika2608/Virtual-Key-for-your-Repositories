""" Basic UI Based Registration Test """
import logging
import sys
import unittest

from tests_integration.utils.cdb_methods import configure_connectors, get_cluster_id_from_expressway
from tests_integration.utils.common_methods import create_log_directory, wait_until_true, wait_for_defuse_to_finish
from tests_integration.utils.config import Config
from tests_integration.utils.predicates import are_connectors_entitled, is_connector_installed
from tests_integration.utils.web_methods import register_expressway, deregister_expressway, create_web_driver, \
    login_expressway, navigate_expressway_menus, enable_expressway_connector

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


class BasicRegisterTest(unittest.TestCase):
    """ BasicRegisterTest """
    config = None
    cluster_id = None

    @classmethod
    def setUpClass(cls):
        LOG.info("Running: setUpClass")
        cls.log_directory = create_log_directory()
        cls.config = Config()

        register_expressway(cls.config.control_hub(),
                            cls.config.org_admin_user(),
                            cls.config.org_admin_password(),
                            cls.config.exp_hostname_primary(),
                            cls.config.exp_admin_user(),
                            cls.config.exp_admin_pass())

        for connector in cls.config.expected_connectors():
            wait_until_true(is_connector_installed, 240, 10,
                            *(cls.config.exp_hostname_primary(),
                              cls.config.exp_root_user(),
                              cls.config.exp_root_pass(),
                              connector))

        # Get cluster id
        cls.cluster_id = get_cluster_id_from_expressway(cls.config.exp_hostname_primary(),
                                                        cls.config.exp_admin_user(),
                                                        cls.config.exp_admin_pass())

    @classmethod
    def tearDownClass(cls):
        LOG.info("Running: tearDownClass")
        deregister_expressway(cls.config.control_hub(),
                              cls.config.org_admin_user(),
                              cls.config.org_admin_password(),
                              cls.cluster_id)

        wait_for_defuse_to_finish(cls.config.exp_hostname_primary(),
                                  cls.config.exp_root_user(),
                                  cls.config.exp_root_pass(),
                                  cls.config.exp_admin_user(),
                                  cls.config.exp_admin_pass(),
                                  cls.config.expected_connectors())

    def setUp(self):
        self.web_driver = create_web_driver()

    def tearDown(self):
        LOG.info("Running: tearDown")
        if sys.exc_info()[0]:
            class_name = self.__class__.__name__
            LOG.info("Log directory: %s/%s_%s.png", self.log_directory, class_name, self._testMethodName)
            self.web_driver.save_screenshot('%s/%s_%s.png' % (self.log_directory, class_name, self._testMethodName))
        self.web_driver.quit()

    def test_connectors_can_be_enabled(self):
        """
        Purpose: Verify that connectors can be enabled via the UI
        Steps:
        1. Verify connectors are entitled
        2. Verify connectors have been installed
        3. Configure
        4. Verify connectors can be enabled
        Notes:
        """
        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_connectors_can_be_enabled.__doc__)

        # Verify all connectors are entitled in the database
        self.assertTrue(wait_until_true(are_connectors_entitled, 60, 5, *(self.config.exp_hostname_primary(),
                                                                          self.config.exp_admin_user(),
                                                                          self.config.exp_admin_pass(),
                                                                          self.config.expected_connectors())),
                        "%s does not have the full list of entitled connectors (%s)."
                        % (self.config.exp_hostname_primary(), str(self.config.expected_connectors())))

        # Verify Connectors are entitled/visible in the Hybrid Services connector table
        login_expressway(
            self.web_driver,
            self.config.exp_hostname_primary(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass())
        navigate_expressway_menus(self.web_driver, ["Applications", "Hybrid Services", "Connector Management"])

        for expected_display in self.config.expected_connectors().values():
            self.assertTrue(self.web_driver.find_element_by_partial_link_text(expected_display),
                            "%s is not displaying on the UI of %s." % (
                                expected_display, self.config.exp_hostname_primary()))

        # Verify connectors are installed
        for connector in self.config.expected_connectors():
            self.assertTrue(wait_until_true(is_connector_installed, 180, 10,
                                            *(self.config.exp_hostname_primary(),
                                              self.config.exp_root_user(),
                                              self.config.exp_root_pass(),
                                              connector)),
                            "%s does not have the connector %s installed." % (
                                self.config.exp_hostname_primary(), connector))

        # Verify connectors are visible on the Components page
        login_expressway(
            self.web_driver,
            self.config.exp_hostname_primary(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass())
        navigate_expressway_menus(self.web_driver, ["Maintenance", "Upgrade"])

        for expected_display in self.config.expected_connectors().values():
            self.assertTrue(self.web_driver.find_element_by_xpath(("//*[contains(text(), '%s')]" % expected_display)),
                            "%s does not show the connector %s on the UI." % (
                                self.config.exp_hostname_primary(), expected_display))

        # Configure the feature connectors so that they can be enabled
        configure_connectors(
            self.config.exp_hostname_primary(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass(),
            self.config.exp_root_user(),
            self.config.exp_root_pass())

        # Enable connectors
        for expected_display in self.config.expected_connectors().values():
            if expected_display != "Management Connector":
                self.assertTrue(
                    enable_expressway_connector(
                        self.web_driver,
                        self.config.exp_hostname_primary(),
                        self.config.exp_admin_user(),
                        self.config.exp_admin_pass(),
                        expected_display),
                    "Connector %s is not enabled on %s." % (expected_display, self.config.exp_hostname_primary()))
