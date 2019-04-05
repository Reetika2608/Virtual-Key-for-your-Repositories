""" Basic UI Based DeRegistration Test """
import logging
import sys
import unittest

from tests_integration.utils.cdb_methods import configure_connectors, get_cluster_id_from_expressway
from tests_integration.utils.common_methods import create_log_directory, wait_until_true, wait_until_false
from tests_integration.utils.config import Config
from tests_integration.utils.predicates import is_connector_installed, is_connector_uninstalled, \
    are_supplied_connectors_installed
from tests_integration.utils.web_methods import deregister_expressway, create_web_driver, \
    deactivate_service, is_in_page_source, is_visible, login_expressway, navigate_expressway_menus, \
    enable_expressway_connector, register_expressway

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


class BasicDeRegisterTest(unittest.TestCase):
    """ BasicDeRegisterTest """
    config = None
    cluster_id = None

    @classmethod
    def setUpClass(cls):
        LOG.info("Running: setUpClass")
        cls.config = Config()

        cls.log_directory = create_log_directory()
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

        # Configure the feature connectors so that they can be enabled
        configure_connectors(cls.config.exp_hostname_primary(),
                             cls.config.exp_admin_user(),
                             cls.config.exp_admin_pass(),
                             cls.config.exp_root_user(),
                             cls.config.exp_root_pass())

        # Enable connectors
        for expected_display in cls.config.expected_connectors().values():
            if expected_display != "Management Connector":
                enable_expressway_connector(None,
                                            cls.config.exp_hostname_primary(),
                                            cls.config.exp_admin_user(),
                                            cls.config.exp_admin_pass(),
                                            expected_display)

        # Get cluster id
        cls.cluster_id = get_cluster_id_from_expressway(cls.config.exp_hostname_primary(),
                                                        cls.config.exp_admin_user(),
                                                        cls.config.exp_admin_pass())

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

    def test_deactivate_and_deregister(self):
        """
        Purpose: Check Deregister
        Steps:
        1. Deactivate a service in Control Hub.
        2. Check that connector is purged.
        3. Deregister the Expressway
        4. Check that remaining connectors have uninstalled.
        Notes:
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_deactivate_and_deregister.__doc__)

        LOG.info("Deactivate a service in control hub")
        deactivate_service(self.config.control_hub(),
                           self.config.org_admin_user(),
                           self.config.org_admin_password(),
                           self.cluster_id)

        self.assertFalse(wait_until_false(are_supplied_connectors_installed, 60, 5, *(
            self.config.exp_hostname_primary(),
            self.config.exp_root_user(),
            self.config.exp_root_pass(),
            self.config.expected_connectors())),
                         "%s still has full list of entitled connectors (%s) installed."
                         % (self.config.exp_hostname_primary(), str(self.config.expected_connectors())))

        deregister_expressway(self.config.control_hub(),
                              self.config.org_admin_user(),
                              self.config.org_admin_password(),
                              self.cluster_id)

        login_expressway(self.web_driver,
                         self.config.exp_hostname_primary(),
                         self.config.exp_admin_user(),
                         self.config.exp_admin_pass())

        navigate_expressway_menus(self.web_driver, ["Applications", "Hybrid Services", "Connector Management"])
        self.assertTrue(wait_until_true(is_in_page_source, 120, 5,
                                        *(self.web_driver, " is not yet registered with the Cisco Webex Cloud.")),
                        "%s did not defuse successfully." % self.config.exp_hostname_primary())

        for connector in self.config.expected_connectors():
            if connector != "c_mgmt":
                wait_until_true(is_connector_uninstalled, 360, 10,
                                *(self.config.exp_hostname_primary(),
                                  self.config.exp_root_user(),
                                  self.config.exp_root_pass(),
                                  connector))

        navigate_expressway_menus(self.web_driver, ["Maintenance", "Upgrade"])

        for expected_display in self.config.expected_connectors().values():
            if expected_display != "Management Connector":
                self.assertFalse(is_visible(self.web_driver, "//*[contains(text(), '%s')]" % expected_display),
                                 "Connector %s was not successfully uninstalled from %s."
                                 % (expected_display, self.config.exp_hostname_primary()))
