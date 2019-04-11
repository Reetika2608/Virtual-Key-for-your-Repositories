""" Basic UI Based DeRegistration Test """
import sys
import unittest

from tests_integration.utils import ci
from tests_integration.utils.cdb_methods import disable_fmc_upgrades, set_poll_time, enable_cert_management
from tests_integration.utils.common_methods import create_log_directory, wait_until_false, \
    wait_for_connectors_to_install, wait_for_defuse_to_finish
from tests_integration.utils.config import Config
from tests_integration.utils.fms import enable_cloud_fusion
from tests_integration.utils.integration_test_logger import get_logger
from tests_integration.utils.predicates import are_supplied_connectors_installed, is_text_on_page
from tests_integration.utils.web_methods import deregister_expressway, create_web_driver, \
    deactivate_service

LOG = get_logger()


class BasicDeRegisterTest(unittest.TestCase):
    """ BasicDeRegisterTest """
    config = None
    cluster_id = None

    @classmethod
    def setUpClass(cls):
        LOG.info("Running: setUpClass")
        cls.config = Config()
        cls.access_token, cls.refresh_token, cls.session = ci.get_new_access_token(cls.config.org_admin_user(),
                                                                                   cls.config.org_admin_password())
        cls.log_directory = create_log_directory()

        enable_cert_management(cls.config.exp_hostname_primary(),
                               cls.config.exp_admin_user(),
                               cls.config.exp_admin_pass())

        set_poll_time(cls.config.exp_hostname_primary(), cls.config.exp_admin_user(), cls.config.exp_admin_pass(), 9)
        disable_fmc_upgrades(
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
                         "{} still has full list of entitled connectors ({}) installed."
                         .format(self.config.exp_hostname_primary(), str(self.config.expected_connectors())))

        deregister_expressway(self.config.control_hub(),
                              self.config.org_admin_user(),
                              self.config.org_admin_password(),
                              self.cluster_id)
        LOG.info("Wait for connectors to uninstall and CDB to be cleaned up...")
        wait_for_defuse_to_finish(
            self.config.exp_hostname_primary(),
            self.config.exp_root_user(),
            self.config.exp_root_pass(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass(),
            self.config.expected_connectors())

        LOG.info("Verify that the upgrade page shows that the connectors are not installed")
        for expected_display in self.config.expected_connectors().values():
            if expected_display != "Management Connector":
                self.assertFalse(is_text_on_page(self.config.exp_hostname_primary(),
                                                 self.config.exp_admin_user(),
                                                 self.config.exp_admin_pass(),
                                                 "upgrade",
                                                 expected_display),
                                 "Connector {} was not successfully uninstalled from {}"
                                 .format(expected_display, self.config.exp_hostname_primary()))
