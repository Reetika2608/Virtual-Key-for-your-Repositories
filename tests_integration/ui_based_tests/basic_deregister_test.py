""" Basic UI Based DeRegistration Test """
import sys
import unittest

from tests_integration.utils import ci
from tests_integration.utils.cdb_methods import disable_fmc_upgrades, set_poll_time, enable_cert_management, \
    set_cdb_entry, get_cdb_entry, delete_cdb_entry
from tests_integration.utils.common_methods import create_log_directory, wait_until_false, \
    wait_for_connectors_to_install, wait_for_defuse_to_finish
from tests_integration.utils.config import Config
from tests_integration.utils.fms import enable_cloud_fusion
from tests_integration.utils.integration_test_logger import get_logger
from tests_integration.utils.predicates import are_supplied_connectors_installed, is_text_on_page, \
    is_connector_installed, does_cdb_entry_exist
from tests_integration.utils.ssh_methods import get_connector_pid
from tests_integration.utils.web_methods import deregister_expressway, create_web_driver, \
    deactivate_service, create_screenshotting_retrying_web_driver

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

        for connector in self.config.expected_connectors():
            LOG.info("Setting a dummy CDB value for {}".format(connector))
            set_cdb_entry(self.config.exp_hostname_primary(),
                          self.config.exp_admin_user(),
                          self.config.exp_admin_pass(),
                          self.dummy_path_for_connector(connector),
                          {"value": "dummy"})

    def tearDown(self):
        LOG.info("Running: tearDown")
        if sys.exc_info()[0]:
            class_name = self.__class__.__name__
            LOG.info("Saving screenshot: %s/%s_%s.png", self.log_directory, class_name, self._testMethodName)
            self.web_driver.save_screenshot("{}/{}_{}.png".format(self.log_directory, class_name, self._testMethodName))

            LOG.info("Saving source code: %s/%s_%s.txt", self.log_directory, class_name, self._testMethodName)
            with open("{}/{}_{}.txt".format(self.log_directory, class_name, self._testMethodName), "w") as f:
                f.write(self.web_driver.page_source.encode('utf-8'))
        self.web_driver.quit()

        LOG.info("Removing dummy CDB entries")
        for connector in self.config.expected_connectors():
            delete_cdb_entry(self.config.exp_hostname_primary(),
                             self.config.exp_admin_user(),
                             self.config.exp_admin_pass(),
                             self.dummy_path_for_connector(connector))

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
                           self.cluster_id,
                           create_screenshotting_retrying_web_driver(log_dir=self.log_directory, max_retries=1))

        LOG.info("Waiting for a connector not to be installed")
        self.assertFalse(wait_until_false(are_supplied_connectors_installed, 60, 5, *(
            self.config.exp_hostname_primary(),
            self.config.exp_root_user(),
            self.config.exp_root_pass(),
            self.config.expected_connectors())),
                         "{} still has full list of entitled connectors ({}) installed."
                         .format(self.config.exp_hostname_primary(), str(self.config.expected_connectors())))

        # Figure out which connector is not running (the one we deactivated in control hub earlier)
        deactivated_connector = None
        for connector in self.config.expected_connectors():
            if not is_connector_installed(self.config.exp_hostname_primary(),
                                          self.config.exp_root_user(),
                                          self.config.exp_root_pass(),
                                          connector):
                deactivated_connector = connector
                break
        else:  # nobreak
            self.fail("{} still has full list of entitled connectors ({}) installed."
                      .format(self.config.exp_hostname_primary(), str(self.config.expected_connectors())))

        LOG.info("Verifying that the deactivated connector ({}) does not have a PID file".format(deactivated_connector))
        self.assertIsNone(get_connector_pid(self.config.exp_hostname_primary(),
                                            self.config.exp_root_user(),
                                            self.config.exp_root_pass(),
                                            deactivated_connector))

        LOG.info("Verifying that the deactivated connector ({}) does not have CDB entry".format(deactivated_connector))
        self.assertFalse(wait_until_false(does_cdb_entry_exist, 20, 0.5,
                                          *(self.config.exp_hostname_primary(),
                                            self.config.exp_admin_user(),
                                            self.config.exp_admin_pass(),
                                            self.dummy_path_for_connector(deactivated_connector))),
                         "Expected {} not to have a CDB entries, found something at {}"
                         .format(deactivated_connector, self.dummy_path_for_connector(deactivated_connector)))

        deregister_expressway(self.config.control_hub(),
                              self.config.org_admin_user(),
                              self.config.org_admin_password(),
                              self.cluster_id,
                              create_screenshotting_retrying_web_driver(log_dir=self.log_directory, max_retries=1))
        LOG.info("Wait for connectors to uninstall and CDB to be cleaned up...")
        self.assertTrue(wait_for_defuse_to_finish(
            self.config.exp_hostname_primary(),
            self.config.exp_root_user(),
            self.config.exp_root_pass(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass(),
            self.config.expected_connectors()),
            "Did not defuse in time")

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

    @staticmethod
    def dummy_path_for_connector(connector):
        return "/api/management/configuration/cafe/cafeblobconfiguration/name/{}_dummy_value".format(connector)
