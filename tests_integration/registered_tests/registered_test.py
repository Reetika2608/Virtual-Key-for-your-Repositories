import logging
import unittest

from tests_integration.utils.cdb_methods import clear_rollback_blacklist
from tests_integration.utils.common_methods import wait_until
from tests_integration.utils.config import Config
from tests_integration.utils.predicates import is_connector_installed, can_connector_be_rolled_back, \
    has_version_changed, is_blob_empty, has_connector_pid_changed, is_blacklist_empty
from tests_integration.utils.ssh_methods import rollback_connector, get_installed_connector_version, get_connector_pid

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


class RegisteredTest(unittest.TestCase):
    """ Hybrid Services tests on a registered system """
    config = None

    @classmethod
    def setUpClass(cls):
        LOG.info("Running: setUpClass")
        cls.config = Config()

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
            self.assertTrue(wait_until(is_connector_installed, 10, 1,
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
            self.assertTrue(wait_until(has_version_changed, 30, 1, *(self.config.exp_hostname_primary(),
                                                                     self.config.exp_root_user(),
                                                                     self.config.exp_root_pass(),
                                                                     "c_mgmt",
                                                                     current_version)),
                            "c_mgmt did not roll back in time and is still running version %s" % current_version)
            self.assertTrue(wait_until(is_connector_installed, 45, 1, *(self.config.exp_hostname_primary(),
                                                                        self.config.exp_root_user(),
                                                                        self.config.exp_root_pass(),
                                                                        "c_mgmt")),
                            "c_mgmt did not install in time and is still not ready")
            self.assertTrue(wait_until(has_connector_pid_changed, 30, 1, *(self.config.exp_hostname_primary(),
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
            self.assertTrue(wait_until(has_version_changed, 60, 1, *(self.config.exp_hostname_primary(),
                                                                     self.config.exp_root_user(),
                                                                     self.config.exp_root_pass(),
                                                                     "c_mgmt",
                                                                     rollback_version)),
                            "c_mgmt did not upgrade in time and is still running version %s" % rollback_version)
            self.assertTrue(wait_until(is_connector_installed, 45, 1, *((self.config.exp_hostname_primary(),
                                                                         self.config.exp_root_user(),
                                                                         self.config.exp_root_pass(),
                                                                         "c_mgmt"))),
                            "c_mgmt upgrade did not install in time and is still not ready")
            self.assertTrue(wait_until(has_connector_pid_changed, 90, 1, *(self.config.exp_hostname_primary(),
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
            self.assertTrue(wait_until(can_connector_be_rolled_back, 300, 1, *(self.config.exp_hostname_primary(),
                                                                               self.config.exp_root_user(),
                                                                               self.config.exp_root_pass(),
                                                                               "c_mgmt")),
                            "Upgrade did not repopulate the rollback TLPs")
