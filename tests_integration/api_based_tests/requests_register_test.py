""" Hybrid Services Registration tests via requests library """
import logging
import unittest

from tests_integration.utils import ci
from tests_integration.utils.cdb_methods import configure_connectors, enable_expressway_connector, get_serialno, \
    set_poll_time, disable_fmc_upgrades
from tests_integration.utils.common_methods import wait_until_true, wait_for_connectors_to_install, \
    wait_for_defuse_to_finish
from tests_integration.utils.config import Config
from tests_integration.utils.fms import enable_cloud_fusion, deregister_cluster
from tests_integration.utils.predicates import are_connectors_entitled, \
    is_connector_installed, is_connector_running
from tests_integration.utils.ssh_methods import get_process_count

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


class RequestsRegisterTest(unittest.TestCase):
    """ Hybrid Services Registration tests via requests library """
    config = None
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
        disable_fmc_upgrades(
            cls.config.exp_hostname_primary(),
            cls.config.exp_admin_user(),
            cls.config.exp_admin_pass())
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

        LOG.info("Cluster has been de-registered. Wait for cleanup to complete on %s"
                 % cls.config.exp_hostname_primary())

        wait_for_defuse_to_finish(
            cls.config.exp_hostname_primary(),
            cls.config.exp_root_user(),
            cls.config.exp_root_pass(),
            cls.config.exp_admin_user(),
            cls.config.exp_admin_pass(),
            cls.config.expected_connectors())

    def test_connectors_can_be_enabled_with_correct_process_count(self):
        """
        Purpose: Verify that connectors when enabled, have the correct number of running processes
        Steps:
        1. Verify connectors are entitled
        2. Verify connectors have been installed
        3. Configure, and Enable connectors
        4. Verify that connectors are running with no more than one process
        5. Verify that at least one connector was successfully started (not all as bad connector pushes would hurt us)
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_connectors_can_be_enabled_with_correct_process_count.__doc__)

        self.assertTrue(wait_until_true(are_connectors_entitled, 60, 5, *(self.config.exp_hostname_primary(),
                                                                          self.config.exp_admin_user(),
                                                                          self.config.exp_admin_pass(),
                                                                          self.config.expected_connectors())),
                        "%s does not have the full list of entitled connectors (%s)."
                        % (self.config.exp_hostname_primary(), str(self.config.expected_connectors())))

        for connector in self.config.expected_connectors():
            self.assertTrue(wait_until_true(is_connector_installed, 180, 10,
                                            *(self.config.exp_hostname_primary(),
                                              self.config.exp_root_user(),
                                              self.config.exp_root_pass(),
                                              connector)),
                            "%s does not have the connector %s installed."
                            % (self.config.exp_hostname_primary(), connector))

        configure_connectors(
            self.config.exp_hostname_primary(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass(),
            self.config.exp_root_user(),
            self.config.exp_root_pass())

        # Enable all other connectors
        running_connectors = []
        for connector in self.config.expected_connectors():
            if connector != "c_mgmt":
                enable_expressway_connector(self.config.exp_hostname_primary(),
                                            self.config.exp_admin_user(),
                                            self.config.exp_admin_pass(),
                                            connector)
                # Soft wait for the connector to start up
                wait_until_true(is_connector_running, 10, 1,
                                *(self.config.exp_hostname_primary(),
                                  self.config.exp_root_user(),
                                  self.config.exp_root_pass(),
                                  connector))
            process_count = get_process_count(self.config.exp_hostname_primary(),
                                              self.config.exp_root_user(),
                                              self.config.exp_root_pass(),
                                              connector)
            if process_count > 0:
                running_connectors.append(connector)
            self.assertLessEqual(
                process_count,
                1,
                "The number of processes for connector %s on %s is %s. It should be not be greater than 1"
                % (connector, self.config.exp_hostname_primary(), process_count))

        LOG.info("%s has running processes for %s out of the expected list of %s", self.config,
                 self.config.exp_hostname_primary(), running_connectors, self.config.expected_connectors())
        self.assertNotEqual(running_connectors, ["c_mgmt"],
                            "No feature connectors have running process on {}. Has starting of services broken?"
                            .format(self.config.exp_hostname_primary()))
