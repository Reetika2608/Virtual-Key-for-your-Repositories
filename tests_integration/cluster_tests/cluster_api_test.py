import random
import unittest

from tests_integration.utils import ci
from tests_integration.utils.cdb_methods import configure_connectors, enable_expressway_connector, get_serialno, \
    set_poll_time, disable_fmc_upgrades, enable_cert_management
from tests_integration.utils.common_methods import wait_until_true, wait_for_defuse_to_finish, \
    wait_for_connectors_to_install
from tests_integration.utils.config import Config
from tests_integration.utils.fms import enable_maintenance_mode, \
    disable_maintenance_mode, enable_cloud_fusion, deregister_cluster
from tests_integration.utils.integration_test_logger import get_logger
from tests_integration.utils.predicates import are_connectors_entitled, \
    is_connector_installed, is_text_on_page, is_maintenance_mode_enabled, is_maintenance_mode_disabled, \
    is_connector_running
from tests_integration.utils.ssh_methods import get_process_count

LOG = get_logger()


class ClusterSmokeTest(unittest.TestCase):
    """ Hybrid Services Registration using a cluster of two nodes """

    config = None
    ci = None
    cluster_id = None
    access_token = None
    refresh_token = None
    session = None
    cluster_nodes = []

    @classmethod
    def setUpClass(cls):
        LOG.info("Running: setUpClass")

        cls.config = Config()
        cls.cluster_nodes.append(cls.config.exp_hostname_primary())
        cls.cluster_nodes.append(cls.config.exp_hostname_secondary())
        cls.access_token, cls.refresh_token, cls.session = ci.get_new_access_token(cls.config.org_admin_user(),
                                                                                   cls.config.org_admin_password())

        enable_cert_management(cls.config.exp_hostname_primary(),
                               cls.config.exp_admin_user(),
                               cls.config.exp_admin_pass())
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

        for expressway in cls.cluster_nodes:
            wait_for_connectors_to_install(
                expressway,
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

        LOG.info(
            "Cluster has been de-registered. Wait for cleanup to complete on nodes: %s & %s"
            % (cls.config.exp_hostname_primary(), cls.config.exp_hostname_secondary()))

        # Make sure defuse finishes on both nodes. The checks should pass pretty mush instantly on node #2
        for expressway in cls.cluster_nodes:
            wait_for_defuse_to_finish(
                expressway,
                cls.config.exp_root_user(),
                cls.config.exp_root_pass(),
                cls.config.exp_admin_user(),
                cls.config.exp_admin_pass(),
                cls.config.expected_connectors())

    def test_cluster_registration_smoke_test(self):
        """
        Purpose: Verify that a cluster can be registered to the cloud
        Steps:
        1. Verify that the UI on all nodes says we are registered
        2. Verify connectors are entitled in the DB
        3. Verify connectors have been installed
        4. Verify that the connectors are displayed on all nodes UI
        5. Configure, and Enable connectors
        6. Verify that connectors are running with no more than one process
        7. Verify that at least one connector was successfully started (not all as bad connector pushes would hurt us)
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_cluster_registration_smoke_test.__doc__)

        # 1. Verify that the UI on all nodes says we are registered
        for expressway in self.cluster_nodes:
            self.assertTrue(
                is_text_on_page(
                    expressway,
                    self.config.exp_admin_user(),
                    self.config.exp_admin_pass(),
                    "fusionregistration",
                    "cluster is registered with the Cisco"),
                "%s is not registered to the cloud" % expressway)

        # 2. Verify connectors are entitled in the DB
        for expressway in self.cluster_nodes:
            self.assertTrue(wait_until_true(are_connectors_entitled, 60, 5, *(expressway,
                                                                              self.config.exp_admin_user(),
                                                                              self.config.exp_admin_pass(),
                                                                              self.config.expected_connectors())),
                            "%s does not have the full list of entitled connectors (%s)."
                            % (expressway, str(self.config.expected_connectors())))

        # 3. Verify connectors have been installed
        for expressway in self.cluster_nodes:
            for connector in self.config.expected_connectors():
                self.assertTrue(wait_until_true(is_connector_installed, 180, 10,
                                                *(expressway,
                                                  self.config.exp_root_user(),
                                                  self.config.exp_root_pass(),
                                                  connector)),
                                "%s does not have the connector %s installed."
                                % (expressway, connector))

        # 4. Verify that the connectors are displayed on all nodes UI
        for expressway in self.cluster_nodes:
            for connector in self.config.expected_connectors():
                self.assertTrue(
                    is_text_on_page(
                        expressway,
                        self.config.exp_admin_user(),
                        self.config.exp_admin_pass(),
                        "fusionregistration",
                        connector),
                    "%s is not showing on the UI of %s" % (connector, expressway))

        # 5. Configure, and Enable connectors
        configure_connectors(
            self.config.exp_hostname_primary(),
            self.config.exp_admin_user(),
            self.config.exp_admin_pass(),
            self.config.exp_root_user(),
            self.config.exp_root_pass())

        for expressway in self.cluster_nodes:
            running_connectors = []
            for connector in self.config.expected_connectors():
                if connector != "c_mgmt":
                    enable_expressway_connector(self.config.exp_hostname_primary(),
                                                self.config.exp_admin_user(),
                                                self.config.exp_admin_pass(),
                                                connector)
                    # Soft wait for the connector to start up
                    wait_until_true(is_connector_running, 10, 1,
                                    *(expressway, self.config.exp_root_user(), self.config.exp_root_pass(), connector))

                # 6. Verify that connectors are running with correct number of processes
                process_count = get_process_count(expressway,
                                                  self.config.exp_root_user(),
                                                  self.config.exp_root_pass(),
                                                  connector)
                if process_count > 0:
                    running_connectors.append(connector)
                self.assertLessEqual(
                    process_count,
                    1,
                    "The number of processes for connector %s on %s is %s. It should be not be greater than 1" % (
                        connector, expressway, process_count))
            LOG.info("%s has running processes for %s out of the expected list of %s",
                     expressway, running_connectors, self.config.expected_connectors())
            self.assertNotEqual(running_connectors, ["c_mgmt"],
                                "No feature connectors have running process on {}. Has starting of services broken?"
                                .format(expressway))

    def test_smoke_test_hybrid_maintenance_mode(self):
        """
        Purpose: Verify that a node can be put into maintenance mode and will display a banner on the UI
        Steps:
        1. Pick one of the expressways at random and enable maintenance mode in FMS
        2. Wait for maintenance mode to be passed down to management connector in the heartbeat provisioning
        3. Verify the maintenance mode banner is displayed on the node we picked but not displayed on the other
        4. Disable maintenance mode again on the node in FMS
        5. Wait for the disable be passed down to management connector in the heartbeat provisioning
        6. Verify that no nodes are showing the maintenance mode banner
        """

        LOG.info("Running test: %s", self._testMethodName)
        LOG.info(self.test_smoke_test_hybrid_maintenance_mode.__doc__)

        # 1. Pick one of the expressways at random and enable maintenance mode in FMS
        random_expressway = random.choice(self.cluster_nodes)
        serial = get_serialno(
            random_expressway,
            self.config.exp_admin_user(),
            self.config.exp_admin_pass())

        LOG.info("Enabling maintenance mode on %s with serial number %s", random_expressway, serial)
        enable_maintenance_mode(self.config.org_id(), serial, self.config.fms_server(), self.access_token)

        # 2. Wait for maintenance mode to be passed down to management connector in the heartbeat provisioning
        self.assertTrue(wait_until_true(is_maintenance_mode_enabled, 45, 1, *(
            random_expressway,
            self.config.exp_root_user(),
            self.config.exp_root_pass())),
                        "Maintenance mode was not enabled on %s".format(random_expressway))

        # 3. Verify the maintenance mode banner is displayed on the node we picked but not displayed on the other
        for expressway in self.cluster_nodes:
            if expressway == random_expressway:
                LOG.info("Verify that the maintenance mode banner is showing on %s", expressway)
                self.assertTrue(
                    is_text_on_page(
                        expressway,
                        self.config.exp_admin_user(),
                        self.config.exp_admin_pass(),
                        "fusionregistration",
                        "Cloud Maintenance Mode"),
                    "%s is not showing the maintenance mode banner" % expressway)
            else:
                LOG.info("Verify that the maintenance mode banner is NOT showing on %s", expressway)
                self.assertFalse(
                    is_text_on_page(
                        expressway,
                        self.config.exp_admin_user(),
                        self.config.exp_admin_pass(),
                        "fusionregistration",
                        "Cloud Maintenance Mode"),
                    "%s is mistakenly showing the maintenance mode banner" % expressway)

        # 4. Disable maintenance mode again on the node in FMS
        LOG.info("Disabling maintenance mode on %s", random_expressway)
        disable_maintenance_mode(self.config.org_id(), serial, self.config.fms_server(), self.access_token)
        # 5. Wait for the disable be passed down to management connector in the heartbeat provisioning
        self.assertTrue(wait_until_true(is_maintenance_mode_disabled, 45, 1, *(
            random_expressway,
            self.config.exp_root_user(),
            self.config.exp_root_pass())),
                        "Maintenance mode was not disabled on %s".format(random_expressway))

        # 6. Verify that no nodes are showing the maintenance mode banner
        LOG.info("Verify that the maintenance mode banner is NOT showing on any node")
        for expressway in self.cluster_nodes:
            self.assertFalse(
                is_text_on_page(
                    expressway,
                    self.config.exp_admin_user(),
                    self.config.exp_admin_pass(),
                    "fusionregistration",
                    "Cloud Maintenance Mode"),
                "%s is mistakenly showing the maintenance mode banner" % expressway)
