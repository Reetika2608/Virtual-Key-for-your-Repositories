import os
import unittest

from tests_integration.utils.cdb_methods import enable_fmc_upgrades
from tests_integration.utils.common_methods import create_log_directory, wait_until_true
from tests_integration.utils.config import Config
from tests_integration.utils.integration_test_logger import get_logger
from tests_integration.utils.ssh_methods import run_ssh_command
from tests_integration.utils.web_methods import login_expressway, \
    navigate_expressway_menus, is_in_page_source, bootstrap_expressway, create_screenshotting_retrying_web_driver

LOG = get_logger()


class BasicBootstrapTest(unittest.TestCase):
    config = None

    @classmethod
    def setUpClass(cls):
        cls.log_directory = create_log_directory()
        certs_location = os.environ.get("BROKEN_CERTS_LOCATION")
        cls.broken_certs_location = certs_location if certs_location is not None else "all_cas_removed.pem"
        cls.config = Config()

        enable_fmc_upgrades(cls.config.exp_hostname_primary(),
                            cls.config.exp_admin_user(),
                            cls.config.exp_admin_pass())

    def setUp(self):
        self.web_driver = create_screenshotting_retrying_web_driver(self.log_directory, 10)

    def test_bootstrap_fuse_flow(self):
        """
        Purpose: Validate prefuse checks, namely the bootstrap and register pages.
        Steps:
            1. Break our current certificates
            2. Load fusion registration page and validate the we are at the go-to-cloud page.
            3. Write the bootstrap data to the DB.
            4. Load fusion registration page and validate the we are at the registration page.
            5. Verify that we fail to fuse with our broken certs
            6. Verify that we're able to initiate a fuse when we let Cisco provide non-broken certs
            7. Un-break our current certificates
        """

        certs_backed_up = False
        try:
            # Back up certs file
            run_ssh_command(self.config.exp_hostname_primary(),
                            self.config.exp_root_user(),
                            self.config.exp_root_pass(),
                            "cp /tandberg/persistent/certs/ca.pem /tandberg/persistent/certs/ca.bak")
            certs_backed_up = True

            # Replace cert file contents with our broken one
            with open(self.broken_certs_location) as broken_cert_file:
                run_ssh_command(self.config.exp_hostname_primary(),
                                self.config.exp_root_user(),
                                self.config.exp_root_pass(),
                                "cat <<EOF > /tandberg/persistent/certs/ca.pem\n{broken_cert_contents}\nEOF"
                                .format(broken_cert_contents=broken_cert_file.read()))

            # Verify that we're not currently fused
            login_expressway(self.web_driver,
                             self.config.exp_hostname_primary(),
                             self.config.exp_admin_user(),
                             self.config.exp_admin_pass())

            navigate_expressway_menus(self.web_driver, ["Applications", "Hybrid Services", "Connector Management"])
            self.assertTrue(wait_until_true(is_in_page_source, 30, 1,
                                            *(self.web_driver,
                                              'You must first register your Expressway as a resource through Cisco')),
                            '"You must first register your Expressway as a resource through Cisco" not displayed')

            # Create a cluster, enable all services, pass bootstrap data to Expressway
            bootstrap_expressway(self.config.control_hub(),
                                 self.config.org_admin_user(),
                                 self.config.org_admin_password(),
                                 self.config.exp_hostname_primary(),
                                 self.web_driver)

            self.web_driver.wrapped_driver.switch_to.window(self.web_driver.wrapped_driver.window_handles[1])

            # Verify bootstrapped UI state
            self.assertTrue(wait_until_true(is_in_page_source, 30, 1,
                                            *(self.web_driver,
                                              'The Webex cloud handed out a token to the Expressway')),
                            '"The Webex cloud handed out a token to the Expressway" not displayed')

            # Attempt to fuse without certificates, verify error message
            self.web_driver.find_element_by_css_selector('input[type="submit"]#register').click()
            self.assertTrue(wait_until_true(is_in_page_source, 30, 1,
                                            *(self.web_driver,
                                              '<b>Failed</b>: Error occurred when upgrading Management Connector')),
                            'Error message not displayed when trying to pre-fuse without certs')

            # Fuse, letting Cisco provide certs
            self.web_driver.find_element_by_css_selector('input[type="checkbox"]#use_fusion_ca').send_keys(' ')
            self.web_driver.find_element_by_css_selector('input[type="submit"]#register').click()

            # Verify prefuse UI
            self.assertTrue(wait_until_true(is_in_page_source, 30, 1,
                                            *(self.web_driver,
                                              'The latest software was successfully installed and all the prerequisites are met for this Expressway to be registered for Hybrid Services.'
                                              )),
                            'Pre-fuse text not displayed')
        finally:
            if certs_backed_up:
                LOG.info("De-ruining certs for {}".format(self.config.exp_hostname_primary()))
                run_ssh_command(self.config.exp_hostname_primary(),
                                self.config.exp_root_user(),
                                self.config.exp_root_pass(),
                                "cp /tandberg/persistent/certs/ca.bak /tandberg/persistent/certs/ca.pem")
                run_ssh_command(self.config.exp_hostname_primary(),
                                self.config.exp_root_user(),
                                self.config.exp_root_pass(),
                                "chown _nobody:nobody /tandberg/persistent/certs/ca.pem")
