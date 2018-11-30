import unittest

# Standard library imports
import logging
import os
import shutil
import time
import json

# Local application / library specific imports
from ni.managementconnector.config.cafeproperties import CAFEProperties
from ni.unittests.cafedynamic.mockcafemanager import MockCAFEManager
from ni.cafedynamic.cafestatusmanager import CAFEStatusManager
import ni.utils.filesystem.path as nipath

DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class CAFEComponentConfigTest(unittest.TestCase):
    """
        CAFE Component Config Test Class
    """

    def setUp(self):
        """
            CAFE Component Config Test Setup
        """

        DEV_LOGGER.info('***TEST CAFEComponentConfigTest Setup***')

        self.cafe_manager = None
        self.xcp_component = {}
        self.nobody_component = {}
        self.working_directory = '/tmp/test_cafecomponentconfig/'

        self.setup_cafe_properties(self.working_directory)
        self.create_dir(self.working_directory)
        self.setup_components()
        self.config_wait_time = CAFEProperties.get_update_config_wait_time() + 3

        self.start_mock_cafe_manager()

    # -------------------------------------------------------------------------

    def tearDown(self):
        """
            CAFE Component Config Test TearDown
        """

        DEV_LOGGER.info('***TEST CAFEComponentConfigTest TearDown***')

        self.stop_mock_cafe_manager()
        self.cafe_manager = None

        self.delete_dir(self.working_directory)

    # -------------------------------------------------------------------------

    @staticmethod
    def setup_cafe_properties(base_directory):
        """
            Setup CAFEProperties for particular testname
        """

        CAFEProperties.COMPONENT_TEMPLATE_DIR = base_directory + 'tandberg/fusion/template'
        CAFEProperties.TEMPLATE_FILENAME_PATTERN = r'.*?(' + CAFEProperties.COMPONENT_TEMPLATE_DIR + r'[^.].*?_template.(?:[a-z\d]+)(?![\w\.]))\Z'
        CAFEProperties.COMPONENT_CONFIG_STAGING_DIR = base_directory + 'tmp/cafe/staging'
        CAFEProperties.CONFIG_FILEPATH_FORMAT = base_directory + 'tandberg/persistent/fusion/config/%s.%s'
        CAFEProperties.COMPONENT_CONFIG_STATUS_DIR = base_directory + 'tmp/cafe/status'
        CAFEProperties.COMPONENT_OWNER_FORMAT = '%s'
        CAFEProperties.UPDATE_CONFIG_WAIT_TIME = 1

    # -------------------------------------------------------------------------

    def setup_components(self):
        """
            Setup the component files/directories for the test
        """

        # 'xcp' component variables
        self.xcp_component['name'] = '_xcp'
        self.xcp_component['extension'] = 'json'
        self.xcp_component['template_path'] = CAFEProperties.get_component_template_dir() + '/%s_template.%s' % (self.xcp_component['name'], self.xcp_component['extension'])
        self.xcp_component['status_file'] = CAFEProperties.get_config_status_file_format() % (CAFEProperties.get_config_status_dir(), self.xcp_component['name'])
        self.xcp_component['config_file'] = CAFEProperties.get_config_filepath_format() % (self.xcp_component['name'], self.xcp_component['extension'])
        self.create_dir(os.path.dirname(self.xcp_component['config_file']))

        # 'nobody' component variables
        self.nobody_component['name'] = '_nobody'
        self.nobody_component['extension'] = 'xml'
        self.nobody_component['template_path'] = CAFEProperties.get_component_template_dir() + '/%s_template.%s' % (self.nobody_component['name'], self.nobody_component['extension'])
        self.nobody_component['status_file'] = CAFEProperties.get_config_status_file_format() % (CAFEProperties.get_config_status_dir(), self.nobody_component['name'])
        self.nobody_component['config_file'] = CAFEProperties.get_config_filepath_format() % (self.nobody_component['name'], self.nobody_component['extension'])
        self.create_dir(os.path.dirname(self.nobody_component['config_file']))

    # -------------------------------------------------------------------------

    def start_mock_cafe_manager(self):
        """
            Create and start a MockCAFEManager instance
        """
        # Create a CAFEManager instance
        if not self.cafe_manager or not self.cafe_manager.started:
            self.cafe_manager = MockCAFEManager('options')
            self.cafe_manager._initialise_database()
            self.cafe_manager.start()
            time.sleep(self.config_wait_time)

    # -------------------------------------------------------------------------

    def stop_mock_cafe_manager(self):
        """
            Stop MockCAFEManager instance
        """
        if self.cafe_manager:
            self.cafe_manager.stop()
            # sleep to allow any component threads to cleanup and die
            time.sleep(self.config_wait_time)

    # -------------------------------------------------------------------------

    @staticmethod
    def create_file(filepath, content):
        """
            Write the template content to a filename
        """
        with open(filepath, 'w') as template_file:
            template_file.write(content)

    # -------------------------------------------------------------------------

    @staticmethod
    def delete_file(filepath):
        """
            Delete the filepath specified
        """
        if os.path.exists(filepath):
            os.remove(filepath)

    # -------------------------------------------------------------------------

    @staticmethod
    def create_dir(dirpath):
        """
            Create the directory path specified
        """

        if os.path.exists(dirpath):
            shutil.rmtree(dirpath)
        nipath.make_path(dirpath)

    # -------------------------------------------------------------------------

    @staticmethod
    def delete_dir(dirpath):
        """
            Delete the directory specified
        """

        if os.path.exists(dirpath):
            shutil.rmtree(dirpath)

    # -------------------------------------------------------------------------

    def verify_component_success_status(self, status_file, component_name):
        """
            Assert that the status file for the given component has a success status
        """

        with open(status_file, 'r') as status:
            status_data = json.load(status)

        self.assertEqual(status_data['component']['name'], component_name,
                         '%s Status file did not contain the right component name. Expected "%s", got "%s"' % (component_name, component_name, status_data['component']['name']))
        self.assertEqual(status_data['component']['status'], CAFEStatusManager.success(),
                         '%s Status file did not contain the right status. Expected "%s", got "%s"' % (component_name, CAFEStatusManager.success(), status_data['component']['status']))
        self.assertEqual(len(status_data['component']['error']), 0,
                         '%s Status file incorrectly contained an error: "%s"' % (component_name, status_data['component']['error']))

    # -------------------------------------------------------------------------

    def test_cafe_component_config_initial_write(self):
        """
            Test that a CAFE Component Config instance initialises correctly
        """

        DEV_LOGGER.info('***TEST*** test_cafe_component_config_initial_write')

        # create template files
        self.create_file(self.xcp_component['template_path'], XCP_TEMPLATE)
        self.create_file(self.nobody_component['template_path'], NOBODY_TEMPLATE)

        # trigger the handler for a template update
        self.cafe_manager._on_template_change(self.xcp_component['template_path'])
        self.cafe_manager._on_template_change(self.nobody_component['template_path'])

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_initial_write: Waiting for component config to be written.')
        time.sleep(self.config_wait_time)


        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_initial_write: Verifying that CAFEComponentConfig instances were created.')
        self.assertIsNotNone(self.cafe_manager.managed_component_configs[self.xcp_component['template_path']], 'XCP CAFEComponentConfig instance was not successfully created.')
        self.assertIsNotNone(self.cafe_manager.managed_component_configs[self.nobody_component['template_path']], 'Nobody CAFEComponentConfig instance was not successfully created.')


        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_initial_write: Verifying that component configuration files were created.')
        self.assertTrue(os.path.exists(self.xcp_component['config_file']), 'XCP component config file was not created. File="%s"' % self.xcp_component['config_file'])
        self.assertTrue(os.path.exists(self.nobody_component['config_file']), 'Nobody component config file was not created. File="%s"' % self.nobody_component['config_file'])

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_initial_write: Verifying that component status files were created.')
        self.assertTrue(os.path.exists(self.xcp_component['status_file']), 'XCP component status file was not created. File="%s"' % self.xcp_component['status_file'])
        self.assertTrue(os.path.exists(self.nobody_component['status_file']), 'Nobody component status file was not created. File="%s"' % self.nobody_component['status_file'])


        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_initial_write: Verifying that component status files contain a success status.')
        self.verify_component_success_status(self.xcp_component['status_file'], self.xcp_component['name'])
        self.verify_component_success_status(self.nobody_component['status_file'], self.nobody_component['name'])

    # -------------------------------------------------------------------------

    def test_cafe_component_config_non_updatable_change(self):
        """
            Test that a CAFE Component Config instance do not update config files if there is no actual change
        """

        DEV_LOGGER.info('***TEST*** test_cafe_component_config_non_updatable_change')

        # create template files
        self.create_file(self.xcp_component['template_path'], XCP_TEMPLATE)
        self.create_file(self.nobody_component['template_path'], NOBODY_TEMPLATE)

        # trigger the handler for a template update
        self.cafe_manager._on_template_change(self.xcp_component['template_path'])
        self.cafe_manager._on_template_change(self.nobody_component['template_path'])

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_non_updatable_change: Waiting for component config to be written.')
        time.sleep(self.config_wait_time)

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_non_updatable_change: Verifying that component configuration files were created.')
        self.assertTrue(os.path.exists(self.xcp_component['config_file']), 'XCP component config file was not created. File="%s"' % self.xcp_component['config_file'])
        self.assertTrue(os.path.exists(self.nobody_component['config_file']), 'Nobody component config file was not created. File="%s"' % self.nobody_component['config_file'])

        # get the current modified time of the components config files
        xcp_modified_time = time.ctime(os.path.getmtime(self.xcp_component['config_file']))
        nobody_modified_time = time.ctime(os.path.getmtime(self.nobody_component['config_file']))

        # trigger an update which should result in no change
        self.cafe_manager.managed_component_configs[self.xcp_component['template_path']].schedule_config_update()
        self.cafe_manager.managed_component_configs[self.nobody_component['template_path']].schedule_config_update()

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_non_updatable_change: Waiting for component config to be written.')
        time.sleep(self.config_wait_time)


        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_non_updatable_change: Verifying that component configuration files were not updated.')
        current_modified_time = time.ctime(os.path.getmtime(self.xcp_component['config_file']))
        self.assertEqual(xcp_modified_time, current_modified_time, 'Modified time on XCP component config file was unexpectantly changed. File="%s"' % self.xcp_component['config_file'])
        current_modified_time = time.ctime(os.path.getmtime(self.nobody_component['config_file']))
        self.assertEqual(nobody_modified_time, current_modified_time, 'Modified time on Nobody component config file was unexpectantly changed. File="%s"' % self.nobody_component['config_file'])

    # -------------------------------------------------------------------------

    def test_cafe_component_config_updatable_change(self):
        """
            Test that a CAFE Component Config instance do update config files if there is an actual change
        """

        DEV_LOGGER.info('***TEST*** test_cafe_component_config_updatable_change')

        DEV_LOGGER.info('***TEST*** test_cafe_component_config_updatable_change CAFEProperties.TEMPLATE_FILENAME_PATTERN= %s'
                %(CAFEProperties.TEMPLATE_FILENAME_PATTERN))

        # create template files
        self.create_file(self.xcp_component['template_path'], XCP_TEMPLATE)
        self.create_file(self.nobody_component['template_path'], NOBODY_TEMPLATE)

        # trigger the handler for a template update
        self.cafe_manager._on_template_change(self.xcp_component['template_path'])
        self.cafe_manager._on_template_change(self.nobody_component['template_path'])

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_updatable_change: Waiting for component config to be written.')
        time.sleep(self.config_wait_time)

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_updatable_change: Verifying that component configuration files were created.')
        self.assertTrue(os.path.exists(self.xcp_component['config_file']), 'XCP component config file was not created. File="%s"' % self.xcp_component['config_file'])
        self.assertTrue(os.path.exists(self.nobody_component['config_file']), 'Nobody component config file was not created. File="%s"' % self.nobody_component['config_file'])

        # get the current modified time of the components config files
        xcp_modified_time = time.ctime(os.path.getmtime(self.xcp_component['config_file']))
        nobody_modified_time = time.ctime(os.path.getmtime(self.nobody_component['config_file']))

        # update template files
        self.create_file(self.xcp_component['template_path'], XCP_TEMPLATE2)
        self.create_file(self.nobody_component['template_path'], NOBODY_TEMPLATE2)

        # trigger the handler for a template update
        self.cafe_manager._on_template_change(self.xcp_component['template_path'])
        self.cafe_manager._on_template_change(self.nobody_component['template_path'])

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_updatable_change: Waiting for component config to be written.')
        time.sleep(self.config_wait_time)

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_updatable_change: Verifying that component configuration files were updated.')
        current_modified_time = time.ctime(os.path.getmtime(self.xcp_component['config_file']))
        self.assertNotEqual(xcp_modified_time, current_modified_time, 'Modified time on XCP component config file was not updated. File="%s"' % self.xcp_component['config_file'])
        current_modified_time = time.ctime(os.path.getmtime(self.nobody_component['config_file']))
        self.assertNotEqual(nobody_modified_time, current_modified_time, 'Modified time on Nobody component config file was not updated. File="%s"' % self.nobody_component['config_file'])

    # -------------------------------------------------------------------------


    def test_cafe_component_config_cleanup(self):
        """
            Test that a CAFE Component Config instance cleans up INotify's when destroyed.
        """

        DEV_LOGGER.info('***TEST*** test_cafe_component_config_cleanup')

        # create template files
        self.create_file(self.xcp_component['template_path'], XCP_TEMPLATE)
        self.create_file(self.nobody_component['template_path'], NOBODY_TEMPLATE)

        # trigger the handler for a template update
        self.cafe_manager._on_template_change(self.xcp_component['template_path'])
        self.cafe_manager._on_template_change(self.nobody_component['template_path'])

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_cleanup: Waiting for component config to be written.')
        time.sleep(self.config_wait_time)

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_cleanup: Verifying that component configuration files were created.')
        self.assertTrue(os.path.exists(self.xcp_component['config_file']), 'XCP component config file was not created. File="%s"' % self.xcp_component['config_file'])
        self.assertTrue(os.path.exists(self.nobody_component['config_file']), 'Nobody component config file was not created. File="%s"' % self.nobody_component['config_file'])

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_initial_write: Verifying that CAFEComponentConfig instances were destroyed.')
        self.delete_file(self.xcp_component['template_path'])
        self.cafe_manager._on_template_change(self.xcp_component['template_path'])
        self.assertNotIn(self.xcp_component['template_path'], self.cafe_manager.managed_component_configs, 'XCP CAFEComponentConfig instance was not successfully destroyed.')

        self.delete_file(self.nobody_component['template_path'])
        self.cafe_manager._on_template_change(self.nobody_component['template_path'])
        self.assertNotIn(self.nobody_component['template_path'], self.cafe_manager.managed_component_configs, 'Nobody CAFEComponentConfig instance was not successfully destroyed.')

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_initial_write: Waiting for CAFEComponentConfig instance threads to stop and be destroyed.')
        time.sleep(self.config_wait_time)

        DEV_LOGGER.debug('***TEST*** test_cafe_component_config_initial_write: Verifying that CAFEManager has no managed components.')
        self.assertDictEqual(self.cafe_manager.managed_component_configs, {}, 'CAFEManager managed_component_configs dictionary was not empty. "%s"' % self.cafe_manager.managed_component_configs)


# =============================================================================


# CDB tables referenced in these templates should have dummy data added to the MockCAFEDatabase class
XCP_TEMPLATE = """\
{
    "connector": {
        "ci_machine_account": "AppFusionSvc.machAcct",
        "ci_machine_password": "{cipher}xxxxxxxx",
        "ci_client_id": "Cd1e0aaac0b48762efe2a622351aaecd3d57d2944e4ec82ef237806d455279538",
        "ci_secret": "{cipher}xxxxx"
    },
    "expressway": {
        "ipv4_address": "@!EXPRESSWAY_IPV4_INTERNAL_ADDRESS!@",
        "ipv6_address": "@!EXPRESSWAY_IPV6_INTERNAL_ADDRESS!@"
    },
    "sip_domains": [#!
        $!setvar('sip_domain_records', '[domain for domain in CDB["/configuration/sipdomain"]]')!$
        <!--(for sip_domain_records_index, domain in enumerate(sip_domain_records))-->
        {
            "name": "@!domain["name"]!@",
            "sip": @!domain["edgesip"]!@,
            "federation": @!domain["xmppfederation"]!@,
            "client": @!domain["edgexmpp"]!@#!
            $!setvar('closing_bracket', '"}," if sip_domain_records_index < len(sip_domain_records) - 1 else "}"')!$
        @!closing_bracket!@
        <!--(end)-->
    ]
}
"""

NOBODY_TEMPLATE = """\
{
    "connector": {
        "ci_machine_account": "AppFusionSvc.machAcct",
        "ci_machine_password": "{cipher}xxxxxxxx",
        "ci_client_id": "Cd1e0aaac0b48762efe2a622351aaecd3d57d2944e4ec82ef237806d455279538",
        "ci_secret": "{cipher}xxxxx"
    },
    "expressway": {
        "ipv4_address": "@!EXPRESSWAY_IPV4_INTERNAL_ADDRESS!@",
        "ipv6_address": "@!EXPRESSWAY_IPV6_INTERNAL_ADDRESS!@"
    },
    "cucm_cluster_records": [#!
        $!setvar('cucm_publisher_records', '[cucm for cucm in CDB["/configuration/edgeconfigprovisioning/cucm"] if cucm["role"] == "Publisher"]')!$
        <!--(for cucm_publisher_records_index, cucm_publisher in enumerate(cucm_publisher_records))-->
        {
            "axl_username": "@!cucm_publisher['axl_username']!@",
            "axl_password": "@!cucm_publisher['axl_password']!@",
            "cucm_records": [#!
                $!setvar('cucm_records', '[cucm for cucm in CDB["/configuration/edgeconfigprovisioning/cucm"] if cucm["publisher"] == cucm_publisher["publisher"]]')!$
                <!--(for cucm_records_index, cucm in enumerate(cucm_records))-->
                {
                    "host": "@!cucm["address"]!@",#!
                    $!setvar('is_publisher', '"true" if cucm["role"] == "Publisher" else "false"')!$
                    "publisher": @!is_publisher!@#!
                    $!setvar('closing_bracket', '"}," if cucm_records_index < len(cucm_records) - 1 else "}"')!$
                @!closing_bracket!@
                <!--(end)-->
            ]#!
            $!setvar('closing_bracket', '"}," if cucm_publisher_records_index < len(cucm_publisher_records) - 1 else "}"')!$
        @!closing_bracket!@
        <!--(end)-->
    ],
    "sip_domains": [#!
        $!setvar('sip_domain_records', '[domain for domain in CDB["/configuration/sipdomain", "name/test-domain3.com"]]')!$
        <!--(for sip_domain_records_index, domain in enumerate(sip_domain_records))-->
        {
            "name": "@!domain["name"]!@",
            "sip": @!domain["edgesip"]!@,
            "federation": @!domain["xmppfederation"]!@,
            "client": @!domain["edgexmpp"]!@#!
            $!setvar('closing_bracket', '"}," if sip_domain_records_index < len(sip_domain_records) - 1 else "}"')!$
        @!closing_bracket!@
        <!--(end)-->
    ]
}
"""

XCP_TEMPLATE2 = NOBODY_TEMPLATE
NOBODY_TEMPLATE2 = XCP_TEMPLATE

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
