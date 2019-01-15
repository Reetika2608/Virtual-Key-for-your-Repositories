import unittest

# Standard library imports
import os
import logging
import json
import shutil

import sys
sys.path.append("/opt/c_mgmt/src/")

# Local application / library specific imports
from cafedynamic.cafestatusmanager import CAFEStatusManager
from managementconnector.config.cafeproperties import CAFEProperties
from cafedynamic.cafexutil import CafeXUtils


DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class CAFEStatusManagerTest(unittest.TestCase):
    """
        CAFE Status Manager Test Class
    """

    def setUp(self):
        """
            CAFE Status Manager Test Setup
        """

        DEV_LOGGER.info('***TEST CAFEStatusManagerTest Setup***')

        self.working_directory = '/tmp/test_cafestatusmanager/'
        CAFEProperties.COMPONENT_CONFIG_STATUS_DIR = self.working_directory + 'tmp/cafe/status'

        if os.path.exists(CAFEProperties.get_config_status_dir()):
            shutil.rmtree(CAFEProperties.get_config_status_dir())
        CafeXUtils.make_path(CAFEProperties.get_config_status_dir())

        self.cafe_status_manager = CAFEStatusManager(CAFEProperties.get_config_status_dir())

        self.assertTrue(os.path.exists(CAFEProperties.get_config_status_dir()),
                        'Config status directory "%s" was not created.' % CAFEProperties.get_config_status_dir())

        self.assertIsNotNone(self.cafe_status_manager, 'CAFEStatusManager instance was not successfully created')

    # -------------------------------------------------------------------------

    def tearDown(self):
        """
            CAFE Status Manager Test TearDown
        """

        DEV_LOGGER.info('***TEST CAFEStatusManagerTest TearDown***')

        self.cafe_status_manager = None

        if os.path.exists(self.working_directory):
            shutil.rmtree(self.working_directory)

        self.assertFalse(os.path.exists(self.working_directory),
                         'Working directory "%s" was not deleted on teardown.' % self.working_directory)

    # -------------------------------------------------------------------------

    def test_cafe_status_manager_success_status(self):
        """
            Test CAFE Status Manager Success Status
        """

        DEV_LOGGER.info('***TEST*** test_cafe_status_manager_success_status')

        component_name = 'my_success_component'
        status_file = CAFEProperties.get_config_status_file_format() % (CAFEProperties.get_config_status_dir(), component_name)
        self.cafe_status_manager.set_status(component_name, CAFEStatusManager.success())

        DEV_LOGGER.debug('***TEST*** test_cafe_status_manager_success_status: Verifying success status.')
        self.assertTrue(os.path.exists(status_file),
                        'Status file "%s" not written for component "%s"' % (status_file, component_name))

        status_data = None;
        with open(status_file, 'r') as status:
            status_data = json.load(status)

        self.assertEqual(status_data['component']['name'], component_name,
                         'Status file did not contain the right component name. Expected "%s", got "%s"' % (component_name, status_data['component']['name']))
        self.assertEqual(status_data['component']['status'], CAFEStatusManager.success(),
                         'Status file did not contain the right status. Expected "%s", got "%s"' % (CAFEStatusManager.success(), status_data['component']['status']))
        self.assertEqual(len(status_data['component']['error']), 0,
                         'Status file incorrectly contained an error: "%s"' % (status_data['component']['error']))


    # -------------------------------------------------------------------------

    def test_cafe_status_manager_error_status(self):
        """
            Test CAFE Status Manager Error Status
        """

        DEV_LOGGER.info('***TEST*** test_cafe_status_manager_error_status')

        component_name = 'my_failure_component'
        status_file = CAFEProperties.get_config_status_file_format() % (CAFEProperties.get_config_status_dir(), component_name)

        for error_type, error_msg in CAFEStatusManager.error_type_to_msg_map().iteritems():
            self.cafe_status_manager.set_status(component_name, CAFEStatusManager.error(), error_type)
            DEV_LOGGER.debug('***TEST*** test_cafe_status_manager_error_status: Verifying error type "%s" error msg "%s".' % (error_type, error_msg))
            self.assertTrue(os.path.exists(status_file),
                            'Status file "%s" not written for component "%s"' % (status_file, component_name))

            status_data = None;
            with open(status_file, 'r') as status:
                status_data = json.load(status)

            self.assertEqual(status_data['component']['name'], component_name,
                             'Status file did not contain the right component name. Expected "%s", got "%s"' % (component_name, status_data['component']['name']))
            self.assertEqual(status_data['component']['status'], CAFEStatusManager.error(),
                             'Status file did not contain the right status. Expected "%s", got "%s"' % (CAFEStatusManager.success(), status_data['component']['status']))
            self.assertEqual(len(status_data['component']['error']), 2,
                             'Status file does not contain an error: "%s"' % (status_data['component']['error']))
            self.assertEqual(status_data['component']['error']['error_type'], error_type,
                             'Status file did not contain the right error type. Expected "%s", got "%s"' % (error_type, status_data['component']['error']['error_type']))
            self.assertEqual(status_data['component']['error']['error_msg'], error_msg,
                             'Status file did not contain the right error msg. Expected "%s", got "%s"' % (error_msg, status_data['component']['error']['error_msg']))
    # -------------------------------------------------------------------------

    def test_cafe_status_manager_invalid_error_type(self):
        """
            Test CAFE Status Manager Invalid Error Status
        """

        DEV_LOGGER.info('***TEST*** test_cafe_status_manager_invalid_error_type')

        component_name = 'my_invalid_error_component'
        invalid_error_type = 'test_cafe_status_manager_invalid_error_type'
        status_file = CAFEProperties.get_config_status_file_format() % (CAFEProperties.get_config_status_dir(), component_name)

        self.cafe_status_manager.set_status(component_name, CAFEStatusManager.error(), invalid_error_type)

        DEV_LOGGER.debug('***TEST*** test_cafe_status_manager_invalid_error_type: Verifying invalid status.')
        self.assertTrue(os.path.exists(status_file),
                        'Status file "%s" not written for component "%s"' % (status_file, component_name))

        status_data = None;
        with open(status_file, 'r') as status:
            status_data = json.load(status)

        self.assertEqual(status_data['component']['name'], component_name,
                         'Status file did not contain the right component name. Expected "%s", got "%s"' % (component_name, status_data['component']['name']))
        self.assertEqual(status_data['component']['status'], CAFEStatusManager.error(),
                         'Status file did not contain the right status. Expected "%s", got "%s"' % (CAFEStatusManager.error(), status_data['component']['status']))
        self.assertEqual(len(status_data['component']['error']), 2,
                         'Status file does not contain an error: "%s"' % (status_data['component']['error']))
        self.assertEqual(status_data['component']['error']['error_type'], CAFEStatusManager.cafeunknownerror(),
                         'Status file did not contain the right error type. Expected "%s", got "%s"'
                         % (CAFEStatusManager.cafeunknownerror(), status_data['component']['error']['error_type']))
        self.assertEqual(status_data['component']['error']['error_msg'], CAFEStatusManager.error_type_to_msg_map()[CAFEStatusManager.cafeunknownerror()],
                         'Status file did not contain the right error msg. Expected "%s", got "%s"'
                         % (CAFEStatusManager.error_type_to_msg_map()[CAFEStatusManager.cafeunknownerror()], status_data['component']['error']['error_msg']))

# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
