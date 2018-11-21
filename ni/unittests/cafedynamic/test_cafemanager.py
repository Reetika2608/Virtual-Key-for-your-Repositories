import unittest

# Standard library imports
import os
import logging
import shutil

import ni.unittests.mock._platform
# Local application / library specific imports
from ni.unittests.cafedynamic.mockcafemanager import MockCAFEManager
from ni.managementconnector.config.cafeproperties import CAFEProperties
import ni.utils.filesystem.path as nipath


DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class CAFEManagerTest(unittest.TestCase):
    """
        CAFE Manager Test Class
    """

    def setUp(self):
        """
            CAFE Manager Test Setup
        """

        DEV_LOGGER.info('***TEST CAFEManagerTest Setup***')

        self.working_directory = '/tmp/test_cafemanager/'
        CAFEProperties.COMPONENT_TEMPLATE_DIR = self.working_directory + 'tandberg/fusion/template'
        CAFEProperties.COMPONENT_CONFIG_STAGING_DIR = self.working_directory + 'tmp/cafe/staging'
        CAFEProperties.CONFIG_FILEPATH_FORMAT = self.working_directory + 'tandberg/persistent/fusion/config/%s.%s'
        CAFEProperties.COMPONENT_CONFIG_STATUS_DIR = self.working_directory + 'tmp/cafe/status'

        if os.path.exists(self.working_directory):
            shutil.rmtree(self.working_directory)
        nipath.make_path(self.working_directory)

        self.cafe_manager = MockCAFEManager('options')
        self.cafe_manager._initialise_database()

        self.assertIsNotNone(self.cafe_manager, 'CAFEManager instance was not successfully created')

    # -------------------------------------------------------------------------

    def tearDown(self):
        """
            CAFE Manager Test TearDown
        """

        DEV_LOGGER.info('***TEST CAFEManagerTest TearDown***')

        if self.cafe_manager and self.cafe_manager.started:
            self.cafe_manager.stop()
        self.cafe_manager = None

        if os.path.exists(self.working_directory):
            shutil.rmtree(self.working_directory)

    # -------------------------------------------------------------------------

    def test_cafe_manager_started_and_stopped(self):
        """
            Test CAFE Manager Started
        """

        DEV_LOGGER.info('***TEST*** test_cafe_manager_started_and_stopped')

        DEV_LOGGER.debug('***TEST*** test_cafe_manager_started_and_stopped: Starting CAFEManager')
        self.cafe_manager.start()
        self.assertTrue(self.cafe_manager.started)

        DEV_LOGGER.debug('***TEST*** test_cafe_manager_started_and_stopped() - Verifying CAFEManager directories created')
            # Verify that all directories were created correctly
        self.assertTrue(os.path.exists(CAFEProperties.get_component_template_dir()),
                            'CAFEManager template directory "%s" does not exist' % CAFEProperties.get_component_template_dir())
        self.assertTrue(os.path.exists(CAFEProperties.get_config_status_dir()),
                            'CAFEManager config status directory "%s" does not exist' % CAFEProperties.get_config_status_dir())
        self.assertTrue(os.path.exists(CAFEProperties.get_config_staging_dir()),
                            'CAFEManager config staging directory "%s" does not exist' % CAFEProperties.get_config_staging_dir())

        DEV_LOGGER.debug('***TEST*** test_cafe_manager_started_and_stopped: Stopping CAFEManager')
        self.cafe_manager.stop()
        self.assertFalse(self.cafe_manager.started)

        DEV_LOGGER.debug('***TEST*** test_cafe_manager_started_and_stopped() - Verifying CAFEManager directories deleted')
        self.assertFalse(os.path.exists(CAFEProperties.get_config_status_dir()),
                            'CAFEManager config status directory "%s" was not deleted' % CAFEProperties.get_config_status_dir())
        self.assertFalse(os.path.exists(CAFEProperties.get_config_staging_dir()),
                            'CAFEManager config staging directory "%s" was not deleted' % CAFEProperties.get_config_staging_dir())


# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
