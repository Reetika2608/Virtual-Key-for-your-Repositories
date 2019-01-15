"""
    Class to manage status updates to a particular directory.
"""

# Standard library imports
import datetime
import json
import os

# Local application / library specific imports
from managementconnector.config.cafeproperties import CAFEProperties
from cafedynamic.cafefilewriter import CAFEFileWriter

DEV_LOGGER = CAFEProperties.get_dev_logger()
ADMIN_LOGGER = CAFEProperties.get_admin_logger()


# =============================================================================


class CAFEStatusManager(object):
    """
        Class to manage status updates to a particular directory.
    """

    # -------------------------------------------------------------------------

    def __init__(self, status_directory):
        """
            CAFE Status Manager initialiser
        """

        DEV_LOGGER.debug('Detail="Initialising CAFE Status Manager"')
        if not status_directory:
            DEV_LOGGER.error('Detail="Programmer error. Empty status director passed to constructor"')
            return

        self.status_directory = status_directory
        self.status_filepath_format = CAFEProperties.get_config_status_file_format()

        self. error_msg_map = CAFEStatusManager.error_type_to_msg_map()

    # -------------------------------------------------------------------------

    def __del__(self):
        """
            Destructor for CAFE Status Manager
        """
        DEV_LOGGER.debug('Detail="Destroying CAFE Status Manager"')

    # -------------------------------------------------------------------------

    def set_status(self, component_name, status, error_type=None):
        """
            Write the status to the status file
        """

        status_dataset = dict()

        if not component_name or not status:
            DEV_LOGGER.error('Detail="Programmer error. Empty component_name or status passed to function"')
            return

        status_dataset['component_name'] = component_name

        if status == CAFEStatusManager.success() or status == CAFEStatusManager.error():
            status_dataset['status'] = status
        else:
            DEV_LOGGER.error('Detail="Programmer error. Status should be %s or %s"' % (CAFEStatusManager.error(), CAFEStatusManager.success()))
            return

        status_dataset['is_failure'] = False

        if status == CAFEStatusManager.error():
            status_dataset['is_failure'] = True
            if not error_type or error_type not in self.error_msg_map:
                status_dataset['error_type'] = CAFEStatusManager.cafeunknownerror()
                status_dataset['error_msg'] = self.error_msg_map[CAFEStatusManager.cafeunknownerror()]
            else:
                status_dataset['error_type'] = error_type
                status_dataset['error_msg'] = self.error_msg_map[error_type]

        status_file = self.status_filepath_format % (self.status_directory, component_name)

        status_dataset['timestamp'] = datetime.datetime.now().isoformat('T')

        try:
            DEV_LOGGER.debug('Detail="Writing status for component" '
                             'Status="%s" '
                             'Component="%s" '
                             'Error Type="%s"' % (status, component_name, error_type))

            CAFEFileWriter(status_file).config_file_write(status_dataset, CAFEProperties.get_config_status_template())
        except SyntaxError as ex:
            ADMIN_LOGGER.error(
                'Detail="Error while attempting to write component status file" '
                'Status File="%s" '
                'Component="%s"' % (status_file, component_name))
            DEV_LOGGER.error(
                'Detail="Error while attempting to write component status file" '
                'Status File="%s" '
                'Component="%s" '
                'Status Dataset="%s" '
                'Error ="%r - %s"' % (status_file, component_name, status_dataset, ex, ex.__str__()))

    # -------------------------------------------------------------------------

    def get_status(self, component_name):
        """
            Using the status file that CafeManager writes when a connector has been configured,
            determine if the connector has been configured.

            returns a dictionary:
            {
                'status': 'Not Configured'|'Success'|'Error'
                # if 'status' is 'Success'|'Error' then the dictionary also has a 'timestamp'
                'timestamp': 'ISO 8601 UTC Date'
                # if 'status' is 'Error' then the dictionary also has a 'error_type'
                'error_type': 'Any of the CAFEStatusManager error types'
            }
        """

        configuration_status = {'status': CAFEStatusManager.not_configured()}
        component_status_file = self.status_filepath_format % (self.status_directory, component_name)

        if os.path.exists(component_status_file):
            with open(component_status_file, 'r') as status_file:

                data = json.load(status_file)
                configuration_status['status'] = data['component']['status']
                configuration_status['timestamp'] = data['timestamp']

                if configuration_status['status'] == CAFEStatusManager.success():
                    DEV_LOGGER.debug('Detail="Configuration Status file indicates that component was successfully configured" '
                                     'Component="%s" '
                                     'Status File="%s"' % (component_name, component_status_file))
                else:
                    error_msg = data['component']['error']['error_msg']
                    error_type = data['component']['error']['error_type']
                    configuration_status['error_type'] = error_type
                    DEV_LOGGER.error('Detail="Configuration Status file indicates that component was not successfully configured" '
                                     'Component="%s" '
                                     'Status File="%s" '
                                     'Error Type="%s" '
                                     'Error="%s"' % (component_name, component_status_file, error_type, error_msg))
        else:
            DEV_LOGGER.debug('Detail="Configuration Status file did not exist for component" '
                             'Component="%s" '
                             'Status File="%s"' % (component_name, component_status_file))

        return configuration_status

    # -------------------------------------------------------------------------

    @staticmethod
    def error():
        """
            Return the error string status
        """
        return 'Error'

    # -------------------------------------------------------------------------

    @staticmethod
    def success():
        """
            Return the success string status
        """
        return 'Success'

    # -------------------------------------------------------------------------

    @staticmethod
    def not_configured():
        """
            Return the not configured string status
        """
        return 'Not Configured'

    # -------------------------------------------------------------------------

    @staticmethod
    def cafetemplatesyntaxerror():
        """
            Return the CafeTemplateSyntaxError string
        """
        return 'CafeTemplateSyntaxError'

    # -------------------------------------------------------------------------

    @staticmethod
    def cafetemplatecontenterror():
        """
            Return the CafeTemplateContentError string
        """
        return 'CafeTemplateContentError'

    # -------------------------------------------------------------------------

    @staticmethod
    def cafeconfigwriteerror():
        """
            Return the CafeConfigWriteError string
        """
        return 'CafeConfigWriteError'

    # -------------------------------------------------------------------------

    @staticmethod
    def cafeconfiggenerationerror():
        """
            Return the CafeConfigGenerationError string
        """
        return 'CafeConfigGenerationError'

    # -------------------------------------------------------------------------

    @staticmethod
    def cafeunknownerror():
        """
            Return the CafeUnknownError string
        """
        return 'CafeUnknownError'

    # -------------------------------------------------------------------------

    @staticmethod
    def error_type_to_msg_map():
        """
            Return the map of error types to error messages
        """
        return {
            CAFEStatusManager.cafetemplatesyntaxerror():     'Invalid syntax within components template file',
            CAFEStatusManager.cafetemplatecontenterror():    'Invalid CDB or Convenience reference within components template file',
            CAFEStatusManager.cafeconfigwriteerror():        'FileSystem/Permission error while writing components configuration file',
            CAFEStatusManager.cafeconfiggenerationerror():   'Error encountered while generating components configuration file',
            CAFEStatusManager.cafeunknownerror():            'Unknown error was encountered while generating components configuration file'
        }


# =============================================================================
