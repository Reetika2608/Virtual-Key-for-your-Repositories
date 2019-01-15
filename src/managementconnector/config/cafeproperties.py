"""
    Class to hold properties used across multiple CAFE Dynamic  modules
"""

# Standard library imports
import logging
import re

# Local application / library specific imports
# none


# =============================================================================

class CAFEProperties(object):
    """
        Class to hold properties used across multiple CAFE Dynamic modules
    """
    # -------------------------------------------------------------------------
    # Loggers
    # -------------------------------------------------------------------------

    HYBRID_LOGGER_NAME = 'hybridservices.cafedynamic'
    DEV_LOGGER_NAME = 'developer.cafe.cafedynamic'
    ADMIN_LOGGER_NAME = 'administrator.cafe.cafemdynamic'

    STATUS_LOGGER = "developer.xmlapi.cafestatus"

    LOGGER_NAMES = {"default": HYBRID_LOGGER_NAME, "8.6": DEV_LOGGER_NAME, "8.7": DEV_LOGGER_NAME}
    LOGGERS_STATUS = {"default": HYBRID_LOGGER_NAME, "8.6": STATUS_LOGGER, "8.7": STATUS_LOGGER}

    # -------------------------------------------------------------------------

    @staticmethod
    def get_dev_logger():
        """
            Return CAFE developer logger
        """
        module = CAFEProperties.LOGGER_NAMES['default']

        return logging.getLogger(module)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_status_logger():
        """
            Return CAFE developer logger
        """
        module = CAFEProperties.LOGGERS_STATUS['default']

        return logging.getLogger(module)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_admin_logger():
        """
            Return CAFE administrator logger
        """
        return logging.getLogger(CAFEProperties.ADMIN_LOGGER_NAME)

    # -------------------------------------------------------------------------
    # CAFE Component related directories
    # -------------------------------------------------------------------------

    COMPONENT_TEMPLATE_DIR = '/mnt/harddisk/current/fusion/template'
    COMPONENT_CONFIG_STAGING_DIR = '/tmp/fusion/staging'
    CONFIG_FILEPATH_FORMAT = '/tandberg/persistent/fusion/config/%s.%s'
    COMPONENT_OWNER_FORMAT = '_%s'

    # -------------------------------------------------------------------------

    @staticmethod
    def get_component_template_dir():
        """
            Return the directory where component template files will be stored
        """
        return CAFEProperties.COMPONENT_TEMPLATE_DIR

    # -------------------------------------------------------------------------

    @staticmethod
    def get_config_staging_dir():
        """
            Return the directory where component config files will be initially staged
        """
        return CAFEProperties.COMPONENT_CONFIG_STAGING_DIR

    # -------------------------------------------------------------------------

    @staticmethod
    def get_config_filepath_format():
        """
            Return the component config filepath format
        """
        return CAFEProperties.CONFIG_FILEPATH_FORMAT

    # -------------------------------------------------------------------------

    @staticmethod
    def get_component_owner_format():
        """
            Return the format of the component owner name
        """
        return CAFEProperties.COMPONENT_OWNER_FORMAT

    # -------------------------------------------------------------------------
    # Status template & directory
    # -------------------------------------------------------------------------

    CONFIG_STATUS_TEMPLATE = """\
{
    "timestamp":"@!timestamp!@",
    "component":{
        "name":"@!component_name!@",
        "status":"@!status!@",
        "error":{
            <!--(if (is_failure == True))-->
            "error_type":"@!error_type!@",
            "error_msg":"@!error_msg!@"
            <!--(end)-->
        }
    }
}
"""

    COMPONENT_CONFIG_STATUS_DIR = '/tmp/fusion/status'
    CONFIG_STATUS_FILE_FORMAT = '%s/%s_status.json'

    # -------------------------------------------------------------------------

    @staticmethod
    def get_config_status_template():
        """
            Return the directory where the CDB schema json files are located
        """
        return CAFEProperties.CONFIG_STATUS_TEMPLATE

    # -------------------------------------------------------------------------

    @staticmethod
    def get_config_status_dir():
        """
            Return the directory where status will be posted
        """
        return CAFEProperties.COMPONENT_CONFIG_STATUS_DIR

    # -------------------------------------------------------------------------

    @staticmethod
    def get_config_status_file_format():
        """
            Return the status filepath format
        """
        return CAFEProperties.CONFIG_STATUS_FILE_FORMAT

    # -------------------------------------------------------------------------
    # CAFE Component template regular expressions
    # -------------------------------------------------------------------------

    TEMPLATE_CDB_REFERENCE_PATTERN = r'.*?(CDB\[.*?\])'
    TEMPLATE_CDB_TABLE_PATTERN = r'((?:\/[\w\.\-]+)+)[^\w^\?]+((?:\/?[\w\.\-\?\=]?)+)'
    TEMPLATE_FILENAME_PATTERN = r'.*?(' + COMPONENT_TEMPLATE_DIR + r'[^.].*?_template.(?:[a-z\d]+)(?![\w\.]))\Z'
    TEMPLATE_EXPRESSWAY_PATTERN = r'.*?@!(EXPRESSWAY_.*?)!@'

    # -------------------------------------------------------------------------

    @staticmethod
    def get_template_cdb_ref_regex():
        """
            Return the regex to find CDB references in CAFE component config templates
        """
        return re.compile(CAFEProperties.TEMPLATE_CDB_REFERENCE_PATTERN, re.IGNORECASE | re.DOTALL)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_template_cdb_table_regex():
        """
            Return the regex to find CDB table references in CAFE component config templates
        """
        return re.compile(CAFEProperties.TEMPLATE_CDB_TABLE_PATTERN, re.IGNORECASE | re.DOTALL)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_template_filename_regex():
        """
            Return the regex to validate the filenames of CAFE component config template
        """
        return re.compile(CAFEProperties.TEMPLATE_FILENAME_PATTERN, re.IGNORECASE | re.DOTALL)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_template_expressway_regex():
        """
            Return the regex to find Expressway convenience method references in CAFE component config templates
        """
        return re.compile(CAFEProperties.TEMPLATE_EXPRESSWAY_PATTERN, re.IGNORECASE | re.DOTALL)

    # -------------------------------------------------------------------------
    # CAFE Manager Initialisation modes
    # -------------------------------------------------------------------------

    CAFE_MANAGER_BASIC_MODE = 'basic'
    CAFE_MANAGER_FULL_MODE = 'full'

    # -------------------------------------------------------------------------

    @staticmethod
    def get_cafe_manager_basic_mode():
        """
            Return the CAFE Manager 'basic' mode string
        """
        return CAFEProperties.CAFE_MANAGER_BASIC_MODE

    # -------------------------------------------------------------------------

    @staticmethod
    def get_cafe_manager_full_mode():
        """
            Return the CAFE Manager 'full' mode string
        """
        return CAFEProperties.CAFE_MANAGER_FULL_MODE

    # -------------------------------------------------------------------------
    # Other CAFE settings
    # -------------------------------------------------------------------------

    CDB_JSON_SCHEMA_DIR = '/share/erlang/cdb_schema/'
    UPDATE_CONFIG_WAIT_TIME = 1  # seconds

    # -------------------------------------------------------------------------

    @staticmethod
    def get_cdb_json_schema_dir():
        """
            Return the directory where the CDB schema json files are located
        """
        return CAFEProperties.CDB_JSON_SCHEMA_DIR

    # -------------------------------------------------------------------------

    @staticmethod
    def get_update_config_wait_time():
        """
            Return the number of seconds that the Config Updater should wait for further changes,
            before updating a Components configuration
        """
        return CAFEProperties.UPDATE_CONFIG_WAIT_TIME


# =============================================================================
