"""
    Class to hold ManagementConnector properties
"""
# Standard library imports
import logging
import os
from datetime import datetime


class ManagementConnectorProperties(object):  # nosec - /tmp usage validated
    """
        ManagementConnector properties
    """
    # -------------------------------------------------------------------------
    # OAUTH
    # -------------------------------------------------------------------------
    IDP_URL = 'idb/oauth2/v1/access_token'

    # Amount of days before a machine account is updated
    MACHINE_ACCOUNT_REFRESH = 30
    # Amount of seconds before an access token is updated
    ACCESS_TOKEN_REFRESH = 300
    # Amount of seconds before a refresh token is updated
    REFRESH_TOKEN_REFRESH = 86400

    # Allowed list of common missing parts from Manifest
    accepted_missing = [["proxy", "enabled"],
                        ["proxy", "username"],
                        ["proxy", "port"],
                        ["proxy", "address"],
                        ["alarms", "exclude"],
                        ["cgroupLimits", "cpuPriorityPercentage"],
                        ["cgroupLimits", "memoryPercentageLimit"]]

    @staticmethod
    def get_idp_url():
        """
            Returns IDP URL
        """

        return ManagementConnectorProperties.IDP_HOST + '/' + ManagementConnectorProperties.IDP_URL

    # -------------------------------------------------------------------------
    # Loggers
    # -------------------------------------------------------------------------

    LOGGER_DB_PATH = "/configuration/hybridserviceslogger"
    LOGGER_INOTIFY = "/tmp/management/notifications/diagnostics/hybridserviceslogger"

    HYBRID_PREFIX = "hybridservices."
    HYBRID_LOGGER_NAME = HYBRID_PREFIX + "managementconnector"
    CAFE_LOGGER_NAME = HYBRID_PREFIX + "cafedynamic"
    DEFAULT_LOGGERS = [HYBRID_LOGGER_NAME, CAFE_LOGGER_NAME]

    DEV_LOGGER_NAME = 'developer.cafe.managementconnector'
    ADMIN_LOGGER_NAME = 'administrator.cafe.managementconnector'

    LOGGER_NAMES = {"default": HYBRID_LOGGER_NAME, "8.6": DEV_LOGGER_NAME, "8.7": DEV_LOGGER_NAME}

    # -------------------------------------------------------------------------

    @staticmethod
    def get_dev_logger():
        """
            Return CAFE developer/hybridservices logger depending on Expressway Version
        """
        module = ManagementConnectorProperties.LOGGER_NAMES['default']

        return logging.getLogger(module)

    # -------------------------------------------------------------------------

    @staticmethod
    def get_admin_logger():
        """
            Return CAFE administrator logger
        """
        return logging.getLogger(ManagementConnectorProperties.ADMIN_LOGGER_NAME)

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------

    CONFIG_FILE_STATUS_LOCATION = "/tandberg/persistent/fusion/status/%s.configured"
    CONFIG_FILE_STATUS_MGMT = CONFIG_FILE_STATUS_LOCATION % "c_mgmt"
    CONFIG_FILE_LOCATION = '/opt/c_mgmt/etc/config/c_mgmt.json'

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------

    CAFE_BLOB_CDB_PATH = '/configuration/cafe/cafeblobconfiguration/'
    STATIC_CDB_PATH = '/configuration/cafe/cafestaticconfiguration/'

    BLOB_CDB_PATH = CAFE_BLOB_CDB_PATH + 'name/c_mgmt_'
    STATIC_MGMT_CDB_PATH = STATIC_CDB_PATH + 'name/c_mgmt_'

    DATABASE_TABLES = [CAFE_BLOB_CDB_PATH, STATIC_CDB_PATH]

    # -------------------------------------------------------------------------

    CONNECTOR_PREFIX = 'c_'

    DEPENDENCY_PREFIX = 'd_'

    SERVICE_NAME = 'c_mgmt'

    SERVICE_LIST = {'c_mgmt', 'c_ccucmgmt'}

    DEPENDENCY_MAP = {"Calendar Connector": ["d_openj"]}

    HTTP_TIMEOUT = 15
    WS_PING_TIMEOUT = 10
    WS_PING_INTERVAL = 30

    SYS_SUCCESS_CODE = 0
    SYS_UNKNOWN_ERROR_CODE = 1
    SYS_ERROR_CODE = 99

    GENERIC_STATUS_FILE = '/var/run/%s/status.json'

    STATUS_FILE = GENERIC_STATUS_FILE % SERVICE_NAME

    UPGRADE_EVENTS_FILE = '/var/run/%s/upgrade_events.json'

    WHITEBOX_STATUS = {"state": "operational", "initialized": "true"}

    INSTALLING_STATUS_FILE = '/var/run/%s/installing_status.json'

    LAST_KNOWN_LOG_ID = '/mnt/harddisk/persistent/fusion/log/log_id.json'

    EVENT_SUCCESS = "success"
    EVENT_FAILURE = "failure"
    PUSH_FAILURE = "pushFailure"
    ARCHIVE_FAILURE = "archiveFailure"

    UPGRADE_REASON_CERT = "cert"
    UPGRADE_REASON_DOWNLOAD = "download"
    UPGRADE_REASON_INSTALL = "install"
    UPGRADE_REASON_DISABLE = "disable"
    UPGRADE_REASON_ENABLE = "enable"

    LIBRARY_PATH = '/opt/%s/lib/' % SERVICE_NAME

    SERVICE_CHANGE_TRIGGER = '/tmp/request/servicechange'
    SERVICE_CONTROL_REQUEST = '/tmp/request/requestservicestart'

    INSTALL_PACKAGE_DIR = '/tmp/pkgs/new'
    REMOVE_FILE = INSTALL_PACKAGE_DIR + '/files.rem'

    HEARTBEAT_EXTENSION = ".heartbeat"
    C_MGMT_VAR_RUN = '/var/run/' + SERVICE_NAME
    UPGRADE_HEARTBEAT_FILE = '/var/run/%s' + '/%s' + HEARTBEAT_EXTENSION

    EVENT_DAMPENER_INTERVAL = 10

    MERCURY_EXTENSION = ".mercury"
    MERCURY_FILE = '/var/run/%s' + '/%s' + MERCURY_EXTENSION

    REMOTE_DISPATCHER_EXTENSION = ".remotedispatcher"
    REMOTE_DISPATCHER_FILE = '/var/run/%s' + '/%s' + REMOTE_DISPATCHER_EXTENSION

    WATCHDOG_EXTENSION = ".watchdog"
    WATCHDOG_FILE = C_MGMT_VAR_RUN + '/%s' + WATCHDOG_EXTENSION
    WATCHDOG_FILE_PATH = WATCHDOG_FILE % SERVICE_NAME

    FULL_VAR = C_MGMT_VAR_RUN + '/' + SERVICE_NAME + "%s"

    WATCHDOG_WORKING_STATE = "working"

    HOSTS = 'hosts'

    DEFUSE_ATTEMPT_LIMIT = 30

    SHUT_DOWN_WAIT = 8

    # Should be updated every time there is a change to Mgmt Connector DB Schema
    CDB_VERSION_CURRENT = "1.0"

    # This matches the template in case the config comes back as None.
    DEFAULT_POLL_TIME = 30

    # TODO: Check if USER_AGENT can be changed to 'User-Agent'
    # This affects 'User-Agent' headers in src/cloud/atlaslogger.py that is sent to client logs service
    USER_AGENT = 'User-agent'
    USER_AGENT_VALUE = 'FMC'

    CDB_CLEAN_TIMEOUT = 30

    # -------------------------------------------------------------------------
    # Configuration Paths
    # -------------------------------------------------------------------------

    CONFIG = "config_"
    ERROR_POLL_TIME = CONFIG + "errorPollTime"
    POLL_TIME = CONFIG + "pollTime"
    REGISTER_URL = CONFIG + "registerUrl"
    EVENT_URL = CONFIG + "eventUrl"
    CLUSTER_URL = CONFIG + "clusterUrl"
    MACHINE_POLL_TIME = CONFIG + "machineAccountPollTime"
    DEFAULT_MACHINE_POLL_TIME = 86400
    MACHINE_POLL_TIME_FAIL = 300
    MACHINE_ACC_EXPIRY = CONFIG + "machineAccountExpiry"
    DEFAULT_MACHINE_ACC_EXPIRY = 45
    MERCURY_HEARTBEAT_POLL_TIME = CONFIG + "mercuryHeartbeatPollTime"
    WATCHDOG_POLL_TIME = CONFIG + "watchdogPollTime"
    DEFAULT_WATCHDOG_TIME = 43200
    INITIAL_WATCHDOG_POLL = CONFIG + "initialWatchdogPoll"
    DEFAULT_INITIAL_POLL = 4200
    DEFAULT_U2C_POLL_TIME = 86400

    # -------------------------------------------------------------------------
    # Logging API Paths
    # -------------------------------------------------------------------------

    LOGGING_API = "logging_"

    LOGGING_HOST = LOGGING_API + "host"
    LOGGING_ASK_URL = LOGGING_API + "askurl"
    LOGGING_META_URL = LOGGING_API + "metaurl"
    LOGGING_IDENTIFIER = LOGGING_API + "identifier"
    LOGGING_QUANTITY = LOGGING_API + "quantity"
    LOGGING_QUANTITY_DEFAULT = 50

    # -------------------------------------------------------------------------
    # Features API Paths
    # -------------------------------------------------------------------------

    FEATURES = "features"
    FEATURES_BASE = FEATURES + "_"

    FEATURES_ENTRIES = FEATURES_BASE + "entries"
    FEATURES_HOST = FEATURES_BASE + "featuresHost"
    FEATURES_URL = FEATURES_BASE + "featuresUrl"
    FEATURE_HEARTBEAT_POLL_TIME = FEATURES_BASE + "pollTime"

    FEATURES_PREFIX = "fmc-"
    FEATURE_VAL_ID = "val"
    FEATURES_GROUP = "developer"

    # -------------------------------------------------------------------------
    # UCMGMT API Paths
    # -------------------------------------------------------------------------

    UCMGMT_API = "ucmgmt_"

    UCMGMT_CONTROLLER_HOST = UCMGMT_API + "controllerHost"
    UCMGMT_GATEWAY_HOST = UCMGMT_API + "gatewayHost"
    UCMGMT_LICENSING_HOST = UCMGMT_API + "licensingHost"
    UCMGMT_MIGRATION_HOST = UCMGMT_API + "migrationHost"
    UCMGMT_TELEMETRY_MGMT_HOST = UCMGMT_API + "telemetryMgmtHost"
    UCMGMT_UPGRADE_HOST = UCMGMT_API + "upgradeHost"
    UCMGMT_WEB_HOST = UCMGMT_API + "webHost"

    # -------------------------------------------------------------------------
    # Metrics Paths
    # -------------------------------------------------------------------------

    # Means 240 heartbeats
    METRICS_STATUS_FILTER = 240

    METRICS = "metrics_"

    METRICS_HOST = METRICS + "metricsHost"
    METRICS_URL = METRICS + "metricsUrl"
    METRICS_UA = METRICS + "userAgent"
    METRICS_ENABLED = METRICS + "enabled"
    METRICS_TESTMODE = METRICS + "testmode"

    PREVENT_MGMT_CONN_UPGRADE = CONFIG + "preventMgmtConnUpgrade"
    PREVENT_CONN_UPGRADE = CONFIG + "preventConnUpgrade"

    CERT = "certs_"
    FUSION_CA = CERT + "ca"
    ADD_FUSION_CERTS = CERT + "addFusionCertsToCA"

    DEFAULT_EXPRESSWAY_CA_FILE = '/tandberg/persistent/certs/ca.pem'
    CERTS_ADDED_TO_CA_DIR = '/tandberg/persistent/certs/fusionadded/'
    FUSION_REMOVE_CERTS_REQUEST = "/tmp/request/removefusioncerts"
    FUSION_ADD_CERTS_REQUEST = "/tmp/request/addfusioncerts"
    FUSION_CERTS_DIR_ADD_REQUEST = "/tmp/request/createfusioncertsdir"
    FUSION_CERTS_DIR_DEL_REQUEST = "/tmp/request/deletefusioncertsdir"
    FUSION_CA_FILE = '/mnt/harddisk/persistent/fusion/certs/fusion.pem'
    COMBINED_CA_FILE = '/mnt/harddisk/persistent/fusion/certs/all_certs.pem'

    @staticmethod
    def is_fusion_certs_added():
        """
            returns if fusion certs added (existence of CERTS_ADDED_TO_CA_DIR)
        """
        return os.path.exists(ManagementConnectorProperties.CERTS_ADDED_TO_CA_DIR)

    # {  'name': u'c_cal':
    #       { 'url': u'https://sqfusion-jenkins.cisco.com/job/PIPELINE_CALCLOUD_PROMOTED/93/artifact/c_cal_8.6-1.0.905.tlp',
    #          'version': u'8.6-1.0.905'},
    #    'name': u'c_ucm':
    #       { 'url': '',
    #          'version': ''},
    SUPPORTED_EXTENSIONS = ['tlp']
    PACKAGE_EXTENSION = ".tlp"
    INSTALL_UPGRADES = "installed_"
    INSTALL_BLACK_LIST = INSTALL_UPGRADES + "blacklist"
    ROLLBACK_BLACK_LIST = "rollback_blacklist"
    INSTALL_PREVIOUS_DIR = "/mnt/harddisk/persistent/fusion/previousversions"
    INSTALL_CURRENT_DIR = "/mnt/harddisk/persistent/fusion/currentversions"
    INSTALL_DOWNLOADS_DIR = "/mnt/harddisk/persistent/fusion/downloads"
    INSTALL_DOWNLOAD_FILE = "/mnt/harddisk/persistent/fusion/downloads/%s" + PACKAGE_EXTENSION

    SERVICE_CDB_CACHE_FILE = INSTALL_PREVIOUS_DIR + "/%s_cdb_cache.json"

    OAUTH_MACHINE_ACCOUNT_DETAILS = "oauthMachineAccountDetails"

    EXCLUDE_LIST = {CAFE_BLOB_CDB_PATH: {"%s_%s" % (SERVICE_NAME, INSTALL_BLACK_LIST),
                                         "%s_%s" % (SERVICE_NAME, OAUTH_MACHINE_ACCOUNT_DETAILS)}}

    # -------------------------------------------------------------------------

    @staticmethod
    def get_current_time(time_format):
        """
            return formatted time
        """
        return datetime.now().strftime(time_format)

    @staticmethod
    def get_utc_time(time_format):
        """
            return utc formatted time
        """
        return datetime.utcnow().strftime(time_format)

    PROXY = "proxy_"
    PROXY_ADDRESS = PROXY + "address"
    PROXY_PORT = PROXY + "port"
    PROXY_USERNAME = PROXY + "username"
    PROXY_PASSWORD = PROXY + "password"
    PROXY_ENABLED = PROXY + "enabled"

    SYSTEM = "system_"
    IPV4_ADDRESS = SYSTEM + "ipv4Address"
    IPV6_ADDRESS = SYSTEM + "ipv6Address"
    HOSTNAME = SYSTEM + "hostname"
    DOMAINNAME = SYSTEM + "domainname"
    CLUSTER_NAME = SYSTEM + "clusterName"
    CLUSTER_ID = SYSTEM + "clusterId"
    TEMP_TARGET_ORG_ID = SYSTEM + "tempTargetOrgId"
    TEAMS_CLUSTER_ID = SYSTEM + "teamsClusterId"
    BOOTSTRAP_PARAMS = SYSTEM + "bootstrapParams"
    CDB_VERSION = SYSTEM + "cdb_version"
    FUSED = SYSTEM + "fused"
    TARGET_TYPE = SYSTEM + "targetType"
    SERIAL_NUMBER = SYSTEM + "serialNumber"
    CLUSTER_SERIALS = SYSTEM + "clusterSerials"
    VERSION = SYSTEM + "version"
    ENABLED_SERVICES = SYSTEM + "enabledServices"
    ENABLED_SERVICES_STATE = SYSTEM + "enabledServicesState"
    CONFIGURED_SERVICES_STATE = SYSTEM + "configuredServicesState"
    ENTITLED_SERVICES = SYSTEM + "entitledServices"
    OPERATIONAL = SYSTEM + "operational"
    REREGISTER = SYSTEM + "reRegisterRequired"
    WATCHDOG_STATUS = SYSTEM + "watchdogStatus"
    LAST_HEARTBEAT_TIME = "lastHeartbeatTime_"
    LAST_MERCURY_TIME = "lastMercuryTime_"
    WATCHDOG_RESTART_TIME = "watchdogRestartTime_"
    FMS_HOST = SYSTEM + "fmsUrl"

    ALARMS = "alarms_"
    ALARMS_RAISED = ALARMS + "raised"
    PLATFORM_ALARMS_RAISED = ALARMS + "raisedPlatform"

    OAUTH_BASE = "oauth"
    OAUTH = OAUTH_BASE + "_"
    IDP_HOST = OAUTH + "idpHost"
    ATLAS_URL_PREFIX = OAUTH + "atlasUrlPrefix"
    CLIENT_ID = OAUTH + "clientId"
    CLIENT_SECRET = OAUTH + "clientSecret"

    COMMANDS_BASE = "commands"
    COMMANDS = COMMANDS_BASE + "_"
    WDM_HOST = COMMANDS + "wdmHost"
    WDM_URL = COMMANDS + "wdmUrl"
    WDM_REFRESH = COMMANDS + "wdmRefreshInterval"
    COMMANDS_TEST_MODE = COMMANDS + "testmode"
    COMMANDS_TEST_PUB_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsk9fC14rfeP5p29nW+FmSGTq05Lmd5Yh/oJ+mtioZ3bxZVVdwwhNgCNBRy6l3wvfz8YE7mY3rWZd3Z/fVNTndonKDm2uzzbyNV6Gzg7XTi+0t7QoA5+ooYwzNhmE2dXAo3CFXU0ZmPS32wgcaU520Rqr64EotWyVtg3OYF3ETwuNP/xdaMm0qAtl5O0bVyTfyfmZntaJ4RfL0SoUzXIGxQomrdVLT7aOiiYBVKhNU2YEupYnn7cLGSRnymJT+ywvz1uoTAFqVK4XcIOWtxHz54XpQzORq514V2u1JstTSkmZSUHsd7QP/gh3RIEctWpldp4N2gnpdlSdfiXWDwkRFwIDAQAB'
    REMOTE_DISPATCHER_HOST = COMMANDS + "remotedispatcherHost"
    REMOTE_DISPATCHER_URL = COMMANDS + "remotedispatcherUrl"
    MERCURY_PROBE_LIMIT = 5
    MERCURY_PROBE_TIMEOUT = 60

    MAINTENANCE_MODE = "maintenanceMode"

    DEVICE_TYPE = "CONNECTOR"

    REGISTRATION_TIME_OUT_LIMIT = 5

    CORE_DUMP_PATHS = ['/mnt/harddisk/core/processed/CSI.*']

    # -------------------------------------------------------------------------
    # U2C API Paths
    # -------------------------------------------------------------------------

    U2C = "u2c"
    U2C_BASE = U2C + "_"
    U2C_HOST = U2C_BASE + "u2cHost"
    U2C_SERVICE_URL = U2C_BASE + "serviceUrl"
    U2C_USER_SERVICE_URL = U2C_BASE + "userUrl"
    U2C_HEARTBEAT_POLL_TIME = U2C_BASE + "pollTime"
    U2C_CLIENT_LOGS = BLOB_CDB_PATH + LOGGING_HOST + "_u2c"
    U2C_WDM = BLOB_CDB_PATH + WDM_HOST + "_u2c"
    U2C_METRICS = BLOB_CDB_PATH + METRICS_HOST + "_u2c"
    U2C_RD = BLOB_CDB_PATH + REMOTE_DISPATCHER_HOST + "_u2c"
    U2C_FEATURE = BLOB_CDB_PATH + FEATURES_HOST + "_u2c"
    U2C_UCMGMT_CONTROLLER_HOST = BLOB_CDB_PATH + UCMGMT_CONTROLLER_HOST + "_u2c"
    U2C_UCMGMT_GATEWAY_HOST = BLOB_CDB_PATH + UCMGMT_GATEWAY_HOST + "_u2c"
    U2C_UCMGMT_LICENSING_HOST = BLOB_CDB_PATH + UCMGMT_LICENSING_HOST + "_u2c"
    U2C_UCMGMT_MIGRATION_HOST = BLOB_CDB_PATH + UCMGMT_MIGRATION_HOST + "_u2c"
    U2C_UCMGMT_TELEMETRY_MGMT_HOST = BLOB_CDB_PATH + UCMGMT_TELEMETRY_MGMT_HOST + "_u2c"
    U2C_UCMGMT_UPGRADE_HOST = BLOB_CDB_PATH + UCMGMT_UPGRADE_HOST + "_u2c"
    U2C_UCMGMT_WEB_HOST = BLOB_CDB_PATH + UCMGMT_WEB_HOST + "_u2c"
    U2C_IDB_HOST = "system_idpHost_u2c"
    U2C_IDBROKER = BLOB_CDB_PATH + U2C_IDB_HOST
    U2C_IDENTITY_HOST = "system_identityHost_u2c"
    U2C_IDENTITY = BLOB_CDB_PATH + U2C_IDENTITY_HOST
    U2C_FMS = BLOB_CDB_PATH + "system_fmsUrl"
    U2C_ADMIN_PORTAL = BLOB_CDB_PATH + "system_atlas_portal_u2c"
