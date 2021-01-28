""" Management Connector Listener Class for Deploy"""

import os
import threading
import traceback

# Local application / library specific imports

from managementconnector.config.config import Config
from managementconnector.config.databasehandler import register_all_default_loggers
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.deploy import Deploy
from managementconnector.deployrunner import DeployRunner
from managementconnector.config import jsonhandler
from managementconnector.config.certhandler import CertHandler, merge_certs
from managementconnector.lifecycle.machineaccountrunner import MachineAccountRunner
from managementconnector.lifecycle.mercuryrunner import MercuryRunner
from managementconnector.platform.serviceutils import ServiceUtils
from managementconnector.platform.logarchiver import LogArchiver
from cafedynamic.cafemanager import CAFEManager

from managementconnector.lifecycle.threadrunner import ThreadRunner
from managementconnector.lifecycle.featurethread import FeatureThread
from managementconnector.lifecycle.u2cthread import U2CThread
from managementconnector.lifecycle.watchdog import WatchdogThread
from managementconnector.cloud.features import Features

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()

# =============================================================================


class ManagementConnector(object):
    """
    Management Connector Listener
    """

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Management Connector Class'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self):
        """Management Connector __init__"""
        DEV_LOGGER.debug('Detail="FMC_Lifecycle ManagementConnector init called"')

        # Initialise listener waiting for deploy
        self._config = Config()
        self._cert_handler = CertHandler(ManagementConnectorProperties.DEFAULT_EXPRESSWAY_CA_FILE,
                                         True, self.check_for_certs)

        self._init_events()

        self._deploy = Deploy(self._config)
        self._deploy_runner = DeployRunner(self._deploy)
        self._mercury_runner = MercuryRunner(self._config, self._mercury_stop_event)
        self._machine_runner = MachineAccountRunner(self._config, self._machine_stop_event)
        self._feature_runner = ThreadRunner(self._config, self._feature_stop_event, FeatureThread)
        self._u2c_runner = ThreadRunner(self._config, self._u2c_stop_event, U2CThread)
        self._watchdog_runner = ThreadRunner(self._config, self._watchdog_stop_event, WatchdogThread)

        self._cached_features = {}

        self.deployed = False

        self._cafe_manager = CAFEManager('options')

        self.all_certs_size_pre_repair = 0

    # -------------------------------------------------------------------------

    def _init_events(self):
        """ Initialise stop events for threads """
        self._mercury_stop_event = threading.Event()
        self._machine_stop_event = threading.Event()
        self._feature_stop_event = threading.Event()
        self._watchdog_stop_event = threading.Event()
        self._u2c_stop_event = threading.Event()

        self._stop_events = [self._mercury_stop_event, self._machine_stop_event, self._feature_stop_event,
                             self._watchdog_stop_event, self._u2c_stop_event]

    # -------------------------------------------------------------------------

    def start(self):
        """Management Connector start"""
        DEV_LOGGER.info('Detail="FMC_Lifecycle ManagementConnector started"')
        ADMIN_LOGGER.info('Detail="FMC_Lifecycle ManagementConnector started"')

        # Kick off the Cafe Manager
        self._cafe_manager.start()

        self.check_for_certs()
        self.register_listener()

        register_all_default_loggers()

        self.write_schema_version()

        enabled_services_states = self._config.read(ManagementConnectorProperties.ENABLED_SERVICES_STATE)
        target_type = self._config.read(ManagementConnectorProperties.TARGET_TYPE)

        if ServiceUtils.blob_mode_on(target_type, enabled_services_states):
            self.deployed = True
            ServiceUtils.set_operational_state(True)
            self._watchdog_runner.start()
            self._machine_runner.start()
            self._deploy_runner.start()
            self._mercury_runner.start()
            self._u2c_runner.start()
            # Uncomment following if feature toggles are needed in future, also see mc_features_tests in oak-tests
            #self._feature_runner.start()
            #self.toggle_features()

    # -------------------------------------------------------------------------

    def stop(self):
        """ Management Connector Stop """
        DEV_LOGGER.info('Detail="FMC_Lifecycle ManagementConnector stopped"')
        ADMIN_LOGGER.info('Detail="FMC_Lifecycle ManagementConnector stopped"')

        jsonhandler.delete_file(ManagementConnectorProperties.STATUS_FILE)

        self._handle_stop()

        self.unregister_listener()
        self._cafe_manager.stop()

    # -------------------------------------------------------------------------

    def write_schema_version(self):
        """ Management Connector DB Update """
        DEV_LOGGER.debug('Detail="ManagementConnector write_schema_version"')

        self._config.write_static(ManagementConnectorProperties.CDB_VERSION, ManagementConnectorProperties.CDB_VERSION_CURRENT)

    # -------------------------------------------------------------------------

    def register_listener(self):
        """ Register Config Listener """
        DEV_LOGGER.debug('Detail="ManagementConnector register listener"')
        self._config.add_observer(self.on_config_update)

    # -------------------------------------------------------------------------

    def unregister_listener(self):
        """ Management Connector Un-register Listener """
        DEV_LOGGER.debug('Detail="ManagementConnector un-register listener"')
        self._config.remove_observer(self.on_config_update)

    # -------------------------------------------------------------------------

    def on_config_update(self):
        """ Callback from CDB update """

        DEV_LOGGER.debug('Detail="ManagementConnector on_config_update"')

        self.check_for_certs()
        LogArchiver.push_logs_async(self._config, self._deploy.get_oauth())

        # Currently enabled service
        enabled_services = self._config.read(ManagementConnectorProperties.ENABLED_SERVICES)

        # Service states we want to apply
        enabled_services_states = self._config.read(ManagementConnectorProperties.ENABLED_SERVICES_STATE)

        target_type = self._config.read(ManagementConnectorProperties.TARGET_TYPE)

        if enabled_services is not None and enabled_services_states:
            for name in enabled_services_states.keys():
                if name == target_type:
                    # Check if Enabled and not already deployed
                    DEV_LOGGER.debug('Detail="ManagementConnector checking blob mode to manage deploy state for Connector:%s"', target_type)
                    if ServiceUtils.blob_mode_on(target_type, enabled_services_states):
                        if not self.deployed:
                            DEV_LOGGER.debug('Detail="FMC_Lifecycle ManagementConnector initial deploy"')
                            self.deployed = True
                            self._watchdog_runner.start()
                            self._machine_runner.start()
                            self._deploy_runner.start()
                            self._mercury_runner.start()
                            self._u2c_runner.start()
                            # Uncomment following if feature toggles are needed in future, also see mc_features_tests in oak-tests
                            #self._feature_runner.start()

                        else:
                            DEV_LOGGER.debug('Detail="FMC_Lifecycle ManagementConnector tried to re deploy"')

                    else:
                        self._handle_stop()

                    # Finish when Management Connector is applied
                    break

        # Map the Service Cluster level entry to the service configuration
        ServiceUtils.map_cluster_to_service(self._config)

        # Uncomment following if feature toggles are needed in future, also see mc_features_tests in oak-tests
        #self.toggle_features()

    # -------------------------------------------------------------------------

    def toggle_features(self):
        """ Handles starting/stopping feature threads """
        try:
            if self.deployed:
                temp_cache = self._cached_features
                self._cached_features, delta = Features.compare_features(self._config, self._cached_features)

                if delta:
                    DEV_LOGGER.info('Detail="FMC_Features toggle_features: previous cache: %s new list: %s"',
                                    temp_cache, self._cached_features)
                for feature, mode in delta.iteritems():
                    DEV_LOGGER.info('Detail="FMC_Features feature: %s mode: %s"', feature, mode)
        except Exception as feature_error:  # pylint: disable=W0703
            # Don't allow additional Features to potentially take down the main Thread.
            DEV_LOGGER.error('Detail="FMC_Lifecycle toggle_features: error occurred. Exception=%s, stacktrace=%s"'
                             % (repr(feature_error), traceback.format_exc()))

    # -------------------------------------------------------------------------

    def _handle_stop(self):
        """ Handles stopping from unregister and sigterm """
        if self.deployed:
            try:
                join_threads = ["MachineAccountThread", "MercuryThread", "FeatureThread"]
                DEV_LOGGER.debug('Detail="FMC_Lifecycle handling stopping of threads"')
                for event in self._stop_events:
                    event.set()

                self._deploy_runner.stop()
                # Trigger Stop using Set event, and finally try and join threads, as last cleanup/
                for thread in threading.enumerate():
                    if thread.getName() in join_threads:
                        DEV_LOGGER.debug('Detail="FMC_Lifecycle Joining %s thread"' % thread.getName())
                        thread.join(ManagementConnectorProperties.SHUT_DOWN_WAIT)
                        DEV_LOGGER.info('Detail="FMC_Lifecycle %s Thread isAlive returns %s."'
                                        % (thread.getName(), thread.isAlive()))
                self.deployed = False
            finally:
                # Backup for each thread event
                for event in self._stop_events:
                    event.clear()
        else:
            DEV_LOGGER.debug('Detail="FMC_Lifecycle ManagementConnector tried to un deploy"')

    # -------------------------------------------------------------------------

    def check_for_certs(self):
        """ Management Connector Check if certs need to be added or removed """

        # add_certs can be 3 values:
        # "true"    - managing certs.
        # "false"   - not managing certs.
        # None      - never managed certs.
        add_certs = self._config.read(ManagementConnectorProperties.ADD_FUSION_CERTS)

        # define locations for new certs
        existing_expressway_certs = ManagementConnectorProperties.DEFAULT_EXPRESSWAY_CA_FILE
        new_fusion_certs = ManagementConnectorProperties.FUSION_CA_FILE
        all_certs = ManagementConnectorProperties.COMBINED_CA_FILE
        fusion_added_dir = ManagementConnectorProperties.CERTS_ADDED_TO_CA_DIR 

        DEV_LOGGER.debug('Detail="check_for_certs called with add_certs = %s"' % (add_certs))

        use_fusion_ca = add_certs == "true"

        all_certs_size_pre_repair = self.all_certs_size_pre_repair
        # get sizes of existing cert files (used for comparison)
        try:
            exp_certs_size = os.path.getsize(existing_expressway_certs)
        except OSError: 
            exp_certs_size = 0
        try:
            fusion_certs_size = os.path.getsize(new_fusion_certs)
        except OSError: 
            fusion_certs_size = 0


        if add_certs:
            if use_fusion_ca:
                DEV_LOGGER.debug('all_certs_size_pre_repair = %s"' % (all_certs_size_pre_repair))
                DEV_LOGGER.debug('exp_certs_size = %s"' % (exp_certs_size))
                DEV_LOGGER.debug('fusion_certs_size = %s"' % (fusion_certs_size))
                if all_certs_size_pre_repair != exp_certs_size + fusion_certs_size:
                    DEV_LOGGER.info('Detail="ManagementConnector adding fusion Certs"')
                    jsonhandler.write_json_file(ManagementConnectorProperties.FUSION_CERTS_DIR_ADD_REQUEST, "")
                    self.all_certs_size_pre_repair =  merge_certs([existing_expressway_certs,new_fusion_certs],all_certs)

            else:
                if all_certs_size_pre_repair != exp_certs_size:
                    DEV_LOGGER.info('Detail="ManagementConnector removing fusion Certs "')
                    self.all_certs_size_pre_repair = merge_certs([existing_expressway_certs],all_certs)
                    try:
                        if not os.listdir(fusion_added_dir):
                            jsonhandler.write_json_file(ManagementConnectorProperties.FUSION_CERTS_DIR_DEL_REQUEST, "")
                    except OSError:
                        pass

        else:
            if all_certs_size_pre_repair != exp_certs_size:
                DEV_LOGGER.info('Detail="ManagementConnector is not adding fusion Certs"')
                self.all_certs_size_pre_repair = merge_certs([existing_expressway_certs],all_certs)

    # -------------------------------------------------------------------------
