"""
    Feature Thread
"""

import threading
import time
import traceback

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.cloud.oauth import OAuth
from ni.managementconnector.cloud.features import Features
from ni.managementconnector.lifecycle.lifecycleutils import LifecycleUtils
from ni.managementconnector.platform.system import System

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class FeatureThread(threading.Thread):
    """
        Class to Manage FeatureThread Thread
    """

    def __init__(self, config, stop_event):
        threading.Thread.__init__(self, name='FeatureThread')
        self._config = config
        self._stop_event = stop_event
        self._oauth = None
        self._oauth_init = False
        self._feature = None

    # -------------------------------------------------------------------------

    def start(self):
        """ Start FeatureThread  """
        DEV_LOGGER.debug('Detail="FMC_Lifecycle FeatureThread: start()"')
        threading.Thread.start(self)

    # -------------------------------------------------------------------------

    def run(self):
        """ Run content of Thread """
        DEV_LOGGER.info('Detail="FMC_Lifecycle FeatureThread: run()"')
        # wait two seconds for startup to allow cafe manager time to update the config
        if not System.am_i_master():
            DEV_LOGGER.info('Detail="FMC_Lifecycle FeatureThread: not running on peer nodes"')
            return

        time.sleep(2)

        self._oauth = OAuth(self._config)
        self._feature = Features(self._config, self._oauth)

        while True:
            if self._stop_event.is_set():
                DEV_LOGGER.info('Detail="FMC_Lifecycle FeatureThread a stop event, '
                                'breaking out of polling and stopping."')
                self._oauth = None
                self._oauth_init = False
                return

            self._do_heartbeat()

    # -------------------------------------------------------------------------

    def _do_heartbeat(self):
        """ Do Feature Heartbeat """
        try:
            if not self._oauth_init:
                self._oauth_init = self._oauth.init()

            DEV_LOGGER.debug('Detail="FMC_Lifecycle FeatureThread: calling heartbeat"')
            self._feature.update_latest_features()

        except Exception as feature_error:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="FMC_Lifecycle FeatureThread: error during heartbeat. Exception=%s, stacktrace=%s"'
                             % (repr(feature_error), traceback.format_exc()))

        finally:
            self._stop_event.wait(LifecycleUtils.get_poll_time(
                self._config, ManagementConnectorProperties.FEATURE_HEARTBEAT_POLL_TIME))
