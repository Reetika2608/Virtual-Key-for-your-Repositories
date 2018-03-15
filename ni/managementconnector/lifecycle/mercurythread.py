"""
    Class to Manage Mercury Thread
"""

import threading
import traceback
import time

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

from ni.managementconnector.lifecycle.lifecycleutils import LifecycleUtils
from ni.managementconnector.cloud.mercury import Mercury
from ni.managementconnector.cloud.metrics import Metrics
from ni.managementconnector.cloud.oauth import OAuth

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class MercuryThread(threading.Thread):
    """
        Class to Manage Mercury Thread
    """

    def __init__(self, config, stop_event):
        threading.Thread.__init__(self, name='MercuryThread')
        self._config = config
        self._stop_event = stop_event
        self._oauth = None
        self._mercury_connection = None
        self._metrics = None
        self._oauth_init = False

    # -------------------------------------------------------------------------

    def run(self):
        """ Run content of Thread """
        DEV_LOGGER.debug('Detail="FMC_Lifecycle MercuryThread: run()"')
        # wait two seconds for startup to allow cafe manager time to update the config
        time.sleep(2)

        self.register_listener()
        self._oauth = OAuth(self._config)
        self._mercury_connection = Mercury(self._config, self._oauth)
        self._metrics = Metrics(self._config, self._oauth)

        while True:
            if self._stop_event.is_set():
                if self._mercury_connection:
                    self.unregister_listener()
                    self._mercury_connection.shutdown()
                    self._oauth = None
                    self._oauth_init = False
                DEV_LOGGER.info('Detail="FMC_Lifecycle MercuryThread a stop event, '
                                'breaking out of polling and stopping."')
                # Clearing event for re-enablement case, as this event is only for this thread.
                self._stop_event.clear()
                return

            self._do_heartbeat()

    # -------------------------------------------------------------------------

    def _do_heartbeat(self):
        """ Do Mercury Heartbeat """
        try:
            if not self._oauth_init:
                self._oauth_init = self._oauth.init()

            DEV_LOGGER.debug('Detail="FMC_Lifecycle MercuryThread: calling heartbeat"')
            self._mercury_connection.heartbeat()

        except Exception as wdm_error:  # pylint: disable=W0703
            self._mercury_connection.handle_mercury_exception(wdm_error)

        finally:
            self._stop_event.wait(LifecycleUtils.get_poll_time(
                self._config, ManagementConnectorProperties.MERCURY_HEARTBEAT_POLL_TIME))

    # -------------------------------------------------------------------------

    def register_listener(self):
        """ Register Config Listener """
        DEV_LOGGER.debug('Detail="MercuryThread register listener"')
        self._config.add_observer(self.on_config_update)

    # -------------------------------------------------------------------------

    def unregister_listener(self):
        """ Management Connector Un-register Listener """
        DEV_LOGGER.debug('Detail="MercuryThread un-register listener"')
        self._config.remove_observer(self.on_config_update)

    # -------------------------------------------------------------------------

    def on_config_update(self):
        """ Callback from CDB update """

        DEV_LOGGER.debug('Detail="MercuryThread on_config_update"')
        try:
            if self._mercury_connection:
                self._mercury_connection.check_for_proxy_changes()
        except Exception as wdm_error: # pylint: disable=W0703
            DEV_LOGGER.error('Detail="Un-handled Exception occurred:%s, stacktrace=%s"' % (repr(wdm_error),
                                                                                           traceback.format_exc()))

    # -------------------------------------------------------------------------
