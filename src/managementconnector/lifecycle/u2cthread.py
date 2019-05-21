"""
    U2C Thread
"""

import threading
import time
import traceback

from managementconnector.cloud.oauth import OAuth
from managementconnector.cloud.u2c import U2C
from managementconnector.config.databasehandler import DatabaseHandler
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.platform.http import Http
from managementconnector.platform.system import System

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class U2CThread(threading.Thread):
    """
        Class to Manage Thread for monitoring U2C Service Catalog
    """

    def __init__(self, config, stop_event):
        threading.Thread.__init__(self, name='U2CThread')
        self._config = config
        self._stop_event = stop_event
        self._oauth = None
        self._oauth_init = False
        self._u2c = None

    # -------------------------------------------------------------------------

    def start(self):
        """ Start U2CThread  """
        DEV_LOGGER.debug('Detail="FMC_Lifecycle U2CThread: start()"')
        threading.Thread.start(self)

    # -------------------------------------------------------------------------

    def run(self):
        """ Run content of Thread """
        DEV_LOGGER.info('Detail="FMC_Lifecycle U2CThread: run()"')
        # wait two seconds for startup to allow cafe manager time to update the config
        if not System.am_i_master():
            DEV_LOGGER.info('Detail="FMC_Lifecycle U2CThread: not running on peer nodes"')
            return

        time.sleep(2)

        self._oauth = OAuth(self._config)
        self._u2c = U2C(self._config, self._oauth, Http, DatabaseHandler())

        while True:
            if self._stop_event.is_set():
                DEV_LOGGER.info('Detail="FMC_Lifecycle U2CThread a stop event, '
                                'breaking out of polling and stopping."')
                self._oauth = None
                self._oauth_init = False
                return

            self._do_heartbeat()

    # -------------------------------------------------------------------------

    def _do_heartbeat(self):
        """ Do U2C Heartbeat """
        try:
            if not self._oauth_init:
                self._oauth_init = self._oauth.init()

            DEV_LOGGER.debug('Detail="FMC_Lifecycle U2CThread: calling heartbeat"')
            self._u2c.update_user_catalog()

        except Exception as u2c_error:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="FMC_Lifecycle U2CThread: error during heartbeat. Exception=%s, stacktrace=%s"'
                             % (repr(u2c_error), traceback.format_exc()))

        finally:
            poll_time = int(self._config.read(ManagementConnectorProperties.U2C_HEARTBEAT_POLL_TIME,
                                              ManagementConnectorProperties.DEFAULT_U2C_POLL_TIME))
            DEV_LOGGER.info('Detail="FMC_Lifecycle U2CThread: sleeping for %s seconds"' % poll_time)
            self._stop_event.wait(poll_time)
