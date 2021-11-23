"""
    Class to Manage Mercury Lifecycle
"""

import threading

from managementconnector.lifecycle.mercurythread import MercuryThread
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class MercuryRunner(object):

    """
        Class to Manage Mercury Lifecycle
    """

    def __init__(self, config, stop_event):
        self.lock = threading.Lock()
        self._config = config
        self._mercury_thread = None
        self._stop_event = stop_event

    # -------------------------------------------------------------------------

    def start(self):
        """ Start Mercury Thread """
        with self.lock:
            if not self.running():
                self._mercury_thread = MercuryThread(self._config, self._stop_event)
                self._mercury_thread.start()

    # -------------------------------------------------------------------------

    def running(self):
        """ Is the MercuryThread running """
        running = False

        if self._mercury_thread:
            running = self._mercury_thread.is_alive()

        return running

    # -------------------------------------------------------------------------
