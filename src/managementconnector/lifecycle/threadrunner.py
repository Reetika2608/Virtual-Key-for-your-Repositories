"""
    Class to Manage Thread Lifecycle
"""

import threading

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class ThreadRunner(object):

    """
        Class to Manage Thread Runners
    """

    def __init__(self, config, stop_event, thread):
        self.lock = threading.Lock()
        self._config = config
        self._stop_event = stop_event
        self._thread_pointer = thread
        self._thread = None

    # -------------------------------------------------------------------------

    def start(self):
        """ Start Mercury Thread """
        with self.lock:

            DEV_LOGGER.debug('Detail="FMC_Lifecycle ThreadRunner: start()"')
            if not self.running():
                self._thread = self._thread_pointer(self._config, self._stop_event)
                self._thread.start()

    # -------------------------------------------------------------------------

    def running(self):
        """ Is the Thread running """
        running = False

        if self._thread:
            running = self._thread.isAlive()

        return running

    # -------------------------------------------------------------------------