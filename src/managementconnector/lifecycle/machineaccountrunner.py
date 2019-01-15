"""
    Class to Manage MachineAccount Lifecycle
"""

import threading

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.lifecycle.machineaccountthread import MachineAccountThread
from managementconnector.platform.system import System

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class MachineAccountRunner(object):

    """
        Class to Manage MachineAccount Lifecycle
    """

    def __init__(self, config, stop_event):
        self.lock = threading.Lock()
        self._config = config
        self._stop_event = stop_event
        self._machine_thread = None

    # -------------------------------------------------------------------------

    def start(self):
        """ Start MachineAccount Thread """
        with self.lock:
            master = System.am_i_master()
            DEV_LOGGER.info('Detail="FMC_Lifecycle MachineAccountRunner: start() am_i_master={}"'.format(master))

            if master:
                if not self.running():
                    self._machine_thread = MachineAccountThread(self._config, self._stop_event)
                    self._machine_thread.start()

    # -------------------------------------------------------------------------

    def running(self):
        """ Is the MachineAccountThread running """
        running = False

        if self._machine_thread:
            running = self._machine_thread.isAlive()

        return running

    # -------------------------------------------------------------------------