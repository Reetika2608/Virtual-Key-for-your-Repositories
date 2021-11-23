"""
    Class to Manage Deploy Lifecycle
"""

import threading

from managementconnector.deploythread import DeployThread
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class DeployRunner(object):

    """
        Class to Manage Deploy Lifecycle
    """

    def __init__(self, deploy):
        self.lock = threading.Lock()
        self._deploy = deploy
        self._deploy_thread = None

    # -------------------------------------------------------------------------

    def start(self):
        """ Start Deploy Thread """
        with self.lock:
            DEV_LOGGER.debug('Detail="FMC_Lifecycle DeployRunner: start()"')
            if not self.running():
                self._deploy_thread = DeployThread(self._deploy)
                self._deploy_thread.start()

    # -------------------------------------------------------------------------

    def stop(self):
        """ Stop Deploy Thread """
        DEV_LOGGER.debug('Detail="FMC_Lifecycle DeployRunner: stop()"')
        with self.lock:
            if self._deploy_thread is not None:
                self._deploy_thread.stop()
                self._deploy_thread.join(ManagementConnectorProperties.SHUT_DOWN_WAIT)
                DEV_LOGGER.info('Detail="DeployRunner: isAlive returns %s."' % (self._deploy_thread.is_alive()))
                self._deploy_thread = None

    # -------------------------------------------------------------------------

    def running(self):
        """ Check if Deploy Thread is running """
        running = False

        if self._deploy_thread:
            running = self._deploy_thread.is_alive()

        return running

    # -------------------------------------------------------------------------
