"""
    Class to Manage Deploy Thread
"""

import threading

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class DeployThread(threading.Thread):
    """
        Class to Manage Deploy Thread
    """

    def __init__(self, deploy):
        threading.Thread.__init__(self, name='DeployThread')
        self._deploy = deploy

    # -------------------------------------------------------------------------

    def start(self):
        """ Start Deploy Thread """
        DEV_LOGGER.debug('Detail="FMC_Lifecycle DeployThread: start()"')
        threading.Thread.start(self)

    # -------------------------------------------------------------------------

    def stop(self):
        """ Stop Deploy Thread """
        DEV_LOGGER.debug('Detail="FMC_Lifecycle DeployThread: stop()"')
        self._deploy.un_deploy_fusion()

    # -------------------------------------------------------------------------

    def run(self):
        """ Run content of Thread """
        DEV_LOGGER.debug('Detail="FMC_Lifecycle DeployThread: run()"')
        self._deploy.deploy_fusion()

    # -------------------------------------------------------------------------
