"""
    Utility class for Managing Lifecycles
"""

from random import randint
from time import sleep

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class LifecycleUtils(object):
    """
    Utilities methods Lifecycle management
    """

    @staticmethod
    def poll_sleep(config, config_path):
        """ Method to sleep between polls """
        sleep_interval = LifecycleUtils.get_poll_time(config, config_path)

        DEV_LOGGER.debug('Detail="sleep for %d seconds"' % sleep_interval)

        sleep(sleep_interval)

    @staticmethod
    def get_poll_time(config, config_path):
        """ Returns a randomly modified poll time """
        poll_time = int(config.read(config_path,
                                    ManagementConnectorProperties.DEFAULT_POLL_TIME))
        sleep_interval = abs(randint(poll_time - 5, poll_time + 5))
        return sleep_interval