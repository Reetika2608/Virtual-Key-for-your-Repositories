""" Utility methods for tests  """

import logging

LOGGER = None


class IntegrationTestLogger(object):
    logger = None

    def __init__(self):
        sys_log_handler = logging.StreamHandler()
        sys_log_handler.setFormatter(
            logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(module)s(%(lineno)d) %(message)s',
                              datefmt='%Y-%m-%d %H:%M:%S'))
        logging.getLogger().addHandler(sys_log_handler)
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("selenium").setLevel(logging.INFO)
        logging.getLogger("default").setLevel(logging.INFO)
        self.logger = logging.getLogger("default")


def get_logger():
    global LOGGER
    if not LOGGER:
        LOGGER = IntegrationTestLogger()
    return LOGGER.logger
