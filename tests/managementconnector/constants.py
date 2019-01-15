""" Utility methods for tests  """

import logging

# Single SysLog handler to prevent duplicate handlers being added in tests
SYS_LOG_HANDLER = logging.StreamHandler()
