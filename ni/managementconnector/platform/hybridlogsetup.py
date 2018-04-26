"""
This class will make the application handle for the Hybrid Services Logger available to connectors
"""

# Ignore "Using the global statement" warnings        pylint: disable=W0603
# Ignore "Invalid name" warnings                      pylint: disable=C0103

import logging
import os
import sys
import time

try:
    from ni.utils.logging.setup import LoggingFramework
except (ImportError, IOError):
    from ni.cmgmtlog.setup import LoggingFramework


HYBRIDSERVICES_LOGGING_FRAMEWORK = None


class HybridServicesLogger(LoggingFramework):
    """Class to configure the HybridServices logging framework """

    name = "hybridservices"
    try:
        facility = logging.handlers.SysLogHandler.LOG_LOCAL7
    except AttributeError:
        facility = 23

    def __init__(self, enable_crash_report_handler, application_name=None):
        LoggingFramework.__init__(self)
        if application_name is None:
            application_name, _extension = os.path.splitext(os.path.basename(sys.argv[0]))
        self.syslog_formatter = logging.Formatter(
            application_name.lower() + ': UTCTime="%(asctime)s,%(msecs)d" Module="%(name)s" Level="%(levelname)s" '
                                       'CodeLocation="%(module)s(%(lineno)d)" %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
        self.syslog_formatter.converter = time.gmtime
        self.console_formatter = logging.Formatter("%(levelname)-3.3s: %(asctime)s - %(message)s", datefmt="%H:%M:%S")

        self.initialise()
        if enable_crash_report_handler:
            self.enable_crash_report_handler()


def initialise_logging_hybrid_services(application_name=None):
    """
    Initialise the logging framework. This will setup Hybrid Services logger
    Ensure duplicate handlers are not created.
    """
    global HYBRIDSERVICES_LOGGING_FRAMEWORK
    logger = logging.getLogger("hybridservices")

    if HYBRIDSERVICES_LOGGING_FRAMEWORK is None and not logger.handlers:

        HYBRIDSERVICES_LOGGING_FRAMEWORK = HybridServicesLogger(True, application_name)
