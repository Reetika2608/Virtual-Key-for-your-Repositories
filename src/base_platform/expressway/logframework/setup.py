# Ignore "Line too long" warnings.              pylint: disable=C0301
# Ignore "Invalid name" warnings.               pylint: disable=C0103
# Ignore "Method could be a function" warnings. pylint: disable=R0201
# Ignore "Redefining built-in" warnings.        pylint: disable=W0622
# Ignore "Using the global statement" warnings. pylint: disable=W0603
# Ignore "No name in module" warnings                 pylint: disable=E0611
# Ignore "Unable to import" warnings                  pylint: disable=F0401
# Ignore "Wrong Import Position" warnings       pylint: disable=C0413

"""This module includes functions and classes to assist in logging
to the administrator and developer logs"""

# Standard library imports
import atexit
import inspect
import logging
import logging.handlers
import errno
import os
import os.path
import socket
import sys
import time
import traceback
import types
import xml.etree.cElementTree as ElementTree
import __main__

# Third party imports
# Force an early import of pyinotify and fix up the repurcussions it has on the
# logging module by restoring the default logger class.
# Ignore "Unused import" warnings.              pylint: disable=W0611
pre_logging_class = logging.getLoggerClass()
import pyinotify

logging.setLoggerClass(pre_logging_class)

# Local application/library specific imports
from cafedynamic.cafexutil import CafeXUtils
from base_platform.expressway.logframework import log4configuration
from base_platform.expressway.cdb import restclient
from base_platform.expressway.cdb import webrestclient
from base_platform.expressway.filesystem.umask import umask

DEVELOPER_LOGGING_FRAMEWORK = None
ADMIN_LOGGING_FRAMEWORK = None
CONFIG_LOGGING_FRAMEWORK = None
NETWORK_LOGGING_FRAMEWORK = None
LOG_LEVEL_MONITOR = None
ORIGINAL_LOGGING_GETLOGGER = logging.getLogger
LOGGER_REGISTRATION_PATH = '/tmp/management/logging'


class NoACRExceptionFilter(logging.Filter):
    """
    This is a filter which injects Exceptions that are ignored, so that ACRs
    are not generated for them.
    """
    bin_trial = '/bin/trial'

    def __init__(self):
        super(NoACRExceptionFilter, self).__init__()
        self.ExceptionsNotCausingAcr = set()

    def filter(self, record):
        """
        Method used by the logging framework whether to check if ACR generation
        is needed or not. This filter is used by CrachReportHandler.
        """
        return __main__.__file__ != self.bin_trial and record.exc_info and record.exc_info[
            0] not in self.ExceptionsNotCausingAcr

    def add_exception(self, exc_type):
        """
        Adds the given exception to the set of exceptions for which ACR is
        not generated.
        """
        self.ExceptionsNotCausingAcr.add(exc_type)


no_acr_filter = NoACRExceptionFilter()


def add_exception_to_not_cause_acr(exc_type):
    """
    Add an exception class to not trigger an ACR
    """
    no_acr_filter.add_exception(exc_type)


def get_and_register_logger(logger_name=None):
    """
    Calls through to the logging getLogger, but also registers the logger with
    the diagnostics manager.
    """
    register_logger(logger_name, None)
    return ORIGINAL_LOGGING_GETLOGGER(logger_name)


def map_loggers(function):
    """Apply a callable method to every registered logger"""
    # Ignore "Access to a protected member" warnings. pylint: disable=W0212
    try:
        logging._acquireLock()
        for logger_name, logger in logging.Logger.manager.loggerDict.items():
            function(logger_name, logger)
    finally:
        logging._releaseLock()


def register_existing_loggers():
    """
    Registers the logger with the diagnostics manager so that the logger can be
    initialised in the database.
    """
    map_loggers(register_logger)


def register_logger(logger_name, _logger):
    """
    Registers the logger with the diagnostics manager so that the logger can be
    initialised in the database.
    """
    if logger_name:
        logger_registration_file = os.path.join(LOGGER_REGISTRATION_PATH, logger_name)
        if not os.path.exists(logger_registration_file):
            # Make sure the file is created world writable, this works around
            # a problem where two processes with different privileges race to
            # create the file.
            with umask(0o111):
                with open(logger_registration_file, "w") as registration_file:
                    registration_file.write("")


def get_safe_string(value):
    """
    returns a string suitable for logging
    """
    if isinstance(value, bytes):
        return value.decode()
    else:
        return value


def get_unicode_string(value):
    """
    returns a unicode string even if input is a byte array
    """
    if isinstance(value, bytes):
        value = value.decode('utf-8')
    return value.replace("\x00", '^@')


class SysLogHandler(logging.handlers.SysLogHandler):
    """This class is responsible for creating a logging handler which sends
       logs to the UNIX syslog.
       It also provides a method for encoding said messages as UTF-8"""
    MAX_MESSAGE_LENGTH = 16000  # we can log upto 32768, allow 16768 bytes for other stuff in log

    def __init__(self, facility):
        logging.handlers.SysLogHandler.__init__(self,
                                                address='/dev/log', facility=facility)

    def format(self, record):
        """Formats "record" as a utf-8 string"""
        msg = logging.handlers.SysLogHandler.format(self, record)
        return get_safe_string(msg)

    def handleError(self, record):
        """
        Some messages are larger than the MTU of the socket we talk to syslog on.
        In this case the socket.error exception is raised with errno == EMGSIZE.

        This is a naive hack to split these large messages and retransmit.

        An optimisation would be to rewrite the class to do socket.send multiple times
        when the formatted message is too large, rather than sending a number of records.

        A further optimisation would be autodetecting the MAX_MESSAGE_LENGTH rather than
        guessing.
        """
        exc_type, exc_value, _traceback = sys.exc_info()
        if issubclass(exc_type, socket.error) and exc_value.errno == errno.EMSGSIZE:
            msg = record.msg
            split_messages = [msg[i:i + self.MAX_MESSAGE_LENGTH]
                              for i in range(0, len(msg), self.MAX_MESSAGE_LENGTH)]

            for index, item in enumerate(split_messages):
                record.msg = ('Message-Split="True" Section="%d/%d" %s' %
                              (index + 1, len(split_messages), item))
                self.emit(record)
        else:
            super(SysLogHandler, self).handleError(record)


class DummySysLogHandler(logging.FileHandler):
    """
    When syslog isn't up yet this class will be used instead to output
    messages to a file in /tmp.  When syslog starts, this file will be read and
    its contents inserted into the real syslog.
    """

    output_filename = '/tmp/syslogd_startup.lst'

    def __init__(self, facility):
        logging.FileHandler.__init__(self, self.output_filename)

        # Map the facility number to a name
        self.facility = [key for key, value
                         in logging.handlers.SysLogHandler.facility_names.items()
                         if value == facility][0]

    def format(self, record):
        """
        Formats "record" in the format required by the syslogd startup script.
        """

        # Map the logging level to a syslog priority
        if record.levelname in logging.handlers.SysLogHandler.priority_map:
            priority = logging.handlers.SysLogHandler.priority_map[record.levelname]
        else:
            priority = 'warning'

        frames = inspect.getouterframes(inspect.currentframe())
        filename = os.path.basename(frames.pop()[1])
        return "%s %s %s %s" % (filename, self.facility, priority, logging.FileHandler.format(self, record))


class ConsoleLogHandler(logging.StreamHandler):
    """This class is responsible for creating a logging handler which sends
       logs to the Console.
       It also provides a method for encoding said messages as UTF-8"""

    def __init__(self, stream):
        logging.StreamHandler.__init__(self, stream)

    def format(self, record):
        """Formats "record" as a utf-8 string"""
        msg = logging.StreamHandler.format(self, record)
        return get_safe_string(msg)


# Register ClusterDatabases CDBDownException not to generate ACR
add_exception_to_not_cause_acr(restclient.CDBDownException)


class CrashReportHandler(logging.Handler):
    """This class is responsible for creating a logging handler which sends
       exception logs to the crash reporting daemon."""

    file_base_name = 'crash.log'
    target_log_directory = '/tandberg/crash/raw'
    host_log_directory = '/tmp/crash/raw'

    def __init__(self):
        logging.Handler.__init__(self)
        logging.Handler.setLevel(self, logging.ERROR)

        self.lazy_setup_done = False
        self.product_name = None
        self.product_version = None
        self.product_build_revision = None
        self.product_builder = None
        self.software_id = None
        self.log_directory = None
        self.addFilter(no_acr_filter)

    def _lazy_setup(self):
        """Loading the platforminfo module is expensive, so it should be done
           lazily only when required."""

        if self.lazy_setup_done:
            return
        self.lazy_setup_done = True

        from base_platform.expressway import platforminfo

        platform_info = platforminfo.PlatformInfo()
        self.product_name = platform_info.product_name
        self.product_version = platform_info.version_description
        self.product_build_revision = platform_info.build_revision
        self.product_builder = platform_info.build_user
        self.software_id = platform_info.software_id

        if platform_info.target:
            self.log_directory = self.target_log_directory
        else:
            self.log_directory = self.host_log_directory
        CafeXUtils.make_path(self.log_directory, 0o777)

    def _get_log_file_path(self):
        """Returns the full path for the next crash report log file."""
        self._lazy_setup()

        file_name = ".".join([self.file_base_name, str(os.getpid()), str(time.time())])
        return os.path.join(self.log_directory, file_name)

    def setLevel(self, _level):
        """The log level for the crash report handler is immutable, attempts to
        change the level are ignored"""
        pass

    def emit(self, record):
        """Emit a record.

        If a formatter is specified, it is used to format the record. The
        record is then written to a new crash report file.
        """
        # Only emit the log if there is exc_info which indicates that the log
        # is actually an exception (not just a standard error log)
        try:
            msg = self.format(record)
            with open(self._get_log_file_path(), "w") as log_file:
                log_file.write(msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # pylint: disable=W0703
            self.handleError(record)

    @staticmethod
    def _tb_to_list(tback):
        """Convert traceback to a list thats easier to navigate.
        The list should start with the innermost stack frame"""
        tback_list = []
        while True:
            tback_list.append(tback)
            tback = tback.tb_next
            if not tback:
                break
        tback_list.reverse()
        return tback_list

    @classmethod
    def _tb_ignore(cls, frame):
        """Check if we should ignore frame in traceback"""
        ignore = False
        for filename in cls.FILENAMES_IGNORE:
            if filename.startswith(frame.f_code.co_filename):
                ignore = True
        return ignore

    @classmethod
    def _tb_to_acr_formatter(cls, tback_list):
        """Take tback and generate strings for file, line, function,
        local_variables and member variables."""
        functions = []
        files = []
        lines = []
        frame = None
        for tback in tback_list:
            frame = tback.tb_frame
            files.append(frame.f_code.co_filename)
            functions.append(frame.f_code.co_name)
            lines.append(frame.f_lineno)
            if not cls._tb_ignore(frame):
                break
        seperator = "|"
        results = {}
        results["function"] = seperator.join(functions)
        results["file"] = seperator.join(files)
        results["line"] = seperator.join([str(line) for line in lines])
        results["local_variables"] = ""
        results["member_variables"] = ""
        if isinstance(frame.f_locals, dict):
            results["local_variables"] = cls._format_dictionary(frame.f_locals)
            if 'self' in frame.f_locals and isinstance(frame.f_locals['self'], dict):
                results["member_variables"] = cls._format_dictionary(frame.f_locals['self'].__dict__)
        return results

    # List of files that if found in a traceback are ignored. They still get mentioned in the ACR
    # but we will also mention whatever is above them
    FILENAMES_IGNORE = (
        webrestclient.__file__,
        restclient.__file__)

    def format(self, record):
        """Format a log record as a crash report."""
        self._lazy_setup()

        root = ElementTree.Element("applicationfailure")
        ElementTree.SubElement(root, "version").text = self.product_version
        ElementTree.SubElement(root, "build").text = self.product_build_revision
        ElementTree.SubElement(root, "builder").text = self.product_builder
        ElementTree.SubElement(root, "name").text = self.software_id
        ElementTree.SubElement(root, "instance").text = os.path.basename(sys.argv[0])
        ElementTree.SubElement(root, "product_name").text = self.product_name
        ElementTree.SubElement(root, "process_id").text = str(os.getpid())
        ElementTree.SubElement(root, "thread_id").text = str(record.thread)
        ElementTree.SubElement(root, "thread_name").text = str(record.threadName)
        ElementTree.SubElement(root, "time").text = str(record.created)
        ElementTree.SubElement(root, "reason").text = record.getMessage()
        ElementTree.SubElement(root, "stack").text = "".join(traceback.format_exception(
            record.exc_info[0],
            record.exc_info[1],
            record.exc_info[2]))
        if record.exc_info[2] is not None:
            # Get the innermost stack frame
            tback = record.exc_info[2]
            tback_list = self._tb_to_list(tback)
            fields = self._tb_to_acr_formatter(tback_list)
            ElementTree.SubElement(root, "file").text = fields["file"]
            ElementTree.SubElement(root, "line").text = fields["line"]
            ElementTree.SubElement(root, "function").text = fields["function"]
            ElementTree.SubElement(root, "local_variables").text = fields["local_variables"]
            ElementTree.SubElement(root, "member_variables").text = fields["member_variables"]
        else:
            ElementTree.SubElement(root, "file").text = record.pathname
            ElementTree.SubElement(root, "line").text = str(record.lineno)
            ElementTree.SubElement(root, "function").text = record.funcName

        return ElementTree.tostring(root, encoding='utf-8')

    @staticmethod
    def _format_dictionary(dictionary):
        """Returns a string description of the dictionary contents."""
        # Although traceback._some_str is protected, it's better to access it
        # than create our own.  pylint: disable=W0212
        items = ["%s: %s" % (get_unicode_string(key), get_unicode_string(traceback._some_str(value))) for key, value in
                 dictionary.items() if not key.startswith("__")]
        return "\n".join(items)


class LoggingFramework(object):
    """Class to configure the logging framework"""

    name = None
    level = logging.INFO
    facility = None

    def __init__(self):
        self.logger = None
        self.syslog_formatter = None
        self.console_formatter = None
        self.syslog_handler = None
        self.console_handler = None
        self.crash_report_handler = None

    def initialise(self):
        """Initialise """
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(self.level)

        # Remove any default handlers
        for handler in self.logger.handlers:
            self.logger.removeHandler(handler)

        # Add a handler for syslog
        self.enable_syslog_handler()

    def enable_syslog_handler(self, enable=True):
        """Enable or disable syslog handler"""
        if enable and self.syslog_handler is None:
            # Create a handler to log to syslog (developer logs use facility LOCAL5)
            try:
                self.syslog_handler = SysLogHandler(facility=self.facility)
            except socket.error:
                self.syslog_handler = DummySysLogHandler(facility=self.facility)  # pylint: disable=R0204

            self.syslog_handler.setFormatter(self.syslog_formatter)
            self.logger.addHandler(self.syslog_handler)
        elif self.syslog_handler is not None:
            self.logger.removeHandler(self.syslog_handler)
            self.syslog_handler = None

    def enable_console_handler(self, enable=True):
        """Enable or disable logging to stdout"""
        if enable and self.console_handler is None:
            self.console_handler = ConsoleLogHandler(stream=sys.stdout)
            self.console_handler.setFormatter(self.console_formatter)
            self.logger.addHandler(self.console_handler)
        elif self.console_handler is not None:
            self.logger.removeHandler(self.console_handler)
            self.console_handler = None

    def enable_crash_report_handler(self, enable=True):
        """Enable or disable logging of exceptions to crash reports"""
        if enable and self.crash_report_handler is None:
            self.crash_report_handler = CrashReportHandler()
            self.logger.addHandler(self.crash_report_handler)
        elif self.console_handler is not None:
            self.logger.removeHandler(self.crash_report_handler)
            self.crash_report_handler = None

    def enable_debug(self, enable_debug=True, enable_console=True):
        """Enable/disable debug level output"""
        self.enable_console_handler(enable_console)

        if enable_debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

    def add_custom_handler(self, handler):
        """Add custom handler"""
        handler.setFormatter(self.syslog_formatter)
        self.logger.addHandler(handler)

    def remove_custom_handler(self, handler):
        """Remove custom handler"""
        self.logger.removeHandler(handler)


class AdminLogger(LoggingFramework):
    """Class to configure the administrator logging framework"""

    name = "administrator"
    facility = logging.handlers.SysLogHandler.LOG_LOCAL0

    def __init__(self, application_name=None):
        LoggingFramework.__init__(self)
        if application_name is None:
            application_name, _extension = os.path.splitext(os.path.basename(sys.argv[0]))
        format = application_name.lower() + ': Level="%(levelname)s" %(message)s UTCTime="%(asctime)s,%(msecs)03d"'
        self.syslog_formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        self.syslog_formatter.converter = time.gmtime
        self.console_formatter = logging.Formatter("%(levelname)-3.3s: %(asctime)s - %(message)s", datefmt="%H:%M:%S")

        self.initialise()


class ConfigLogger(AdminLogger):
    """Class to configure the config logging framework"""

    name = "config"
    facility = logging.handlers.SysLogHandler.LOG_LOCAL1


class NetworkLogger(LoggingFramework):
    """Class to configure the network logging framework"""

    name = "network"
    facility = logging.handlers.SysLogHandler.LOG_LOCAL6

    def __init__(self, application_name=None):
        LoggingFramework.__init__(self)
        if application_name is None:
            application_name, _extension = os.path.splitext(os.path.basename(sys.argv[0]))
        format = application_name.lower() + ' UTCTime="%(asctime)s,%(msecs)03d" Module="%(name)s" Level="%(levelname)s" %(message)s'
        self.syslog_formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        self.syslog_formatter.converter = time.gmtime
        self.console_formatter = logging.Formatter("%(levelname)-3.3s: %(asctime)s - %(message)s", datefmt="%H:%M:%S")

        self.initialise()


class DeveloperLogger(LoggingFramework):
    """Class to configure the developer logging framework """

    name = "developer"
    facility = logging.handlers.SysLogHandler.LOG_LOCAL5

    def __init__(self, enable_crash_report_handler, application_name=None):
        LoggingFramework.__init__(self)
        if application_name is None:
            application_name, _extension = os.path.splitext(os.path.basename(sys.argv[0]))
        self.syslog_formatter = logging.Formatter(
            application_name.lower() + ': UTCTime="%(asctime)s,%(msecs)03d" Module="%(name)s" Level="%(levelname)s" CodeLocation="%(module)s(%(lineno)d)" %(message)s',
            datefmt="%Y-%m-%d %H:%M:%S")
        self.syslog_formatter.converter = time.gmtime
        self.console_formatter = logging.Formatter("%(levelname)-3.3s: %(asctime)s - %(message)s", datefmt="%H:%M:%S")

        self.initialise()
        if enable_crash_report_handler:
            self.enable_crash_report_handler()


def enable_developer_debug(debug=True, console=True):
    """Enable debug level output in the developer logs"""
    DEVELOPER_LOGGING_FRAMEWORK.enable_debug(debug, console)


def enable_administrator_debug(debug=True, console=True):
    """Enable debug level output in the administrator logs"""
    ADMIN_LOGGING_FRAMEWORK.enable_debug(debug, console)


def enable_network_debug(debug=True, console=True):
    """Enable debug level output in the network logs"""
    NETWORK_LOGGING_FRAMEWORK.enable_debug(debug, console)


def reset_log_level(logger_name, logger):
    """\
    Reset the log level of a logger so that it inherits from its parent.
    Note, root loggers are not reset.
    """
    if "." in logger_name and not isinstance(logger, logging.PlaceHolder):
        logger.setLevel(logging.NOTSET)


def update_log_levels(new_log_levels):
    """Updates the log levels for any existing logger.
    If the logger does not exist, a new logger is created, this allows loggers
    to be configured before they are created.
    """

    # Reset all child loggers so that they will default to the parent unless
    # explicitly set
    map_loggers(reset_log_level)

    # Apply the new log levels
    for logger_name, log_level in new_log_levels.items():
        logging.getLogger(logger_name).setLevel(log_level)


def initialise_logging(application_name=None, with_log4configuration_monitor=True, with_twisted=True,
                       twisted_reactor=None, enable_crash_reporting=True, default_twisted_log_level=None):
    """
    Initialise the logging framework. This will setup admin, network and
    developer logging.

    If ``with_log4configuration_monitor`` is True then the framework will
    continually monitor the ttlog.conf for changes to logger levels. Otherwise
    it will use ttlog.conf to configure the logger levels once during
    initialisation.

    Note, intialise_logging should be called before all other application
    imports so that any logging during module initialisation is performed at
    the correct level.
    """
    # Initialise developer logging
    # Ignore complaints about the "global" statement.  pylint: disable=W0603
    global DEVELOPER_LOGGING_FRAMEWORK
    global ADMIN_LOGGING_FRAMEWORK
    global CONFIG_LOGGING_FRAMEWORK
    global NETWORK_LOGGING_FRAMEWORK

    # Make sure the logging directories are available
    CafeXUtils.make_path(LOGGER_REGISTRATION_PATH, 0o777)

    # Register any loggers that have already been created
    register_existing_loggers()

    # Hook in the registration version to get a logger
    logging.getLogger = get_and_register_logger

    if DEVELOPER_LOGGING_FRAMEWORK is None:
        DEVELOPER_LOGGING_FRAMEWORK = DeveloperLogger(
            enable_crash_report_handler=enable_crash_reporting,
            application_name=application_name)

    if ADMIN_LOGGING_FRAMEWORK is None:
        ADMIN_LOGGING_FRAMEWORK = AdminLogger(application_name)

    if CONFIG_LOGGING_FRAMEWORK is None:
        CONFIG_LOGGING_FRAMEWORK = ConfigLogger(application_name)

    if NETWORK_LOGGING_FRAMEWORK is None:
        NETWORK_LOGGING_FRAMEWORK = NetworkLogger(application_name)

    if with_twisted:
        _initialise_twisted(application_name, default_twisted_log_level)

    _initialise_log4configuration(monitoring=with_log4configuration_monitor,
                                  with_twisted=with_twisted,
                                  twisted_reactor=twisted_reactor)


def _initialise_twisted(application_name, default_log_level=None):
    """ Initialise twisted logging integration """
    try:
        from ni.utils.logging import twistedsetup
    except ImportError:
        # if we don't have twisted we don't care, we just won't have this class in scope
        pass
    else:
        if twistedsetup.TWISTED_LOGGING_OBSERVER is None:
            twistedsetup.TWISTED_LOGGING_OBSERVER = \
                twistedsetup.OurTwistedPythonLoggingObserver(
                    DEVELOPER_LOGGING_FRAMEWORK,
                    loggerName='developer.%s.twisted' % (application_name),
                    default_log_level=default_log_level)
            twistedsetup.TWISTED_LOGGING_OBSERVER.start()


def _initialise_log4configuration(monitoring=True, with_twisted=False, twisted_reactor=None):
    """Initialise logging based on the log4configuration file"""

    # If monitoring is enabled, create a monitor otherwise we do a one shot
    # load of the configured log levels
    if monitoring:
        global LOG_LEVEL_MONITOR
        if LOG_LEVEL_MONITOR is None:
            if with_twisted and twisted_reactor is not None:
                LOG_LEVEL_MONITOR = (
                    log4configuration.Log4ConfigurationMonitor())
            else:
                LOG_LEVEL_MONITOR = log4configuration.Log4ConfigurationMonitor()  # pylint: disable=R0204
    else:
        log4configuration.Log4ConfigurationLoader().update_log_levels()


def stop_monitoring_log_configuration_file(delete_monitor=True):
    """Stop monitoring the log configuration file"""
    global LOG_LEVEL_MONITOR
    if LOG_LEVEL_MONITOR is not None:
        LOG_LEVEL_MONITOR.stop()
        if delete_monitor:
            LOG_LEVEL_MONITOR = None


def start_monitoring_log_configuration_file():
    """Start monitoring the log configuration file"""
    if LOG_LEVEL_MONITOR is not None:
        LOG_LEVEL_MONITOR.start()


@atexit.register
def check_log_monitoring_is_inactive():
    """Check that applications disable log monitoring before shutdown"""
    if LOG_LEVEL_MONITOR is not None:
        print("**** Unclean logging shutdown in %s" % (sys.argv[0],))
    # Assert will be enabled once more confidence has been obtained that all
    # the applications have been updated.

    # assert LOG_LEVEL_MONITOR is None
