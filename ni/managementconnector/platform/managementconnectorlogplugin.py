# Ignore "Method could be a function" warnings        pylint: disable=R0201

""" This file will dynamically change the syslog-ng config file generation """

from ni.utils.logging.plugin import Plugin


class HybridServicesLogPlugin(Plugin):
    """ Hybrid Services setup plugin """

    def syslogstringappender(self):
        """  function to append string for syslog-ng configuration """

        #Define String that needs to be part of the template
        template_dest = """\
destination hybrid_services { file("/mnt/harddisk/log/hybrid_services_log" perm(0644) template("$R_ISODATE $HOST $MSGHDR$MSG\n") ); };
filter f_local7 { facility(local7); };
"""

        template_log = """\
log { source(s_everything); filter(f_local7);   rewrite( r_nocrlfs );   destination(hybrid_services); };
"""

        syslogappend = [template_dest, template_log]
        return syslogappend

    def log4stringappender(self):
        """ function to append string for log4 configuration"""
        log4_boilerplate = """\
###############################################################################

# Setup the hybridServicesAppender
log4j.appender.hybridservicesAppender=org.apache.log4j.SyslogAppender
log4j.appender.hybridservicesAppender.sysloghost=localhost
log4j.appender.hybridservicesAppender.facility=local7
log4j.appender.hybridservicesAppender.layout=org.apache.log4j.PatternLayout
log4j.appender.hybridservicesAppender.layout.ConversionPattern=UTCTime="%d{}{GMT}" Module="%c" Level="%p" CodeLocation="%l" Detail="%m%n"
# Make sure hybridservicesAppender can also log via the rootLogger (or other ancestor)
log4j.additivity.hybridservices=true

"""
        log4_boilerplate_logger = """\
log4j.logger.hybridservices=INFO, hybridservicesAppender
"""

        log4append = [log4_boilerplate, log4_boilerplate_logger]
        return log4append

    def loglevelpathappender(self):
        """ function to append database path string for new log level table management """

        # Bug 240363
        try:
            from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
            logger_db_path = ManagementConnectorProperties.LOGGER_DB_PATH
            logger_inotify = ManagementConnectorProperties.LOGGER_INOTIFY
        except ImportError:
            logger_db_path = "/configuration/hybridserviceslogger"
            logger_inotify = "/tmp/management/notifications/diagnostics/hybridserviceslogger"

        log_level_db = (logger_db_path, logger_inotify)
        return log_level_db


PLUGIN_CLASSES = (
    HybridServicesLogPlugin,
)
