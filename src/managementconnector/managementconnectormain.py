#!/usr/bin/env python3

# Ignore "C0413(wrong-import-position)" pylint: disable=C0413

""" This module starts ManagementConnector """
# Append all required paths to the syspath for library imports.
from managementconnector.platform.libraryutils import LibraryUtils
LibraryUtils.append_library_path()
LibraryUtils.append_python_library_path()

# Initialise logging framework before all other application imports
import base_platform.expressway.logframework.setup as logging_setup


# Local application / library specific imports
from managementconnector.applicationrunner import ApplicationRunner
from managementconnector.mgmtconnector import ManagementConnector
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
logging_setup.initialise_logging("managementconnector")

#Initialise logging application handle for hybridservices
from managementconnector.platform.hybridlogsetup import initialise_logging_hybrid_services
initialise_logging_hybrid_services("managementconnector")


class ManagementConnectorApplicationRunner(ApplicationRunner):
    """Class to manage the lifetime of the Management Connector"""

# -------------------------------------------------------------------------


def main():
    """main"""
    pid_file_path = "/var/run/" + ManagementConnectorProperties.SERVICE_NAME + "/" + \
                    ManagementConnectorProperties.SERVICE_NAME + ".pid"

    application = ManagementConnector()

    application_runner = ManagementConnectorApplicationRunner(application, pid_file_path, ManagementConnectorProperties.get_dev_logger())
    application_runner.launch()


if __name__ == '__main__':
    main()
