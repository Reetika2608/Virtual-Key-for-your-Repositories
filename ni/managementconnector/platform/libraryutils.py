""" Utility class to handling all things library related """

import os
import sys

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class LibraryUtils(object):
    """ Utilities to deal with libraries """

    @staticmethod
    def append_library_path():
        """ Append all required libraries to the sys path for library imports """
        lib_path = ManagementConnectorProperties.LIBRARY_PATH

        for lib in os.listdir(lib_path):
            full_path = os.path.join(lib_path, lib)
            if os.path.isdir(full_path):
                sys.path.append(full_path)
