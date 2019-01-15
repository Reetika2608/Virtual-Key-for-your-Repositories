"""
The plugin module contains some base classes that plugins will probably
subclass.
"""

# Ignore "Method could be a function" warnings        pylint: disable=R0201

import logging
import pkgutil
import sys
import traceback

DEV_LOGGER = logging.getLogger("developer.ni.utils.logging.plugin")

def _load_plugins(module_name):
    """
    Generator that instantiates all the classes in the PLUGIN_CLASSES list in
    child modules of the given module.
    """

    # Ignore "Catching too general exception" warnings  pylint: disable=W0703

    __import__(module_name)
    parent_module = sys.modules[module_name]

    for loader, name, ispkg in pkgutil.iter_modules(parent_module.__path__):
        if ispkg:
            continue

        fullname = "%s.%s" % (module_name, name)

        DEV_LOGGER.debug('Detail="Loading plugin" Module="%s" Loader="%s"',
                         fullname, loader)

        try:
            loaded_module = loader.find_module(fullname).load_module(fullname)

            try:
                classes = getattr(loaded_module, "PLUGIN_CLASSES")
            except AttributeError:
                pass
            else:
                for cls in classes:
                    yield cls()
        except Exception:
            DEV_LOGGER.exception(
                'Detail="Failed to load plugin" Module="%s" Loader="%s"',
                fullname, loader)
            traceback.print_exc()


class Plugin(object):
    """
    This plugin class can be extended to create plugins that will
    help in creating product specific config files.The product conf
    is appended to the platform conf
    """
    def __init__(self):
        """
        init func
        """
        pass

    def datasetmodifier(self, dataset):
        """
        This function will add necessary cdb value set into the dict
        that is used to create syslog-ng Template in pyratempfilewriter
        """
        pass

    def log4stringappender(self):
        """
        returns the list of values that needs to be appended for log4configuration
        currently it should return a list of length equal to 2.
        1st element in list will hold appender info
        2nd element in the list will hold logger info
        """
        return []

    def syslogstringappender(self):
        """
        returns the list of values that needs to be appended for logingmanager
        currently it should return a list of length equal to 2.
        1st element in list will hold destination info
        2nd element in the list will hold log info
        """
        return []

    @staticmethod
    def load_all():
        """
        Returns a generator that instantiates all the Plugin subclasses in
        ni.utils.logging.plugins
        """

        return _load_plugins("ni.utils.logging.plugins")
