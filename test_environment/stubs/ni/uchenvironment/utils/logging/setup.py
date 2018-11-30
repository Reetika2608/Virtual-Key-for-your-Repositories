"""
This file allows us to redirect initialize_logging function from
 ni.utils.logging.setup to here.

ni.utils.logging.setup is great on hedge, but quite a lot needs to be true
 for it to work anywhere else, and as many 'main' files call it, overriding
 it once is not sufficient, meaning you end up with multiple changes and then
 give up).

Though a 'hack', this does mean that we can quickly use modules that prevoiusly
 only ran on hedge or a box made look like hedge. Which helps decouple code.

"""

# Ignore "String statement has no effect" warnings    pylint: disable=W0105
# Ignore "Method could be a function" warnings        pylint: disable=R0201
# Ignore "Missing docstring" warnings                 pylint: disable=C0111
# Ignore "Invalid name" warnings                      pylint: disable=C0103
# Ignore "Redefining name from outer scope" warnings  pylint: disable=W0621
# Ignore "Unused variable" warnings                   pylint: disable=W0612
# Ignore "no-name-in-module" errors                   pylint: disable=E0611
# Ignore "no-member" errors                           pylint: disable=E1101
# Ignore "Unused import" warnings                     pylint: disable=W0611
# Ignore "Unable to import" warnings                  pylint: disable=F0401


import sys
import logging
# This is a problem, because when it gets put on hedge
# it should be 'ni.uchenvironments'.

import ni.uchenvironment.utils.logging


def insert_enviroment_module_over_logging_module():
    """
    Injects code into sys.modules to prevent initialize_logging running from anywhere.
    :return:
    """
    # Trial and Error between module name in [] (if statements) and with a dot (.) for
    # final assignment - package verses module I suppose.
    if 'ni.utils' not in sys.modules:
        print("Populated ni.utils")
        sys.modules['ni.utils'] = sys.modules['ni.uchenvironment.utils']
    if 'ni.utils.logging' not in sys.modules:
        print("Populated ni.utils.logging")
        sys.modules['ni.utils.logging'] = sys.modules['ni.uchenvironment.utils.logging']

    sys.modules['ni.utils.logging'].setup = sys.modules['ni.uchenvironment.utils.logging.setup']


try:
    """
    Populates ni.utils.logging in sys.modules.
    """
    import ni.utils.logging.setup
    initial_logging_function = ni.utils.logging.setup.initialise_logging
except ImportError:
    initial_logging_function = None


class InitializeLoggingFunction:
    """
    Manages which version of intialize_logger should be called.
    First time, tries ni.utils.logging.setup, but if this fails, provides an alternative
    implementation and writes that implementation into sys.modules, controlling subsequent
    calls.
    """

    def __init__(self):
        self.current_implementation = initial_logging_function or self.alternative_implemenation
        self._tried = False
        self.root_logger = None

    def alternative_implemenation(self, name):
        """
        Alternative implementation of 'ni,utils.logging.initialise_logging'
        :param name:

        """
        if not self.root_logger:
            self.root_logger = logging.getLogger()
            self.root_logger.setLevel(logging.INFO)
            console = logging.StreamHandler()
            formatter = logging.Formatter(
                    "%(name)-20s %(levelname)-8s %(pathname)s:%(lineno)s  %(message)s")
            console.setLevel(logging.DEBUG)
            console.setFormatter(formatter)
            self.root_logger.addHandler(console)
        log = logging.getLogger(__name__)
        log.info("Logging to Stdout for %s" % name)


    def __call__(self, name):
        """
        Redirect initialise_logger calls to appropriate function.
        :param name:
        :return:
        """
        if self._tried is False:
            self._tried = True
            try:
                return self.current_implementation(name)
            except (IOError, OSError):
                insert_enviroment_module_over_logging_module()
                self.current_implementation = self.alternative_implemenation
        return self.current_implementation(name)


initialise_logging = InitializeLoggingFunction()
