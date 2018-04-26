#!/usr/bin/env python

""" This module starts Cafe Manager """

# Standard library imports
import os
import os.path
import signal
import time
import sys

# Local application / library specific imports

import ni.utils.logging.setup

import ni.utils.application.pidfile


class ApplicationRunner:

    """Class to manage the lifetime of the application. """

    def __init__(self, application, pid_file_path, logger):
        self.application = application
        self.logger = logger

        self.name, _extension = os.path.splitext(os.path.basename(sys.argv[0]))
        self.pid_file = ni.utils.application.pidfile.PIDFile(pid_file_path)
        self.started_pid_file = ni.utils.application.pidfile.PIDFile(pid_file_path + '.started')

    def launch(self):
        """Launches the application."""
        if self.pid_file.exists():
            self.logger.warning('Detail="FMC_Lifecycle ApplicationRunner - Exiting because application is already running" Application="%s" Pid="%d" Directory="%s" Arguments="%s"' %
                                (self.name, os.getpid(), os.getcwd(), " ".join(sys.argv[1:])))
        else:

            try:

                self.on_startup()
                self.application.start()

                self.run()
            except (KeyboardInterrupt, SystemExit):
                pass
            finally:
                self.on_shutdown()

    # -------------------------------------------------------------------------

    def run(self):
        """Central Thread that prevents Program from exiting while application runs in the background"""
        self.logger.info('Detail="FMC_Lifecycle ApplicationRunner running" Application="%s" Pid="%d"' %
                         (self.name, os.getpid()))

        while True:
            time.sleep(2)

    # -------------------------------------------------------------------------

    def on_startup(self):
        """Called when the application is about to start."""
        self.logger.info('Detail="FMC_Lifecycle ApplicationRunner on_startup called" Application="%s" Pid="%d" Directory="%s" Arguments="%s"' %
                         (self.name, os.getpid(), os.getcwd(), " ".join(sys.argv[1:])))
        signal.signal(signal.SIGTERM, self.handle_sigterm)
        self.pid_file.create()
        self.started_pid_file.create()

    # -------------------------------------------------------------------------

    def on_shutdown(self):
        """Called when the application shuts down."""
        self.logger.info('Detail="FMC_Lifecycle ApplicationRunner on_shutdown called" Application="%s" Pid="%d"' %
                         (self.name, os.getpid()))
        self.application.stop()
        ni.utils.logging.setup.stop_monitoring_log_configuration_file()
        self.pid_file.delete()
        self.started_pid_file.delete()
        self.logger.info('Detail="FMC_Lifecycle ApplicationRunner on_shutdown complete"')

    # -------------------------------------------------------------------------

    @staticmethod
    def handle_sigterm(_signal, _frame):
        """Signal handler for SIGTERM
        Registering a handler for the SIGTERM signal allows the finally block
        in run to execute so that clean up can be performed.
        """
        sys.exit(0)
