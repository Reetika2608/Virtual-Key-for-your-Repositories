"""Management plugin to manage the filesystem
"""

# Standard library imports
import logging

# Local application/library specific imports
from base_platform.expressway.filesystem.monitor import DirectoryMonitor, FileMonitor


DEV_LOGGER = logging.getLogger("developer.management.filesystemmanager")


class FilesystemManager(object):
    """Manager to deal with filesystem actions"""

    def __init__(self, _options, _application_manager):
        self.file_monitor = FileMonitor()
        self.directory_monitor = DirectoryMonitor()

    def start(self):
        """Start the filesystem manager application"""
        DEV_LOGGER.info('Detail="Starting file system monitoring."')
        self.file_monitor.start()
        self.directory_monitor.start()

    def stop(self):
        """Stop the filesystem manager application"""
        self.file_monitor.stop()
        self.directory_monitor.stop()
        DEV_LOGGER.info('Detail="Stopped file system monitoring."')

    def register_file_observer(self, file_path, observer):
        """Register an observer for file modifications.
        
        The observer must be a callable object which takes one parameter, the
        file_path of the file modified.
        """
        self.file_monitor.register_file_observer(file_path, observer)

    def register_directory_observer(self, directory_path, observer):
        """Register an observer for modifications to files in a directory.
        
        The observer must be a callable object which takes one parameter, the
        file_path of the file modified.
        """
        self.directory_monitor.register_directory_observer(
            directory_path,
            observer)
