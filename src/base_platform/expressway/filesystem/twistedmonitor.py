# Ignore "can't find blah members" but they do exist in base classes pylint: disable=E1101

"""File system monitor that integrates nicely inside a Twisted reactor."""
import exceptions
import pyinotify
from twisted.internet import abstract
from base_platform.expressway.filesystem.monitor import DirectoryMonitor, FileMonitor


class _TwistedInotifyReader(abstract.FileDescriptor):
    '''Give twisted the fd and handle the read when twisted asks us'''
    #  invalid names but need to, as it is inherited pylint: disable=C0103

    def __init__(self, watch_manager, notifier):
        abstract.FileDescriptor.__init__(self)
        self.watch_manager = watch_manager
        self.notifier = notifier

    def fileno(self):
        """
        Return the inotify watch filedescriptor for twisted to do select/poll
        etc.
        """
        return self.watch_manager._fd  # Use of protected member pylint: disable=W0212

    def doRead(self):
        """
        When twisted's reactor wants to read, it will call this which should
        get pyinotify to process the events
        """
        self.notifier.read_events()
        self.notifier.process_events()

    def writeSomeData(self, data):
        """Inotify fds are not meant to be written to like normal ones"""
        pass


class TwistedDirectoryMonitor(DirectoryMonitor):
    '''Class to monitor for changes to directories.

    Uses twisted's reactor rather than starting threads.
    '''

    def __init__(self, reactor):
        DirectoryMonitor.__init__(self, threaded=False)
        self.reactor_obj = reactor
        self.inotify_reader = None
        self.watched_directories = {}
        self.watch_manager = pyinotify.WatchManager()
        self.notifier = pyinotify.Notifier(self.watch_manager, self)
        self.start()

    def start(self):
        """
        non threaded notifier has no start method
        """
        if self.inotify_reader is None:
            # Get twisted to select/poll on the inotify fd
            self.inotify_reader = _TwistedInotifyReader(self.watch_manager, self.notifier)
            self.reactor_obj.addReader(self.inotify_reader)

    def stop(self):
        """
        remove notifier fd from twisted
        """
        if self.inotify_reader is not None:
            try:
                self.reactor_obj.removeReader(self.inotify_reader)
            except exceptions.IOError:
                # this is expected as the fd is not a true one
                pass
            self.inotify_reader = None


class TwistedFileMonitor(FileMonitor):
    '''
    Class to monitor files in the reactor thread.
    Callbacks will therefore occur on the reactor thread.

    Note that the observer callback does not have to return a deferred or anything else and will
    not be yielded.
    For example:

    >>> from twisted.internet import reactor
    >>> class MyClass(object):
    ...     def __init__(self):
    ...         self.monitor = TwistedFileMonitor(reactor)
    ...         self.monitor.register_file_observer("/tmp/myfile", self._on_change)
    ...     def _on_change(self, file_path):
    ...         print "The file %s was modified" % file_path

    '''
    def __init__(self, reactor):
        FileMonitor.__init__(self, threaded=False)
        self.inotify_reader = None
        self.directory_monitor = TwistedDirectoryMonitor(reactor)
        self.reactor_obj = reactor
