# Ignore "Line too long" warnings.                    pylint: disable=C0301
# Ignore "Invalid name" warnings.                     pylint: disable=C0103
# Ignore "Method could be a function" warnings.       pylint: disable=R0201
# Ignore "Catch Exception" warnings.                  pylint: disable=W0703

"""File system monitor.
"""

# Library modules
import logging
import os.path
import threading
import time

# Third party libraries
import pyinotify


DEV_LOGGER = logging.getLogger("developer.platform.filesystem")


class DirectoryMonitor(pyinotify.ProcessEvent):
    """Class to monitor for changes to the contents of a directory.
    """

    events_to_monitor = pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVED_TO | pyinotify.IN_Q_OVERFLOW | pyinotify.IN_DELETE
    max_callback_time = 60.0
    warn_callback_time = 5.0

    def __init__(self, threaded=True):
        self.threaded = threaded
        self.notifier_active = False
        pyinotify.ProcessEvent.__init__(self)

        self.watched_directories = {}
        self.watch_manager = pyinotify.WatchManager()
        if self.threaded:
            self.notifier = pyinotify.ThreadedNotifier(self.watch_manager, self)
            self.notifier.setDaemon(True)
        else:
            self.notifier = pyinotify.Notifier(self.watch_manager, self)

    def register_directory_observer(self, directory_path, observer, recursive=True):
        """Register an observer to be notified about modifications to the
        specified directory contents.
        """
        directory_path = os.path.abspath(directory_path)

        if directory_path in self.watched_directories:
            if observer not in self.watched_directories[directory_path]:
                self.watched_directories[directory_path].append(observer)
        else:
            DEV_LOGGER.debug('Detail="File system monitoring enabled for directory" Directory="%s"' % (directory_path,))
            self.watched_directories[directory_path] = [observer]
            self.watch_manager.add_watch(directory_path, self.events_to_monitor, rec=recursive)

    def start(self):
        """Start monitoring all registered files"""
        if hasattr(self.notifier, "start"):
            self.notifier.start()
        self.notifier_active = True

    def stop(self):
        """Stop monitoring all registered files"""
        if self.notifier_active:
            self.notifier.stop()
            self.notifier_active = False

    def process_IN_MOVED_TO(self, event):
        """Handle the moved to event, notifying all observers"""

        DEV_LOGGER.debug('Detail="File move to detected" Event-path="%s" Event-name="%s"' % (event.path, event.name))
        self.process_file_change(event)

    def process_IN_CLOSE_WRITE(self, event):
        """Handle the modification event, notifying all observers"""

        DEV_LOGGER.debug('Detail="File change detected" Event-path="%s" Event-name="%s"' % (event.path, event.name))
        self.process_file_change(event)

    def process_IN_DELETE(self, event):
        """Handle the deletion event, notifying all observers"""

        DEV_LOGGER.debug('Detail="File deletion detected" Event-path="%s" Event-name="%s"' % (event.path, event.name))
        self.process_file_change(event)

    def process_file_change(self, event):
        """Handle the modification event, notifying all observers"""

        if event.path in self.watched_directories:
            observers = self.watched_directories[event.path]
            for observer in observers:
                try:
                    if event.name is not None:
                        changed_file_path = os.path.join(event.path, event.name)
                    else:
                        changed_file_path = event.path
                    # Notify all observers of the directory about the change to a file
                    self._notify_observer(observer, changed_file_path)
                except Exception:
                    DEV_LOGGER.exception('Detail="Failed to notify file system observer" File-name="%s"' % (event.path,))

    def process_IN_Q_OVERFLOW(self, _):
        """Handle the case where we become flooded with events"""
        DEV_LOGGER.error('Detail="File system monitoring notification queue overflow occurred. Application may be out of sync."')

    def _notify_observer(self, observer, file_path):
        """Notify an observer of a file change event"""
        if self.threaded:
            # Run the observer on a seperate thread to monitor that it finishes
            # in a timely manner.
            thread = threading.Thread(target=observer, args=(file_path,))
            thread.daemon = True
            start_time = time.time()
            thread.start()
            thread.join(self.max_callback_time)
            elapsed = time.time() - start_time

            fmt = 'Detail="File monitoring callback took too long." Timeout="%f" Observer="%s" Filepath="%s"'
            if elapsed < self.warn_callback_time:
                pass
            elif elapsed < self.max_callback_time:
                DEV_LOGGER.warning(fmt % (elapsed, _full_function_name(observer), file_path))
            else:
                DEV_LOGGER.error(fmt % (elapsed, _full_function_name(observer), file_path))
        else:
            observer(file_path)


def _full_function_name(a_callable):
    """
    Returns the dotted name of a callable, including the module and class
    name.
    """

    ret = []

    # Get the class name if the callable is a bound method
    try:
        ret.append(a_callable.__self__.__class__.__name__)
    except AttributeError:
        pass

    # Get the function name
    try:
        ret.append(a_callable.__name__)
    except AttributeError:
        pass

    if ret:
        return ".".join(ret)
    else:
        return repr(a_callable)


class FileMonitor(object):
    '''Class to monitor for changes to files.

    The monitor watches the parent directories of the files it is asked to
    monitor. This means that although the directory has to exist at
    registration time, the file does not.

    Note that callbacks will occur on the monitor's thread.

    For example:

    >>> class MyClass(object):
    ...     def __init__(self):
    ...         self.monitor = FileMonitor()
    ...         self.monitor.register_file_observer("/tmp/myfile", self._on_change)
    ...         self.monitor.start()
    ...     def _on_change(self, file_path):
    ...         print "The file %s was modified" % file_path
    '''

    def __init__(self, threaded=True):
        self.watched_files = {}
        self.directory_monitor = DirectoryMonitor(threaded=threaded)

    def start(self):
        """Start monitoring all registered files"""
        self.directory_monitor.start()

    def stop(self):
        """Stop monitoring all registered files"""
        self.directory_monitor.stop()

    def register_file_observer(self, file_path, observer):
        """Register an observer to be notified about modifications to the
           specified file.
        """
        file_path = os.path.abspath(file_path)
        directory_path = os.path.dirname(file_path)

        if file_path in self.watched_files:
            DEV_LOGGER.debug('Detail="Adding another observer to already watched file" File-name="%s"' % (file_path,))
            self.watched_files[file_path].append(observer)
        else:
            DEV_LOGGER.debug('Detail="Adding path to directory watcher" File-name="%s"' % (file_path,))
            self.watched_files[file_path] = [observer]
            self.directory_monitor.register_directory_observer(directory_path, self.on_file_change)

    def on_file_change(self, file_path):
        """Called when a file in a monitored directory changes."""
        if file_path in self.watched_files:
            for observer in self.watched_files[file_path]:
                observer_name = _full_function_name(observer)
                try:
                    # Notify all observers of the file
                    DEV_LOGGER.debug('Detail="Notifying observer about file change" File-name="%s" Observer="%s"' % (file_path, observer_name))
                    observer(file_path)
                except Exception:
                    DEV_LOGGER.exception('Detail="Failed to notify file system observer" File-name="%s" Observer="%s"' % (file_path, observer_name))
