# Ignore "Line too long" warnings.                  pylint: disable=C0301
# Ignore "Catch Exception" warnings.                pylint: disable=W0703

"""Utilities for managing files.
"""

# Library modules
import errno
import logging
import os
import os.path
import shutil
import threading
from pwd import getpwnam

# Local application/library specific imports
from cafedynamic.cafexutil import CafeXUtils


DEV_LOGGER = logging.getLogger("developer.platform.filesystem")


def touch(file_name, times=None):
    """Touch the specified file name."""
    with file(file_name, 'a'):
        os.utime(file_name, times)


class FileWriter(object):
    """Class to write out a file. Any existing file is moved to a backup"""

    encoding = 'utf-8'
    only_write_on_changes = False   # Skip updating the file if the contents are unchanged
    comparitor_line_skip_count = 0  # Number of lines to skip over when comparing file contents
    lock = threading.Lock() # process lock

    def __init__(self, file_path, permissions=None, make_backup=True, owner=None, group=None):
        self.file_path = file_path
        self.permissions = permissions
        self.owner = owner
        self.group = group
        self.make_backup = make_backup

        (dirname, filename) = os.path.split(self.file_path)

        self.backup_file_path = os.path.join(dirname, ".%s.bak" % filename)
        self.temp_file_base_path = os.path.join(dirname, ".%s.%d" % (
            filename,
            os.getpid()))

        # Make sure the destination directory exists
        CafeXUtils.make_path(os.path.dirname(self.file_path))

    def exists(self):
        """Returns True if the file owned by the writer already exists."""
        return os.path.exists(self.file_path)

    def get_file_path(self):
        """Returns the file path."""
        return self.file_path

    def get_backup_path(self):
        """Returns the path used for the backup file."""
        return self.backup_file_path

    def write_file(self, contents):
        """Write the contents into the file. Backs up any existing file and
        attempts to make the write as atomic as possible.
        """

        if self._should_write_contents(contents):
            # Do everything within a lock to avoid thread contention if two
            # threads attempt to write the file via the same writer
            with self.lock:
                # Create the file in a temporary location
                temp_file_path = "%s.%d.tmp" % (self.temp_file_base_path, threading.current_thread().ident)

                DEV_LOGGER.debug('Detail="Created temporary file" File="%s"', temp_file_path)
                new_file = open(temp_file_path, mode="wb")
                if self.encoding is not None:
                    new_file.write(contents.encode(self.encoding))
                else:
                    new_file.write(contents)
                new_file.close()

                if self.make_backup:
                    # error handling as .bak files may be asynchronously deleted during upgrade
                    try:
                        DEV_LOGGER.debug('Detail="Deleting existing backup file" File="%s"', self.backup_file_path)
                        os.remove(self.backup_file_path)
                    except (IOError, OSError) as exp:
                        if exp.errno != errno.ENOENT:
                            raise

                    # Backup any existing file
                    if os.path.exists(self.file_path):
                        DEV_LOGGER.debug('Detail="Creating backup file" File="%s"', self.backup_file_path)
                        shutil.copyfile(self.file_path, self.backup_file_path)
                        # error handling as .bak files may be asynchronously deleted during upgrade
                        try:
                            self._set_permissions(self.backup_file_path)
                        except (IOError, OSError) as exp:
                            if exp.errno != errno.ENOENT:
                                raise

                # If everything succeeded, then make the new file "live"
                DEV_LOGGER.debug('Detail="Making temporary file live" Temp-file="%s" File="%s"', temp_file_path, self.file_path)

                # We use move so that we get an atomic operation i.e. we never have a
                # window where the file does not exist. Note, this is unlikely to be
                # portable as it relies on the posix behaviour which copes with the
                # destination file already existing.
                shutil.move(temp_file_path, self.file_path)
                self._set_permissions(self.file_path)
                self._set_ownership(self.file_path)
        else:
            DEV_LOGGER.info('Detail="Skipping file update" Reason="Contents identical" File="%s"' % (self.file_path,))

    def _set_permissions(self, file_path):
        """If the file writer has been configured with permissions, use these
        to ensure the file is written with the correct access rights."""
        if self.permissions is not None:
            os.chmod(file_path, self.permissions)

    def _set_ownership(self, file_path):
        """If the file writer has been configured with any ownership (owner or group), use these
        to ensure the file is written with the correct ownership."""
        if self.owner is not None or self.group is not None:
            uid = -1  # unless actually specified, leave owner alone
            if self.owner is not None:
                try:
                    uid = getpwnam(self.owner).pw_uid
                except KeyError:
                    DEV_LOGGER.error('Detail="Failed to find uid for specified user,'
                                     ' ownership not changed'
                                     ' User="%s" File="%s"'
                                     ,self.owner, self.file_path)
                    raise
                else:
                    DEV_LOGGER.info('Detail="Setting file ownership'
                                     ' User="%s" File="%s"'
                                     ,self.owner, self.file_path)

            gid = -1  # unless actually specified, leave group alone
            if self.group is not None:
                try:
                    gid = getpwnam(self.owner).pw_gid
                except KeyError:
                    DEV_LOGGER.error('Detail="Failed to find gid for specified group,'
                                     ' ownership not changed'
                                     ' Group="%s" File="%s"'
                                     ,self.group, self.file_path)
                    raise

                else:
                    DEV_LOGGER.info('Detail="Setting file ownership'
                                    ' Group="%s" File="%s"'
                                    ,self.group, self.file_path)

            try:
                os.chown(file_path, uid, gid)
            except OSError:
                DEV_LOGGER.error('Detail="Problem setting ownership,'
                                 ' File="%s" Uid="%s", Gid="%s"'
                                 ,self.file_path, uid, gid)

                raise

    def _should_write_contents(self, new_contents):
        """Returns True if the contents of the file should be udpated"""
        should_write_contents = True
        if self.only_write_on_changes:
            try:
                current_contents = open(self.file_path).read()
                if self._get_significant_contents(current_contents) == self._get_significant_contents(new_contents):
                    should_write_contents = False
            except (IOError, OSError):
                # Encountering any IOError for the existing file is treated as
                # requiring new contents to be written.
                pass
        return should_write_contents

    def _get_significant_contents(self, contents):
        """Returns the significant part of the contents"""
        lines = contents.split(os.linesep)
        significant_lines = lines[self.comparitor_line_skip_count:]
        return os.linesep.join(significant_lines)
