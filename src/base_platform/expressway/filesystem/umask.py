"""
Thread-safe umask handling, using a Context Manager

Usage:

    with umask(mask):
        ... perform file action

On entry the umask is locked with an advisory thread-safe lock.
os.umask(mask) is called, setting the process's umask mask.
On exit the umask value is restored.

Note :- all instances of os.umask() need to be changed to ensure
that the function is thread-safe.
"""

import os
import threading
import contextlib

umask_lock = threading.Lock()


@contextlib.contextmanager
def umask(value):
    """ Make threadsafe temporary modifications to os.umask() """
    with umask_lock:
        old_value = os.umask(value)
        try:
            yield old_value
        finally:
            os.umask(old_value)
