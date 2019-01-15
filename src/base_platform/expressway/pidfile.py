""" PIDFile creation and handling """
import os


class PIDFile(object):
    """Class to manage the life time of a PID file to allow the application to
    be integrated with the OS as a service.
    """

    def __init__(self, pid_file_path):
        self.pid_file_path = pid_file_path
        self.pid = os.getpid()

    def create(self):
        """Create the PID file."""

        pid_file = open(self.pid_file_path, "w")
        try:
            pid_file.write(str(self.pid))
        finally:
            pid_file.close()

    def delete(self):
        """Delete the PID file."""

        os.unlink(self.pid_file_path)

    def exists(self):
        """Check if there is a valid PID file."""
        if not os.path.exists(self.pid_file_path):
            return False

        try:
            pid_file = open(self.pid_file_path)
            pid = pid_file.readline().rstrip()
        finally:
            pid_file.close()

        # Check if this process exists
        try:
            os.kill(int(pid), 0)
            return True
        except os.error:
            return False
