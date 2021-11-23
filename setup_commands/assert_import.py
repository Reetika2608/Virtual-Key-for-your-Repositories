from distutils.cmd import Command

import os
import sys


class AssertImportCommand(Command):
    """
    Custom setup.py command to assert for correct import path
    """
    description = "Ensures the correct import paths are supplied for the ni py files"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    @staticmethod
    def assert_module_paths():
        """
        This function is used to asserts all FMC module paths contain
        a reference to 'managementconnector' or 'cafedynamic' to prevent
        import issues in long standing running code i.e managementframework
        - xstatus.
        """
        ni_dir = "debian/data/share/python/site-packages/ni/"
        if os.path.isdir(ni_dir):
            for root, _, files in os.walk(ni_dir):
                for filename in files:
                    # Join the two strings in order to form the full filepath.
                    filepath = os.path.join(root, filename)
                    if "managementconnector" in filepath or "cafedynamic" in filepath:
                        continue
                    print("Neither required patterns found in filepath: {}".format(filepath))
                    sys.exit(1)
        else:
            print("audit_import_paths: Failure: should be ran on ni build directory {}, but did not exist as expected"\
                .format(ni_dir))
            sys.exit(1)

    def run(self):
        AssertImportCommand.assert_module_paths()
