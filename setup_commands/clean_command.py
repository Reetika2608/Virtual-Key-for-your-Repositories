import os
from distutils.cmd import Command


class CleanCommand(Command):
    """
    Custom clean script for removing unwanted, built related files/directories
    """
    description = "Cleans up temporary files from the build"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        cmd_list = dict(
            pyc="find ./src -name *.pyc | xargs rm -f; "
                "find ./tests -name *.pyc | xargs rm -f; "
                "find ./setup_commands -name *.pyc | xargs rm -f; ",
            files_pyc="rm files/__init__.pyc files/opt/__init__.pyc files/opt/c_mgmt/__init__.pyc "
                      "files/opt/c_mgmt/xcommand/__init__.pyc files/opt/c_mgmt/xstatus/__init__.pyc",
            build_dirs="rm -rf build/ dist/ debian/_build/ debian/data/ debian/control/_build ./*.egg-info test-results.xml",
        )
        for key, cmd in cmd_list.items():
            os.system(cmd)
