from distutils.cmd import Command

import os


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
            build_dirs="rm -rf build/ dist/ debian/_build/ debian/data/ debian/control/_build ./*.egg-info test-results.xml",
        )
        for key, cmd in cmd_list.items():
            os.system(cmd)
