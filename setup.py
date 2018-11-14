from distutils.cmd import Command
from setuptools import setup, find_packages

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
            DS_Store="find . -name .DS_Store -print0 | xargs -0 rm -f;",
            pyc="find . -name '*.pyc' -exec rm -rf {} \;",
            egg_info="find . -name 'management_connector.*egg-info' -type  d  -print | xargs rm -rf {};",
            _build_dir="rm -rf deb/_build/",
            build_dir="rm -rf build/;"
        )
        for key, cmd in cmd_list.items():
            os.system(cmd)


setup(
    name='management_connector',
    version='0.1',
    cmdclass={'clean': CleanCommand},
    packages=find_packages(),
    namespace_packages=['ni'],
    install_requires=('websocket_client', 'pycrypto', 'pyratemp'),
    description='Provides an environment and utils for management connector package when not on Expressway',
)
