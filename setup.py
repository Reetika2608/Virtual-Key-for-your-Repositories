from setuptools import setup, find_packages
from setup_commands.assert_import import AssertImportCommand
from setup_commands.clean_command import CleanCommand
from setup_commands.pylint_command import PylintCommand


setup(
    name='management_connector',
    version='0.1',
    cmdclass={'clean': CleanCommand, 'audit_import_paths': AssertImportCommand, 'pylint': PylintCommand},
    package_dir={'': 'src'},
    packages=find_packages('src'),
    install_requires=('websocket_client', 'pycrypto', 'pyratemp'),
    description='Provides an environment and utils for management connector package when not on Expressway',
)
