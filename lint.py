from setuptools import setup, find_packages
from setup_commands.pylint_command import PylintCommand


setup(
    name='management_connector',
    version='0.1',
    cmdclass={'pylint': PylintCommand},
    package_dir={'': 'src'},
    packages=find_packages('src'),
    install_requires=('websocket_client', 'cryptography', 'pyratemp'),
    description='Provides an environment and utils for management connector package when not on Expressway',
)