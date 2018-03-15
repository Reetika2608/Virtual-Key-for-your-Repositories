from setuptools import setup, find_packages

setup(
    name='management_connector',
    version='0.1',
    packages=find_packages(),
    namespace_packages=['ni'],
    install_requires=('websocket_client', 'pycrypto', 'pyratemp'),
    description='Provides an environment and utils for management connector package when not on Expressway',
)
