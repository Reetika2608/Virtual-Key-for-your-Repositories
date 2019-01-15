# Ignore "Line too long" warnings.                  pylint: disable=C0301
# Ignore "Catch Exception" warnings.                pylint: disable=W0703
# Ignore "Anomalous backslash in string" warnings   pylint: disable=W1401

"""This module contains a class to manage the platform information"""

# Standard library modules
import logging
import os
import os.path
import re
import subprocess
import xml.etree.cElementTree as ElementTree


DEV_LOGGER = logging.getLogger("developer.platform.platforminfo")


class PlatformInfo(object):
    """
    Describes the platform that we are running on.

    Information is available via instance attributes.  These are:

    .. py:attribute:: build_date

        Example: ``2012-07-23 13:10``

    .. py:attribute:: build_revision

        Example: ``294361``

    .. py:attribute:: build_type

        Example: ``Test SW``

    .. py:attribute:: build_user

        Example: ``dsa``

    .. py:attribute:: network_interfaces

        Example: ``[{'device': 'eth0', 'name': 'LAN1'}]``

    .. py:attribute:: option_key_prefix

        Example: ``116341``

    .. py:attribute:: product_info_path

        Example: ``/info/product_info.xml``

    .. py:attribute:: product_name

        Example: ``Cisco Application Server``

    .. py:attribute:: release_key

        Example: ``3790039961766684``

    .. py:attribute:: release_key_is_valid

        Example: ``True``

    .. py:attribute:: release_key_path

        Example: ``/tandberg/etc/rk``

    .. py:attribute:: release_type

        Example: ``PreAlpha``

    .. py:attribute:: release_version

        Example: ``1``

    .. py:attribute:: rkvfy_path

        Example: ``/bin/rkvfy``

    .. py:attribute:: snmp_system_oid

        Example: ``.1.3.6.1.4.1.5596.180.6.4.1``

    .. py:attribute:: software_encryption

        Example: ``True``

    .. py:attribute:: software_id


    .. py:attribute:: target

        Example: ``True``

    .. py:attribute:: version_code

        Example: ``XA``

    .. py:attribute:: version_description

        Example: ``XA1.0PreAlpha1 (Test SW)``

    .. py:attribute:: version_maintenance

        Example: ``0``

    .. py:attribute:: version_major

        Example: ``1``

    .. py:attribute:: version_minor

        Example: ``0``

    .. py:attribute:: user_agent

        Example: Cisco-Application-Server/XA1.0

    """

    product_info_path = '/info/product_info.xml'
    release_key_path = '/tandberg/etc/rk'
    rkvfy_path = '/bin/rkvfy'
    serialno_re = re.compile('SERIALNO=(.+)$', re.MULTILINE)
    releasekey_re = re.compile('(\d+).*')

    def __init__(self):
        self.target = True
        self.product_name = ''
        self.version_code = ''
        self.version_major = ''
        self.version_minor = ''
        self.version_maintenance = ''
        self.version_description = ''
        self.release_type = ''
        self.release_version = ''
        self.snmp_system_oid = ''
        self.software_id = ''
        self.software_encryption = ''
        self.option_key_prefix = ''
        self.uses_installwizard = ''
        self.build_date = ''
        self.build_revision = ''
        self.build_type = ''
        self.build_user = ''
        self.network_interfaces = []
        self.release_key_raw = ''
        self.release_key = ''
        self.release_key_is_valid = False
        self._hardware_serial_number = None
        self.user_agent = ''
        self.is_hedge = False

        self._load_product_info(self.product_info_path)
        self.version_description = self._get_version_description()
        self.is_docker = self._is_docker()

    def _load_product_info(self, filename):
        """Load product info from xml file."""
        tree = ElementTree.parse(filename)
        self.product_name = tree.findtext('name')
        self.version_code = tree.findtext('code')
        self.version_major = tree.findtext('version/major')
        self.version_minor = tree.findtext('version/minor')
        self.version_maintenance = tree.findtext('version/maintenance')
        self.release_type = tree.findtext('version/release/type')
        self.release_version = tree.findtext('version/release/version')
        self.software_id = tree.findtext('software/id')
        self.software_encryption = tree.findtext('software/encryption')
        self.option_key_prefix = tree.findtext('software/option_prefix')
        self.uses_installwizard = tree.findtext('software/uses_installwizard')
        self.build_date = tree.findtext('build/date')
        self.build_revision = tree.findtext('build/revision')
        self.build_type = tree.findtext('build/type')
        self.build_user = tree.findtext('build/builder')
        self.snmp_system_oid = tree.findtext('snmp/system_oid')
        self.is_hedge = self.version_code == 'XH'

        self.network_interfaces = []
        for interface_element in tree.findall('hardware/network/interface'):
            try:
                self.network_interfaces.append({
                    'name' : interface_element.findtext('name'),
                    'device' : interface_element.findtext('device'),
                    })
                virtual_ifaces = int(interface_element.findtext('virtual_interfaces'))
                for index in range(0, virtual_ifaces):
                    self.network_interfaces.append({
                        'name' : interface_element.findtext('name'),
                        'device' : interface_element.findtext('device')  + ":" + str(index),
                        })
            except (TypeError, ValueError):
                # ignore malformed / missing (virtual) interfaces
                pass
        self.release_key = self._get_release_key()
        self.release_key_raw = self._get_raw_release_key()
        self.release_key_is_valid = self._is_release_key_valid()

        self.user_agent = self._get_user_agent()

    def _get_version_description(self):
        """Returns a string representation of the product version"""
        version_description = self.version_code + self.version_major + "." + self.version_minor

        # Omit the maintenance version if this is not a maintenance release
        if self.version_maintenance != '0':
            version_description += "." + self.version_maintenance

        # Omit the release type if this is an official release
        if self.release_type != 'Release':
            version_description += self.release_type + self.release_version

        # Omit the build type if this is an official release
        if self.build_type != 'Release':
            version_description += " (%s)" % self.build_type

        return version_description

    @staticmethod
    def _is_docker():
        """Detects if we are running inside a docker container."""
        cgroupinfo = ''.join(file('/proc/1/cgroup', 'r').readlines())
        return re.search(r'\b:/docker/\b', cgroupinfo)

    def _get_user_agent(self):
        """Returns a string to be used as User-Agent in HTTP requests"""
        maint = '' if self.version_maintenance == '0' else '.' + self.version_maintenance
        user_agent = '%s/%s%s.%s%s' % (self.product_name.replace(' ', '-'),
                self.version_code, self.version_major, self.version_minor, maint)
        return user_agent

    def _get_serial_number(self):
        """Returns the hardware serial number."""
        try:
            output, stderr = subprocess.Popen(["/sbin/serialno"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            match = self.serialno_re.search(output)
            if not match:
                DEV_LOGGER.error('Detail="Failed to read serial number: %s"' % stderr)
                return ''
            else:
                return match.group(1)
        except Exception:
            DEV_LOGGER.exception('Detail="Failed to read serial number"')
            return ''

    def _get_raw_release_key(self):
        """Returns the raw release key"""
        release_key = ''
        try:
            with open(self.release_key_path, 'r') as rkfile:
                release_key = rkfile.read()
        except IOError:
            # The release key file is optional on test builds so do not treat
            # this case as an error
            DEV_LOGGER.debug('Detail="Failed to read release key"')
        return release_key

    def _get_release_key(self):
        """Returns the release key. If the key is not in the valid format then
        return ''"""
        raw_release_key = self._get_raw_release_key()
        match = self.releasekey_re.search(raw_release_key)
        if match:
            return match.group(1)
        else:
            DEV_LOGGER.warn('Detail="Release key file invalid"')
            return ''

    def _is_release_key_valid(self):
        """Returns True if this is a test build _or_ if it's a release build and the release key is valid;
           returns False otherwise"""
        try:
            if os.path.exists(self.rkvfy_path):
                null = open("/dev/null", "w")
                retcode = subprocess.call([self.rkvfy_path, self.release_key], stderr=null, stdout=null)
                return (retcode == 0)
            else:
                # No rkvfy; this is a test build
                return True
        except Exception:
            DEV_LOGGER.exception('Detail="Failed to check serial number validity"')
            return False

    @property
    def hardware_serial_number(self):
        """Example: ``52A19557``"""

        # We only initialise the hardware serial number if it's really required.
        # Doing lazy initialisation allows apps that do not have the privelages
        # to run the serial no program access to the rest of productinfo.
        if not self._hardware_serial_number:
            self._hardware_serial_number = self._get_serial_number()
        return self._hardware_serial_number

def is_hedge():
    """
    Utility method to check if the node is a hedge
    """
    return PlatformInfo().is_hedge

def is_docker():
    """
    Utility method to check if the node is running inside a docker container
    """
    return PlatformInfo().is_docker

def is_ce1200():
    """
    Utility method to check if the box is of CE1200 hardware type.
    Currently CE1200 hardware serial number starts with 52E.
    """
    if PlatformInfo().hardware_serial_number.startswith("52") and PlatformInfo().version_code == "X":
        return PlatformInfo().hardware_serial_number[2] not in  ["A", "B", "C", "D"]
    return False

def uses_installwizard():
    '''
       Utility to check if the node makes use of install wizard
    '''
    return (PlatformInfo().uses_installwizard.lower() == "true")
