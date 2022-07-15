import unittest
import logging
import mock
import sys
from io import StringIO
from pyfakefs import fake_filesystem_unittest
from .productxml import PRODUCT_XML_CONTENTS
from .constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.platform.system import System
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class ManagementConnectorTest(fake_filesystem_unittest.TestCase):

    ''' Management Connector Test Class '''

    def setUp(self):
        ''' Manamgent Connector System Test Setup '''

        DEV_LOGGER.debug('***TEST Setup***')
        self._system = System()
        assert self._system is not None

    @mock.patch('builtins.open')
    def test_management_connector_system_memory(self, mock_file):
        ''' Test Management Connector System memory '''

        DEV_LOGGER.debug('***TEST*** test_management_connector_system_memory')
        mock_file.return_value = StringIO("cpu 123\ncpu 123\ncpu 123")
        system_memory = System.get_system_mem()

        DEV_LOGGER.debug(system_memory)
        self.assertNotEqual(system_memory['total_kb'], 0)
        self.assertNotEqual(system_memory['percent'], '')
        self.assertNotEqual(system_memory['total_gb'], '')

    @mock.patch('builtins.open')
    def test_management_connector_system_cpu_time(self, mock_file):
        ''' Test Management Connector System cpu '''

        DEV_LOGGER.debug('***TEST*** test_management_connector_system_cpu_time')
        mock_file.return_value = StringIO("cpu 123\ncpu 123\ncpu 123")
        cpu_time = System.get_system_cpu_time()

        DEV_LOGGER.debug(cpu_time)

        self.assertNotEqual(cpu_time, 0)

    @mock.patch('builtins.open')
    def test_management_connector_get_system_cpu(self, mock_file):
        DEV_LOGGER.debug('***TEST*** test_management_connector_get_system_cpu')

        mock_file.return_value = StringIO("cpu 123\ncpu 123\ncpu 123")

        system_cpu = self._system.get_system_cpu_time()
        DEV_LOGGER.debug(system_cpu)

        self.assertNotEqual(system_cpu, 0)

    def test_version_from_filename(self):
        """
            User Story: DE1919: Connector Rollback not working in a Clustered Environment
            Purpose: test_version_from_filename - To verify version is extracted from file path correctly.
            Notes: Used when reading current/previous tlp versions from file path
        """
        DEV_LOGGER.debug('***TEST*** test_version_from_filename')

        # example = {"path": "expected"}
        examples = {"/mnt/harddisk/persistent/fusion/previousversions/c_mgmt_8.6-1.0.318200.tlp": "8.6-1.0.318200",
                    "/mnt/harddisk/persistent/fusion/currentversions/c_mgmt_8.6-1.0.318200.tlp": "8.6-1.0.318200",
                    "c_mgmt_8.6-1.0.318999.tlp": "8.6-1.0.318999",
                    "c_mgmt.tlp": None,
                    "": None}

        for path, expected in examples.items():
            version = System.get_version_from_file(path)
            self.assertEqual(version, expected)

    @mock.patch('managementconnector.platform.system.get_expressway_version')
    def test_unsupported_version_status(self, mock_get_expressway_version):
        """
            User Story: US13965: Alert the Admin in case of unsupported version
            Purpose: To verify Expressway version is not unsupported version.
        """

        DEV_LOGGER.debug('***TEST*** test_unsupported_version_status')

        mock_get_expressway_version.return_value = "12.5"
        self.assertTrue(System.get_platform_supported_status())

        mock_get_expressway_version.return_value = "12.4"
        self.assertFalse(System.get_platform_supported_status())

        mock_get_expressway_version.return_value = "14.0"
        self.assertTrue(System.get_platform_supported_status())

    @mock.patch('managementconnector.platform.system.get_expressway_version')
    def test_penultimate_unsupported_version_status(self, mock_get_expressway_version):
        """
            User Story: US23713: Alert the Admin in case of version soon to be unsupported
            Purpose: To verify Expressway version w.r.t minimum Expressway supported version.
        """

        DEV_LOGGER.debug('***TEST*** test_penultimate_unsupported_version_status')

        mock_get_expressway_version.return_value = "12.5"
        self.assertTrue(System.is_penultimate_version())

        mock_get_expressway_version.return_value = "12.0"
        self.assertFalse(System.is_penultimate_version())

        mock_get_expressway_version.return_value = "14.0"
        self.assertFalse(System.is_penultimate_version())

    @mock.patch('builtins.open', create=True)
    def test_get_platform_type(self, mock_file):
        DEV_LOGGER.debug('***TEST*** test_get_platform_type')

        # virtual machine
        mock.mock_open(mock_file, read_data='hypervisor')
        self.assertEqual("virtual", System.get_platform_type())

        # physical machine
        mock.mock_open(mock_file, read_data='')
        self.assertEqual("physical", System.get_platform_type())

        # error
        mock_file.side_effect = IOError()
        self.assertEqual(None, System.get_platform_type())

    @mock.patch('subprocess.check_output')
    def test_get_cpu_cores(self, mock_sub):
        DEV_LOGGER.debug('***TEST*** test_get_cpu_cores')
        mock_sub.return_value = "2\n".encode('UTF-8')
        res = System.get_cpu_cores()
        cmd = ["nproc", "--all"]
        mock_sub.assert_called_with(cmd)
        self.assertEqual("2", res)

    @mock.patch('subprocess.check_output')
    def test_get_system_disk(self, mock_sub):
        DEV_LOGGER.debug('***TEST*** test_get_system_disk')
        mock_sub.return_value = 'Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda5         960840  625688    285512  69% /\ndevtmpfs         3049708       0   3049708   0% /dev\nnone             3052088     252   3051836   1% /run\n/dev/ram0         193687    2995    180692   2% /var\n/dev/loop20      1470176   18595   1376879   2% /tmp\n/dev/sda7         960840  161936    749264  18% /tandberg\n/dev/sdb2      121657444 9149632 106321316   8% /mnt/harddisk\ntotal          131344783 9959098 115015207   8% -\n'.encode('UTF-8')
        cmd = ["df", "--total"]
        res = System.get_system_disk()
        mock_sub.assert_called_with(cmd)
        self.assertEqual({'total_gb': '0.1', 'percent': '8.0', 'total_kb': 128266.3896484375}, res)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
