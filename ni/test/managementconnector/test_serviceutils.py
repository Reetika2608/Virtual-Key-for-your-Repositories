''' Test ServiceUtils Class '''

import unittest
import mock

from ni.managementconnector.service.service import Service
from ni.managementconnector.platform.serviceutils import ServiceUtils
from ni.managementconnector.config.config import Config
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


install_black_list = {}
current_version = "8.6-1.0.1"
previous_version = "8.6-1.0.0"
entitled_connectors = [{"name": "c_mgmt", "display_name": "Manamgent Connector"},
                       {"name": "c_cal", "display_name": "Calendar Connector"}]


def config_read_side_effect(arg, default=None):
    global install_black_list
    global entitled_connectors
    if arg == ManagementConnectorProperties.INSTALL_BLACK_LIST:
        return install_black_list
    elif arg == ManagementConnectorProperties.ENTITLED_SERVICES:
        return entitled_connectors


def config_write_side_effect(arg, txt):
    global install_black_list
    if arg == ManagementConnectorProperties.INSTALL_BLACK_LIST:
        install_black_list = txt


def get_tlp_filepath(directory, name):
    global current_version
    global previous_version

    ret_val = None

    if directory == ManagementConnectorProperties.INSTALL_CURRENT_DIR:
        ret_val = "{}/{}_{}.tlp".format(ManagementConnectorProperties.INSTALL_CURRENT_DIR, name, current_version)

    elif directory == ManagementConnectorProperties.INSTALL_PREVIOUS_DIR:
        ret_val = "{}/{}_{}.tlp".format(ManagementConnectorProperties.INSTALL_PREVIOUS_DIR, name, previous_version)

    return ret_val


class ServiceUtilsTest(unittest.TestCase):
    ''' ServiceUtils Test Class '''

    @mock.patch('ni.managementconnector.platform.serviceutils.jsonhandler')
    @mock.patch('ni.managementconnector.platform.serviceutils.CafeXUtils')
    def test_get_version(self, mock_cafeutils, mock_json):
        '''
         User Story: US6887 Dev: Connectors (excluding management c) are updatable from squared
         Purpose: Test get version from JSON when it's not installed.
         Steps:
            1. Mock out JSON read.
            2. Ensure we get a version from 'file' if installed is None.
         '''
        DEV_LOGGER.info('*** test_get_version ***')

        mock_cafeutils.get_package_version.return_value = '2.0'

        self.assertTrue(ServiceUtils.get_version('something') == '2.0')

        mock_cafeutils.get_package_version.return_value = None
        mock_json.read_json_file.return_value = {'something': 'installing', 'version': '3.0'}

        self.assertTrue(ServiceUtils.get_version('something') == '3.0')

    # -------------------------------------------------------------------------

    @mock.patch('ni.managementconnector.platform.serviceutils.os')
    @mock.patch('ni.managementconnector.platform.serviceutils.jsonhandler')
    def test_get_installing_state(self, mock_json, mock_path):
        '''
         User Story: US6887 Dev: Connectors (excluding management c) are updatable from squared
         Purpose: Test getting the installing state from JSON 'file'.
         Steps:
            1. Mock out JSON read.
            2. Ensure we installing state from 'file' is installing is None.
         '''

        mock_json.read_json_file.return_value = {'something': 'installing', 'version': '2.0'}
        mock_path.path.isfile.return_value = True

        self.assertTrue(ServiceUtils.is_installing('something') == 'installing')

    # -------------------------------------------------------------------------

    def test_blob_mode_on(self):
        ''' Test _blob_mode_on '''

        test1 = ServiceUtils.blob_mode_on('test1', {'test1': 'true', 'test2': 'false'})
        test2 = ServiceUtils.blob_mode_on('test2', {'test1': 'true', 'test2': 'false'})

        self.assertTrue(test1)
        self.assertFalse(test2)

    # -------------------------------------------------------------------------

    @mock.patch('ni.managementconnector.platform.serviceutils.ServiceUtils._delete_current_connector_tlp')
    @mock.patch('ni.managementconnector.platform.serviceutils.ServiceUtils._delete_previous_connector_tlp')
    @mock.patch('ni.managementconnector.platform.serviceutils.os')
    @mock.patch('ni.managementconnector.platform.serviceutils.CafeXUtils')
    @mock.patch('ni.managementconnector.platform.serviceutils.shutil')
    @mock.patch('ni.managementconnector.platform.serviceutils.ServiceUtils.get_previous_versions')
    @mock.patch('ni.managementconnector.platform.serviceutils.ServiceUtils.get_current_versions')
    def test_save_tlps_for_rollback(self, mock_get_current, mock_get_previous, mock_shutil, mock_xutils, mock_os, mock_del_pre_tlp, mock_del_cur_tlp):
        """
            User Story: DE1919 Connector Rollback not working in a Clustered Environment
            Purpose: To verify simplified rollback logic works as expected.
            Notes:
            Steps:
                1. Set up Mock and Return values
                2. Trigger Save off Tlp
                3. Assert as Expected.
        """

        # Step 1. Set Mock Side effect

        mock_config = MockConfig()
        mock_get_current.side_effect = StashedData.get_current
        mock_get_previous.side_effect = StashedData.get_previous

        cur_dir = ManagementConnectorProperties.INSTALL_CURRENT_DIR
        pre_dir = ManagementConnectorProperties.INSTALL_PREVIOUS_DIR

        # Starting from base version 0 in current.
        c_mgmt_0_version = "8.6-1.0.0"
        current = {"c_mgmt": {"version": c_mgmt_0_version, "url": "{}/{}.tlp".format(cur_dir, c_mgmt_0_version)}}
        previous = {}
        StashedData.set(current, previous)

        mock_config.write(ManagementConnectorProperties.INSTALL_BLACK_LIST, {})

        mock_xutils.get_package_version.return_value = "8.6-1.0.0"
        mock_os.isfile.return_value = True

        # Install 8.6-1.0.0 on top of itself. Expect 1 os.remove call
        # to remove the bogus tlp
        ServiceUtils.save_tlps_for_rollback(mock_config, "c_mgmt")
        self.assertEquals(mock_shutil.move.call_count, 0)
        self.assertEquals(mock_os.remove.call_count, 1)

        mock_shutil.move.reset_mock()
        mock_os.remove.reset_mock()

        mock_xutils.get_package_version.return_value = "8.6-1.0.1"

        # Install 8.6-1.0.1. Expect 1 call to delete previous and
        # two call to shutil.move to cycle the TLPs
        ServiceUtils.save_tlps_for_rollback(mock_config, "c_mgmt")
        self.assertEquals(mock_shutil.move.call_count, 2)
        self.assertEquals(mock_del_pre_tlp.call_count, 1)

        mock_shutil.move.reset_mock()
        mock_del_pre_tlp.reset_mock()

        mock_xutils.get_package_version.return_value = "8.6-1.0.2"

        c_mgmt_1_version = "8.6-1.0.1"
        current = {"c_mgmt": {"version": c_mgmt_1_version, "url": "{}/{}.tlp".format(cur_dir, c_mgmt_1_version)}}
        previous = {"c_mgmt": {"version": c_mgmt_0_version, "url": "{}/{}.tlp".format(pre_dir, c_mgmt_0_version)}}
        StashedData.set(current, previous)

        # Install 8.6-1.0.2 when we already have current and previous.
        # Expect 1 call to delete previous and two call to shutil.move
        # to cycle the TLPs
        ServiceUtils.save_tlps_for_rollback(mock_config, "c_mgmt")
        self.assertEquals(mock_shutil.move.call_count, 2)
        self.assertEquals(mock_del_pre_tlp.call_count, 1)

        mock_shutil.move.reset_mock()
        mock_del_pre_tlp.reset_mock()

        black_list = {"c_mgmt": {"url": "current/c_mgmt_8.6-1.0.1.tlp", "version": "8.6-1.0.1"}}
        mock_config.write(ManagementConnectorProperties.INSTALL_BLACK_LIST, black_list)
        mock_xutils.get_package_version.return_value = "8.6-1.0.0"

        # Blacklist 8.6-1.0.1 and make 8.6-1.0.0 the newly
        # installed version(the standard rollback scenario). Expect
        # 1 call to delete current tlp and 1 call to shutil.move
        # to put the new tlp into current.
        ServiceUtils.save_tlps_for_rollback(mock_config, "c_mgmt")
        self.assertEquals(mock_shutil.move.call_count, 1)
        self.assertEquals(mock_del_cur_tlp.call_count, 1)

    # -------------------------------------------------------------------------

    def test_remove_exclude_paths(self):
        """
             User Story: DE1846: Snapshot CDB on upgrade and reapply on rollback breaks rollback logic
             Purpose: Test remove exclude paths from rollback snapshot data. Used before writing file.
             Steps:
                1. Test table1 remove
                2. Test 2 tables removed
                3. Test "None" exclude
                4. Test "None" data
            Notes:
        """

        # Step 1.
        data = {"table1": {"path1": "value"}, "table2": {"path1": "value"}}
        exclude_list = {"table1": {"path1"}}
        expected = {"table1": {}, "table2": {"path1": "value"}}

        ServiceUtils.remove_exclude_paths(data, exclude_list)

        self.assertEqual(expected, data)

        # Step 2.

        data = {"table1": {"path1": "value"}, "table2": {"path1": "value"}}
        exclude_list = {"table1": {"path1"}, "table2": {"path1"}}
        expected = {"table1": {}, "table2": {}}

        ServiceUtils.remove_exclude_paths(data, exclude_list)

        self.assertEqual(expected, data)

        # Step 3.

        data = {"table1": {"path1": "value"}, "table2": {"path1": "value"}}
        exclude_list = None
        expected = {"table1": {"path1": "value"}, "table2": {"path1": "value"}}

        ServiceUtils.remove_exclude_paths(data, exclude_list)

        self.assertEqual(expected, data)

        # Step 4.

        data = None
        exclude_list = {"table1": {"path1"}, "table2": {"path1"}}
        expected = None

        ServiceUtils.remove_exclude_paths(data, exclude_list)

        self.assertEqual(expected, data)

    # -------------------------------------------------------------------------

    @mock.patch('ni.managementconnector.platform.serviceutils.System.get_tlp_filepath')
    def test_get_version_information(self, get_file_path):
        """
            User Story: DE1919: Connector Rollback not working in a Clustered Environment
            Purpose: get_version_information - Verify version information is retrieved as expected..
            Steps:
                1. Set up expected and entitled information
                2. Get previous & current
                3. Ensure expected == actual
            Notes: Used when reading current/previous tlp versions
        """
        get_file_path.side_effect = get_tlp_filepath

        entitled_services = [{"display_name": "Calendar Connector", "name": "c_cal"},
                             {"display_name": "Management Connector", "name": "c_mgmt"}]

        global current_version
        global previous_version

        # Step 1
        current_c_mgmt = "{}/c_mgmt_{}.tlp".format(ManagementConnectorProperties.INSTALL_CURRENT_DIR, current_version)
        previous_c_mgmt = "{}/c_mgmt_{}.tlp".format(ManagementConnectorProperties.INSTALL_PREVIOUS_DIR, previous_version)
        current_c_cal = "{}/c_cal_{}.tlp".format(ManagementConnectorProperties.INSTALL_CURRENT_DIR, current_version)
        previous_c_cal = "{}/c_cal_{}.tlp".format(ManagementConnectorProperties.INSTALL_PREVIOUS_DIR, previous_version)

        expected_current = {"c_mgmt": {"url": current_c_mgmt, "version": current_version},
                            "c_cal": {"url": current_c_cal, "version": current_version}}

        expected_previous = {"c_mgmt": {"url": previous_c_mgmt, "version": previous_version},
                             "c_cal": {"url": previous_c_cal, "version": previous_version}}

        mock_config = MockConfig()
        mock_config.write(ManagementConnectorProperties.ENTITLED_SERVICES, entitled_services)
        mock_entitled_services = mock_config.read(ManagementConnectorProperties.ENTITLED_SERVICES)

        DEV_LOGGER.info("*** test_get_version_information - mock entitled: %s ***" % mock_entitled_services)

        # Step 2
        previous = ServiceUtils.get_previous_versions(mock_config)
        current = ServiceUtils.get_current_versions(mock_config)

        # Step 3
        self.assertEquals(previous, expected_previous)
        self.assertEquals(current, expected_current)

    @mock.patch('ni.managementconnector.platform.serviceutils.ServiceUtils._delete_previous_connector_tlp')
    @mock.patch('ni.managementconnector.platform.serviceutils.ServiceUtils._delete_current_connector_tlp')
    @mock.patch('ni.managementconnector.platform.serviceutils.shutil')
    def test_process_tlps(self, mock_shutil, mock_delete_current, mock_delete_previous):
        """ Test TLP Process for Rollback """

        name = "c_cal"
        tlp_path = "%s/%s_%s.tlp"
        current_1 = {"url": tlp_path % (ManagementConnectorProperties.INSTALL_CURRENT_DIR, name, "1"), "version": "1"}
        current_2 = {"url": tlp_path % (ManagementConnectorProperties.INSTALL_CURRENT_DIR, name, "2"), "version": "2"}
        current_3 = {"url": tlp_path % (ManagementConnectorProperties.INSTALL_CURRENT_DIR, name, "3"), "version": "3"}
        previous_1 = {"url": tlp_path % (ManagementConnectorProperties.INSTALL_PREVIOUS_DIR, name, "1"), "version": "1"}
        previous_2 = {"url": tlp_path % (ManagementConnectorProperties.INSTALL_PREVIOUS_DIR, name, "2"), "version": "2"}

        # Data matrix: Six scenarios of input and expected output of TLP state.
        #################################################################################################################
        #   Scenario   #   Pre-previous   #   Pre-current   #   Just-installed   #   Post-previous   #   Post-current   #
        #################################################################################################################
        #       1      #        -                 -                   v1                   -                  v1        #
        #       2      #        -                 v1                  v1                   -                  v1        #
        #       3      #        -                 v1                  v2                   v1                 v2        #
        #       4      #        -                 v1                  v3                   v1                 v3        #
        #       5      #        v1                v2                  v3                   v2                 v3        #
        #       6      #        v1                v2                  v2                   v1                 v2        #
        #################################################################################################################

        data = [{"previous": None, "current": None,             "installed": "1"},  # Scenario 1 input data
                {"previous": None, "current": current_1,        "installed": "1"},  # Scenario 2 input data
                {"previous": None, "current": current_1,        "installed": "2"},  # Scenario 3 input data
                {"previous": None, "current": current_1,        "installed": "3"},  # Scenario 4 input data
                {"previous": previous_1, "current": current_2,  "installed": "3"},  # Scenario 5 input data
                {"previous": previous_1, "current": current_2,  "installed": "2"}]  # Scenario 6 input data

        expected = [({},            current_1),  # Scenario 1 expected output
                    ({},            current_1),  # Scenario 2 expected output
                    (previous_1,    current_2),  # Scenario 3 expected output
                    (previous_1,    current_3),  # Scenario 4 expected output
                    (previous_2,    current_3),  # Scenario 5 expected output
                    (previous_1,    current_2)]  # Scenario 6 expected output
        actual = list()

        for scenario in data:
            actual.append(ServiceUtils._process_tlps(name, scenario['previous'], scenario['current'], scenario['installed']))

        i = 1
        for x, y in zip(actual, expected):
            self.assertEquals(x, y, "Actual: %s did not match Expected: %s... Scenario: %d" % (x, y, i))
            i = i + 1

    def test_connector_version_compare(self):
        """
            assert compare("8.6-1.0.318454", "8.6-1.0.318968") < 0
            assert compare("8.6-1.0.318968", "8.6-1.0.318968") == 0
            assert compare("8.6-1.0.318999", "8.6-1.0.318968") > 0
        """
        # Test Revision
        self.assertEquals(-1, ServiceUtils.version_number_compare("8.6-1.0.318454", "8.6-1.0.318968"))
        self.assertEquals(0, ServiceUtils.version_number_compare("8.6-1.0.318968", "8.6-1.0.318968"))
        self.assertEquals(1, ServiceUtils.version_number_compare("8.6-1.0.318999", "8.6-1.0.318968"))

        # Test Minor
        self.assertEquals(-1, ServiceUtils.version_number_compare("8.6-1.0.318968", "8.6-1.1.318968"))
        self.assertEquals(1, ServiceUtils.version_number_compare("8.6-1.1.318968", "8.6-1.0.318968"))

        # Test Major
        self.assertEquals(-1, ServiceUtils.version_number_compare("8.6-1.0.318968", "8.6-2.0.318968"))
        self.assertEquals(1, ServiceUtils.version_number_compare("8.6-2.0.318968", "8.6-1.0.318968"))

    @mock.patch('ni.managementconnector.service.service.Service.get_suppressed_alarms')
    @mock.patch('ni.managementconnector.service.service.Service.get_alarms')
    def test_get_suppressed_alarms(self, mock_alarms, mock_suppressed):
        """
        User Story: US16897: FMC: Use FMC's manifest file to suppress unactionable alarms
        Purpose: Ensure certain alarms are not posted to FMS.
        Steps:
        1. Get list of alarms raised alarms.
        2. Verify that only suppressed alarms are included.
        Notes:
        """

        alarm1 = {'first_reported': '1417011612',
                  'id': '60051',
                  'last_reported': '1417011811',
                  'parameters': [500, 'https://hercules.hitest.huron-dev.com/v1/connectors'],
                  'severity': 'error',
                  'solution_links': '',
                  'uuid': 'cbbf0813-09cb-4e23-9182-f3996d24cc9e'}

        alarm1_formatted = {'first_reported': '2014-11-26T14:20:12',
                            'description': u'HTTP error code 500 from Cisco Collaboration Cloud (address: https://hercules.hitest.huron-dev.com/v1/connectors)',
                            'title': u'[Hybrid services] Communication error',
                            'last_reported': '2014-11-26T14:23:31',
                            'solution': u'Check Hybrid Services status on the VCS-C. Check status.ciscospark.com '
                                        u'for outages. If the error remains, go to admin.ciscospark.com, click your'
                                        u' admin username, and then click Feedback to open a case for '
                                        u'further investigation.',
                            'id': '60051',
                            'solution_replacement_values': [],
                            'severity': 'error'}

        alarm2 = {'first_reported': '1417011612',
                  'id': '60058',
                  'last_reported': '1417011811',
                  'parameters': ['https://hercules.hitest.huron-dev.com/v1/connectors'],
                  'severity': 'error',
                  'solution_links': 'trustedcacertificate',
                  'uuid': '635afce6-0ae8-4b84-90f5-837a2234002b'}

        mock_suppressed.return_value = ["60050", "60051", "60053", "60054", "60062",
                                        "60063", "60065", "60066", "60070"]

        service = Service('c_mgmt', Config(), None)
        mock_alarms.return_value = []

        # test no suppressed alarms are raised
        expected = []
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=False, include_suppressed=True))

        # test one suppressed alarm is raised
        mock_alarms.return_value = [alarm1]
        expected = [alarm1_formatted]
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=False, include_suppressed=True))

        # test multiple alarms raised
        mock_alarms.return_value = [alarm1, alarm2]
        expected = [alarm1_formatted]
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=False, include_suppressed=True))

    @mock.patch('ni.managementconnector.service.service.Service.get_suppressed_alarms')
    @mock.patch('ni.managementconnector.service.service.Service.get_alarms')
    def test_get_only_permitted_alarms(self, mock_alarms, mock_suppressed):
        """
        User Story: US16897: FMC: Use FMC's manifest file to suppress unactionable alarms
        Purpose: Ensure certain alarms are not posted to FMS.
        Steps:
        1. Get list of alarms raised alarms.
        2. Verify that suppressed alarms are not included.
        Notes:
        """

        alarm1 = {'first_reported': '1417011612',
                  'id': '60051',
                  'last_reported': '1417011811',
                  'parameters': [500, 'https://hercules.hitest.huron-dev.com/v1/connectors'],
                  'severity': 'error',
                  'solution_links': '',
                  'uuid': 'cbbf0813-09cb-4e23-9182-f3996d24cc9e'}

        alarm2 = {'first_reported': '1417011612',
                  'id': '60058',
                  'last_reported': '1417011811',
                  'parameters': ['https://hercules.hitest.huron-dev.com/v1/connectors'],
                  'severity': 'error',
                  'solution_links': 'trustedcacertificate',
                  'uuid': '635afce6-0ae8-4b84-90f5-837a2234002b'}

        alarm2_formatted = {'first_reported': '2014-11-26T14:20:12',
                            'description': u"Cannot securely connect to the Cisco Collaboration Cloud because the root CA that signed the certificate from https://hercules.hitest.huron-dev.com/v1/connectors is not in the VCS's trusted CA list.",
                            'title': u'[Hybrid services] Connection failed because the CA certificate was not found',
                            'last_reported': '2014-11-26T14:23:31',
                            'solution': '%s',
                            'id': '60058',
                            'solution_replacement_values': [
                                {'text': u"Update the VCS's trusted CA list to include the CA that signed the received certificate.",
                                 'link': 'httptrustedcacertificate'}
                            ],
                            'severity': 'error'}

        mock_suppressed.return_value = ["60050", "60051", "60053", "60054", "60062",
                                        "60063", "60065", "60066", "60070"]
        service = Service('c_mgmt', Config(), None)
        mock_alarms.return_value = []

        # test no suppressed alarms are raised
        expected = []
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=True, include_suppressed=False))

        # test only suppressed alarm is raised
        mock_alarms.return_value = [alarm1]
        expected = []
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=True, include_suppressed=False))

        # test no suppressed alarms are raised
        mock_alarms.return_value = [alarm1, alarm2]
        expected = [alarm2_formatted]
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=True, include_suppressed=False))

    @mock.patch('ni.managementconnector.service.service.Service.get_suppressed_alarms')
    @mock.patch('ni.managementconnector.service.service.Service.get_alarms')
    def test_get_all_alarms(self, mock_alarms, mock_suppressed):
        """
        User Story: US16897: FMC: Use FMC's manifest file to suppress unactionable alarms
        Purpose: Ensure certain alarms are not posted to FMS.
        Steps:
        1. Get list of alarms raised alarms.
        2. Verify that suppressed alarms are not included.
        Notes:
        """

        alarm1 = {'first_reported': '1417011612',
                  'id': '60051',
                  'last_reported': '1417011811',
                  'parameters': [500, 'https://hercules.hitest.huron-dev.com/v1/connectors'],
                  'severity': 'error',
                  'solution_links': '',
                  'uuid': 'cbbf0813-09cb-4e23-9182-f3996d24cc9e'}

        alarm1_formatted = {'first_reported': '2014-11-26T14:20:12',
                            'description': u'HTTP error code 500 from Cisco Collaboration Cloud (address: https://hercules.hitest.huron-dev.com/v1/connectors)',
                            'title': u'[Hybrid services] Communication error',
                            'last_reported': '2014-11-26T14:23:31',
                            'solution': u'Check Hybrid Services status on the VCS-C. Check status.ciscospark.com '
                                        u'for outages. If the error remains, go to admin.ciscospark.com, click your '
                                        u'admin username, and then click Feedback to open a case '
                                        u'for further investigation.',
                            'id': '60051',
                            'solution_replacement_values': [],
                            'severity': 'error'}

        alarm2 = {'first_reported': '1417011612',
                  'id': '60058',
                  'last_reported': '1417011811',
                  'parameters': ['https://hercules.hitest.huron-dev.com/v1/connectors'],
                  'severity': 'error',
                  'solution_links': 'trustedcacertificate',
                  'uuid': '635afce6-0ae8-4b84-90f5-837a2234002b'}

        alarm2_formatted = {'first_reported': '2014-11-26T14:20:12',
                            'description': u"Cannot securely connect to the Cisco Collaboration Cloud because the root CA that signed the certificate from https://hercules.hitest.huron-dev.com/v1/connectors is not in the VCS's trusted CA list.", 'title': u'[Hybrid services] Connection failed because the CA certificate was not found', 'last_reported': '2014-11-26T14:23:31', 'solution': '%s', 'id': '60058',
                            'solution_replacement_values': [
                                {'text': u"Update the VCS's trusted CA list to include the CA that signed the received certificate.",
                                 'link': 'httptrustedcacertificate'}
                            ],
                            'severity': 'error'}

        mock_suppressed.return_value = ["60050", "60051", "60053", "60054", "60062",
                                        "60063", "60065", "60066", "60070"]
        service = Service('c_mgmt', Config(), None)
        mock_alarms.return_value = []

        # test no alarms are raised
        expected = []
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=True, include_suppressed=True))

        # test only suppressed alarm is raised
        mock_alarms.return_value = [alarm1]
        expected = [alarm1_formatted]
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=True, include_suppressed=True))

        # test only unsuppressed alarm is raised
        mock_alarms.return_value = [alarm2]
        expected = [alarm2_formatted]
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=True, include_suppressed=True))

        # test both permitted and suppressed alarms are raised
        mock_alarms.return_value = [alarm1, alarm2]
        expected = [alarm1_formatted, alarm2_formatted]
        self.assertEquals(expected, ServiceUtils.get_alarms(service, "http", permitted=True, include_suppressed=True))

    def test_is_supported_extension(self):
        """
        User Story: DE2502: c_mgmt: add check & log of connector downloaded to /mnt/harddisk/persistent/fusion/downloads
        Purpose: Ensure only supported connector types can be installed
        Steps:
        1. Verify supported package type.
        2. Verify unsupported package type.
        Notes:
        """

        url1 = 'https://www.abc.com/connector.tlp'
        url2 = 'https://www.abc.com/connector.abc'

        # test supported package type
        self.assertTrue(ServiceUtils.is_supported_extension(url1), "Unsupported file package incorrecly disallowed")

        # test supported package type
        self.assertFalse(ServiceUtils.is_supported_extension(url2), "Unsupported file package incorrecly allowed")

    def test_cdb_configured_is_set_true(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure you can determine between cdb set and .configured file set
        Steps:
        1. Verify when CDB value has true, returns true
        Notes:
        """
        mock_config = mock.Mock()
        mock_config.read.return_value = {"c_cal": "true", "c_something": "false"}
        self.assertEquals(ServiceUtils.get_configured_via_cdb_entry(mock_config, "c_cal"), "true",
                          msg="CDB entry should have a string of true")
        mock_config.read.assert_called_once_with("system_configuredServicesState")

    def test_cdb_configured_is_set_false(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure you can determine between cdb set and .configured file set
        Steps:
        1. Verify when CDB value exists returns value false
        Notes:
        """
        mock_config = mock.Mock()
        mock_config.read.return_value = {"c_cal": "false", "c_something": "false"}
        self.assertEquals(ServiceUtils.get_configured_via_cdb_entry(mock_config, "c_cal"), "false")
        mock_config.read.assert_called_once_with("system_configuredServicesState")

    def test_cdb_configured_is_not_set(self):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure you can determine between cdb set and .configured file set
        Steps:
        1. Verify when CDB value doesn't exist return nothing/none
        Notes:
        """
        mock_config = mock.Mock()
        mock_config.read.return_value = {}
        self.assertEquals(ServiceUtils.get_configured_via_cdb_entry(mock_config, "c_cal"), None)
        mock_config.read.assert_called_once_with("system_configuredServicesState")

    @mock.patch('ni.managementconnector.platform.serviceutils.os')
    def test_is_configured_status_cdb_true(self, mock_os):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure you can determine between cdb set and .configured file set
        Steps:
        1. Verify when CDB value doesn't exist return nothing/none
        Notes:
        """
        mock_config = mock.Mock()
        mock_config.read.return_value = {"c_cal": "true", "c_something": "false"}
        self.assertTrue(ServiceUtils.is_configured_status(mock_config, "c_cal"),
                        msg="cdb value should end up as boolean True")
        mock_config.read.assert_called_once_with("system_configuredServicesState")

    @mock.patch('ni.managementconnector.platform.serviceutils.os')
    def test_is_configured_status_cdb_false(self, mock_os):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure you can determine between cdb set and .configured file set
        Steps:
        1. Verify when CDB value doesn't exist return nothing/none
        Notes:
        """
        mock_config = mock.Mock()
        mock_config.read.return_value = {"c_cal": "false", "c_something": "false"}
        self.assertFalse(ServiceUtils.is_configured_status(mock_config, "c_cal"),
                         msg="cdb value should end up as boolean False")
        mock_config.read.assert_called_once_with("system_configuredServicesState")

    @mock.patch('ni.managementconnector.platform.serviceutils.os')
    def test_is_configured_status_file_system_true(self, mock_os):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure you can determine between cdb set and .configured file set
        Steps:
        1. Verify when CDB value doesn't exist return nothing/none
        Notes:
        """
        mock_config = mock.Mock()
        mock_config.read.return_value = {}
        mock_os.path.exists.return_value = True
        self.assertTrue(ServiceUtils.is_configured_status(mock_config, "c_cal"),
                        msg="filesystem value should be true")
        mock_config.read.assert_called_once_with("system_configuredServicesState")

    @mock.patch('ni.managementconnector.platform.serviceutils.os')
    def test_is_configured_status_file_system_true_when_config_returns_none(self, mock_os):
        """
        User Story: US25227: FMC: Support new CDB configured state
        Purpose: Ensure you can determine between cdb set and .configured file set
        Steps:
        1. Verify when CDB value doesn't exist return nothing/none
        Notes:
        """
        mock_config = mock.Mock()
        mock_config.read.return_value = None
        mock_os.path.exists.return_value = True
        self.assertTrue(ServiceUtils.is_configured_status(mock_config, "c_cal"),
                        msg="filesystem value should be true")
        mock_config.read.assert_called_once_with("system_configuredServicesState")


class MockConfig():
    """ Mock Config Class """

    def __init__(self):
        self.config = {}

    def write(self, path, content):
        """ Write config to database """
        self.config[path] = content

    def read(self, path, default=None):
        """ Read config from """
        return self.config[path]


class StashedData(object):

    current = {}
    previous = {}

    @classmethod
    def get_current(cls, config):
        """ Write config to database """
        return cls.current

    @classmethod
    def get_previous(cls, config):
        """ Read config from """
        return cls.previous

    @classmethod
    def set(cls, current, previous):
        cls.current = current
        cls.previous = previous
