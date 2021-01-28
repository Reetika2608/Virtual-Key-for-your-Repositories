""" Metrics Test """




import sys
import mock
import json
import unittest
import logging
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud.metrics import Metrics

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
HEADERS = {'Content-Type': 'application/json'}
CURRENT_TIME = 'current_time'
CERT_MANAGED = ''

def get_current_time(unused):
    return CURRENT_TIME




class MetricsTest(unittest.TestCase):
    maxDiff = None
    def setUp(self):
        """ setUp """
        self.oauth = mock.Mock()
        self.oauth.oauth_response = json.loads('{"access_token" : "aaa"}')

    def config_read(self, path):
        """ config class mock """
        DEV_LOGGER.debug("ConfigMock: read path %s" % path)
        global CERT_MANAGED

        if path == ManagementConnectorProperties.METRICS_HOST:
            return "metrics_host/"
        if path == ManagementConnectorProperties.METRICS_URL:
            return "metrics_url"
        elif path == ManagementConnectorProperties.VERSION:
            return "vcs_version"
        elif path == ManagementConnectorProperties.SERIAL_NUMBER:
            return "serialnumber"
        elif path == ManagementConnectorProperties.TARGET_TYPE:
            return "service_name"
        elif path == ManagementConnectorProperties.METRICS_ENABLED:
            return "true"
        elif path == ManagementConnectorProperties.METRICS_TESTMODE:
            return "metrics_testmode"
        elif path == ManagementConnectorProperties.IPV4_ADDRESS:
            return "ipv4_address"
        elif path == ManagementConnectorProperties.IPV6_ADDRESS:
            return "ipv6_address"
        elif path == ManagementConnectorProperties.CLUSTER_ID:
            return "guid"
        elif path == ManagementConnectorProperties.CLUSTER_NAME:
            return "clustername"
        elif path == ManagementConnectorProperties.HOSTNAME:
            return "hostname"
        elif path == ManagementConnectorProperties.METRICS_UA:
            return "user_agent"
        elif path == ManagementConnectorProperties.DOMAINNAME:
            return "domain.com"
        elif path == ManagementConnectorProperties.ALARMS_RAISED:
            rtn_str = '[{ "uuid" : "cbbf0813-09cb-4e23-9182-f3996d24cc9e", "id" : "60051", ' \
                    '"first_reported" :  "1417011612", "last_reported" :  "1417011811", "severity" :  "error", ' \
                    '"parameters":  [500, "https://hercules.hitest.huron-dev.com/v1/connectors"] }]'
            return json.loads(rtn_str)
        elif path == ManagementConnectorProperties.ADD_FUSION_CERTS:
            return CERT_MANAGED
        else:
            DEV_LOGGER.debug("ConfigMock: Unexpected path passed: %s" % path)


    """ Management Connector Metric Test Class """

    @mock.patch('managementconnector.cloud.metrics.Http')
    @mock.patch('managementconnector.service.service.Service')
    @mock.patch('managementconnector.cloud.metrics.ServiceUtils')
    @mock.patch('managementconnector.cloud.metrics.ManagementConnectorProperties.get_utc_time', side_effect=get_current_time)
    def test_send_metrics_accountexpiration(self, mock_time, mock_utils, mock_service, mock_http):
        """ test_send_metrics_accountexpiration"""

        DEV_LOGGER.info('test_send_metrics_accountexpiration: start')

        config = mock.MagicMock()
        config.read.side_effect = self.config_read

        mock_utils.get_version.return_value = 'service_version'
        mock_utils.get_connector_status.return_value = 'on'
        mock_utils.get_service_start_time.return_value = 'on'
        mock_utils.get_current_versions.return_value = {"service_name": {"url": "some_current_path", "version": "service_version"}}
        mock_utils.get_previous_versions.return_value = {"service_name": {"url": "some_previous_path", "version": "service_version"}}

        mock_service.get_name.return_value = 'c_mgmt'
        mock_service.get_composed_status.return_value = 'running'
        mock_service.get_service_metrics.return_value = ('10', '10')

        metrics = Metrics(config, self.oauth)

        metrics.send_metrics(HEADERS, mock_service)

        # Returns a list of tuples with call arguments
        called_with = mock_http.post.call_args
        json_value_str = json.dumps(called_with[0][2])
        self.assertFalse("accountExpiration" in json_value_str, "Should not contain accountExpiration Field")

        self.oauth.oauth_response = json.loads('{"access_token" : "aaa", "accountExpiration" : 272}')

        metrics.send_metrics(HEADERS, mock_service)
        called_with = mock_http.post.call_args
        json_value_str = json.dumps(called_with[0][2])
        self.assertTrue("accountExpiration" in json_value_str, "Should contain accountExpiration Field")

        mock_service.get_name.return_value = 'some_service'
        metrics.send_metrics(HEADERS, mock_service)
        called_with = mock_http.post.call_args
        json_value_str = json.dumps(called_with[0][2])
        self.assertFalse("accountExpiration" in json_value_str, "Should not contain accountExpiration Field")


        DEV_LOGGER.info('test_send_metrics_accountexpiration: end')



    @mock.patch('managementconnector.cloud.metrics.Http')
    @mock.patch('managementconnector.service.service.Service')
    @mock.patch('managementconnector.cloud.metrics.ServiceUtils')
    @mock.patch('managementconnector.cloud.metrics.ManagementConnectorProperties.get_utc_time', side_effect=get_current_time)
    def test_send_metrics(self, mock_time, mock_utils, mock_service, mock_http):
        """ Send Metrics"""

        DEV_LOGGER.info('test_send_metrics: start')

        config = mock.MagicMock()
        config.read.side_effect = self.config_read

        mock_utils.get_version.return_value = 'service_version'
        mock_utils.get_connector_status.return_value = 'on'
        mock_utils.get_service_start_time.return_value = 'on'
        mock_utils.get_current_versions.return_value = {"service_name": {"url": "some_current_path", "version": "service_version"}}
        mock_utils.get_previous_versions.return_value = {"service_name": {"url": "some_previous_path", "version": "service_version"}}

        mock_service.get_name.return_value = 'service_name'
        mock_service.get_composed_status.return_value = 'running'
        mock_service.get_service_metrics.return_value = ('10', '10')

        alarm_list_str = '[{ "uuid" : "cbbf0813-09cb-4e23-9182-f3996d24cc9e", "id" : "60051", ' \
                    '"first_reported" :  "1417011612", "last_reported" :  "1417011811", "severity" :  "error", ' \
                    '"parameters":  [500, "https://hercules.hitest.huron-dev.com/v1/connectors"], ' \
                    '"solution_links" : "" }]'

        DEV_LOGGER.info('test_post_status: alarm_list_str %s' %(alarm_list_str))

        mock_service.get_alarms.return_value = json.loads(alarm_list_str)

        metrics = Metrics(config, self.oauth)

        metrics.send_metrics(HEADERS, mock_service)

        # Returns a list of tuples with call arguments
        called_with = mock_http.post.call_args

        self.assertEquals(called_with[0][0], 'metrics_host/metrics_url')
        self.assertEquals(called_with[0][1], {'Content-Type': 'application/json', 'User-agent': 'user_agent/service_version'})

        json_value = json.loads(called_with[0][2])
        metrics_value = {"metrics": [{"value": {"connector_previous": {"url": "some_previous_path", "version": "service_version"}, "connector_current": {"url": "some_current_path", "version": "service_version"}, "connector_status": "on", "connector_state": "running", "connector_memory": "10", "connector_start": "on", "connector_cpu": "10"}, "context": {"connector_version": "service_version", "connector_type": "service_name", "cluster_id": "guid", "vcs_version": "vcs_version", "connector_id": "service_name@serialnumber"}, "key": "connector_status", "time": "current_time"}]}
        self.assertEquals(json_value, metrics_value)


    @mock.patch('managementconnector.cloud.metrics.Http')
    @mock.patch('managementconnector.cloud.metrics.ServiceUtils.get_version')
    @mock.patch('managementconnector.service.service.Service')
    @mock.patch('managementconnector.cloud.metrics.ManagementConnectorProperties.get_utc_time', side_effect=get_current_time)
    def test_send_metrics_alarms_keep_c_mgmt_description(self, mock_time, mock_service, mock_version, mock_http):
        """
            User Story: DE2116 Description is removed from FMC alarms and it should not be
            Purpose: To verify description is kept for c_mgmt.
            Notes:
            Steps:
                1. Create c_mgmt service
                2. Send Metrics
                3. Ensure metrics alarm information still contains description

           Args: None
           Returns: N/A
           Raises: None
        """

        DEV_LOGGER.info('test_send_metrics_alarms_keep_c_mgmt_description: start')

        # Step 1.
        mock_version.return_value = 'service_version'

        config = mock.MagicMock()
        config.read.side_effect = self.config_read

        mock_service.get_name.return_value = 'c_mgmt'
        mock_service.get_composed_status.return_value = 'running'
        mock_service.get_service_metrics.return_value = ('10', '10')

        alarm_list_str = '[{ "uuid" : "aaaf0813-09cb-4e23-9182-f3996d24cc9e", "id" : "66666", ' \
                         '"first_reported" :  "1417011612", "last_reported" :  "1417011811", ' \
                         '"severity" :  "error", ' \
                         '"parameters":  [500, "https://hercules.hitest.huron-dev.com/v1/connectors"], ' \
                         '"solution_links" : "" }]'

        alarm_json = json.loads(alarm_list_str)
        mock_service.get_alarms.return_value = alarm_json

        # Step 2.
        metrics = Metrics(config, self.oauth)

        metrics.send_metrics(HEADERS, mock_service, True)

        # Returns a list of tuples with call arguments
        called_with = mock_http.post.call_args

        self.assertEquals(called_with[0][0], 'metrics_host/metrics_url')
        self.assertEquals(called_with[0][1], {'Content-Type': 'application/json', 'User-agent': 'user_agent/service_version'})

        json_value = json.loads(called_with[0][2])

        # Alarm title, description etc get generated as "alm.uuid.*" as the alarm id doesn't actually exist
        expected_alarm = {u'description': u'alm.aaaf0813-09cb-4e23-9182-f3996d24cc9e.description',
                          u'title': u'alm.aaaf0813-09cb-4e23-9182-f3996d24cc9e.title', u'last_reported': u'2014-11-26T14:23:31',
                          u'solution': u'alm.aaaf0813-09cb-4e23-9182-f3996d24cc9e.solution',
                          u'solution_replacement_values': [], u'first_reported': u'2014-11-26T14:20:12', u'id': u'66666',
                          u'severity': u'error'}

        metrics_value = {"metrics": [{"value": expected_alarm, "context": {"connector_version": "service_version", "connector_type": "service_name", "cluster_id": "guid", "vcs_version": "vcs_version", "connector_id": "service_name@serialnumber"}, "key": "connector_alarm", "time": "current_time"}]}

        # Step 3.
        self.assertEquals(json_value, metrics_value)
        self.assertIn("description", json_value['metrics'][0]['value'])


    @mock.patch('managementconnector.cloud.metrics.Http')
    @mock.patch('managementconnector.cloud.metrics.ServiceUtils.get_version')
    @mock.patch('managementconnector.service.service.Service')
    @mock.patch('managementconnector.cloud.metrics.ManagementConnectorProperties.get_utc_time', side_effect=get_current_time)
    def xtest_send_metrics_alarms_remove_connectors_description(self, mock_time, mock_service, mock_version, mock_http):
        """
            User Story: DE2116 Description is removed from FMC alarms and it should not be
            Purpose: To verify description is removed for non c_mgmt.
            Notes:
            Steps:
                1. Create non c_mgmt service
                2. Send Metrics
                3. Ensure metrics alarm information does not contain description

           Args: None
           Returns: N/A
           Raises: None
        """

        DEV_LOGGER.info('test_send_metrics_alarms_remove_connectors_description: start')

        # Step 1.
        mock_version.return_value = 'service_version'

        config = mock.MagicMock()
        config.read.side_effect = self.config_read

        mock_service.get_name.return_value = 'c_test'
        mock_service.get_composed_status.return_value = 'running'
        mock_service.get_service_metrics.return_value = ('10', '10')

        alarm_list_str = '[{ "uuid" : "aaaf0813-09cb-4e23-9182-f3996d24cc9e", "id" : "66666", ' \
                         '"first_reported" :  "1417011612", "last_reported" :  "1417011811", ' \
                         '"severity" :  "error", ' \
                         '"parameters":  [500, "https://hercules.hitest.huron-dev.com/v1/connectors"], ' \
                         '"solution_links" : "" }]'

        alarm_json = json.loads(alarm_list_str)
        mock_service.get_alarms.return_value = alarm_json

        # Step 2.
        metrics = Metrics(config, self.oauth)

        metrics.send_metrics(HEADERS, mock_service, True)

        # Returns a list of tuples with call arguments
        called_with = mock_http.post.call_args

        self.assertEquals(called_with[0][0], 'metrics_host/metrics_url')
        self.assertEquals(called_with[0][1], {'Content-Type': 'application/json', 'User-agent': 'user_agent/service_version'})

        json_value = json.loads(called_with[0][2])

        # Alarm title, description etc get generated as "alm.uuid.*" as the alarm id doesn't actually exist
        expected_alarm = {u'title': u'alm.aaaf0813-09cb-4e23-9182-f3996d24cc9e.title', u'last_reported': u'2014-11-26T14:23:31',
                          u'solution': u'alm.aaaf0813-09cb-4e23-9182-f3996d24cc9e.solution',
                          u'solution_replacement_values': [], u'first_reported': u'2014-11-26T14:20:12', u'id': u'66666',
                          u'severity': u'error'}

        metrics_value = {"metrics": [{"value": expected_alarm, "context": {"connector_version": "service_version", "connector_type": "c_test", "cluster_id": "guid", "vcs_version": "vcs_version", "connector_id": "c_test@serialnumber"}, "key": "connector_alarm", "time": "current_time"}]}

        # Step 3.
        self.assertEquals(json_value, metrics_value)
        self.assertNotIn("description", json_value['metrics'][0]['value'])


    @mock.patch('managementconnector.cloud.metrics.Http')
    @mock.patch('managementconnector.service.service.Service')
    @mock.patch('managementconnector.cloud.metrics.ServiceUtils')
    @mock.patch('managementconnector.cloud.metrics.ManagementConnectorProperties.get_utc_time', side_effect=get_current_time)
    def test_send_metrics_certmanagement(self, mock_time, mock_utils, mock_service, mock_http):
        """
            User Story: US11316: CSCux24358: Add mechanism to better configure CA trust for particular services - Phase 1
            Purpose: To verify cert management value is posted as part of metrics.
            Notes:
            Steps:
                1. Create c_mgmt metrics post
                2. Send Metrics
                3. Ensure metrics contains cert management value {}
                4. Repeat with values of "true" and false"

           Args: None
           Returns: N/A
           Raises: None
        """

        DEV_LOGGER.info('test_send_metrics_certmanagement: start')
        global CERT_MANAGED
        config = mock.MagicMock()
        config.read.side_effect = self.config_read

        mock_utils.get_version.return_value = 'service_version'
        mock_utils.get_connector_status.return_value = 'on'
        mock_utils.get_service_start_time.return_value = 'on'
        mock_utils.get_current_versions.return_value = {"service_name": {"url": "some_current_path", "version": "service_version"}}
        mock_utils.get_previous_versions.return_value = {"service_name": {"url": "some_previous_path", "version": "service_version"}}

        mock_service.get_name.return_value = 'c_mgmt'
        mock_service.get_composed_status.return_value = 'running'
        mock_service.get_service_metrics.return_value = ('10', '10')

        # test with a blank entry - this is equivalent to unmanaged
        metrics = Metrics(config, self.oauth)
        metrics.send_metrics(HEADERS, mock_service)

        # Returns a list of tuples with call arguments
        called_with = mock_http.post.call_args
        json_resp = json.loads(called_with[0][2])
        self.assertEquals(json_resp["metrics"][0]["value"]["certManagement"], "")

        # test with a value of "true" - this is equivalent to managed
        CERT_MANAGED = 'true'
        metrics = Metrics(config, self.oauth)
        metrics.send_metrics(HEADERS, mock_service)
        called_with = mock_http.post.call_args
        json_resp = json.loads(called_with[0][2])
        self.assertEquals(json_resp["metrics"][0]["value"]["certManagement"], "true")

        # test with a value of "false" - this is equivalent to managed
        CERT_MANAGED = 'false'
        metrics = Metrics(config, self.oauth)
        metrics.send_metrics(HEADERS, mock_service)
        called_with = mock_http.post.call_args
        json_resp = json.loads(called_with[0][2])
        self.assertEquals(json_resp["metrics"][0]["value"]["certManagement"],"false")

        DEV_LOGGER.info('test_send_metrics_certmanagement: end')


    @mock.patch('managementconnector.cloud.metrics.Http')
    @mock.patch('managementconnector.cloud.metrics.ServiceUtils.get_version')
    @mock.patch('managementconnector.service.service.Service')
    @mock.patch('managementconnector.cloud.metrics.ManagementConnectorProperties.get_utc_time', side_effect=get_current_time)
    def test_send_metrics_alarms_suppressed_alarms_sent(self, mock_time, mock_service, mock_version, mock_http):
        """
            User Story: US16949: FMC: Post suppressed alarms to Metrics
            Purpose: To verify that a suppressed alarm is sent to metrics.
            Notes:
            Steps:
                1. Create c_mgmt service
                2. Send Metrics
                3. Ensure metrics alarm information for suppressed alarm is sent

           Args: None
           Returns: N/A
           Raises: None
        """

        DEV_LOGGER.info('test_send_metrics_alarms_suppressed_alarms_sent_once_threshold_reached: start')

        # Step 1.
        mock_version.return_value = 'service_version'

        config = mock.MagicMock()
        config.read.side_effect = self.config_read

        mock_service.get_name.return_value = 'c_mgmt'
        mock_service.get_composed_status.return_value = 'running'
        mock_service.get_service_metrics.return_value = ('10', '10')
        mock_service.get_suppressed_alarms.return_value = ["60050", "60051"]

        alarm_list_str = '[{ "uuid" : "cbbf0813-09cb-4e23-9182-f3996d24cc9e", "id" : "60051", ' \
                         '"first_reported" :  "1417011612", "last_reported" :  "1483545136", ' \
                         '"parameters":  [500, "https://hercules.hitest.huron-dev.com/v1/connectors"], ' \
                         '"solution_links" : "", "severity": "error" }]'

        alarm_json = json.loads(alarm_list_str)
        mock_service.get_alarms.return_value = alarm_json

        # Step 2.
        metrics = Metrics(config, self.oauth)

        metrics.send_metrics(HEADERS, mock_service, True)

        # Step 3.
        # Returns a list of tuples with call arguments
        called_with = mock_http.post.call_args_list
        alarm_posts = [call for call in called_with if '"key": "connector_alarm"' in call[0][2]]
        self.assertTrue(alarm_posts)

        mock_http.reset_mock()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
