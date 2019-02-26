"""
    Test ConnectivityCheck
"""
# Ignore "Redefinition of type" warnings        pylint: disable=R0204
import unittest
import subprocess
import io
import logging
import urllib2
import mock
import sys
from constants import SYS_LOG_HANDLER

# Pre-import a mocked taacrypto
sys.modules['taacrypto'] = mock.Mock()
sys.modules['pyinotify'] = mock.MagicMock()

logging.getLogger().addHandler(SYS_LOG_HANDLER)

from managementconnector.platform.http import CertificateExceptionFusionCA
from managementconnector.platform.connectivitycheck import ConnectivityCheck
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class ConnectivityCheckTest(unittest.TestCase):
    """ConnectivityCheck unit tests"""

    def setUp(self):
        """ ConnectivityCheck Test Setup """

        DEV_LOGGER.debug('***TEST Setup***')

    @mock.patch('subprocess.call')
    def test_ping_test_https(self, mock_subprocess):
        """ User Story: SPARK-31235 RD: New Command to Test Connectivity """
        url = "https://www.123.abc"
        mock_subprocess.return_value = 0
        res = ConnectivityCheck.ping_test(url)
        mock_subprocess.assert_called_with(["/bin/ping", "-c1", "-w2", "www.123.abc"], stdout=subprocess.PIPE)
        self.assertEqual(res, 'passed', '%s does not equal "passed"' % res)

        mock_subprocess.reset_mock()
        mock_subprocess.return_value = 1
        res = ConnectivityCheck.ping_test(url)
        mock_subprocess.assert_called_with(["/bin/ping", "-c1", "-w2", "www.123.abc"], stdout=subprocess.PIPE)
        self.assertEqual(res, 'failed', '%s does not equal "failed"' % res)

        url = "https://www.123.abc/"
        mock_subprocess.reset_mock()
        mock_subprocess.return_value = 0
        res = ConnectivityCheck.ping_test(url)
        mock_subprocess.assert_called_with(["/bin/ping", "-c1", "-w2", "www.123.abc"], stdout=subprocess.PIPE)
        self.assertEqual(res, 'passed', '%s does not equal "passed"' % res)

    @mock.patch('managementconnector.platform.http.Http.get')
    def test_get_test(self, mock_http):
        """ User Story: SPARK-31235 RD: New Command to Test Connectivity """
        url = 'https://www.123.abc'

        res = ConnectivityCheck.get_test(url)
        mock_http.assert_called_with(url, {'Content-Type': 'application/json'})
        self.assertEqual(res, 'passed', '%s does not equal "passed"' % res)

        mock_http.reset_mock()
        stream = io.TextIOWrapper(io.BytesIO("not_found"))
        mock_http.side_effect = urllib2.HTTPError('https://www.123.abc', "401", "unauthorized", "hdrs", stream)
        res = ConnectivityCheck.get_test(url)
        mock_http.assert_called_with(url, {'Content-Type': 'application/json'})
        self.assertEqual(res, 'http_error', '%s does not equal "http_error"' % res)

        mock_http.reset_mock()
        mock_http.side_effect = urllib2.URLError('not found')
        res = ConnectivityCheck.get_test(url)
        mock_http.assert_called_with(url, {'Content-Type': 'application/json'})
        self.assertEqual(res, 'not_found', '%s does not equal "not_found"' % res)

        mock_http.reset_mock()
        mock_http.side_effect = CertificateExceptionFusionCA("")
        res = ConnectivityCheck.get_test(url)
        mock_http.assert_called_with(url, {'Content-Type': 'application/json'})
        self.assertEqual(res, 'cert_error', '%s does not equal "cert_error"' % res)

        url = 'www.123.abc'
        mock_http.reset_mock()
        mock_http.side_effect = None
        res = ConnectivityCheck.get_test(url)
        mock_http.assert_called_with('https://www.123.abc', {'Content-Type': 'application/json'})
        self.assertEqual(res, 'passed', '%s does not equal "passed"' % res)

    @mock.patch('managementconnector.service.eventsender.EventSender.post_simple')
    @mock.patch('managementconnector.platform.connectivitycheck.ConnectivityCheck.get_test')
    @mock.patch('managementconnector.platform.connectivitycheck.ConnectivityCheck.ping_test')
    def test_check_connectivity_to_url(self, mock_ping, mock_get, _):
        """ User Story: SPARK-31235 RD: New Command to Test Connectivity """
        oauth = mock.MagicMock()
        config = mock.MagicMock()
        url = 'https://www.123.abc'
        mock_ping.return_value = 'passed'
        mock_get.return_value = 'passed'
        config.read.return_value = '12345'
        res = ConnectivityCheck.check_connectivity_to_url(oauth, config, url)
        mock_ping.assert_called_with(url)
        mock_get.assert_called_with(url)
        self.assertEqual(res, {'pingResult': 'passed', 'getResult': 'passed', 'url': url})


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()