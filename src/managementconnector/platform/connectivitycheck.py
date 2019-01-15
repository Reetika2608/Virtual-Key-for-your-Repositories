""" Connectivity check processor """
import urllib2
import subprocess
import time

from managementconnector.service.eventsender import EventSender
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.platform.http import Http, CertificateExceptionFusionCA, CertificateExceptionNameMatch, CertificateExceptionInvalidCert

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class ConnectivityCheck(object):
    """ Class for checking connectivity to a given URL"""

    @staticmethod
    def check_connectivity_to_url(oauth, config, url):
        """ Ping/GET the given URL """
        output = {}
        serial_number = config.read(ManagementConnectorProperties.SERIAL_NUMBER)
        output["pingResult"] = ConnectivityCheck.ping_test(url)
        output["getResult"] = ConnectivityCheck.get_test(url)
        output["url"] = url
        DEV_LOGGER.info('Detail=Check connectivity to %s for serial %s"', url, serial_number)
        EventSender.post_simple(oauth,
                         config,
                         EventSender.CONNECTION_CHECK,
                         ManagementConnectorProperties.SERVICE_NAME,
                         int(time.time()),
                         output)
        return output

    @staticmethod
    def get_test(url):
        """ Part of connectivity check - verify connection to the given URL using HTTP GET """
        https_url = url
        if not url.startswith("https://"):
            https_url = "https://" + url
        DEV_LOGGER.info('Detail="Check connectivity testing GET %s"', url)
        headers = dict()
        headers['Content-Type'] = 'application/json'
        try:
            Http.get(https_url, headers)
            status = "passed"
        except urllib2.HTTPError as http_error:
            DEV_LOGGER.error('Detail="Check connectivity response, http failure: %s, reason: %s"',
                             http_error, http_error.reason)
            status = "http_error"
        except CertificateExceptionFusionCA as cert_exception:
            DEV_LOGGER.error('Detail="Check connectivity response, cert failure(1): %s"', cert_exception)
            status = "cert_error"
        except CertificateExceptionNameMatch as cert_exception:
            DEV_LOGGER.error('Detail="Check connectivity response, cert failure(2): %s"', cert_exception)
            status = "cert_error"
        except CertificateExceptionInvalidCert as cert_exception:
            DEV_LOGGER.error('Detail="Check connectivity response, cert failure(3): %s"', cert_exception)
            status = "cert_error"
        except urllib2.URLError, url_error:
            DEV_LOGGER.error('Detail="Check connectivity response, http failure(2): %s"', url_error)
            status = "not_found"
        except Exception as exception: # pylint: disable=W0703
            DEV_LOGGER.error('Detail="Check connectivity response, exception: %s"', exception)
            status = "exception"
        return status

    @staticmethod
    def ping_test(url):
        """ Part of connectivity check - verify connection to the given URL using ICMP ping """
        bare_addr = url
        if "https://" in bare_addr:
            bare_addr = bare_addr.replace("https://", "")
        if "/" in bare_addr:
            bare_addr = bare_addr.split("/")[0]
        DEV_LOGGER.info('Detail="Check connectivity testing PING %s"', bare_addr)
        ping_response = subprocess.call(["/bin/ping", "-c1", "-w2", bare_addr], stdout=subprocess.PIPE)
        if ping_response == 0:
            return "passed"
        else:
            return "failed"
