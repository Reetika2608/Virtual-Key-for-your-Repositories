""" Atlas Logger """
import json
import os.path
import os
import time
from uuid import uuid4 as uuid

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.platform.http import Http
from managementconnector.platform.serviceutils import ServiceUtils
from managementconnector.cloud import schema


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class AtlasLogger(object):
    """Class for Pushing Logs to Atlas"""

    def __init__(self, oauth, config):
        """ Constructor """
        self._oauth = oauth
        self._config = config

    def get_oauth(self):
        """ Get oauth object """
        return self._oauth

    def get_headers(self):
        """ Get headers """

        # The User-Agent Field seems significant - Need to match metaData

        version = self._get_version()
        user_agent = self._config.read(ManagementConnectorProperties.METRICS_UA) + "/" + version

        log_headers = {
            'Authorization': 'Bearer ' + self._oauth.get_access_token(),
            'Content-Type': 'application/json',
            'User-agent': user_agent,
        }

        return log_headers

    def post_log(self, tracking_info, log_path):
        """ Public Method - Post log to cloud """

        meta_file = os.path.basename(log_path)

        DEV_LOGGER.info('Detail="post_log: meta_file %s"' % meta_file)

        temp_url, log_file_name = self._get_temp_url(meta_file)

        DEV_LOGGER.info('Detail="post_log: temp_url %s, log_file_name %s"' % (temp_url, log_file_name))

        start_log_timer = time.time()
        self._send_log(temp_url, log_path)
        end_log_timer = time.time()

        self._send_meta_data(tracking_info, log_file_name)

        return [0, end_log_timer - start_log_timer]

    def _get_temp_url(self, logfile_name):
        """ Get SWIFT URL where log file will be held """

        logging_url = self._config.read(ManagementConnectorProperties.LOGGING_HOST) + \
                      self._config.read(ManagementConnectorProperties.LOGGING_ASK_URL)

        data = {"file": logfile_name, 'uploadProtocol': 'content-length'}

        response = Http.post(logging_url, self.get_headers(), json.dumps(data), schema=schema.ASK_URL_RESPONSE)

        DEV_LOGGER.info('Detail="_get_temp_url: response %s"' % (response))

        return response['tempURL'], response["logFilename"]

    # @staticmethod  # removed staticmethod as unittest cases failed to import _send_log
    def _send_log(self, temp_url, log_path):
        """ send the logs to Cloud """

        # The User-Agent Field seems significant - Need to match get_temp_url
        version = self._get_version()

        user_agent = self._config.read(ManagementConnectorProperties.METRICS_UA) + "/" + version

        headers = {'Content-Type': 'application/octet-stream',
                   'User-agent': user_agent,
                   'X-Trans-Id': str(uuid())}  # TODO: Check if we still need this now that we've moved to AWS

        with open(log_path, mode='rb') as file_handle:  # b is important -> binary
            file_content = file_handle.read()

        response = Http.put(temp_url, headers, file_content, silent=True)

        DEV_LOGGER.info('Detail="_send_log: completed with status code {}'.format(response.getcode()))

    def _send_meta_data(self, tracking_info, file_name):
        """ send Meta Data to Cloud """

        # The User-Agent Field seems significant - Need to match get_temp_url
        version = self._get_version()
        user_agent = self._config.read(ManagementConnectorProperties.METRICS_UA) + "/" + version

        log_headers = {
            'Authorization': 'Bearer ' + self._oauth.get_access_token(),
            'Content-Type': 'application/json',
            'User-agent': user_agent,
        }

        logging_url = self._config.read(ManagementConnectorProperties.LOGGING_HOST) + \
                      self._config.read(ManagementConnectorProperties.LOGGING_META_URL)

        data = {'filename': file_name, 'data': [{'key': "Fusion", 'value': tracking_info['tracking_id']},
                                                {'key': "locusid", 'value': tracking_info['serial_number']}]}

        Http.post(logging_url, log_headers, json.dumps(data))

    @staticmethod
    def _get_version():
        """ _get_version """
        return ServiceUtils.get_version(ManagementConnectorProperties.SERVICE_NAME)
