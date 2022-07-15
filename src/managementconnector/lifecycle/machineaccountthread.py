"""
    Class to Manage MachineAccount Thread
"""

import json
import threading
import traceback
import uuid
import time
from urllib.error import HTTPError, URLError

import taacrypto

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.platform.http import Http
from managementconnector.platform.alarms import MCAlarm
from managementconnector.cloud.oauth import OAuth
from managementconnector.cloud import schema

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class MachineAccountThread(threading.Thread):
    """
        Class to Manage MachineAccount Thread
    """

    def __init__(self, config, stop_event):
        threading.Thread.__init__(self, name='MachineAccountThread')
        self._config = config
        self._stop_event = stop_event
        self._alarms = MCAlarm(self._config)
        self._location_url = None
        self._oauth = None
        self.update_failure = False
        self.poll_time = None

    # -------------------------------------------------------------------------

    def start(self):
        """ Start MachineAccount Thread """
        DEV_LOGGER.debug('Detail="FMC_Lifecycle MachineAccountThread: start()"')
        threading.Thread.start(self)

    # -------------------------------------------------------------------------

    def run(self):
        """ Run content of Thread """
        DEV_LOGGER.info('Detail="FMC_Lifecycle MachineAccountThread: run()"')
        # wait two seconds for startup to allow cafe manager time to update the config
        time.sleep(2)
        
        if not self._oauth:
            self._oauth = OAuth(self._config)

        oauth_init = False

        while True: # pylint: disable=R0101
            if self._stop_event.is_set():
                DEV_LOGGER.info('Detail="FMC_Lifecycle MachineAccountThread a stop event, '
                                'breaking out of polling and stopping."')
                self._oauth = None
                self._stop_event.clear()
                return
            try:
                if not oauth_init:
                    oauth_init = self._oauth.init()

                account_expiry = int(self._config.read(ManagementConnectorProperties.MACHINE_ACC_EXPIRY,
                                                       ManagementConnectorProperties.DEFAULT_MACHINE_ACC_EXPIRY))

                days_to_expiry = int(self._oauth.get_account_expiration())

                if days_to_expiry and account_expiry:
                    DEV_LOGGER.info(
                        'Detail="FMC_Lifecycle MachineAccountThread days_to_expiry=%d, account_expiry=%d"' % (
                        days_to_expiry, account_expiry))
                    if days_to_expiry <= account_expiry:
                        try:
                            self._update_machine_acct_password()
                            self.update_failure = False
                        except Exception as error:  # pylint: disable=W0703
                            DEV_LOGGER.error(
                                'Detail="FMC_Lifecycle MachineAccountThread:failed to refresh Machine Account, '
                                'occurred:%s, stacktrace=%s"' % (repr(error), traceback.format_exc()))
                            retry_time = ManagementConnectorProperties.MACHINE_POLL_TIME_FAIL/60
                            self._alarms.raise_alarm('bb1cf2ca-20fd-43cc-9ae2-8a33206fb9fd',
                                                     [self._location_url, retry_time])
                            self.update_failure = True
            except (TypeError, ValueError, URLError, HTTPError) as error:
                DEV_LOGGER.error(
                    'Detail="FMC_Lifecycle MachineAccountThread failed to read machine account details. Error=%s"'
                    % repr(error))
                self.update_failure = True
            finally:
                if self.update_failure:
                    # The update attempt failed, setting retry wait to short time period.
                    self.poll_time = ManagementConnectorProperties.MACHINE_POLL_TIME_FAIL
                else:
                    # If update succeeded or if machine account is working, lower the alarm
                    self._alarms.clear_alarm("bb1cf2ca-20fd-43cc-9ae2-8a33206fb9fd")
                    # Default Poll time supplied as back up in case the config can't be read, same pattern as deploy.
                    self.poll_time = int(self._config.read(ManagementConnectorProperties.MACHINE_POLL_TIME,
                                                           ManagementConnectorProperties.DEFAULT_MACHINE_POLL_TIME))
                DEV_LOGGER.info('Detail="FMC_Lifecycle MachineAccountThread: sleeping for %s seconds"' % self.poll_time)
                self._stop_event.wait(self.poll_time)

    # -------------------------------------------------------------------------

    def _store_machine_response_in_db(self, machine_response):
        """ Store Machine Details in the DB """
        # Convert to JSON Dict and write to DB
        machine_response['password'] = taacrypto.encrypt_with_system_key(machine_response['password'])

        self._config.write_blob(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS, machine_response)

    # -------------------------------------------------------------------------

    def _get_machine_details_from_json(self):
        """Retrieve OAuth Detail from the DB"""

        # MACHINE_ACCOUNT_CDB_taaPOSTFIX = 'oauth_machine_account_details'
        rtn_value = self._config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)

        if not rtn_value:
            DEV_LOGGER.error('Detail="FMC_MachineAccount _get_machine_details_from_json Failed to read a record."')
            return None

        rtn_value_copy = rtn_value.copy()
        rtn_value_copy['password'] = taacrypto.decrypt_with_system_key(rtn_value_copy['password'])

        return rtn_value_copy

    # -------------------------------------------------------------------------

    def _update_machine_acct_password(self):
        """ Update the Machine Account Password """

        DEV_LOGGER.info('Detail="FMC_MachineAccount _update_machine_acct_password"')

        machine_response = self._get_machine_details_from_json()

        self._location_url = machine_response['location']
        new_password = 'aaBB12$' + str(uuid.uuid4())

        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self._oauth.get_access_token()}
        data = {'password': new_password}

        body = json.dumps(data)

        Http.patch(self._location_url, headers, body, silent=True, schema=schema.MACHINE_ACCOUNT_RESPONSE)

        machine_response['password'] = new_password
        self._store_machine_response_in_db(machine_response)

        DEV_LOGGER.info('Detail="FMC_MachineAccount _update_machine_acct_password password updated"')
