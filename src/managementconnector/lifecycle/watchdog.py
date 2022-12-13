"""WatchDogThread"""
# Ignore "Method could be a function" warnings        pylint: disable=R0201

import threading
import os
import time
import datetime

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud.oauth import OAuth
from managementconnector.cloud.metrics import Metrics
from managementconnector.config import jsonhandler
from managementconnector.service.eventsender import EventSender
from managementconnector.lifecycle.machineaccountrunner import MachineAccountRunner

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class WatchdogThread(threading.Thread):

    """WatchDogThread"""

    def __init__(self, config, stop_event):
        threading.Thread.__init__(self, name='WatchdogThread')
        self._config = config
        self._stop_event = stop_event
        self._oauth = None
        self._metrics = None
        self._watchdog_poll_interval = None
        self._initial_poll_time = None
        self._machine_account_runner = None

    def run(self):
        """Run content of Thread"""
        DEV_LOGGER.info('Detail="FMC_Watchdog: run()"')
        # Wait two seconds for Cafe Manager to update config, following pattern of other threads
        time.sleep(2)

        self._oauth = OAuth(self._config)
        self._oauth.init()

        self._metrics = Metrics(self._config, self._oauth)

        content = jsonhandler.read_json_file(ManagementConnectorProperties.WATCHDOG_FILE_PATH)
        if content:
            DEV_LOGGER.info('Detail="FMC_Watchdog: automatic restart detected due to connection issues, '
                            'sending metrics"')
            self._metrics.send_watchdog_restart_metrics(self._oauth.get_header(),
                                                        ManagementConnectorProperties.SERVICE_NAME,
                                                        content)
            jsonhandler.delete_file(ManagementConnectorProperties.WATCHDOG_FILE_PATH)

        # Defaults supplied in case the config can't be read, same pattern as deploy and machine account thread.
        self._initial_poll_time = int(self._config.read(ManagementConnectorProperties.INITIAL_WATCHDOG_POLL,
                                                        default=ManagementConnectorProperties.DEFAULT_INITIAL_POLL))

        DEV_LOGGER.info('Detail="FMC_Watchdog: waiting for initial time period: {}"'.format(self._initial_poll_time))
        self._stop_event.wait(self._initial_poll_time)

        while True:
            if self._stop_event.is_set():
                DEV_LOGGER.info('Detail="FMC_Watchdog a stop event, '
                                'breaking out of polling and stopping."')
                self._oauth = None
                return

            self._watchdog_poll_interval = int(self._config.read(ManagementConnectorProperties.WATCHDOG_POLL_TIME,
                                                                 default=ManagementConnectorProperties.DEFAULT_WATCHDOG_TIME))

            if self.is_restart_needed():
                return

            DEV_LOGGER.debug('Detail="FMC_Lifecycle: WatchdogThread: monitoring complete, waiting {} until next check"'
                             .format(self._watchdog_poll_interval))

            self._stop_event.wait(self._watchdog_poll_interval)

    def is_restart_needed(self):
        """Verify if restart of connector/machineaccount thread is necessary"""
        try:
            # A dictionary of states, {"extension": {"timestamp": "2016-12-13T11:17:10Z", "working": true/false}}
            working_states = self.get_working_state()

            broken = False
            if working_states:
                for key, value in working_states.items():
                    if ManagementConnectorProperties.WATCHDOG_WORKING_STATE in value:
                        if not value[ManagementConnectorProperties.WATCHDOG_WORKING_STATE]:
                            if key == ManagementConnectorProperties.MACHINE_ACCOUNT_EXTENSION:
                                if not self._machine_account_runner:
                                    self._machine_account_runner = MachineAccountRunner(self._config, self._stop_event)
                                    self._machine_account_runner.start()
                                    DEV_LOGGER.error('Detail="FMC_Watchdog: MachineAccountRunner restarting MachineAccountThread. Working state: %s"' 
                                                    % working_states)
                                    event_detail = "FMC_Watchdog: MachineAccountRunner restarting MachineAccountThread. Working state: " + \
                                                    str(working_states)
                                    EventSender.post(self._oauth, self._config, EventSender.WATCHDOG_MACHINEACCOUNT_RUNNER_RESTART_THREAD,
                                                    detailed_info=event_detail)               
                            else:
                                broken = True
                                break
                    else:
                        DEV_LOGGER.error('Detail="FMC_Watchdog: {} key not found for: {}, total state: {}"'
                                         .format(ManagementConnectorProperties.WATCHDOG_WORKING_STATE,
                                                 key,
                                                 working_states))
                        broken = True
                        break
            else:
                DEV_LOGGER.error('Detail="FMC_Watchdog: empty connection statuses"')
                broken = True

            if broken:
                DEV_LOGGER.error('Detail="FMC_Lifecycle: WatchdogThread: restart FMC, working_states:{}"'.format(working_states))
                self.restart(working_states)
                return True
        except Exception as ex:
            DEV_LOGGER.error('Detail="FMC_Watchdog: Exception: {}"'.format(ex))
            event_detail = "FMC_Watchdog exception"
            EventSender.post(self._oauth, self._config, EventSender.WATCHDOG_EXCEPTION ,
                                                detailed_info=event_detail) 
            raise

        return False

    def get_working_state(self):
        """Check if FMS and Mercury connections are working"""
        working_state = {}
        connections = [ManagementConnectorProperties.HEARTBEAT_EXTENSION,
                       ManagementConnectorProperties.MERCURY_EXTENSION,
                       ManagementConnectorProperties.MACHINE_ACCOUNT_EXTENSION]

        file_paths = [ManagementConnectorProperties.FULL_VAR % extension for extension in connections]
        status_info = jsonhandler.get_last_modified(file_paths)

        for connection in connections:
            if status_info[connection] is None and connection!=ManagementConnectorProperties.MERCURY_EXTENSION:
                DEV_LOGGER.info('Detail="FMC_Watchdog: File not found for %s"' %connection)
                event_detail = "FMC_Watchdog File not found: c_mgmt" + str(connection)
                EventSender.post(self._oauth, self._config, EventSender.WATCHDOG_FILE_MISSING,
                                                detailed_info=event_detail) 
                break
            working_state[connection] = self.get_connection_state(status_info, connection)

        DEV_LOGGER.debug('Detail="FMC_Watchdog: checking {} working_state"'.format(working_state))
        return working_state

    def get_connection_state(self, status_info, file_extension):
        """ Compare file last modified time and expiry period """
        connection_name = file_extension[1:]
        DEV_LOGGER.debug('Detail="FMC_Watchdog: checking {} connection"'.format(connection_name))
        DEV_LOGGER.debug('Detail="FMC_Watchdog: checking {} status_info"'.format(status_info))

        connection_state = {}
        if file_extension in status_info:
            timestamp = status_info[file_extension]
            simple_current_time = time.mktime(time.localtime())
            since_last_heartbeat = simple_current_time - timestamp

            utc_time = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%dT%H:%M:%SZ')
            connection_state["timestamp"] = utc_time

            if file_extension == ManagementConnectorProperties.MACHINE_ACCOUNT_EXTENSION:
                watchdog_poll_interval = ManagementConnectorProperties.DEFAULT_WATCHDOG_MACHINE_ACCOUNT_TIME
            else:
                watchdog_poll_interval = self._watchdog_poll_interval

            if since_last_heartbeat < watchdog_poll_interval:
                connection_state[ManagementConnectorProperties.WATCHDOG_WORKING_STATE] = True
            else:
                connection_state[ManagementConnectorProperties.WATCHDOG_WORKING_STATE] = False
                DEV_LOGGER.info('Detail="FMC_Watchdog: {} restart timeout exceeded"'.format(connection_name))
        else:
            DEV_LOGGER.error('Detail="FMC_Watchdog: {} file not present"'.format(connection_name))

        return connection_state

    def restart(self, working_state):
        """Restart FMC"""
        DEV_LOGGER.debug('Detail="FMC_Watchdog: restarting FMC due to bad connections, state: {}"'.format(working_state))
        jsonhandler.write_json_file(ManagementConnectorProperties.WATCHDOG_FILE_PATH, working_state)
        os.system("echo 'restart c_mgmt' > /tmp/request/requestservicestart")  # nosec - static input
        EventSender.post(self._oauth, self._config, EventSender.WATCHDOG_RESTART, detailed_info=str(working_state))
