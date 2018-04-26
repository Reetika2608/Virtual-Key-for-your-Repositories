"""
    Class to Manage Mercury Interaction
"""
# Ignore "Unused Arguement" warnings        pylint: disable=W0613


import threading

import traceback
import time
import json
import jsonschema
import websocket

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.platform.http import Http
from ni.managementconnector.cloud.metrics import Metrics
from ni.managementconnector.cloud.wdm import DeviceManager
from ni.managementconnector.cloud.remotedispatcher import RemoteDispatcher
from ni.managementconnector.cloud import schema
from ni.managementconnector.service.eventsender import EventSender

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class Mercury(threading.Thread):
    """
        Mercury WebSocket Thread
    """

    def __init__(self, config, oauth):
        threading.Thread.__init__(self, name='Mercury')
        self._mercury_details = None

        self._oauth = oauth
        self._config = config
        self._metrics = Metrics(self._config, self._oauth)

        self._proxy = None
        self._ws = None

        self._running = False

        self._latest_ws_error = None

        self._last_refreshed = int(round(time.time()))

        self._mercury_probe_timer = None
        self._missed_mercury_probes = 0

        self._restart_needed = False

    # -------------------------------------------------------------------------

    def heartbeat(self):

        """
        Mercury Heartbeat

        Check Mercury Channel Status
        - If running - Periodically Refresh DeviceManager Registration
        - If nor running - Full Registration + Websocket restart

        """

        DEV_LOGGER.info('Detail="FMC_Websocket Mercury heartbeat"')

        # Register Websocket.
        if self._running:
            DEV_LOGGER.debug('Detail="FMC_Websocket Listener Already Running"')
            wdm_refreshed = False

            try:
                # Following Cal Connector Example where WDM is refreshed every 60 minutes

                current_time = int(round(time.time()))

                wdm_refresh = self._config.read(ManagementConnectorProperties.WDM_REFRESH)

                if current_time - self._last_refreshed > wdm_refresh:

                    self._mercury_details = DeviceManager.register(self._oauth.get_header(), self._config,
                                                                   force_create=False)
                    wdm_refreshed = True
                    self._last_refreshed = self._mercury_details['last_refreshed']

                    self._metrics.send_mercury_metrics(self._oauth.get_header(),
                                                       ManagementConnectorProperties.SERVICE_NAME,
                                                       self.get_status())

            except Exception as wdm_error:
                # If there is a problem tear down registration, it will be recreated in next heartbeat
                self.shutdown()
                raise wdm_error
            if wdm_refreshed:
                self.register_with_remote_dispatcher()

        else:
            DEV_LOGGER.info('Detail="FMC_Websocket Mercury Startup"')

            try:
                self._mercury_details = DeviceManager.register(self._oauth.get_header(), self._config,
                                                               force_create=True)

                self._last_refreshed = self._mercury_details['last_refreshed']

                # Start Mercury Connection

                self._ws = websocket.WebSocketApp(self.get_ws_url(),
                                                  header=self._oauth.get_header(),
                                                  on_message=self.on_message,
                                                  on_error=self.on_error,
                                                  on_close=self.on_close)

                self._ws.on_open = self.on_open

                threading.Thread(target=self.run).start()

            except Exception as wdm_error:
                # If there is a problem tear down registration, it will be recreated in next heartbeat
                self.shutdown()
                raise wdm_error


    # -------------------------------------------------------------------------

    def stop(self):
        """ Stop WS Thread
        1. Teardown any existing mercury resources
        """

        DEV_LOGGER.info('Detail="FMC_Websocket Stopping Mercury Listener"')

        if self._ws:
            self._ws.close()

    # -------------------------------------------------------------------------

    def shutdown(self):
        """ Shutdown Mercury Resources
        """

        DEV_LOGGER.info('Detail="FMC_Websocket Shutdown Mercury Listener "')

        self.stop()

    # -------------------------------------------------------------------------

    def get_status(self):
        """ Get the Status of the Mercury Connection """

        proxy_details = Mercury.get_proxy_details(self._proxy)

        proxy_set = True if proxy_details else False

        status = {"running": self._running, "proxy_set": proxy_set,
                  "error": self._latest_ws_error, "device_url": self.get_device_url(),
                  "ws_url": self.get_ws_url(), "last_refreshed": self._last_refreshed}

        return status

    # -------------------------------------------------------------------------

    def get_device_url(self):
        """ Get Device ID """

        device_url = None

        if self._mercury_details:
            if "device_url" in self._mercury_details:
                device_url = self._mercury_details['device_url']

        return device_url

    # -------------------------------------------------------------------------

    def get_ws_url(self):
        """ Get Route Url """
        ws_url = None

        if self._mercury_details:
            if "ws_url" in self._mercury_details:
                ws_url = self._mercury_details['ws_url']

        return ws_url

    # -------------------------------------------------------------------------

    def run(self):
        """
            run method that opens websocket and then blocks on the run_forever method
        """

        self._proxy = Http.get_proxy()

        proxy_details = Mercury.get_proxy_details(self._proxy)

        proxy_address = None
        proxy_port = 0
        proxy_auth = None

        if proxy_details:
            proxy_address = str(proxy_details['address'])
            proxy_port = str(proxy_details['port'])  # pylint: disable=R0204

            if proxy_details['username'] is not None and proxy_details['password'] is not None:
                proxy_auth = (str(proxy_details['username']), str(proxy_details['password']))

        if proxy_details is not None:
            DEV_LOGGER.info('Detail="FMC_Websocket Proxy being used"')

        # This Blocks until websocket is closed

        DEV_LOGGER.info('Detail="FMC_Websocket Mercury Connection Initialised"')

        sslopt_ca_certs = {'ca_certs': ManagementConnectorProperties.COMBINED_CA_FILE}

        if self._ws:
            self._ws.run_forever(sslopt=sslopt_ca_certs, http_proxy_host=proxy_address, http_proxy_port=proxy_port,
                                 http_proxy_auth=proxy_auth,
                                 ping_interval=ManagementConnectorProperties.WS_PING_INTERVAL,
                                 ping_timeout=ManagementConnectorProperties.WS_PING_TIMEOUT)

        DEV_LOGGER.info('Detail="FMC_Websocket: Exiting run_forever thread"')

    # -------------------------------------------------------------------------

    def on_error(self, handler, error):
        """ Error Handler """

        # Cached the exception - used subsequently when reporting metrics
        self._latest_ws_error = traceback.format_exc()

        DEV_LOGGER.error('Detail="FMC_Websocket on_error callback: error=%s, type=%s"', error, traceback.format_exc())

        # If the websocket goes down due to an error, we want to restart immediately, not wait for the next heartbeat
        self._restart_needed = True

        # on_error events seem to be followed by on_close events, check out the run_forever internals

    def on_close(self, handler):
        """ Close Handler """
        DEV_LOGGER.info('Detail="FMC_Websocket on_close callback"')

        try:
            DeviceManager.deregister_from_wdm(self._oauth.get_header())
        except Exception as wdm_error:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="Un-handled Exception occurred:%s, stacktrace=%s"',
                             repr(wdm_error), traceback.format_exc())
            self.handle_mercury_exception(wdm_error)
        finally:
            self._running = False
            self._ws = None
            if self._restart_needed:
                self._restart_needed = False
                self.heartbeat()

    # -------------------------------------------------------------------------

    def on_open(self, handler):
        """ Open Handler """
        DEV_LOGGER.info('Detail="FMC_Websocket on_open callback"')

        self._running = True
        self._latest_ws_error = None

        self.register_with_remote_dispatcher()

    # -------------------------------------------------------------------------

    def on_message(self, handler, message):
        """ Message Handler """
        try:
            message = json.loads(message)

            try:
                # Mercury probe comes in as a message without a command field
                if 'command' not in message['data']:
                    jsonschema.validate(message, schema.MERCURY_PROBE_MESSAGE)
                    self._validate_mercury_probe()
                    DEV_LOGGER.info('Detail="FMC_Websocket Mercury Probe Received. trackingId: %s"',
                                    message["trackingId"])
                    return
                else:
                    jsonschema.validate(message, schema.MERCURY_MESSAGE)
                    self._validate_mercury_probe()
            except ValueError, ex:
                DEV_LOGGER.error(
                    'Detail="FMC_Websocket Error loading json: {}"'.format(ex))
                return
            except (jsonschema.ValidationError, KeyError) as validation_exc:
                DEV_LOGGER.error('Detail="FMC_Websocket ValidationError when validating json:%s, stacktrace=%s"'
                                 % (repr(validation_exc), traceback.format_exc()))
                # Not re-raising exception as it's logged and swallowed in low level App callbacks.
                return

            # Extract required info from RD command
            command_log = {"commandId": message['data']['command']['commandId'],
                           "action": message['data']['command']['action'],
                           "parameters": message['data']['command']['parameters'],
                           "dispatcher": message['data']['command']['dispatcher'],
                           "trackingId": message['trackingId']}

            DEV_LOGGER.info('Detail="FMC_Websocket Command Received: %s"', json.dumps(command_log, sort_keys=True))

            RemoteDispatcher.handle_command(message)

        except Exception as on_message_error:  # pylint: disable=W0703
            self.handle_mercury_exception(on_message_error)

    # -------------------------------------------------------------------------

    def check_for_proxy_changes(self):
        """ check_for_proxy_changes in the Database, a proxy config changes should give rise to Websocket recreation """

        if self._proxy == Http.get_proxy():
            return
        else:
            # Force a register + restart
            DEV_LOGGER.debug('Detail="FMC_Websocket - Proxy config has changed"')
            self._proxy = Http.get_proxy()

            # Initiate Web Socket Closure
            self.stop()

    @staticmethod
    def get_proxy_details(proxy):
        """ get_proxy_details """

        rtn_details = None

        if proxy:
            proxy_enabled = proxy['enabled']

            proxy_on = True if proxy_enabled == "true" else False

            if proxy_on:
                rtn_details = proxy

        return rtn_details

    # -------------------------------------------------------------------------

    def handle_mercury_exception(self, merc_exception):
        """ Handle Mercury Exception """
        stack_trace = traceback.format_exc()

        error_reason = None
        if hasattr(merc_exception, 'reason'):
            error_reason = merc_exception.reason

        error_response = None
        if hasattr(merc_exception, 'read'):
            try:
                error_response = merc_exception.read()
            except IOError:
                pass

        device_url = self.get_device_url()

        error_content = {"error_type": str(merc_exception.__class__), "stacktrace": stack_trace,
                         "error_reason": error_reason, "error_response": error_response, "device_url": device_url}

        DEV_LOGGER.error('Detail="Exception occurred, error_content=%s"' % error_content)

        # Try sending Mercury Exception to Metrics, in order to track live issues
        try:
            self._metrics.send_mercury_error_metrics(self._oauth.get_header(),
                                                     ManagementConnectorProperties.SERVICE_NAME,
                                                     error_content)
        except Exception as metrics_error:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="Error sending Mercury exception to metrics. Exception=%s, stacktrace=%s"'
                             % (repr(metrics_error), traceback.format_exc()))

    def handle_missing_mercury_probe(self):
        """ Handle missing Mercury probe """
        self._missed_mercury_probes += 1
        DEV_LOGGER.debug('Detail="FMC_Websocket - Missed Mercury probe detected"')
        if self._missed_mercury_probes >= ManagementConnectorProperties.MERCURY_PROBE_LIMIT:
            DEV_LOGGER.info('Detail="FMC_Websocket - '
                            'Tearing down Mercury connection due to %s missing probes from Remote Dispatcher"'
                            % self._missed_mercury_probes)
            event_detail = "Reached limit for missed mercury probes: " + \
                           str(ManagementConnectorProperties.MERCURY_PROBE_LIMIT)
            EventSender.post(self._oauth, self._config, EventSender.MERCURY_PROBE_MISSED,
                             detailed_info=event_detail)
            self.shutdown()
            self._missed_mercury_probes = 0
            self.heartbeat()
        else:
            self.register_with_remote_dispatcher()

    def register_with_remote_dispatcher(self):
        """ Register with Remote Dispatcher """
        try:
            self._run_probe_timer(True)
            RemoteDispatcher.register(self._oauth, self._config)
        except Exception as remote_dispatcher_error:  # pylint: disable=W0703
            DEV_LOGGER.error('Detail="Exception occurred while registering with Remote Dispatcher:%s, stacktrace=%s"',
                             repr(remote_dispatcher_error), traceback.format_exc())
            if self._mercury_probe_timer:
                self._run_probe_timer(False)
            RemoteDispatcher.delete_config_from_disk()

    def _run_probe_timer(self, start):
        """ Control Mercury probe timer lifecycle """
        if start:
            self._mercury_probe_timer = threading.Timer(ManagementConnectorProperties.MERCURY_PROBE_TIMEOUT,
                                                        self.handle_missing_mercury_probe)
            self._mercury_probe_timer.start()
        else:
            self._mercury_probe_timer.cancel()
            self._mercury_probe_timer = None

    def _validate_mercury_probe(self):
        """ Handle successful Mercury probe """
        self._missed_mercury_probes = 0
        if self._mercury_probe_timer:
            self._run_probe_timer(False)
