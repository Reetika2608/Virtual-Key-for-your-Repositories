""" Management Connector Deploy Class """
import time
import traceback
from urllib import error as urllib_error
import threading
import ssl
import http.client
import os
import jsonschema

from managementconnector.cloud.atlas import Atlas
from managementconnector.cloud.metrics import Metrics
from managementconnector.platform.http import Http, CertificateExceptionFusionCA, CertificateExceptionNameMatch, \
    CertificateExceptionInvalidCert
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud.oauth import OAuth
from managementconnector.service.service import ServiceException
from managementconnector.service.servicedependency import ServiceDependency
from managementconnector.service.servicemanager import ServiceManager
from managementconnector.platform.alarms import MCAlarm
from managementconnector.platform.system import System
from cafedynamic.cafexutil import CafeXUtils
from managementconnector.platform.serviceutils import ServiceUtils
from managementconnector.lifecycle.lifecycleutils import LifecycleUtils
from managementconnector.service.crashmonitor import CrashMonitor

from base_platform.expressway.i18n import translate

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


# =============================================================================

class Deploy(object):
    """
    Deploy Management Connector
    """

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Deploy Management Connector Class'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self, config):
        """Deploy __init__"""
        DEV_LOGGER.debug('Detail="FMC_Lifecycle Deploy __init__ called"')

        self._oauth_init = False
        self._quit = False
        self._config = config
        self._poll_time = None
        self._error_poll_time = None
        self._alarms = MCAlarm(self._config)
        self._oauth = OAuth(self._config)

        self._service_manager = ServiceManager(self._config, self._oauth)
        self._crash_monitor = CrashMonitor(self._config)

        # Atlas
        self._atlas = Atlas(self._config)
        self._metrics = Metrics(self._config, self._oauth)

        self._system = System()

        self._registration_time_out_counter = 0

    # -------------------------------------------------------------------------

    def get_oauth(self):
        """ Get oauth object """
        return self._oauth

    # -------------------------------------------------------------------------

    def deploy_fusion(self):
        """
            Management Connector Deploy
        """

        DEV_LOGGER.info('Detail="FMC_Lifecycle ManagementConnector deploying with %s"' %
                        (self.is_undeploy_in_progress()))
        ADMIN_LOGGER.info('Detail="FMC_Lifecycle ManagementConnector deploying"')

        mc_type = ManagementConnectorProperties.SERVICE_NAME

        DEV_LOGGER.info('Detail="FMC_Lifecycle ManagementConnector Target_Type before %s"' % (
            self._config.read(ManagementConnectorProperties.TARGET_TYPE)))

        if self._config.read(ManagementConnectorProperties.TARGET_TYPE) == '':
            self._config.write_blob(ManagementConnectorProperties.TARGET_TYPE, 'c_mgmt')

        DEV_LOGGER.info('Detail="FMC_Lifecycle ManagementConnector Target_Type after the default %s"' % (
            self._config.read(ManagementConnectorProperties.TARGET_TYPE)))
        self._oauth_init = False

        # Process any TLP left behind in the downloads directory before we started up
        ServiceUtils.save_tlps_for_rollback(self._config,
                                            mc_type)

        # wait two seconds for startup, before posting
        time.sleep(2)

        if not System.get_platform_supported_status():
            self._alarms.raise_alarm('3e544328-598e-11e6-8b77-86f30ca893d3')
        else:
            self._alarms.clear_alarm("3e544328-598e-11e6-8b77-86f30ca893d3")

        if System.is_penultimate_version():
            self._alarms.raise_alarm("38d69632-5fd8-4b44-94d7-a517b8329eb8")
        else:
            self._alarms.clear_alarm("38d69632-5fd8-4b44-94d7-a517b8329eb8")

        metrics_counter = ManagementConnectorProperties.METRICS_STATUS_FILTER

        while True:
            if self.is_undeploy_in_progress():
                DEV_LOGGER.info('Detail="FMC_Lifecycle Received a quit signal, breaking out of polling and stopping."')
                # Resetting quit to initial state for re-deploy scenario
                self._quit = False
                return
            try:
                # Only want to post metric status every nth time
                # where n = ManagementConnectorProperties.METRICS_STATUS_FILTER
                send_status_metric = False

                if metrics_counter >= ManagementConnectorProperties.METRICS_STATUS_FILTER:
                    send_status_metric = True
                    metrics_counter = 0
                else:
                    metrics_counter = metrics_counter + 1

                if not CafeXUtils.is_backup_restore_occurring(DEV_LOGGER):
                    self._do_register_config_status(mc_type, send_status_metric)

            except Exception as error:  # pylint: disable=W0703
                DEV_LOGGER.error('Detail="Un-handled Exception occurred:%s, stacktrace=%s"' % (repr(error),
                                                                                               traceback.format_exc()))
                service = self._service_manager.get(mc_type)
                try:
                    self._metrics.send_error_metrics(self._oauth.get_header(), service, error=traceback.format_exc())
                except Exception as error:  # pylint: disable=W0703
                    DEV_LOGGER.error('Detail="Error sending un-handled exception to metrics. '
                                     'Exception:%s, stacktrace=%s"' % (repr(error), traceback.format_exc()))
            finally:
                LifecycleUtils.poll_sleep(self._config, ManagementConnectorProperties.POLL_TIME)

    # -------------------------------------------------------------------------

    def un_deploy_fusion(self):
        """ Un deploy hook """

        DEV_LOGGER.info('Detail="FMC_Lifecycle Management Connector un-deploying"')

        self._quit = True

        # No Longer Operational
        ServiceUtils.set_operational_state(False)

        fused = self._config.read(ManagementConnectorProperties.FUSED)

        # No Longer Fused - remove all packages
        if fused == "false":

            # Attempt Defuse 10 times
            for defuse_attempts in range(0, ManagementConnectorProperties.DEFUSE_ATTEMPT_LIMIT):
                # Has upgrade thread stopped
                if self._service_manager.is_upgrade_thread_running is False:
                    self._run_defuse(defuse_attempts)
                    break
                else:
                    # Try again in 1 seconds
                    DEV_LOGGER.info('Detail="FMC_Lifecycle Upgrade Thread still running - defuse_attempts %s"'
                                    % defuse_attempts)
                    time.sleep(1)

                    if defuse_attempts == ManagementConnectorProperties.DEFUSE_ATTEMPT_LIMIT - 1:
                        DEV_LOGGER.info('Detail="FMC_Lifecycle Forcing defuse after %s attempts."' % defuse_attempts)
                        # Defuse anyway with install thread running, after last attempt.
                        self._run_defuse(defuse_attempts)

        else:
            DEV_LOGGER.debug('Detail="FMC_Lifecycle Management Connector not removing Packages."')

        # Clear out the Config Cache
        self._config.clear_cache()
        System.delete_heartbeats()

        for thread in threading.enumerate():
            if thread.getName() == 'InstallThread':
                DEV_LOGGER.debug('Detail="FMC_Lifecycle Joining install thread"')
                thread.join(ManagementConnectorProperties.SHUT_DOWN_WAIT)
                DEV_LOGGER.info('Detail="FMC_Lifecycle Install Thread isAlive returns %s."' % (thread.is_alive()))
                break

        DEV_LOGGER.info('Detail="FMC_Lifecycle Management Connector un-deploying completed."')

    # -------------------------------------------------------------------------

    def _run_defuse(self, defuse_attempt):
        """ Run main defuse logic """
        DEV_LOGGER.info('Detail="FMC_Lifecycle Management Connector removing Packages on attempt %s"' % defuse_attempt)

        try:
            services = []
            # Remove any installed connectors
            installed_dependencies = CafeXUtils.get_installed_connectors(ManagementConnectorProperties.
                                                                         DEPENDENCY_PREFIX)
            installed_connectors = CafeXUtils.get_installed_connectors(ManagementConnectorProperties.
                                                                       CONNECTOR_PREFIX)
            currently_installed = []
            # Make sure Java is NOT removed last, but first, so we don't get the bug where we
            # delete the symlink /mnt/harddisk
            if installed_dependencies:
                currently_installed += installed_dependencies
            if installed_connectors:
                currently_installed += installed_connectors
            for connector in currently_installed:
                if connector not in ManagementConnectorProperties.SERVICE_LIST:
                    services.append(self._service_manager.get(connector))

            excluded_alarms = list()

            if services:
                for service in services:
                    service_name = service.get_name()
                    service_alarms = service.get_exclude_alarms()
                    if service_alarms:
                        excluded_alarms += service_alarms

                    if service_name not in ManagementConnectorProperties.SERVICE_LIST:
                        try:
                            DEV_LOGGER.info('Detail="FMC_Lifecycle Removing Service %s "' % service_name)

                            self._service_manager.purge(service_name)

                        except ServiceException as error:
                            DEV_LOGGER.error('Detail="FMC_Lifecycle Defuse Uninstall Error error=%s, stacktrace=%s"' %
                                             (error, traceback.format_exc()))

            # on deregister, remove certs from CA, if there
            self._config.write_static(ManagementConnectorProperties.ADD_FUSION_CERTS, "false")

            # Clear away and Mgmt Connector Alarms
            self._alarms.clear_alarms(excluded_alarms)
            self._delete_backup_tlps()

            # Cleanup old event files on un-register
            ServiceUtils.remove_upgrade_events_file()
        finally:
            # Blow away Cafe Blob, This will be replicated across the cluster and remove cache
            self._config.delete_blob()

    # -------------------------------------------------------------------------

    def _do_register_config_status(self, mc_type, send_status_metric=False):
        """
            _do_register_config_status
        """
        op_status = False
        try:  # pylint: disable=R0101
            stopped_processes = []
            DEV_LOGGER.debug('Detail="_do_register_config_status: service. name %s send_status_metric %s"'
                             % (mc_type, send_status_metric))

            service = self._service_manager.get(mc_type)

            system_mem = System.get_system_mem()
            DEV_LOGGER.info('Detail="Resource usage expressway. '
                            'Current CPU usage [%s%%], current RAM usage[%s%%, %s GB]"' %
                            (self._system.get_system_cpu(),
                             system_mem['percent'],
                             system_mem['total_gb']))

            if not self.is_undeploy_in_progress():
                if not self._oauth_init:
                    self._oauth_init = self._oauth.init()
            else:
                DEV_LOGGER.debug('Detail="Leaving  _do_register_config_status as defuse in progress"')
                return

            self._crash_monitor.crash_check(self._oauth, self._config)

            if not self.is_undeploy_in_progress():
                self._metrics.send_metrics(self._oauth.get_header(),
                                           service,
                                           send_status=send_status_metric)

                # Get the Provisioning Data
                response = self._atlas.register_connector(self._oauth.get_header(), service)
            else:

                DEV_LOGGER.debug('Detail="Leaving  _do_register_config_status as defuse in progress"')

                return

            # get connector config and register and post connector status
            connectors_config = self._get_config(response['provisioning'])

            if len(connectors_config) == 1:
                self._alarms.raise_alarm('a144127e-57a5-11e5-8ccb-3417ebbf769a')
            else:
                self._alarms.clear_alarm('a144127e-57a5-11e5-8ccb-3417ebbf769a')

            # Post Status
            for config in connectors_config:
                if config['name'] not in ManagementConnectorProperties.SERVICE_LIST:
                    # Register Connector Details
                    dependency = 'dependency' in config
                    service = self._service_manager.get(config['name'], dependency)

                    # Check Connector Status
                    if service and service.get_composed_status() == "stopped" \
                            and not service.get_status()['enabled'] == "disabled":
                        stopped_processes.append(config['display_name'])

                    # No Post Status for Dependencies
                    if service and not isinstance(service, ServiceDependency):
                        if not self.is_undeploy_in_progress():
                            self._atlas.register_connector(self._oauth.get_header(), service)
                            self._metrics.send_metrics(self._oauth.get_header(), service, send_status_metric)
            if stopped_processes:
                DEV_LOGGER.debug('Detail="FMC_Lifecycle Stopped processes %s"', stopped_processes)
            self._process_stopped_alarm(stopped_processes,
                                        '47fd43b0-755a-463f-9899-63f589a2d882',
                                        'err.PROCESS_STOPPED_ERROR_%s')

            # Start the thread for install/upgrade tasks
            if self._is_upgrade_allowed():
                self._service_manager.is_upgrade_thread_running = True
                threading.Thread(target=self._service_manager.upgrade_worker, name='InstallThread',
                                 args=(connectors_config,)).start()

            # if we get to here we can clear HTTPError and URLError errors

            self._alarms.clear_alarm("cbbf0813-09cb-4e23-9182-f3996d24cc9e")
            self._alarms.clear_alarm("ba883968-4b5a-4f83-9e71-50c7d7621b44")
            self._alarms.clear_alarm("635afce6-0ae8-4b84-90f5-837a2234002b")
            self._alarms.clear_alarm("802e15e0-31cf-4356-8b99-b07d364553f9")
            self._alarms.clear_alarm("995ec68e-4c6a-4b16-a615-fdd6b6fe4b43")
            self._alarms.clear_alarm("233f0c18-9c8f-41ba-8800-93937540afe8")
            self._alarms.clear_alarm("b31d5f2c-d183-4559-97e2-d9da9572af26")
            self._alarms.clear_alarm("29417128-4e59-4ae2-802e-77135c6a7fc9")
            self._alarms.clear_alarm("dc463c51-d111-4cc5-9eba-9e09292183b0")

            self._registration_time_out_counter = 0

        except CertificateExceptionFusionCA as cert_exception:
            DEV_LOGGER.error('Detail="CertificateExceptionFusionCA cert_exception=%s, stacktrace=%s"'
                             % (cert_exception, traceback.format_exc()))
            self._alarms.raise_alarm('635afce6-0ae8-4b84-90f5-837a2234002b', [Http.error_url])

        except CertificateExceptionNameMatch as cert_exception:
            DEV_LOGGER.error('Detail="CertificateExceptionNameMatch cert_exception=%s, stacktrace=%s"'
                             % (cert_exception, traceback.format_exc()))
            self._alarms.raise_alarm("802e15e0-31cf-4356-8b99-b07d364553f9", [Http.error_url])

        except CertificateExceptionInvalidCert as cert_exception:
            DEV_LOGGER.error('Detail="CertificateExceptionInvalidCert cert_exception=%s, stacktrace=%s"'
                             % (cert_exception, traceback.format_exc()))
            self._alarms.raise_alarm('995ec68e-4c6a-4b16-a615-fdd6b6fe4b43', [Http.error_url])

        except jsonschema.ValidationError as validation_exc:
            DEV_LOGGER.error('Detail="jsonschema.ValidationError exception=%s, stacktrace=%s"'
                             % (validation_exc, traceback.format_exc()))
            self._alarms.raise_alarm('b31d5f2c-d183-4559-97e2-d9da9572af26', [Http.error_url])

        except ValueError as value_error:
            DEV_LOGGER.error('Detail="ValueError exception=%s, stacktrace=%s"'
                             % (value_error, traceback.format_exc()))
            self._alarms.raise_alarm('b31d5f2c-d183-4559-97e2-d9da9572af26', [Http.error_url])

        except KeyError as key_error:
            DEV_LOGGER.error('Detail="KeyError when mapping key=%s, stacktrace=%s"'
                             % (key_error, traceback.format_exc()))
            self._alarms.raise_alarm('dc463c51-d111-4cc5-9eba-9e09292183b0')

        except urllib_error.HTTPError as http_error:
            DEV_LOGGER.debug('Detail="FMC_Lifecycle HTTP ERROR Triggered%s"', http_error)
            self._handle_http_exception(http_error, service)

        except urllib_error.URLError as url_error:
            DEV_LOGGER.error('Detail="URLError error:%s, %s"' % (url_error, url_error.reason))
            self._alarms.raise_alarm("ba883968-4b5a-4f83-9e71-50c7d7621b44", [Http.error_url])

        except ssl.SSLError as ssl_error:
            poll_time = self._config.read(ManagementConnectorProperties.POLL_TIME,
                                          ManagementConnectorProperties.DEFAULT_POLL_TIME)
            if "timed out" in str(ssl_error.message):
                self._registration_time_out_counter += 1
                if self._registration_time_out_counter <= ManagementConnectorProperties.REGISTRATION_TIME_OUT_LIMIT:
                    DEV_LOGGER.error('Detail="Timed out contacting: %s"' % Http.error_url)
                else:
                    DEV_LOGGER.error('Detail="Timed out %d times contacting: %s, raising alarm"'
                                     % (self._registration_time_out_counter, Http.error_url))
                    self._alarms.raise_alarm("233f0c18-9c8f-41ba-8800-93937540afe8", [Http.error_url, poll_time])
            else:
                DEV_LOGGER.error('Detail="SSLError occurred contacting: %s Message: %s"'
                                 % (Http.error_url, ssl_error.message))
                self._alarms.raise_alarm("233f0c18-9c8f-41ba-8800-93937540afe8", [Http.error_url, poll_time])

        except (TypeError, RuntimeError) as error:
            exc = traceback.format_exc()
            DEV_LOGGER.error('Detail="StandardError occurred:%s, stacktrace=%s"' % (repr(error), exc))
            service = self._service_manager.get(mc_type)
            self._metrics.send_error_metrics(self._oauth.get_header(), service, error=exc)

        except http.client.HTTPException as http_exception:
            # Need to send metric here with low level exception, e.g. BadStatusLine
            DEV_LOGGER.error('Detail="HTTPException occurred, exception=%s, stacktrace=%s"'
                             % (http_exception.__class__.__name__, traceback.format_exc()))
            self._alarms.raise_alarm("29417128-4e59-4ae2-802e-77135c6a7fc9",
                                     [http_exception.__class__.__name__, Http.error_url])

        else:
            op_status = True

        finally:
            ServiceUtils.set_operational_state(op_status, True)

    # -------------------------------------------------------------------------

    def _process_stopped_alarm(self, stopped_connectors, alarm_id, msg):
        """Responsible for clearing/raising alarms"""
        if len(stopped_connectors) == 0:
            self._alarms.clear_alarm(alarm_id)
        else:
            # Don't raise stopped alarm for a connector if its dependencies are being installed
            installing_dependencies = []
            connectors_with_dependencies = ManagementConnectorProperties.DEPENDENCY_MAP
            for connector in stopped_connectors:
                if connector in connectors_with_dependencies:
                    for dependency in connectors_with_dependencies[connector]:
                        if ServiceUtils.is_installing(dependency) is not None:
                            installing_dependencies.append(connector)
                            break
            for connector in installing_dependencies:
                stopped_connectors.remove(connector)
            if not len(stopped_connectors) > 0:
                return

            description_text = ''
            # All the stopped Alarms take display name parameter
            for connector in stopped_connectors:
                desc_line = translate(msg) % (str(connector))
                description_text = description_text + desc_line + "\n"

            DEV_LOGGER.debug('Detail="_process_stopped_alarm: description_text=%s"' % description_text)

            self._alarms.raise_alarm(alarm_id, [description_text])

    # -------------------------------------------------------------------------

    def _get_config(self, mc_provisioning):
        """
            _get_config
        """
        if mc_provisioning is not None:

            connectors_config, entitled_services = Atlas.parse_mc_config(mc_provisioning)
            dependency_config = Atlas.parse_dependency_config(mc_provisioning)
            DEV_LOGGER.debug('Detail="_get_config: management connector config=%s"' % connectors_config)

            cached_services = self._config.read(ManagementConnectorProperties.ENTITLED_SERVICES)
            if Deploy.entitled_services_changed(cached_services, entitled_services):
                DEV_LOGGER.debug('Detail="_get_config: Writing entitled services, cache does not match new."')
                self._config.write_blob(ManagementConnectorProperties.ENTITLED_SERVICES, entitled_services)

            self._overlay_blacklist(connectors_config)

            return dependency_config + connectors_config
        else:
            return []

    def _overlay_blacklist(self, connectors_config):
        """
        overlay blacklist
        """

        black_list = self._config.read(ManagementConnectorProperties.INSTALL_BLACK_LIST, {})
        previous_list = ServiceUtils.get_previous_versions(self._config)
        current_list = ServiceUtils.get_current_versions(self._config)

        # can only black list connectors, not dependencies
        DEV_LOGGER.debug('Detail="_overlay_blacklist: rollback: config=%s, black_list=%s, previous_list=%s"' %
                         (connectors_config, black_list, previous_list))
        fms_requesting_black_listed = []
        if len(black_list) > 0:
            for connector in connectors_config:
                name = connector['name']
                DEV_LOGGER.debug('Detail="_overlay_blacklist: rollback: name in black_list = %d"'
                                 % (name in black_list))
                if name in black_list and connector['version'] == black_list[name]['version']:
                    # found match, we have to black list
                    fms_requesting_black_listed.append({"name": connector['display_name'],
                                                        "version": connector['version']})
                    if name in previous_list:
                        DEV_LOGGER.info('Detail="rollback: _get_config: Config from FMS has been blacklisted, '
                                        'use previous version instead. black_list, name=%s, version=%s"'
                                        % (name, connector['version']))
                        connector['url'] = previous_list[name]['url']
                        connector['version'] = previous_list[name]['version']
                    else:
                        DEV_LOGGER.info('Detail="rollback: _get_config: Config from FMS has been blacklisted, '
                                        'NO previous version. black_list, name=%s, version=%s, current_list[name]=%s "'
                                        % (name, connector['version'], current_list[name]))
                        connector['url'] = current_list[name]['url']
                        connector['version'] = current_list[name]['version']
                else:
                    DEV_LOGGER.debug('Detail="rollback: _get_config: version=%s, of %s is not blacklisted"' %
                                     (connector['name'], connector['version']))

        # handle alarms

        if self._alarms.is_raised("a2a259b5-93a6-4a1a-b03d-36ac0987e6db"):
            # in all cases lower alarm
            DEV_LOGGER.debug('Detail="rollback: _get_config: lower alarm"')
            self._alarms.clear_alarm("a2a259b5-93a6-4a1a-b03d-36ac0987e6db")

        if len(fms_requesting_black_listed):
            # raise alert alarm
            alarm_list = []
            for matching_blacklist in fms_requesting_black_listed:
                alarm_list.append(matching_blacklist['name'] + " " + matching_blacklist['version'])

            alarm_txt = ', '.join(alarm_list)
            DEV_LOGGER.info('Detail="rollback: _get_config: raise alarm fms_requesting_black_listed=%s, alarm_txt=%s"' %
                            (fms_requesting_black_listed, alarm_txt))
            self._alarms.raise_alarm("a2a259b5-93a6-4a1a-b03d-36ac0987e6db", [alarm_txt])

    @staticmethod
    def entitled_services_changed(cached_services, new_services):
        """ Compare cached services versus new config """

        if not cached_services:  # cached_services can be empty dict so checking against None is invalid
            cached_services = []

        DEV_LOGGER.debug('Detail="Comparing entitled services: cached list = %s, new_services = %s"'
                         % (cached_services, new_services))

        return Deploy.cmp(cached_services, new_services) != 0

    # -------------------------------------------------------------------------
    @staticmethod
    def cmp(x, y):
        x.sort(key=lambda d: sorted(list(d.items())))
        y.sort(key=lambda d: sorted(list(d.items())))
        """
        Replacement for built-in function cmp that was removed in Python 3

        Compare the two objects x and y and return an integer according to
        the outcome. The return value is zero if x == y
        and strictly positive if x > y or negative x < y.
        In our case we are returning positive for both (x > y and x < y)
        """

        if x == y:
            return 0
        else:
            return 1

    def _is_upgrade_allowed(self):
        """
        Returns true or false if an upgrade worker is allowed to run.
        Checks if the upgrade thread is already running and if a backup-restore is occurring
        """

        restore_occurring = CafeXUtils.is_backup_restore_occurring(DEV_LOGGER)
        upgrade_allowed = not self._service_manager.is_upgrade_thread_running and not restore_occurring \
                          and not self.is_undeploy_in_progress()

        DEV_LOGGER.debug('Detail="_is_upgrade_allowed: %s thread running: %s Backup restore occurring: %s '
                         'UnDeploying: %s "' % (upgrade_allowed, self._service_manager.is_upgrade_thread_running,
                                                restore_occurring, self.is_undeploy_in_progress()))

        return upgrade_allowed

    # -------------------------------------------------------------------------

    def _delete_backup_tlps(self):
        """
        Purge all backup TLPs from the filesystem except for the current c_mgmt.tlp
        """
        self._system.delete_tlps(ManagementConnectorProperties.INSTALL_CURRENT_DIR,
                                 exclude_list=[ManagementConnectorProperties.SERVICE_NAME])
        self._system.delete_tlps(ManagementConnectorProperties.INSTALL_PREVIOUS_DIR)

    # -------------------------------------------------------------------------

    def is_undeploy_in_progress(self):
        """
        Indicates whether there is a defuse in progress
        """
        return self._quit

    # -------------------------------------------------------------------------

    def _handle_http_exception(self, http_error, service):
        """ Handle Http Exception """

        handled = False
        # May be some interesting data in the Error Response
        try:
            if hasattr(http_error, 'code'):
                handled = Deploy._handle_cloud_deregister(service.get_name(), http_error.code, self._config)

            if not handled:
                if hasattr(http_error, 'read'):
                    error_response = http_error.read()
                    DEV_LOGGER.error('Detail="HTTPError http_error reason =%s, response = %s,  stack trace=%s"' %
                                     (http_error.reason, error_response, traceback.format_exc()))
                else:
                    DEV_LOGGER.error('Detail="HTTPError http_error reason =%s,  stack trace=%s"' %
                                     (http_error.reason, traceback.format_exc()))
        except IOError:
            # Lets not bother with error response - but log what we have
            DEV_LOGGER.error('Detail="HTTPError http_error reason =%s, stack trace=%s"' %
                             (http_error.reason, traceback.format_exc()))
        if not handled:
            self._alarms.raise_alarm("cbbf0813-09cb-4e23-9182-f3996d24cc9e", [http_error.code, http_error.url])

    # -------------------------------------------------------------------------

    @staticmethod
    def _handle_cloud_deregister(service_name, error_code, config):
        """ Handle cloud deregister scenario """

        handled = False
        master_c_mgmt = System.am_i_master() and service_name == ManagementConnectorProperties.SERVICE_NAME
        if error_code == 410:
            # Prevent error logs or alarm being raised for 410 scenario.
            handled = True
            if master_c_mgmt:
                Deploy.trigger_deregister(config)

        return handled

    # -------------------------------------------------------------------------

    @staticmethod
    def trigger_deregister(config):
        """ Initiate deregister across the cluster """
        DEV_LOGGER.info('Detail="Trigger deregister across the cluster"')

        fused = config.read(ManagementConnectorProperties.FUSED)
        targetType = config.read(ManagementConnectorProperties.TARGET_TYPE)

        # Only trigger a defuse - if in defused state
        if fused == "true":
            DEV_LOGGER.info('Detail="Defuse before its true"')
            config.write_blob(ManagementConnectorProperties.FUSED, 'false')
            DEV_LOGGER.info('Detail="Defuse before its false now"')
            if targetType == config.read(ManagementConnectorProperties.SERVICE_NAME):
                config.write_blob(ManagementConnectorProperties.ENABLED_SERVICES_STATE,
                                  {config.read(ManagementConnectorProperties.SERVICE_NAME): 'false'})
            else:
                config.write_blob(ManagementConnectorProperties.ENABLED_SERVICES_STATE,
                                  {config.read(ManagementConnectorProperties.TARGET_TYPE): 'false'})
            # delete create configured file (TBD - This block could be removed as the file is no longer created)
            if os.path.isfile(ManagementConnectorProperties.CONFIG_FILE_STATUS_MGMT):
                os.remove(ManagementConnectorProperties.CONFIG_FILE_STATUS_MGMT)
        else:
            DEV_LOGGER.info('Detail="Ignoring deregister - not in fused state"')

    # -------------------------------------------------------------------------
