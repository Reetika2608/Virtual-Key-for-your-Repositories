"""
    Utility class to interact with Services
"""

import os
import shutil
import time
import datetime
import ni.utils.i18n

from ni.cafedynamic.cafexutil import CafeXUtils
from ni.managementconnector.config import jsonhandler
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from ni.managementconnector.platform.system import System


DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


class ServiceUtils(object):
    """
    Utilities methods for Services
    """

    # -------------------------------------------------------------------------

    @staticmethod
    def remove_installing_state(name):
        """ Remove installing state file """
        DEV_LOGGER.info('Detail="remove_installing_state: Removing installing state file for %s"' % name)
        jsonhandler.delete_file(ManagementConnectorProperties.INSTALLING_STATUS_FILE)

    # -------------------------------------------------------------------------

    @staticmethod
    def set_installing_state(name, version, state):
        """ Set the installing state of the service """
        DEV_LOGGER.info('Detail="set_installing_state: name: %s, version: %s, state: %s"' % (name, version, state))
        jsonhandler.write_json_file(ManagementConnectorProperties.INSTALLING_STATUS_FILE,
                                    {name: state, 'version': version})

    # -------------------------------------------------------------------------

    @staticmethod
    def is_installing(name):
        """ returns installing status of service or None """

        installing_state = None

        try:
            # if file does not exists not installing
            if not os.path.isfile(ManagementConnectorProperties.INSTALLING_STATUS_FILE):
                return installing_state

            state = jsonhandler.read_json_file(ManagementConnectorProperties.INSTALLING_STATUS_FILE)

            if state:
                if name in state:
                    DEV_LOGGER.debug('Detail="is_installing: Setting installing state for: %s to: %s"'
                                     % (name, state[name]))
                    installing_state = state[name]
        except IOError, ioe:
            DEV_LOGGER.error('Detail="is_installing: error reading installing state: %s "' % (ioe))

        return installing_state

    # -------------------------------------------------------------------------

    @staticmethod
    def get_version(name):
        """ get version of connector - installed or installing """

        version = CafeXUtils.get_package_version(name)
        if not version:
            installing_details = jsonhandler.read_json_file(ManagementConnectorProperties.INSTALLING_STATUS_FILE)
            if installing_details:
                if 'version' in installing_details and name in installing_details:
                    version = installing_details['version']

        return version

    # -------------------------------------------------------------------------

    @staticmethod
    def map_cluster_to_service(config):
        """
            Map the Cluster level enablement flag to the service configuration entry.
            This will allow services to start accross a cluster and get mapped to each node.
        """

        # Currently enabled service
        enabled_service = config.read(ManagementConnectorProperties.ENABLED_SERVICES)

        # Service states we want to apply
        enabled_services_states = config.read(ManagementConnectorProperties.ENABLED_SERVICES_STATE)

        if enabled_service is not None and enabled_services_states:
            for name, enabled in enabled_services_states.items():
                if name != ManagementConnectorProperties.SERVICE_NAME:
                    # If the service is in an installing state do not apply service mode state, otherwise
                    #  mimic blob enable flag to service flag, if Name is a new entry or it's value has changed
                    if (name not in enabled_service and enabled == "true") or (name in enabled_service and enabled == "false"):
                        if not CafeXUtils.is_package_installing(name, DEV_LOGGER):
                            if ServiceUtils.blob_mode_on(name, enabled_services_states):
                                DEV_LOGGER.info('Detail="Service: setting connector:%s, mode: on"' % name)
                                config.write("/configuration/service/name/%s" % name, {"mode": "on"})
                            else:
                                DEV_LOGGER.info('Detail="Service: setting connector:%s, mode: off"' % name)
                                config.write("/configuration/service/name/%s" % name, {"mode": "off"})

                            # Ensure service mode change gets handled.
                            ServiceUtils.request_service_change(config)
                        else:
                            DEV_LOGGER.debug('Detail="Service: setting connector:%s in installing state"' % name)
                    else:
                        DEV_LOGGER.debug('Detail="Service: not applying mode, no change. %s : %s : %s "' %
                                         (name, enabled, (name in enabled_service)))

    # -------------------------------------------------------------------------

    @staticmethod
    def blob_mode_on(name, enabled_services_states):
        """ Checks if service mode is on in blob table """
        blob_on = False
        if enabled_services_states:
            for service_name, enabled in enabled_services_states.items():
                DEV_LOGGER.debug('Detail="Blob Mode Check name: %s state: %s"' % (name, enabled))
                if service_name == name and enabled == "true":
                    blob_on = True
                    break
        return blob_on

    # -------------------------------------------------------------------------

    @staticmethod
    def request_service_change(config):
        """ Trigger a service change update to start incorrectly stopped service. """
        DEV_LOGGER.debug('Detail="trigger_service_change: file: %s content: %s"' %
                         (ManagementConnectorProperties.SERVICE_CHANGE_TRIGGER, {}))

        for i in range(15):
            if ServiceUtils.is_service_descrepency(config):
                DEV_LOGGER.debug('Detail="request_service_change: retry state read attempt: %s"' % (i))
                time.sleep(1)
            else:
                return

        DEV_LOGGER.info('Detail="trigger_service_change: proceed with trigger"')
        jsonhandler.write_json_file(ManagementConnectorProperties.SERVICE_CHANGE_TRIGGER, {})

    @staticmethod
    def is_service_descrepency(config):
        """ is_service_descrepency """
        ret_val = False
        enabled_services_states = config.read(ManagementConnectorProperties.ENABLED_SERVICES_STATE)
        if enabled_services_states:
            for name, enabled in enabled_services_states.items():
                if name != ManagementConnectorProperties.SERVICE_NAME:
                    if (enabled == "true") != CafeXUtils.is_connector_running(name, DEV_LOGGER):
                        DEV_LOGGER.debug('Detail="is_service_descrepency: found descrepency: name:%s, enabled=%s "' % (name, enabled))
                        ret_val = True
        DEV_LOGGER.debug('Detail="is_service_descrepency: enabled_services_states: %s, ret_val=%s "' % (enabled_services_states, ret_val))
        return ret_val

    # -------------------------------------------------------------------------

    @staticmethod
    def save_tlps_for_rollback(config, name):
        """
            save_tlps_for_rollback
            save off tlp to current/previous directories
        """

        downloaded_tlp = ManagementConnectorProperties.INSTALL_DOWNLOAD_FILE % name
        current_versions = ServiceUtils.get_current_versions(config)
        previous_versions = ServiceUtils.get_previous_versions(config)
        installed_version = CafeXUtils.get_package_version(name)
        black_listed_versions = config.read(ManagementConnectorProperties.INSTALL_BLACK_LIST, {})
        DEV_LOGGER.info('Detail="save_tlps_for_rollback: start: rollback related code: current name=%s, installed_version=%s, current versions=%s, previous versions=%s, blacklisted version=%s"' %
                        (name, installed_version, current_versions, previous_versions, black_listed_versions))

        current = current_versions[name] if name in current_versions else None
        previous = previous_versions[name] if name in previous_versions else None

        if os.path.isfile(downloaded_tlp):
            if name in black_listed_versions and current_versions[name]['version'] == black_listed_versions[name]['version']:
                # Rollback scenario. Delete whatever is at current and the new TLP becomes the stashed current.
                # If we have the same TLP at previous as we just moved to current (Possible but not guaranteed) then
                # then _audit_backup_tlps will tidy it up
                ServiceUtils._delete_current_connector_tlp(name)
                current_tlp = '{}/{}_{}{}'.format(ManagementConnectorProperties.INSTALL_CURRENT_DIR,
                                                  name,
                                                  installed_version,
                                                  ManagementConnectorProperties.PACKAGE_EXTENSION)
                shutil.move(downloaded_tlp, current_tlp)
            else:
                # This is a stadard TLP install or upgrade
                ServiceUtils._process_tlps(name, previous, current, installed_version)

        ServiceUtils._audit_backup_tlps(config, name)

    # -------------------------------------------------------------------------

    @staticmethod
    def _process_tlps(name, previous, current, installed):
        """_process_tlps"""

        # local_current & local_previous are not used for anything other than unit tests
        local_current = dict(current) if current else dict()
        local_previous = dict(previous) if previous else dict()

        downloaded_tlp = ManagementConnectorProperties.INSTALL_DOWNLOAD_FILE % name

        DEV_LOGGER.info('Detail="_process_tlps: Started: previous stashed version: %s current stashed version: %s"'
                        % (local_previous, local_current))

        if not current:
            # We have no current version of this connector- save it off to current
            current_tlp = '{}/{}_{}{}'.format(ManagementConnectorProperties.INSTALL_CURRENT_DIR,
                                              name,
                                              installed,
                                              ManagementConnectorProperties.PACKAGE_EXTENSION)
            shutil.move(downloaded_tlp, current_tlp)
            local_current['version'] = installed
            local_current['url'] = '{}/{}_{}{}'.format(ManagementConnectorProperties.INSTALL_CURRENT_DIR,
                                                       name,
                                                       installed,
                                                       ManagementConnectorProperties.PACKAGE_EXTENSION)
            DEV_LOGGER.info('Detail="_process_tlps: save TLP for rollback: copy %s tmp TLP (%s) to new current tlp location (%s)"' %
                            (name, downloaded_tlp, current_tlp))
        else:
            if current['version'] != installed:
                # The current version we have stashed is different to what we just installed - cycle the existing
                # current to previous and save off the new one in current
                current_tlp_path = current['url']
                ServiceUtils._delete_previous_connector_tlp(name)
                shutil.move(current_tlp_path, ManagementConnectorProperties.INSTALL_PREVIOUS_DIR)
                current_tlp = '{}/{}_{}{}'.format(ManagementConnectorProperties.INSTALL_CURRENT_DIR,
                                                  name,
                                                  installed,
                                                  ManagementConnectorProperties.PACKAGE_EXTENSION)
                shutil.move(downloaded_tlp, current_tlp)
                local_previous['version'] = current['version']
                local_previous['url'] = '{}/{}_{}{}'.format(ManagementConnectorProperties.INSTALL_PREVIOUS_DIR,
                                                            name,
                                                            current['version'],
                                                            ManagementConnectorProperties.PACKAGE_EXTENSION)
                local_current['version'] = installed
                local_current['url'] = '{}/{}_{}{}'.format(ManagementConnectorProperties.INSTALL_CURRENT_DIR,
                                                           name,
                                                           installed,
                                                           ManagementConnectorProperties.PACKAGE_EXTENSION)
                DEV_LOGGER.info('Detail="_process_tlps: save TLPs for rollback: copy %s tmp TLP (%s) to new current tlp location (%s)"' %
                                (name, downloaded_tlp, current_tlp))
            else:
                # The current verson we have stashed is the same as what we just installed. Do nothing to
                # the stash of tlps and tidy up the downloaded connector.
                if os.path.isfile(downloaded_tlp):
                    os.remove(downloaded_tlp)

        DEV_LOGGER.info('Detail="_process_tlps: Completed: previous stashed version: %s current stashed version: %s"'
                        % (local_previous, local_current))

        return local_previous, local_current

    @staticmethod
    def _audit_backup_tlps(config, name):
        """ audit current and previous version tlps for a service and delete previous if both are the same """
        current_versions = ServiceUtils.get_current_versions(config)
        previous_versions = ServiceUtils.get_previous_versions(config)
        current = current_versions[name] if name in current_versions else None
        previous = previous_versions[name] if name in previous_versions else None

        if not current or not previous:
            return

        if current['version'] == previous['version']:
            DEV_LOGGER.warning('Detail="_audit_backup_tlps: Current tlp(%s) and previous tlp(%s) are the same version. Deleting duplicate previous tlp"' %
                               (current['url'], previous['url']))
            ServiceUtils._delete_previous_connector_tlp(name)

    @staticmethod
    def get_current_versions(config):
        """ get_current_versions """

        return ServiceUtils.get_version_information(config, ManagementConnectorProperties.INSTALL_CURRENT_DIR)

    @staticmethod
    def get_previous_versions(config):
        """ get_previous_versions """

        return ServiceUtils.get_version_information(config, ManagementConnectorProperties.INSTALL_PREVIOUS_DIR)

    @staticmethod
    def get_version_information(config, directory):
        """ get version information from directory """

        versions = dict()

        entitled_services = config.read(ManagementConnectorProperties.ENTITLED_SERVICES)
        DEV_LOGGER.debug('Detail="get_version_information: for %s"' % entitled_services)

        if entitled_services:
            for service in entitled_services:
                file_path = System.get_tlp_filepath(directory, service['name'])
                if file_path:
                    version = System.get_version_from_file(file_path)
                    versions[service['name']] = {"url": file_path, "version": version}

        return versions

    @staticmethod
    def _remove_previous_version(name, previous_versions):
        ''' _removePreviousVersion '''
        del previous_versions[name]
        ServiceUtils._delete_previous_connector_tlp(name)

    @staticmethod
    def _delete_previous_connector_tlp(name):
        ''' _removePreviousVersion '''
        tlp_file = System.get_previous_tlp_filepath(name)
        if tlp_file is not None and os.path.isfile(tlp_file):
            DEV_LOGGER.info('Detail="_delete_previous_connector_tlp: rollback related code: _remove_previous_version remove file:%s"' % tlp_file)
            os.remove(tlp_file)

    @staticmethod
    def _delete_current_connector_tlp(name):
        ''' _removeCurrentVersion '''
        tlp_file = System.get_current_tlp_filepath(name)
        if tlp_file is not None and os.path.isfile(tlp_file):
            DEV_LOGGER.info('Detail="_delete_current_connector_tlp: rollback related code: _remove_current_version remove file:%s"' % tlp_file)
            os.remove(tlp_file)

    @staticmethod
    def get_service_start_time(connector_name):
        ''' get_service_start_time '''
        pid_file_path = '/var/run/%s.pid' % connector_name

        if not os.path.isfile(pid_file_path):
            return ''

        file_time = os.path.getmtime(pid_file_path)

        return datetime.datetime.utcfromtimestamp(file_time).strftime('%Y-%m-%dT%H:%M:%SZ')

    @staticmethod
    def set_operational_state(state, silent=False):
        ''' Set Mgmt Connector Operation State '''

        if not silent:
            DEV_LOGGER.info('Detail="set_operational_state: setting state to :%s"' % state)

        if state is True:

            jsonhandler.write_json_file(ManagementConnectorProperties.STATUS_FILE,
                                        ManagementConnectorProperties.WHITEBOX_STATUS)
        else:
            jsonhandler.delete_file(ManagementConnectorProperties.STATUS_FILE)

    # -------------------------------------------------------------------------
    @staticmethod
    def get_alarms(service, prefix_link, permitted=True, include_suppressed=True):
        """Get any alarm information for the service"""

        DEV_LOGGER.debug('Detail="get_alarms: include_suppressed=%s"', include_suppressed)
        rtn_list = []
        all_alarms = service.get_alarms()

        alarm_list = ServiceUtils.filter_alarm_list(all_alarms, service, permitted, include_suppressed)

        for alarm in alarm_list:
            # Localise title and description
            title = ni.utils.i18n.translate("alm." + alarm['uuid'] + ".title")
            description = ni.utils.i18n.translate("alm." + alarm['uuid'] + ".description")

            param_list = alarm['parameters']

            # Default to description
            formatted_description = description

            # Empty Param = []
            if len(param_list):
                try:
                    formatted_description = description % tuple(param_list)

                except TypeError, ex:
                    # If an exception thrown, unformatted description will be sent to Atlas, this check here in case
                    # Connectors are not generating (formatting) alarms correctly.
                    DEV_LOGGER.error('Detail="_get_alarms:  formatting error with alarm %s with exception %s"' %
                                     (alarm['id'], ex))
            else:
                DEV_LOGGER.debug('Detail="_get_alarms:  No Params - No Formatting Required"')

            # US7794 (alarm solution) & DE1774 (rework of format)
            # *** alarm solution ***
            # In some cases [[PRODUCT]] is in alarm
            # replace this with SYSTEM_TOKEN which could be "ExpresswayC" or "VCSC"
            solution = ni.utils.i18n.translate("alm." + alarm['uuid'] + ".solution")
            if solution.find('[[PRODUCT]]'):
                solution.replace('[[PRODUCT]]', ni.utils.i18n.translate("SYSTEM_TOKEN"))
            DEV_LOGGER.debug('Detail="_get_alarms: solution %s"' % (solution))

            # US7794 (alarm solution) & DE1774 (rework of format)
            # *** alarm solution_links ***
            # there are 3 types of links
            # a) none: ""
            # b) entire solution is link:
            # c) embedded links: example "Check %s for settings"

            solution_links = alarm['solution_links']
            solution_replacement_values = []

            # case a - none (Happens when solution_links is None)
            # solution = 'Check the following...'
            # solution_replacement_values = []
            if isinstance(solution_links, list):
                # case c - embedded links
                # solution = 'Check %s and then check %s'
                # solution_replacement_values = [{'text': 'Alarm text','link': 'Alarm link'}, {'text': 'Alarm text','link': 'Alarm link'}]
                # iterate over array where
                # i = Text (needs to be translated)
                # i+1 = Link (needs to be prefixed)
                for i in range(len(solution_links)/2):
                    index = i*2
                    text = ni.utils.i18n.translate(solution_links[index])
                    if 'http' in solution_links[index+1] and '/' in solution_links[index+1]:
                        link = solution_links[index+1]
                    else:
                        link = prefix_link + solution_links[index+1]
                    solution_replacement_values.append({'text': text, 'link': link})
            else:
                # case b - entire solution is a link
                # solution = '%s'
                # solution_replacement_values = [{'text': 'Alarm text','link': 'Alarm link'}]
                if len(solution_links) > 0:
                    if 'http' in solution_links and '/' in solution_links:
                        link = solution_links
                    else:
                        link = prefix_link + solution_links
                    solution_replacement_values.append({'text': solution, 'link': link})
                    solution = '%s'

            DEV_LOGGER.debug('Detail="_get_alarms:  solution_links:%s"' % (solution_links))

            alarm_dict = {'id': alarm['id'], 'title': title, 'description': formatted_description,
                          'first_reported': datetime.datetime.utcfromtimestamp(float(alarm['first_reported'])).isoformat(),
                          'last_reported': datetime.datetime.utcfromtimestamp(float(alarm['last_reported'])).isoformat(),
                          'severity': alarm['severity'],
                          'solution': solution, 'solution_replacement_values': solution_replacement_values
                          }

            rtn_list.append(alarm_dict)

        if rtn_list:
            DEV_LOGGER.debug('Detail="_get_alarms:  alarm_list is %s, for service %s "' % (rtn_list, service.get_name()))

        return rtn_list

    # -------------------------------------------------------------------------

    @staticmethod
    def filter_alarm_list(all_alarms, service, include_regular=True, include_suppressed=True):
        """filter_alarm_list"""

        suppressed_list = service.get_suppressed_alarms()

        alarm_list = []

        # decide which alarms to return
        if include_regular:
            if include_suppressed:
                alarm_list = all_alarms

            else:
                alarm_list = [alarm for alarm in all_alarms if alarm.get('id') not in suppressed_list]

        else:
            if include_suppressed:
                alarm_list = [alarm for alarm in all_alarms if alarm.get('id') in suppressed_list]

        return alarm_list

    # -------------------------------------------------------------------------

    @staticmethod
    def get_alarm_url_prefix(config):
        """get_alarm_url_prefix"""

        ip_v4 = config.read(ManagementConnectorProperties.IPV4_ADDRESS)

        host_name = config.read(ManagementConnectorProperties.HOSTNAME)
        domain_name = config.read(ManagementConnectorProperties.DOMAINNAME)

        alarm_url_prefix = ip_v4
        if host_name is not None and host_name != '' and domain_name is not None and domain_name != '':
            host_name = host_name + '.' + domain_name
            alarm_url_prefix = host_name
        alarm_url_prefix = "https://" + alarm_url_prefix + "/"

        return alarm_url_prefix

    # -------------------------------------------------------------------------

    @staticmethod
    def get_connector_status(service):
        """get_connector_status"""

        return ServiceUtils.get_connector_status_by_name(service.get_name())

    # -------------------------------------------------------------------------

    @staticmethod
    def get_connector_status_by_name(name):
        """get_connector_status"""

        connector_status = {}

        status_file_path = ManagementConnectorProperties.GENERIC_STATUS_FILE % name
        if os.path.exists(status_file_path):
            connector_status = jsonhandler.read_json_file(status_file_path)
            if connector_status is None:
                connector_status = {}

        return connector_status

    # -------------------------------------------------------------------------

    @staticmethod
    def cache_service_cdb_schema(cdb_handle, service_name, exclude_paths=None):
        """ Stores services cdb path and value in file for rollback """
        DEV_LOGGER.info('Detail="ServiceUtils::cache_service_cdb_schema connector: %s"' % service_name)

        data = cdb_handle.get_service_database_records(service_name)
        if data:
            if exclude_paths:
                ServiceUtils.remove_exclude_paths(data, exclude_paths)

            DEV_LOGGER.info('Detail="ServiceUtils::cache_service_cdb_schema - writing cached data for %s "'
                            % service_name)
            jsonhandler.write_json_file(ManagementConnectorProperties.SERVICE_CDB_CACHE_FILE % service_name, data)
        else:
            DEV_LOGGER.info('Detail="ServiceUtils::cache_service_cdb_schema connector: %s No cdb data to cache"'
                            % service_name)

    # -------------------------------------------------------------------------

    @staticmethod
    def remove_exclude_paths(data, exclude_paths):
        """
            Removes exclude cdb paths from data
            Data Example:   {"table1": {"path1": "value"}, "table2": {"path1": "value"}}
            Exclude Paths:  {"table1": {"path1", "path2", "path2"}}
        """
        DEV_LOGGER.debug('Detail="ServiceUtils::remove_exclude_paths: removing %s"' % exclude_paths)

        if data and exclude_paths:
            for table, path_value_pairs in data.iteritems():
                if table in exclude_paths:
                    for path in exclude_paths[table]:
                        if path in path_value_pairs:
                            del path_value_pairs[path]

    # -------------------------------------------------------------------------

    @staticmethod
    def get_org_id(config):
        """ get_org_id """

        try:
            return config.read(ManagementConnectorProperties.OAUTH_MACHINE_ACCOUNT_DETAILS)['organization_id']
        except KeyError:
            return None

    # -------------------------------------------------------------------------

    @staticmethod
    def get_release_channel():
        """ Get the Release Channel Info From the HeartBeat File"""

        release_channel = ""

        heartbeat_contents = jsonhandler.read_json_file(ManagementConnectorProperties.UPGRADE_HEARTBEAT_FILE % ManagementConnectorProperties.SERVICE_NAME)

        if heartbeat_contents:
            try:
                release_channel = heartbeat_contents['properties']['fms.releaseChannel']
            except KeyError as ex:
                DEV_LOGGER.error('Detail="ServiceUtils::get_release_channel failed: %s"' % ex)

        return release_channel

    # -------------------------------------------------------------------------

    @staticmethod
    def get_configured_via_cdb_entry(config, service_name):
        """ get configured state from CDB; return the true|false string value or None """
        ret_val = None
        enabled_services_states = config.read(ManagementConnectorProperties.CONFIGURED_SERVICES_STATE)
        if enabled_services_states and service_name in enabled_services_states:
            ret_val = enabled_services_states[service_name]
        return ret_val

    # -------------------------------------------------------------------------

    @staticmethod
    def is_configured_status(config, name):
        """ determines if connector has been configured or not """
        cdb_configured = None
        if name == ManagementConnectorProperties.SERVICE_NAME:
            ret_val = True
        else:
            cdb_configured = ServiceUtils.get_configured_via_cdb_entry(config, name)
            if cdb_configured is not None:
                ret_val = None
                if "true" in cdb_configured:
                    ret_val = True
                elif "false" in cdb_configured:
                    ret_val = False
            else:
                configured_status_file = ManagementConnectorProperties.CONFIG_FILE_STATUS_LOCATION % name
                ret_val = os.path.exists(configured_status_file)
        DEV_LOGGER.debug('Detail="ServiceUtils::is_configured_status: name: {} cdb_configured: {} value: {}"'
                         .format(name, cdb_configured, ret_val))
        return ret_val

    @staticmethod
    def is_supported_extension(url):
        ''' determines if file type is supported'''

        if url:
            return url.split('.')[-1] in ManagementConnectorProperties.SUPPORTED_EXTENSIONS
        else:
            return False
