import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry

from tests_integration.utils.cdb_methods import get_full_blob_contents, get_current_machine_account_password, \
    get_entitled_list_from_expressway, get_rollback_blacklist
from tests_integration.utils.fms import get_connector_raised_alarm_ids
from tests_integration.utils.remote_dispatcher import get_command_from_rd
from tests_integration.utils.ssh_methods import file_exists, \
    get_connector_heartbeat_start_time, get_mercury_device_route, get_remote_dispatcher_device_id, \
    get_maintenance_mode_state, get_connector_status, get_connector_pid, get_installed_connector_version, get_file_data

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)


def is_blob_empty(hostname, admin_user, admin_pass):
    return get_full_blob_contents(hostname, admin_user, admin_pass) == {}


def has_machine_password_changed(hostname, admin_user, admin_pass, machine_password):
    return machine_password != get_current_machine_account_password(hostname, admin_user, admin_pass)


def are_connectors_entitled(hostname, username, password, connectors=None):
    """ Checks if the supplied connectors are in the entitled list in CDB. If we get no connectors assume c_mgmt"""
    if connectors is None:
        connectors = ['c_mgmt']
    entitled_list = get_entitled_list_from_expressway(hostname, username, password)

    if entitled_list:
        entitled_list_names = []
        for entitled in entitled_list:
            entitled_list_names.append(entitled['name'])

        for connector in connectors:
            if connector not in entitled_list_names:
                return False
        # Found all connectors
        return True
    else:
        return False


def is_connector_installed(hostname, root_user, root_pass, connector):
    connector_status = get_connector_status(hostname, root_user, root_pass, connector)
    return connector_status is not None and connector_status == "install ok installed"


def is_connector_uninstalled(exp_hostname, exp_root_user, exp_root_pass, connector):
    return not is_connector_installed(exp_hostname, exp_root_user, exp_root_pass, connector)


def has_connector_pid_changed(hostname, root_user, root_pass, connector, old_pid):
    current_pid = get_connector_pid(hostname, root_user, root_pass, connector)
    return current_pid is not None and current_pid != old_pid


def has_connector_heartbeat_start_time_changed(hostname, root_user, root_pass, connector, old_heartbeat_start):
    heartbeat_start_time = get_connector_heartbeat_start_time(hostname, root_user, root_pass, connector)
    return heartbeat_start_time is not None and heartbeat_start_time != old_heartbeat_start


def has_mercury_device_route_changed(hostname, root_user, root_pass, old_mercury_route):
    mercury_route = get_mercury_device_route(hostname, root_user, root_pass)
    return mercury_route is not None and mercury_route != old_mercury_route


def has_remote_dispatcher_device_id_changed(hostname, root_user, root_pass, old_rd_device):
    device_id = get_remote_dispatcher_device_id(hostname, root_user, root_pass)
    return device_id is not None and device_id != old_rd_device


def is_command_complete(org_id, connector_id, rd_server, command_id, token):
    """ Get the command that matches the supplied id and see has it completed """
    return get_command_from_rd(org_id, connector_id, rd_server, command_id, token)["status"] == "complete"


def is_alarm_raised(org_id, cluster_id, fms_server, connector_id, alarm_id, token):
    return alarm_id in get_connector_raised_alarm_ids(org_id, cluster_id, fms_server, connector_id, token)


def can_connector_be_rolled_back(hostname, root_user, root_pass, connector):
    current_connector_search = "/mnt/harddisk/persistent/fusion/currentversions/" + connector + "*.tlp"
    previous_connector_search = "/mnt/harddisk/persistent/fusion/previousversions/" + connector + "*.tlp"
    return file_exists(hostname, root_user, root_pass, current_connector_search) and \
           file_exists(hostname, root_user, root_pass, previous_connector_search)


def has_version_changed(hostname, root_user, root_pass, connector, old_version):
    installed_version = get_installed_connector_version(hostname, root_user, root_pass, connector)
    return installed_version is not None and installed_version != old_version


def is_text_on_page(expressway, admin_user, admin_pass, page, text):
    with requests.Session() as session:
        retries = Retry(total=5,
                        backoff_factor=0.1,
                        status_forcelist=[500, 502, 503, 504])

        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        session.post(
            "https://" + expressway + "/login",
            data={"username": admin_user, "password": admin_pass},
            verify=False)
        page_data = session.get("https://" + expressway + "/" + page, verify=False)
        return text in page_data.text


def is_maintenance_mode_enabled(hostname, root_user, root_pass):
    maintenance_mode = get_maintenance_mode_state(hostname, root_user, root_pass)
    LOG.info("%s maintenance mode state is %s" % (hostname, maintenance_mode))
    return maintenance_mode is not None and maintenance_mode == "on"


def is_maintenance_mode_disabled(hostname, root_user, root_pass):
    maintenance_mode = get_maintenance_mode_state(hostname, root_user, root_pass)
    LOG.info("%s maintenance mode state is %s" % (hostname, maintenance_mode))
    return maintenance_mode is not None and maintenance_mode == "off"


def is_blacklist_empty(hostname, admin_user, admin_pass):
    return get_rollback_blacklist(hostname, admin_user, admin_pass) == {}


def has_log_configuration_updated(hostname, root_user, root_pass):
    ttlog_file_contents = get_file_data(hostname,
                                        root_user,
                                        root_pass,
                                        "/tandberg/etc/ttlog.conf")
    return "log4j.logger.hybridservices.cafe.test=DEBUG" in ttlog_file_contents


def feature_connectors_are_uninstalled(hostname, root_user, root_pass, connectors=None):
    for connector in connectors:
        if connector != "c_mgmt":
            if is_connector_installed(hostname, root_user, root_pass, connector):
                return False
    return True


def is_node_clean_after_defuse(hostname, root_user, root_pass, admin_user, admin_pass, connectors):
    return is_blob_empty(hostname, admin_user, admin_pass) \
           and feature_connectors_are_uninstalled(hostname, root_user, root_pass, connectors)
