import logging

from tests_integration.utils.cdb_methods import get_full_blob_contents, get_current_machine_account_password, \
    get_entitled_list_from_expressway
from tests_integration.utils.remote_dispatcher import get_command_from_rd
from tests_integration.utils.ssh_methods import run_ssh_commands, get_file_data, file_exists, \
    get_connector_heartbeat_start_time, get_mercury_device_route, get_remote_dispatcher_device_id

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


def is_connector_installed(exp_hostname, exp_root_user, exp_root_pass, connector):
    cmds = ["dpkg -l | grep %s" % connector,
            "dpkg -s %s | grep Status" % connector,
            "test -e /var/run/c_mgmt/installing_status.json  && echo Found || echo Not found"]

    results = run_ssh_commands(exp_hostname, exp_root_user, exp_root_pass, cmds)

    if "ii  " not in results[0]:
        LOG.info('"ii" not in  %s' % results)
        return False
    elif 'Status: install ok installed' not in results[1]:
        LOG.info('"Status: install ok installed" not in  %s' % results)
        return False
    elif "Found" in results[2]:
        LOG.info('"Found" not in %s' % results)
        # since the tlp could be installed with a new version downloading wait until everything is installed
        return False
    return True


def is_connector_uninstalled(exp_hostname, exp_root_user, exp_root_pass, connector):
    return not is_connector_installed(exp_hostname, exp_root_user, exp_root_pass, connector)


def has_file_content_changed(hostname, root_user, root_pass, target_file, old_data):
    if old_data == get_file_data(hostname, root_user, root_pass, target_file):
        LOG.info("File contents at %s is unchanged" % target_file)
        return False
    else:
        LOG.info("File contents at %s has changed" % target_file)
        return True


def has_connector_pid_changed(hostname, root_user, root_pass, connector, old_pid):
    pid_file = "/var/run/{}/{}.pid".format(connector, connector)
    if file_exists(hostname, root_user, root_pass, pid_file):
        return has_file_content_changed(hostname, root_user, root_pass, pid_file, old_pid)
    else:
        LOG.info("No PID file found at %s. Should the connector be running?" % pid_file)
        return False


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