""" Generic Useful methods for tests """
import datetime
import errno
import logging
import os
import time

import urllib3

from tests_integration.utils.predicates import has_connector_pid_changed, has_connector_heartbeat_start_time_changed, \
    has_mercury_device_route_changed, has_remote_dispatcher_device_id_changed, is_connector_installed, \
    is_connector_uninstalled, is_blob_empty
from tests_integration.utils.ssh_methods import get_and_log_management_connector_run_data, restart_connector

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)


def wait_until(predicate, timeout, period=0.25, *args):
    """ Waits for a predicate to complete """
    must_end = time.time() + timeout
    while time.time() < must_end:
        if predicate(*args):
            return True
        time.sleep(period)
    return False


def create_log_directory():
    logs_dir = './logs/%s/' % datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    if not os.path.exists(os.path.dirname(logs_dir)):
        try:
            os.makedirs(os.path.dirname(logs_dir))
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
    return os.path.abspath(logs_dir)


def run_full_management_connector_restart(hostname, root_user, root_pass):
    starting_pid, starting_heartbeat_start_time, starting_mercury_route, starting_rd_device = \
        get_and_log_management_connector_run_data(hostname, root_user, root_pass)

    LOG.info("Restarting management connector...")
    restart_connector(hostname, root_user, root_pass, "c_mgmt")
    wait_until(has_connector_pid_changed, 10, 1,
               *(hostname, root_user, root_pass, "c_mgmt", starting_pid))
    wait_until(has_connector_heartbeat_start_time_changed, 20, 1,
               *(hostname, root_user, root_pass, "c_mgmt", starting_heartbeat_start_time))
    wait_until(has_mercury_device_route_changed, 10, 1,
               *(hostname, root_user, root_pass, starting_mercury_route))
    wait_until(has_remote_dispatcher_device_id_changed, 10, 1,
               *(hostname, root_user, root_pass, starting_rd_device))
    LOG.info("Restart of management connector is complete")
    get_and_log_management_connector_run_data(hostname, root_user, root_pass)


def wait_for_connectors_to_install(hostname, root_user, root_pass, connectors):
    for connector in connectors:
        wait_until(is_connector_installed, 240, 10,
                   *(hostname,
                     root_user,
                     root_pass,
                     connector))


def wait_for_defuse_to_finish(hostname, root_user, root_pass, admin_user, admin_pass, connectors):
    wait_until(is_blob_empty, 60, 5, *(hostname, admin_user, admin_pass))
    for connector in connectors:
        if connector != "c_mgmt":
            wait_until(is_connector_uninstalled, 300, 10, *(hostname, root_user, root_pass, connector))
