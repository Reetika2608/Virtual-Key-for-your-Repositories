""" Generic Useful methods for tests """
import datetime
import logging
import paramiko
import requests
import json
import time
import os
import errno
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

logging.getLogger("paramiko").setLevel(logging.WARNING)


def set_cdb_entry(hostname, admin_user, admin_pass, cdb_path, entry):
    """ set a cluster database entry """
    try:
        requests.post('https://' + hostname + cdb_path, data='value=' + json.dumps(entry),
                      auth=(admin_user, admin_pass), verify=False)
    except:
        LOG.error("CDB Set failed: path {} and entry: {}".format(cdb_path, entry))


def delete_cdb_entry(hostname, admin_user, admin_pass, cdb_path):
    """ delete a cluster database entry """
    try:
        requests.delete('https://' + hostname + cdb_path, auth=(admin_user, admin_pass), verify=False)
    except:
        LOG.error("CDB Delete failed for entry: {}".format(cdb_path))


def get_cdb_entry(hostname, admin_user, admin_pass, cdb_path):
    """ get a cluster database entry """
    try:
        resp = requests.get('https://' + hostname + cdb_path, auth=(admin_user, admin_pass), verify=False)
        return resp.json()
    except:
        LOG.error("CDB Get failed for entry: {}".format(cdb_path))


def get_file_data(hostname, root_user, root_pass, filename):
    """ get the contents of a file from a remote server """
    return run_ssh_command(hostname, root_user, root_pass, "cat " + filename)


def get_exit_code(hostname, username, password, command):
    """ ssh to remote machine and run command, and return the exit code  """
    exit_code = 127
    port = 22

    try:
        client = paramiko.Transport((hostname, port))
        client.connect(username=username, password=password)
        session = client.open_channel(kind='session')
        session.exec_command(command)
        while True:
            # Give the session time to complete
            if session.exit_status_ready():
                break
        exit_code = session.exit_status
    except Exception as ex:
        LOG.info('Request failed ' + repr(ex))
    finally:
        session.close()
        client.close()

    return exit_code


def run_ssh_command(hostname, username, password, command):
    """ ssh to remote machine and run command  """
    nbytes = 4096
    port = 22

    client = paramiko.Transport((hostname, port))
    client.connect(username=username, password=password)

    stdout_data = []
    stderr_data = []
    session = client.open_channel(kind='session')
    session.exec_command(command)
    while True:
        if session.recv_ready():
            stdout_data.append(session.recv(nbytes))
        if session.recv_stderr_ready():
            stderr_data.append(session.recv_stderr(nbytes))
        if session.exit_status_ready():
            break

    session.close()
    client.close()
    return ''.join(stdout_data)


def run_ssh_commands(hostname, username, password, commands):
    nbytes = 4096
    port = 22

    client = paramiko.Transport((hostname, port))
    client.connect(username=username, password=password)

    stdout_results = []
    for command in commands:
        stdout_data = []
        stderr_data = []
        session = client.open_channel(kind='session')
        session.exec_command(command)
        while True:
            if session.recv_ready():
                stdout_data.append(session.recv(nbytes))
            if session.recv_stderr_ready():
                stderr_data.append(session.recv_stderr(nbytes))
            if session.exit_status_ready():
                stdout_results.append(''.join(stdout_data))
                break
        session.close()

    client.close()
    return stdout_results


def wait_until(predicate, timeout, period=0.25, *args):
    """ Waits for a predicate to complete """
    must_end = time.time() + timeout
    while time.time() < must_end:
        if predicate(*args):
            return True
        time.sleep(period)
    return False


def get_device_time(hostname, username, password, delta_seconds=None):
    """Returns the local device time as a datatime object. Useful for
    when you need to parse device logs.

    :param delta_seconds: offset the returned datetime object by specified
            number of seconds, e.g. -2.
    """

    # UTC Timestamp
    cmd = 'date -u'
    date = run_ssh_command(hostname, username, password, cmd).strip()
    result = datetime.datetime.strptime(date, '%a %b %d %H:%M:%S %Z %Y')
    if delta_seconds:
        result = result + datetime.timedelta(seconds=delta_seconds)
    return result


def file_exists(hostname, username, password, file_path):
    """ Checks for the existence of a file """
    command = "[ -e {} ]".format(file_path)
    return get_exit_code(hostname, username, password, command) == 0


def is_connector_entitled(hostname, username, password, connectors=None):
    """ Checks if a connector is in the entitled list """
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


def get_entitled_list_from_expressway(hostname, username, password):
    """ get entitled list of connectors from expressway CDB """
    entitled_list = []
    try:
        resp = requests.get(
            'https://' + hostname + '/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_entitledServices/',
            auth=(username, password),
            verify=False)
        entitled_list = json.loads(resp.json()[0]['records'][0]['value'])
    except Exception as ex:
        LOG.info('Request failed ' + repr(ex))
    return entitled_list


def configure_connectors(exp_hostname, admin_user, admin_pass, root_user, root_password):
    """
    Wrapper for connector configuration
    """
    configured_path = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_configuredServicesState/"
    configured = {"c_ucmc": "true", "c_cal": "true", "c_imp": "true"}
    set_cdb_entry(
        exp_hostname,
        admin_user,
        admin_pass,
        configured_path,
        configured)
    set_cal_exchange_lookup(exp_hostname, admin_user, admin_pass, root_user, root_password)
    set_ucm_server(exp_hostname, admin_user, admin_pass, root_user, root_password)


def set_ucm_server(exp_hostname, admin_user, admin_pass, root_user, root_password):
    """
    Sets some junk content for c_ucmc to stay running.
    """

    ucm_path = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_ucmc_ucm_servers/"
    junk_ucm = {
        "username": "SP",
        "password": "SP",
        "address": "111.27.25.236",
        "ctird_config_type": "automatic",
        "ctird_device_pool": "1b1b9eb6-7803-11d3-bdf0-00108302ead1",
        "ctird_location": "29c5c1c4-8871-4d1e-8394-0b9181e8c54d",
        "ctird_css": "",
        "ctird_rrcss": ""
    }

    set_cdb_entry(
        exp_hostname,
        admin_user,
        admin_pass,
        ucm_path,
        junk_ucm)
    run_ssh_command(
        exp_hostname,
        root_user,
        root_password,
        "touch /tandberg/persistent/fusion/status/c_ucmc.configured")


def set_cal_exchange_lookup(exp_hostname, admin_user, admin_pass, root_user, root_password):
    """
    Sets some junk content for c_cal to stay running.
    """
    exchange_path = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_cal_exchange_lookup_servers/"

    junk_config = [
        {"service_username": "aaaa", "service_password": "", "service_enabled": "true", "display_name": "sqfusioninteg",
         "type": "Exchange On-Premises", "version": "2010", "exch_info": {"ews_auth_type": "ntlm",
                                                                          "protocol_info": {"protocol": "https",
                                                                                            "validate_certs": "false"},
                                                                          "autodiscovery_enabled": "false"},
         "host_or_ip": "127.0.0.1", "useProxy": "false", "z_time": "1455661142"}]

    set_cdb_entry(
        exp_hostname,
        admin_user,
        admin_pass,
        exchange_path,
        junk_config)

    tmp_requests_content = '{"connector": "c_cal", "request": "setconfiguredstatus", "value": "True"}'

    cmd = "echo '" + tmp_requests_content + "' > /tmp/request/c_cal_hybrid_request"
    run_ssh_command(exp_hostname, root_user, root_password, cmd)


def get_cluster_id_from_expressway(exp_hostname, admin_user, admin_pass):
    cluster_id = ''
    try:
        resp = requests.get(
            'https://' + exp_hostname + '/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_clusterId/',
            auth=(admin_user, admin_pass),
            verify=False)
        cluster_id = json.loads(resp.json()[0]['records'][0]['value'])
    except:
        LOG.info('Request failed')
    LOG.info('\nCluster id: ' + cluster_id)
    return cluster_id


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


def create_log_directory():
    logs_dir = './logs/%s/' % datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    if not os.path.exists(os.path.dirname(logs_dir)):
        try:
            os.makedirs(os.path.dirname(logs_dir))
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
    return os.path.abspath(logs_dir)


def enable_expressway_connector(exp_hostname, admin_user, admin_pass, connector):
    LOG.info("Turning on " + connector + " in CDB")
    blob_enabled_service_path = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_enabledServicesState/"
    read = get_cdb_entry(exp_hostname, admin_user, admin_pass, blob_enabled_service_path)
    existing_states = json.loads(read[0]["records"][0]["value"])
    existing_states[connector] = "on"
    set_cdb_entry(exp_hostname, admin_user, admin_pass, blob_enabled_service_path, existing_states)

    full_url = 'https://' + exp_hostname + "/api/management/configuration/service/name/" + connector
    LOG.info("full_url " + full_url)
    requests.post(full_url, data='mode=on',
                  auth=(admin_user, admin_pass), verify=False)
    return True


def get_serialno(hostname, admin_user, admin_pass):
    """ get expressway serial number """
    status = get_cdb_entry(hostname, admin_user, admin_pass, "/api/management/status/system/")
    return status[0]['records'][0]['hardware_serial_number']


def set_poll_time(hostname, admin_user, admin_pass, poll_time):
    """
    Change how often management connector will poll FMS
    :param hostname:
    :param admin_user:
    :param admin_pass:
    :param poll_time:
    """
    cdb_path = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_config_pollTime/"
    set_cdb_entry(hostname, admin_user, admin_pass, cdb_path, poll_time)


def get_headers(token):
    """
    Wrap an access token in http header json
    :param token:
    :return: http headers
    """
    return {'Content-Type': 'application/json; charset=UTF-8',
            'Accept': 'application/json; charset=UTF-8',
            'Authorization': 'Bearer ' + token}


def get_machine_account_json(hostname, admin_user, admin_pass):
    """
    get the current machine account
    :param hostname:
    :param admin_user:
    :param admin_pass:
    """
    machine_db_record = get_cdb_entry(
        hostname,
        admin_user,
        admin_pass,
        "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_oauthMachineAccountDetails/")
    return json.loads(machine_db_record[0]["records"][0]["value"])


def get_current_machine_account_password(hostname, admin_user, admin_pass):
    """
    get the current machine account password
    :param hostname:
    :param admin_user:
    :param admin_pass:
    """
    return get_machine_account_json(hostname, admin_user, admin_pass)["password"]


def set_machine_account_expiry(hostname, admin_user, admin_pass, days):
    """
    Change when the machine account thread in management will rotate its password
    :param hostname:
    :param admin_user:
    :param admin_pass:
    :param days:
    :return:
    """
    poll_cdb = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_config_machineAccountExpiry/"
    set_cdb_entry(hostname, admin_user, admin_pass, poll_cdb, days)


def restart_connector(hostname, root_user, root_pass, connector_name):
    """
    Restart the supplied connector
    :param hostname:
    :param root_user:
    :param root_pass:
    :param connector_name:
    """
    command = "/etc/init.d/{} restart".format(connector_name)
    run_ssh_command(hostname, root_user, root_pass, command)


def has_machine_password_changed(hostname, admin_user, admin_pass, machine_password):
    """
    Check if the machine account password has changed from the supplied value
    :param hostname:
    :param admin_user:
    :param admin_pass:
    :param machine_password:
    :return: True or False
    """
    return machine_password != get_current_machine_account_password(hostname, admin_user, admin_pass)


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


def get_connector_heartbeat(hostname, root_user, root_pass, connector):
    heartbeat_file = "/var/run/c_mgmt/{}.heartbeat".format(connector)
    if file_exists(hostname, root_user, root_pass, heartbeat_file):
        try:
            return json.loads(get_file_data(hostname, root_user, root_pass, heartbeat_file))
        except ValueError:
            LOG.info("Invalid JSON found at %s. Should the connector be running?" % heartbeat_file)
    else:
        LOG.info("No heartbeat file found at %s. Should the connector be running?" % heartbeat_file)
    return {}


def get_connector_heartbeat_start_time(hostname, root_user, root_pass, connector):
    heartbeat = get_connector_heartbeat(hostname, root_user, root_pass, connector)
    if "status" in heartbeat and "startTimestamp" in heartbeat["status"]:
        return heartbeat["status"]["startTimestamp"]
    else:
        return None


def has_connector_heartbeat_start_time_changed(hostname, root_user, root_pass, connector, old_heartbeat_start):
    heartbeat_start_time = get_connector_heartbeat_start_time(hostname, root_user, root_pass, connector)
    return heartbeat_start_time is not None and heartbeat_start_time != old_heartbeat_start


def get_mercury_registration(hostname, root_user, root_pass):
    mercury_file = "/var/run/c_mgmt/c_mgmt.mercury"
    if file_exists(hostname, root_user, root_pass, mercury_file):
        try:
            return json.loads(get_file_data(hostname, root_user, root_pass, mercury_file))
        except ValueError:
            LOG.info("Invalid JSON found at %s. Should the connector be running?" % mercury_file)
    else:
        LOG.info("No mercury file found at %s. Should the connector be running?" % mercury_file)
    return {}


def get_mercury_device_route(hostname, root_user, root_pass):
    mercury_registration = get_mercury_registration(hostname, root_user, root_pass)
    if "route" in mercury_registration:
        return mercury_registration["route"]
    else:
        return None


def has_mercury_device_route_changed(hostname, root_user, root_pass, old_mercury_route):
    mercury_route = get_mercury_device_route(hostname, root_user, root_pass)
    return mercury_route is not None and mercury_route != old_mercury_route


def get_remote_dispatcher_registration(hostname, root_user, root_pass):
    remotedispatcher_file = "/var/run/c_mgmt/c_mgmt.remotedispatcher"
    if file_exists(hostname, root_user, root_pass, remotedispatcher_file):
        try:
            return json.loads(get_file_data(hostname, root_user, root_pass, remotedispatcher_file))
        except ValueError:
            LOG.info("Invalid JSON found at %s. Should the connector be running?" % remotedispatcher_file)
    else:
        LOG.info("No RD file found at %s. Should the connector be running?" % remotedispatcher_file)
    return {}


def get_remote_dispatcher_device_id(hostname, root_user, root_pass):
    rd_registration = get_remote_dispatcher_registration(hostname, root_user, root_pass)
    if "deviceId" in rd_registration:
        return rd_registration["deviceId"]
    else:
        return None


def has_remote_dispatcher_device_id_changed(hostname, root_user, root_pass, old_rd_device):
    device_id = get_remote_dispatcher_device_id(hostname, root_user, root_pass)
    return device_id is not None and device_id != old_rd_device


def get_and_log_management_connector_run_data(hostname, root_user, root_pass):
    pid = get_file_data(hostname, root_user, root_pass,
                        "/var/run/c_mgmt/c_mgmt.pid")
    heartbeat_start_time = get_connector_heartbeat_start_time(hostname, root_user, root_pass, "c_mgmt")
    mercury_route = get_mercury_device_route(hostname, root_user, root_pass)
    rd_device = get_remote_dispatcher_device_id(hostname, root_user, root_pass)
    LOG.info("Management connector run data. pid=%s, heartbeat_start_time=%s, mercury_route=%s, rd_device=%s"
             % (pid, heartbeat_start_time, mercury_route, rd_device))
    return pid, heartbeat_start_time, mercury_route, rd_device


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


def get_full_blob_contents(hostname, admin_user, admin_pass):
    blob = get_cdb_entry(
        hostname,
        admin_user,
        admin_pass,
        "/api/management/configuration/cafe/cafeblobconfiguration/")
    if blob:
        return blob[0]["records"]
    return {}


def is_blob_empty(hostname, admin_user, admin_pass):
    return get_full_blob_contents(hostname, admin_user, admin_pass) == {}
