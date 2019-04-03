import datetime
import json
import logging
import paramiko

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)


def get_file_data(hostname, root_user, root_pass, filename):
    """ get the contents of a file from a remote server """
    return run_ssh_command(hostname, root_user, root_pass, "cat " + filename)


def get_exit_code(hostname, username, password, command):
    """ ssh to remote machine and run command, and return the exit code  """
    port = 22
    client = paramiko.Transport((hostname, port))
    client.connect(username=username, password=password)
    session = client.open_channel(kind='session')
    session.exec_command(command)
    while True:
        # Give the session time to complete
        if session.exit_status_ready():
            break
    exit_code = session.exit_status
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


def get_device_time(hostname, username, password):
    """ Returns the local device time as a datetime object. """
    # UTC Timestamp
    cmd = 'date -u'
    date = run_ssh_command(hostname, username, password, cmd).strip()
    result = datetime.datetime.strptime(date, '%a %b %d %H:%M:%S %Z %Y')
    return result


def file_exists(hostname, username, password, file_path):
    """ Checks for the existence of a file """
    command = "[ -e {} ]".format(file_path)
    return get_exit_code(hostname, username, password, command) == 0


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


def get_maintenance_mode_state(hostname, root_user, root_pass):
    heartbeat = get_connector_heartbeat(hostname, root_user, root_pass, "c_mgmt")
    if "provisioning" in heartbeat and "maintenanceMode" in heartbeat["provisioning"]:
        return heartbeat["provisioning"]["maintenanceMode"]
    else:
        return None


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


def get_and_log_management_connector_run_data(hostname, root_user, root_pass):
    pid = get_file_data(hostname, root_user, root_pass,
                        "/var/run/c_mgmt/c_mgmt.pid")
    heartbeat_start_time = get_connector_heartbeat_start_time(hostname, root_user, root_pass, "c_mgmt")
    mercury_route = get_mercury_device_route(hostname, root_user, root_pass)
    rd_device = get_remote_dispatcher_device_id(hostname, root_user, root_pass)
    LOG.info("Management connector run data. pid=%s, heartbeat_start_time=%s, mercury_route=%s, rd_device=%s"
             % (pid, heartbeat_start_time, mercury_route, rd_device))
    return pid, heartbeat_start_time, mercury_route, rd_device


def restart_connector(hostname, root_user, root_pass, connector_name):
    """ Restart the supplied connector """
    command = "/etc/init.d/{} restart".format(connector_name)
    run_ssh_command(hostname, root_user, root_pass, command)
