import datetime
import json

import paramiko

from tests_integration.utils.integration_test_logger import get_logger

LOG = get_logger()


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
    raw_output = ""
    attempt = 0
    max_attempts = 3
    while raw_output == "" and attempt < max_attempts:
        raw_output = paramiko_ssh_command(hostname, username, password, command)
        attempt = attempt + 1
    return raw_output


def paramiko_ssh_command(hostname, username, password, command):
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
            stdout_data.append(session.recv(nbytes).decode())
        if session.recv_stderr_ready():
            stderr_data.append(session.recv_stderr(nbytes).decode())
        if session.exit_status_ready():
            break

    session.close()
    client.close()
    return ''.join(stdout_data)


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


def get_connector_pid(hostname, root_user, root_pass, connector):
    pid_file = "/var/run/{}/{}.pid".format(connector, connector)
    if file_exists(hostname, root_user, root_pass, pid_file):
        file_data = get_file_data(hostname, root_user, root_pass, pid_file)
        if not file_data.strip():  # the PID file exists but has nothing in it
            return None
        else:
            LOG.info("%s PID is %s", connector, file_data.strip())
            return file_data.strip()
    else:
        LOG.info("No PID file found at %s. Should the connector be running?" % pid_file)
        return None


def get_and_log_management_connector_run_data(hostname, root_user, root_pass):
    pid = get_connector_pid(hostname, root_user, root_pass, "c_mgmt")
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


def request_restart_connector(hostname, root_user, root_pass, connector_name):
    """ Request Restart the supplied connector """
    command = "sudo -H -u _nobody bash -c \"echo 'restart {}' > /tmp/request/requestservicestart\"".format(
        connector_name)
    run_ssh_command(hostname, root_user, root_pass, command)


def stop_connector(hostname, root_user, root_pass, connector_name):
    """ Stop the supplied connector """
    command = "/etc/init.d/{} stop".format(connector_name)
    run_ssh_command(hostname, root_user, root_pass, command)


def start_connector(hostname, root_user, root_pass, connector_name):
    """ Start the supplied connector """
    command = "/etc/init.d/{} start".format(connector_name)
    run_ssh_command(hostname, root_user, root_pass, command)


def run_xcommand(hostname, root_user, root_pass, xcommand):
    wrapped_command = "echo '" + xcommand + "' | tsh"
    output = run_ssh_command(hostname, root_user, root_pass, wrapped_command)
    return output


def rollback_connector(hostname, root_user, root_pass, connector):
    LOG.info("Rolling back %s on %s", connector, hostname)
    rollback_status = run_xcommand(hostname, root_user, root_pass, "xcommand Cafe c_mgmt rollback " + connector)
    if "Rollback Complete" in rollback_status:
        LOG.info("Success! Rolled back %s on %s", connector, hostname)
        return True
    else:
        LOG.error("Failed to roll back %s on %s", connector, hostname)
        return False


def get_installed_connector_version(hostname, root_user, root_pass, connector):
    version = run_ssh_command(hostname, root_user, root_pass,
                              "dpkg-query --showformat='${Version}' --show " + connector)
    if version == "dpkg-query: no packages found matching " + connector:
        return None
    else:
        return version.strip()


def get_connector_status(hostname, root_user, root_pass, connector):
    status = run_ssh_command(hostname, root_user, root_pass,
                             "dpkg-query --showformat='${Status}' --show " + connector)
    if status == "dpkg-query: no packages found matching " + connector:
        return None
    else:
        return status.strip()


def get_process_count(hostname, root_user, root_pass, connector):
    process_dict = {'c_cal': 'java',
                    'c_mgmt': 'managementconnectormain',
                    'c_imp': 'java',
                    'c_serab': 'python3'}
    connector_binary = process_dict[connector]
    cmd = "ps aux | grep %s | grep %s | grep -v grep" % (connector, connector_binary)
    result = run_ssh_command(hostname, root_user, root_pass, cmd)
    processes = [p for p in result.split("\n") if p.strip()]  # Remove blank lines
    process_count = len(processes)
    LOG.info("%s output from %s: %d (%s)", cmd, hostname, process_count, processes)
    return process_count


def get_encrypted_string(hostname, root_user, root_pass, input_string):
    '''
    Get Encrypted String from Expressway.
    '''
    LOG.info("Get Encrypted String from Expressway.")
    file_path = "/share/python/site-packages/ni/utils/taacrypto/encrypt.py"
    cmd = "/bin/python %s -input_string '%s'" % (file_path, input_string)
    encrypted_string = run_ssh_command(hostname, root_user, root_pass, cmd)

    LOG.info("Encrypted String: %s" % encrypted_string)

    return encrypted_string.strip()


def get_decrypted_string(hostname, root_user, root_pass, input_string):
    '''
    Get Decrypted String from Expressway.
    '''
    LOG.info("Get Decrypted String from Expressway.")
    file_path = "/share/python/site-packages/ni/utils/taacrypto/decrypt.py"
    cmd = "/bin/python %s -input_string '%s'" % (file_path, input_string)
    decrypted_string = run_ssh_command(hostname, root_user, root_pass, cmd)
    LOG.info("Decrypted String: %s" % decrypted_string)

    return decrypted_string.strip()


def check_taacrypto_compatibility(hostname, root_user, root_pass, input_string):
    '''
    Check TaaCrypto Compatibility on the Expressway
    '''
    LOG.info("Check TaaCrypto Compatibility on the Expressway.")
    encrypted_string = get_encrypted_string(hostname, root_user, root_pass, input_string).strip()
    decrypted_string = get_decrypted_string(hostname, root_user, root_pass, encrypted_string)
    LOG.info(input_string == decrypted_string)
    return input_string == decrypted_string