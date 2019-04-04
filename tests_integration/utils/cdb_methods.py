import json
import logging

import requests

from tests_integration.utils.ssh_methods import run_ssh_command

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
    """ Wrapper for connector configuration """
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
    """ Sets some junk content for c_ucmc to stay running. """

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
    """ Sets some junk content for c_cal to stay running. """
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
    for entry in status:
        if entry["local_peer"]:
            return entry['records'][0]['hardware_serial_number']
    return ""  # Should not be possible


def set_poll_time(hostname, admin_user, admin_pass, poll_time):
    """ Change how often management connector will poll FMS """
    cdb_path = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_config_pollTime/"
    set_cdb_entry(hostname, admin_user, admin_pass, cdb_path, poll_time)


def get_machine_account_json(hostname, admin_user, admin_pass):
    """ get the current machine account """
    machine_db_record = get_cdb_entry(
        hostname,
        admin_user,
        admin_pass,
        "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_oauthMachineAccountDetails/")
    return json.loads(machine_db_record[0]["records"][0]["value"])


def get_current_machine_account_password(hostname, admin_user, admin_pass):
    """ get the current machine account password """
    return get_machine_account_json(hostname, admin_user, admin_pass)["password"]


def get_cluster_id(hostname, admin_user, admin_pass):
    """ get the current machine account password """
    return get_machine_account_json(hostname, admin_user, admin_pass)["cluster_id"]


def set_machine_account_expiry(hostname, admin_user, admin_pass, days):
    """ Change when the machine account thread in management will rotate its password """
    poll_cdb = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_config_machineAccountExpiry/"
    set_cdb_entry(hostname, admin_user, admin_pass, poll_cdb, days)


def get_full_blob_contents(hostname, admin_user, admin_pass):
    blob = get_cdb_entry(
        hostname,
        admin_user,
        admin_pass,
        "/api/management/configuration/cafe/cafeblobconfiguration/")
    if blob:
        return blob[0]["records"]
    return {}


def get_rollback_blacklist(hostname, admin_user, admin_pass):
    LOG.info("Clearing the rollback blacklist on %s", hostname)
    blacklist_location = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_installed_blacklist/"
    blacklist = get_cdb_entry(hostname,
                              admin_user,
                              admin_pass,
                              blacklist_location)
    if blacklist:
        return json.loads(blacklist[0]["records"][0]["value"])
    else:
        return {}


def clear_rollback_blacklist(hostname, admin_user, admin_pass):
    LOG.info("Clearing the rollback blacklist on %s", hostname)
    blacklist_location = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_installed_blacklist/"
    delete_cdb_entry(hostname,
                     admin_user,
                     admin_pass,
                     blacklist_location)


def set_logging_entry_to_blob(hostname, admin_user, admin_pass, uuid):
    """ Add logging entry to blob to initiate log POST. """
    cdb_path = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_logging_identifier/"
    set_cdb_entry(hostname, admin_user, admin_pass, cdb_path, {"uuid": uuid})


def get_logging_host_url(hostname, admin_user, admin_pass):
    """ get the logging host url  """
    logging_url = get_cdb_entry(
        hostname,
        admin_user,
        admin_pass,
        "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_logging_host_u2c/")

    return json.loads(logging_url[0]["records"][0]["value"])


def set_prevent_upgrade_flag(hostname, admin_user, admin_pass, value):
    prevent_update = \
        "/api/management/configuration/cafe/cafestaticconfiguration/name/c_mgmt_config_preventMgmtConnUpgrade/"

    # Manual post as prevent upgrade is in an awkward format
    try:
        requests.post('https://' + hostname + prevent_update, data={"value": value},
                      auth=(admin_user, admin_pass), verify=False)
    except:
        LOG.error("CDB Set failed: path {} and entry: {}".format(prevent_update, value))


def disable_fmc_upgrades(hostname, admin_user, admin_pass):
    set_prevent_upgrade_flag(hostname, admin_user, admin_pass, "on")
