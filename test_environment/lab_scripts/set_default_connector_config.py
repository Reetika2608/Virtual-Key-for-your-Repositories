import json
import sys
import requests


c_cal_config_path = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_cal_exchange_lookup_servers/"
configured_path = "/api/management/configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_configuredServicesState"
configured = {"c_cal": "true"}


fake_c_cal_config = [
    {
        "service_username": "aaaa",
        "service_password": "",
        "service_enabled": "true",
        "display_name": "sqfusioninteg",
        "type": "Exchange On-Premises",
        "version": "2010",
        "exch_info":
            {
                "ews_auth_type": "ntlm",
                "protocol_info":
                    {
                        "protocol": "https",
                        "validate_certs": "false"
                    },
                "autodiscovery_enabled": "false"
            },
        "host_or_ip": "127.0.0.1",
        "useProxy": "false",
        "z_time": "1455661142"
    }
]

def set_cdb_entry(hostname, admin_user, admin_pass, cdb_path, entry):
    """ set a cluster database entry """
    try:
        requests.post('https://' + hostname + cdb_path, data='value=' + json.dumps(entry),
                      auth=(admin_user, admin_pass), verify=False)
    except:
        print("CDB Set failed: path {} and entry: {}".format(cdb_path, entry))


hostname = sys.argv[1]
admin_user = "admin"
admin_pass = "x"

set_cdb_entry(hostname, admin_user, admin_pass, c_cal_config_path, fake_c_cal_config)
set_cdb_entry(hostname, admin_user, admin_pass, configured_path, configured)

