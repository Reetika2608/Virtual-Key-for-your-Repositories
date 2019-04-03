import json
import logging

import requests

from tests_integration.api_based_tests.vcs_http import VCSHttpSession

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)


def enable_cloud_fusion(org_id, cluster_name, fms_server, exp_hostname, exp_admin_user, exp_admin_pass, connectors,
                        token, session):
    """
    Preregister with FMC, creating/provisioning a cluster, and register
    """
    LOG.info("Attempting login to VCS %s, user: %s, pw: %s" %
             (exp_hostname, exp_admin_user, exp_admin_pass))
    exp_session = VCSHttpSession(
        hostname=exp_hostname,
        username=exp_admin_user,
        password=exp_admin_pass
    )

    # Reuse the previously logged in session, saving the cookies to use in the Expressway session
    exp_session.set_session(session)

    # if self.PROXY_SERVER != "":
    #     # Set proxy server
    #     v.set_hybrid_services_proxy(address=self.PROXY_SERVER,
    #                                 port=self.PROXY_PORT,
    #                                 username=self.PROXY_USER,
    #                                 password=self.PROXY_PASSWORD)

    # set servers in cafeblobconfiguration

    cluster_id = create_cluster_with_fms(org_id, cluster_name, fms_server, token)

    LOG.info("Cluster Id: " + cluster_id)

    bootstrap_parameters = whitelist_vcs_with_fms(org_id, exp_hostname, cluster_id, fms_server, token)

    LOG.info("Bootstrap parameters " + bootstrap_parameters)

    provision_cluster(org_id, cluster_id, fms_server, connectors, token)

    exp_session.enable_hybrid_services(bootstrap_parameters)
    return cluster_id


def create_cluster_with_fms(org_id, cluster_name, fms_server, token):
    """
    Create a cluster in FMS and return cluster_id, uses
    """
    LOG.info("create_cluster_with_fms")
    cluster_id = None

    cluster_url = 'https://' + fms_server + '/hercules/api/v2/organizations/{}/clusters'.format(org_id)
    cluster_data = json.dumps({"name": cluster_name, "releaseChannel": "stable", "targetType": "c_mgmt"})
    cluster_resp = requests.api.post(url=cluster_url, headers=get_headers(token), data=cluster_data, verify=False)

    if hasattr(cluster_resp, "content"):
        content = cluster_resp.content
        LOG.info("content: {}".format(content))
        json_content = json.loads(content)

        if json_content and 'id' in json_content:
            cluster_id = json_content['id']
            LOG.info("{}".format("Created cluster with id: {}".format(cluster_id)))

    return cluster_id


def whitelist_vcs_with_fms(org_id, exp_hostname, cluster_id, fms_server, token):
    """
    Adds a VCS to the FMS whitelist so that fuse or defuse can occur.

    :param org_id: org uuid
    :param exp_hostname: exp hostname
    :param cluster_id: cluster uuid
    :param fms_server: Atlas server to be used
    :param token: Access token
    """

    LOG.info("whitelist_vcs_with_fms")
    bootstrap_params = None

    full_url = 'https://' + fms_server + '/hercules/api/v2/organizations/' + org_id + \
               '/clusters/' + cluster_id + '/allowedRegistrationHosts'

    data = json.dumps({"hostname": exp_hostname})
    response = requests.api.post(url=full_url, headers=get_headers(token), data=data, verify=False)

    if hasattr(response, "content"):
        content = response.content
        LOG.info("content: %s", content)
        json_content = json.loads(content)
        if json_content and 'bootstrapUrlParams' in json_content:
            bootstrap_params = json_content['bootstrapUrlParams']
            LOG.info("Got back bootstrap params: %s", bootstrap_params)
    return bootstrap_params


def provision_cluster(org_id, cluster_id, fms_server, connectors, token):
    """
    provisions connectors.

    :param org_id: test org id
    :param cluster_id: cluster_id
    :param fms_server: FMS server to be used
    :param token: access token
    """
    LOG.info("provision_cluster: org_id=%s, cluster_id=%s", org_id, cluster_id)

    # Provision c_cal and c_ucmc
    provision_url = "https://" + fms_server + \
                    "/hercules/api/v2/organizations/{}/clusters/{}/provisioning/actions/add/invoke?connectorType={}"

    for name in connectors:
        # Management Connector is auto provisioned
        if name != "c_mgmt":
            full_url = provision_url.format(org_id, cluster_id, name)
            provision_resp = requests.post(url=full_url, headers=get_headers(token), verify=False)
            LOG.info("{}".format(provision_resp.content))


def deregister_cluster(org_id, cluster_id, fms_server, token):
    # Cluster Wide Delete to FMS
    LOG.info("deregister_cluster. Removing cluster=%s from org=%s" % (cluster_id, org_id))
    full_url = 'https://' + fms_server + '/hercules/api/v2/organizations/' + org_id + '/clusters/' + cluster_id
    response = requests.delete(full_url, headers=get_headers(token), verify=False)
    LOG.info("DELETE cluster url: %s, response: %s" % (full_url, response))


def get_connector(org_id, cluster_id, fms_server, connector_id, token):
    full_url = 'https://' + fms_server + '/hercules/api/v2/organizations/' + org_id + '/clusters/' \
               + cluster_id + '/connectors/' + connector_id + '?fields=@wide'
    response = requests.get(full_url, headers=get_headers(token), verify=False)
    return json.loads(response.content)


def get_connector_raised_alarm_ids(org_id, cluster_id, fms_server, connector_id, token):
    raised_alarms = []
    connector = get_connector(org_id, cluster_id, fms_server, connector_id, token)

    for alarm in connector["alarms"]:
        raised_alarms.append(str(alarm["id"]))
    LOG.info("Found alarms %s on connector %s" % (str(raised_alarms), connector_id))
    return raised_alarms


def get_headers(token):
    return {'Content-Type': 'application/json; charset=UTF-8',
            'Accept': 'application/json; charset=UTF-8',
            'Authorization': 'Bearer ' + token}


def enable_maintenance_mode(org_id, serial, fms_server, token):
    requests.patch(
        'https://' + fms_server + '/hercules/api/v2/organizations/' + org_id + '/hosts/' + serial,
        headers=get_headers(token),
        data=json.dumps({'maintenanceMode': 'on'}),
        verify=False)


def disable_maintenance_mode(org_id, serial, fms_server, token):
    requests.patch(
        'https://' + fms_server + '/hercules/api/v2/organizations/' + org_id + '/hosts/' + serial,
        headers=get_headers(token),
        data=json.dumps({'maintenanceMode': 'off'}),
        verify=False)
