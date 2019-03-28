import json
import logging
import requests


logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)


def dispatch_command_to_rd(org_id, connector_id, rd_server, command, token):
    """
    Send a command to remote dispatcher
    :param org_id:
    :param connector_id:
    :param rd_server:
    :param command:
    :param token:
    :return:
    """
    LOG.info("dispatch_command_to_rd")
    rd_url = "https://" + rd_server + "/remote-dispatcher/api/v1/commands/{}/connectors/{}/command" \
        .format(org_id, connector_id)

    LOG.info("Dispatching command=%s to RD URL=%s" % (json.dumps(command), rd_url))
    response = requests.api.post(url=rd_url, headers=get_headers(token), data=json.dumps(command), verify=False)

    if response.ok:
        LOG.info("Command was dispatched. Response=%s" % json.loads(response.content))
    return json.loads(response.content)["commandId"]


def get_command_from_rd(org_id, connector_id, rd_server, command_id, token):
    """
    Get the current status of a command from remote dispatcher
    :param org_id:
    :param connector_id:
    :param rd_server:
    :param command_id:
    :param token:
    :return:
    """
    LOG.info("get_command_from_rd")
    rd_url = "https://" + rd_server + "/remote-dispatcher/api/v1/commands/{}/connectors/{}/command/{}" \
        .format(org_id, connector_id, command_id)
    LOG.info("Get command status from RD URL=%s" % rd_url)
    response = requests.get(rd_url, headers=get_headers(token), verify=False)
    if response.ok:
        LOG.info("RD returned a command. Response=%s" % json.loads(response.content))
    return json.loads(response.content)


def get_headers(token):
    return {'Content-Type': 'application/json; charset=UTF-8',
            'Accept': 'application/json; charset=UTF-8',
            'Authorization': 'Bearer ' + token}
