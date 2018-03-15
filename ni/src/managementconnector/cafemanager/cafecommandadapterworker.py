"""
Contains XML adapter to implement the Cafe elements
in the Command tree.
"""

import operator
import logging
import time

from ni.clusterdatabase.restclient import ClusterDatabaseRestClient, make_url
from ni.xmlapi.commandadapter import CommandError
from ni.xmlapi.utils import write_element

COMMAND_PATH = "/commands/cafe"
RESULT_PATH = "/commands/result/cafe"


TIMEOUT = 300

DEV_LOGGER = logging.getLogger("developer.xmlapi.cafe")


def _wait_for_result(uuid, rest_client, command_path, result_path, builder):
    """
    Wait for a command to complete
    """
    data = None
    for _ in xrange(0, TIMEOUT):
        data = rest_client.get_records(make_url(command_path, [('uuid', uuid)]))
        if not data:
            raise CommandError(99, "failed to submit command")
        if data[0]['command_state'] in ['succeeded', 'failed']:
            break
        time.sleep(1)

    command_state = data[0]['command_state']

    if command_state == 'failed':
        raise CommandError(99, data[0]['command_error'])

    if command_state in ['queued', 'running']:
        raise CommandError(99, 'timed out in state "%s"' % (command_state,))

    results = sorted(rest_client.get_records(make_url(result_path, [('command_uuid', uuid)])),
                     key=operator.itemgetter("order_emitted"))
    for result in results:
        if result['type'] != '':
            write_element(builder, result['action'], result['items'],
                          args={'type': result['type']})


class CafeAdapterWorker(object):
    """
    Implements the Cafe command
    """
    def __init__(self, rest_client=None):
        if rest_client is None:
            rest_client = ClusterDatabaseRestClient()

        self.rest_client = rest_client

    def run_command(self, arguments, result_builder):
        """
        Execute the Cafe command
        """
        connector = arguments['Connector']
        connector_cmd = arguments['Connector_cmd']
        parameters = arguments['Parameters']

        DEV_LOGGER.debug('Detail="CafeAdaptor run_command()" '
                         'Connector="%s" '
                         'Command="%s"'
                         'Command Path="%s" ' % (connector, connector_cmd, COMMAND_PATH))

        response = self.rest_client.send_post(COMMAND_PATH, {'connector': connector, 'connector_cmd': connector_cmd,
                                                             'parameters': parameters})
        uuid = response[0]['uuid']
        _wait_for_result(uuid, self.rest_client, COMMAND_PATH, RESULT_PATH, result_builder)
