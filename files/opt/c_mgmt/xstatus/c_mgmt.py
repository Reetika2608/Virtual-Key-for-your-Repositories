"""
    ManagementConnector xstatus
"""
import sys

sys.path.insert(0, '/opt/c_mgmt/python/lib/python3.9/')
sys.path.append('/opt/c_mgmt/python/lib/python3.9/lib-dynload/')
# sys.path.append('/opt/c_mgmt/python/lib/python3.9/')
sys.path.append('/opt/c_mgmt/lib/')
sys.path.append('/opt/c_mgmt/bin/')

import xml.etree.cElementTree as ElementTree
import logging
import subprocess
import traceback

# These will have been initialised by the Cafe xstatus framework, for this module
DEV_LOGGER = logging.getLogger('developer.cafe.managementconnector')
ADMIN_LOGGER = logging.getLogger('administrator.cafe.managementconnector')

COMMAND_ERROR = 99


def process_output(output):
    """ handles the validation and processing of the stdout output from status """
    return_value = []
    try:
        DEV_LOGGER.info('process_output- %s, type- %s' % (output, type(output)))
        element_tree = ElementTree.fromstring(output)
        DEV_LOGGER.info('element_tree- %s, type- %s' % (str(element_tree), type(element_tree)))
        return_value.append(element_tree)
    except ElementTree.ParseError as error:
        DEV_LOGGER.error('Detail="Error generating element tree from string: %r %s: %s"',
                         error, error.__str__(), traceback.format_exc())
    return return_value


def get_status(_unused_rest_client, _unused_translate):
    """ get_status adheres to the cafe framework and calls the downstream shell and src xcommand """
    try:
        command = ["/opt/c_mgmt/xstatus/c_mgmt.sh"]
        output = subprocess.check_output(command)
        return process_output(output)

    except subprocess.CalledProcessError as error_content:
        if error_content.returncode != COMMAND_ERROR:
            # Unexpected exit code from subprocess, log and return empty list
            DEV_LOGGER.error('Detail="Unknown internal error when generating XML in xstatus script: '
                             'return_code=%s, output=%s, stacktrace=%s"',
                             error_content.returncode, error_content.output, traceback.format_exc())
        return []

    except OSError as exception:
        # Catch unexpected OS/permissions errors when executing the shell script
        DEV_LOGGER.error('Detail="Error executing xstatus script: %r %s: %s"',
                         exception, exception.__str__(), traceback.format_exc())
        return []
