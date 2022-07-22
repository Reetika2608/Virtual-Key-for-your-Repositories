"""
    ManagementConnector xcommand
"""
import sys

sys.path.append('/opt/c_mgmt/python/lib/')
sys.path.append('/opt/c_mgmt/lib/')
# Sys Path needs to be in place before imports performed
import json
import logging
import subprocess  # nosec - usage validated
import traceback

# These will have been initialised by the Cafe xcommand framework, for this module
DEV_LOGGER = logging.getLogger('developer.cafe.managementconnector')
ADMIN_LOGGER = logging.getLogger('administrator.cafe.managementconnector')

COMMAND_ERROR = 99


def run(command_name, parameters, rest_cdb_adaptor, callback, error_queue):  # pylint: disable=W0613
    """Main run method"""

    def usage():
        """Output correct usage information"""
        message = "Incorrect Command supplied: %s - Current options: " % command_name + ", ".join(run_options)
        callback(message)

    # -------------------------------------------------------------------------

    run_options = ["init", "precheck", "defuse", "rollback", "control", "deregistered_check", "repair_certs",
                   "verify_signature", "prefuse_install"]

    if command_name not in run_options:
        usage()
        return

    def validate_error_output(json_string):
        """ ensure error json string has valid content """
        valid = False
        try:
            # Check for valid json and expected entries, for displaying customer facing issues
            json_content = json.loads(json_string)
            if "label" in json_content and "params" in json_content:
                valid = True

        except ValueError:
            DEV_LOGGER.error('Detail="validate_error_output: invalid json content returned from xcommand: %s"',
                             json_string)

        return valid

    def execute_xcommand():
        """ This method invokes a bash script, to pass along the command and params """

        try:
            command = ["/opt/c_mgmt/xcommand/c_mgmt.sh", "{}".format(command_name), '{}'.format(parameters)]
            output = subprocess.check_output(command)  # nosec - argument has been validated
            callback(output)
        except subprocess.CalledProcessError as error_content:
            # Check for an explicit exit code that will supply content for the error queue on stdout
            if error_content.returncode == COMMAND_ERROR:
                DEV_LOGGER.error('Detail="Management Connector error running xcommand: %s, exit code: %s, message=%s"',
                                 command_name,
                                 error_content.returncode,
                                 error_content.output)
                if validate_error_output(error_content.output):
                    error_queue.put(error_content.output)
            else:
                DEV_LOGGER.error('Detail="execute_xcommand: Unknown exception occurred: '
                                 'Exception:%s, stacktrace=%s"' % (repr(error_content), traceback.format_exc()))
                raise

    execute_xcommand()
