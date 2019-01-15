""" Sets CDB configured state for connectors """

# Ignore "Invalid name" warnings                      pylint: disable=C0103

import json
import traceback
import jsonschema

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.cloud import schema

from managementconnector.platform.hybridlogsetup import initialise_logging_hybrid_services
initialise_logging_hybrid_services("managementconnector")

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


def handle_request(database_handler, connector, request, value):
    """ handles action gets called  """
    if request == "setconfiguredstatus":
        set_configured_status(database_handler, connector, value)
    else:
        DEV_LOGGER.error('Detail="Hybrid Request Handler: unrecognised request: {}"'.format(request))


def set_configured_status(database_handler, connector, value):
    """ handles connector configuration status """
    if value is not None:
        lower_value = str(value).lower()
        if lower_value in ["true", "false"]:
            database_handler.update_blob_entries(ManagementConnectorProperties.CONFIGURED_SERVICES_STATE,
                                                 [connector],
                                                 lower_value)
            DEV_LOGGER.info('Detail="set_configured_status: connector: {}, value: {}"'.format(connector, value))
        else:
            DEV_LOGGER.error('Detail="set_configured_status: invalid param passed, expecting: true|false: connector: {},'
                             ' value: {}"'.format(connector, lower_value))
    else:
        DEV_LOGGER.error('Detail="set_configured_status: invalid param passed: connector: {}, value: {}"'
                         .format(connector, value))


def on_request(database_handler, content):
    """ handle incoming hybrid requests  """
    success = False
    try:
        message = json.loads(content)
        try:
            jsonschema.validate(message, schema.HYBRID_REQUEST_SCHEMA)
            handle_request(database_handler, message['connector'], message['request'], message['value'])
            success = True
        except (jsonschema.ValidationError, KeyError) as validation_exc:
            DEV_LOGGER.error('Detail="Hybrid Request Handler: ValidationError when validating json:%s, stacktrace=%s"'
                             % (repr(validation_exc), traceback.format_exc()))
    except Exception as err:  # pylint: disable=W0703
        DEV_LOGGER.error('Detail="Hybrid Request Handler: error occurred when trying to process request: content: '
                         '%s, exception: %s, stacktrace=%s"' % (content, repr(err), traceback.format_exc()))
    return success