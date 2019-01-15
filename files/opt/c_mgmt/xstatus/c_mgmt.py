"""
    ManagementConnector xstatus
"""

import xml.etree.cElementTree as ElementTree
import json
import traceback

import sys
sys.path.append('/opt/c_mgmt/src/')

from managementconnector.service.service import Service
from managementconnector.config.config import Config
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties
from managementconnector.service.manifest import ServiceManifest

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()
ADMIN_LOGGER = ManagementConnectorProperties.get_admin_logger()


def get_status(rest_cdb_adaptor, i18n_token_translator):
    """
    At a minimum this must return a list with a single <connectors> element.

    if connectors 'hello', and 'csi are installed then the list would at a minumum return a <connectors> element, with
    a subelement for each connector

    e.g

    <connectors item="1">
        <hello>
            <composed_status>not_configured</composed_status>
            <installed>True</installed>
            <enabled>True</enabled>
            <running>True</running>
            <version>8.5-1.111</version>
            <alarms>2</alarms>
            <configured>
                <configured_status>Not Configured|Success|Error</configured_status>
                <!--if configured_status is Success or Error, then add the configuration timestamp-->
                <configured_timestamp>ISO 8601 UTC Date</configured_timestamp>
                <!--if configured_status is Error, then add the error type-->
                <configured_error_type>CafeTemplateSyntaxError|CafeTemplateContentError|CafeConfigWriteError|CafeConfigGenerationError|CafeUnknownError</configured_error_type>
            </configured>
        </hello>
        <csi>
            <composed_status>not_configured</composed_status>
            <installed>True</installed>
            <enabled>False</enabled>
            <running>False</running>
            <version>8.5-1.123</version>
            <alarms>0</alarms>
            <configured>
                <configured_status>Not Configured|Success|Error</configured_status>
                <!--if configured_status is Success or Error, then add the configuration timestamp-->
                <configured_timestamp>ISO 8601 UTC Date</configured_timestamp>
                <!--if configured_status is Error, then add the error type-->
                <configured_error_type>CafeTemplateSyntaxError|CafeTemplateContentError|CafeConfigWriteError|CafeConfigGenerationError|CafeUnknownError</configured_error_type>
            </configured>
        </csi>
    </connectors>

    The list returned can contain additional elements to the <connectors> element, but at stated it must at least
    contain an empty or populated <connectors> element

    """

    entitled_connectors_path = '/configuration/cafe/cafeblobconfiguration/name/c_mgmt_%s?peer=local' % ManagementConnectorProperties.ENTITLED_SERVICES

    try:
        entitled_connectors = rest_cdb_adaptor.get_records(entitled_connectors_path)
    except Exception:  # pylint: disable=W0703:
        DEV_LOGGER.error('Detail="Management Connector entitled connectors path was not found in CDB" '
                         'Entitled Connectors Path="%s" ' % entitled_connectors_path)
        # the name/value pair doesn't exist so return the empty 'connectors' element.
        return []

    DEV_LOGGER.debug('Detail="entitled_connectors="%s" ' % entitled_connectors)

    return _get_status(entitled_connectors, Config(inotify=False), ServiceManifest)


def _get_status(entitled_connectors, _config, manifest_class):
    """Get status"""

    try:
        connectors_elem = ElementTree.Element('connectors')
        if len(entitled_connectors):
            connectors = json.loads(entitled_connectors[0]['value'])

            for connector in connectors:

                connector_name = connector['name']

                DEV_LOGGER.debug('Detail="Creating connector element for connector" '
                                 'Connector="%s"' % connector_name)

                connector_elem = ElementTree.SubElement(connectors_elem, connector_name)

                connector_service = Service(connector_name, _config, None, manifest_class)
                connector_status = connector_service.get_status(False)

                composed_elem = ElementTree.SubElement(connector_elem, 'composed_status')
                composed_elem.text = connector_service.get_composed_status(False)

                installing_elem = ElementTree.SubElement(connector_elem, 'installing')
                installing_elem.text = str(connector_status['installing'])

                installed_elem = ElementTree.SubElement(connector_elem, 'installed')
                installed_elem.text = str(connector_status['installed'])

                enabled_elem = ElementTree.SubElement(connector_elem, 'enabled')
                enabled_elem.text = str(connector_status['enabled'])

                running_elem = ElementTree.SubElement(connector_elem, 'running')
                running_elem.text = str(connector_status['running'])

                op_status_elem = ElementTree.SubElement(connector_elem, 'operational_status')
                op_status_elem.text = str(connector_status['operational_status'])

                version_elem = ElementTree.SubElement(connector_elem, 'version')
                version_elem.text = str(connector_status['version'])

                alarms_elem = ElementTree.SubElement(connector_elem, 'alarms')

                # filter out external alarms
                all_alarms = connector_service.get_alarms()
                ext_alarms = connector_service.get_external_alarms()
                alarms = [alarm for alarm in all_alarms if int(alarm.get('id')) not in ext_alarms]
                alarms_elem.text = str(len(alarms))

                configured_elem = ElementTree.SubElement(connector_elem, 'configured')
                configured_elem.text = str(connector_status['configured'])

    except Exception as ex:
        DEV_LOGGER.error('Detail="Error creating connector element: %r %s: %s"' % (ex, ex.__str__(), traceback.format_exc()))
        raise ex

    return [connectors_elem]
