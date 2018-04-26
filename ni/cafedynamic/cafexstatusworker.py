"""Contains XML adapter providing status of Cafe"""

import logging
import xml.etree.cElementTree as ElementTree
import copy
from Queue import Empty
from multiprocessing import Queue
from multiprocessing.process import Process
from ni.cafedynamic.cafexutil import CafeXUtils
from ni.clusterdatabase.restclient import ClusterDatabaseRestClient
from ni.utils.i18n import translate

from ni.managementconnector.config.cafeproperties import CAFEProperties

try:
    # Initialise logging application handle for hybridservices, for XStatus
    from ni.managementconnector.platform.hybridlogsetup import initialise_logging_hybrid_services
    initialise_logging_hybrid_services("managementconnector")
except ImportError:
    # Backwards compatibility
    pass


DEV_LOGGER = CAFEProperties.get_dev_logger()
ADMIN_LOGGER = logging.getLogger("administrator.cvs")


# =============================================================================


class CafeStatusError(Exception):
    """
    Status Error
    """
    pass


# =============================================================================


class CafeXStatusWorker(object):
    """
    Implements relevant Cafe stats elements in Status tree

    example:
    https://connect_hostname/getxml?location=/Status/Cafe

    <?xml version="1.0" encoding="UTF-8"?>
    <Status xmlns="http://www.tandberg.no/XML/CUIL/1.0">
        <Cafe item="1">
            <managementconnector item="1">
                <installed item="1">True</installed>
                <enabled item="1">True</enabled>
                <running item="1">True</running>
                <additional item="1">
                    <!--Pulled from managementconnector xstatus module.-->
                    <!--It must return a connectors element containing the following status for each connector-->
                    <connectors item="1">
                        <hello item="1" name="hello">
                            <installed item="1">True</installed>
                            <enabled item="1">True</enabled>
                            <running item="1">True</running>
                            <version item="1">8.5-1.111</version>
                            <configured>
                                <configured_status>Not Configured|Success|Error</configured_status>
                                <!--if configured_status is Success or Error, then add the configuration timestamp-->
                                <configured_timestamp>ISO 8601 UTC Date</configured_timestamp>
                                <!--if configured_status is Error, then add the error type-->
                                <configured_error_type>CafeTemplateSyntaxError|CafeTemplateContentError|CafeConfigWriteError|CafeConfigGenerationError|CafeUnknownError</configured_error_type>
                            </configured>
                        </hello>
                    </connectors>
                    <!--any other status which management connector wishes to publish-->
                </additional>
            </managementconnector>
            <connectors item="1">
                <hello item="1" name="hello">
                    <!--installed, enabled, running, version are retrieved from managementconnectors xstatus module-->
                    <installed item="1">True</installed>
                    <enabled item="1">True</enabled>
                    <running item="1">True</running>
                    <version item="1">8.5-1.111</version>
                    <configured>
                        <configured_status>Not Configured|Success|Error</configured_status>
                        <!--if configured_status is Success or Error, then add the configuration timestamp-->
                        <configured_timestamp>ISO 8601 UTC Date</configured_timestamp>
                        <!--if configured_status is Error, then add the error type-->
                        <configured_error_type>CafeTemplateSyntaxError|CafeTemplateContentError|CafeConfigWriteError|CafeConfigGenerationError|CafeUnknownError</configured_error_type>
                    </configured>
                    <additional item="1">
                        <!--This information is returned from the specific connectors xstatus module-->
                        <connections item="1">100</connections>
                        <reason item="1">DNS failed to resolve the remote host gwydlvm-dummy.</reason>
                    </additional>
                </hello>
            </connectors>
        </Cafe>
    </Status>

    """

    managementconnector = 'c_mgmt'

    def __init__(self):
        """
        CafeStatusAdapter initialiser
        """

        DEV_LOGGER.debug('Detail="Initialising CafeStatusAdapter"')

        self.rest_client = ClusterDatabaseRestClient()

    # -------------------------------------------------------------------------

    def get(self):
        """
        Generates the Cafe status list for managementconnector and installed fusion connectors
        """

        DEV_LOGGER.debug('Detail="CafeStatusAdapter get() called."')

        cafe_elem = ElementTree.Element('Cafe')
        managementconnector_elem = self._create_mc_status()
        cafe_elem.append(managementconnector_elem)

        connectors = copy.deepcopy(managementconnector_elem.find('additional/connectors'))
        connectors_elem = ElementTree.SubElement(cafe_elem, 'connectors')

        if connectors:
            for connector in connectors:
                connectors_elem.append(connector)
                try:
                    connectors_elem.find(connector.tag).append(self._get_additional_status(connector.tag))
                except CafeStatusError as ex:
                    # catch and log. We shouldn't stop other connectors from presenting their status
                    DEV_LOGGER.error('Detail="Error while retrieving additional status from connector" '
                                     'Connector="%s" '
                                     'Error="%r %s"' % (connector.tag, ex, ex.__str__()))
        return cafe_elem

    # -------------------------------------------------------------------------

    def _create_mc_status(self):
        """
        Create Management Connector status element
        """

        DEV_LOGGER.debug('Detail="CafeStatusAdapter: Creating management connector status"')

        managementconnector_elem = ElementTree.Element(self.managementconnector)
        try:
            managementconnector_elem.extend(self._get_managementconnector_status())
            managementconnector_elem.append(self._get_additional_status(self.managementconnector))
        except CafeStatusError as ex:
            DEV_LOGGER.error('Detail="Error while creating status for Management Connector" '
                             'Error="%r %s"' % (ex, ex.__str__()))
        return managementconnector_elem

    # -------------------------------------------------------------------------

    def _get_managementconnector_status(self):
        """
        Get ManagementConnectors basic status
        """

        DEV_LOGGER.debug('Detail="CafeStatusAdapter: Retrieving management connector status"')

        element_list = []

        try:
            installed_elem = ElementTree.Element('installed')
            installed_elem.text = str(CafeXUtils.is_package_installed(self.managementconnector))
            element_list.append(installed_elem)

            enabled_elem = ElementTree.Element('enabled')
            enabled_elem.text = str(CafeXUtils.is_connector_enabled(self.rest_client, self.managementconnector))
            element_list.append(enabled_elem)

            running_elem = ElementTree.Element('running')
            running_elem.text = str(CafeXUtils.is_connector_running(self.managementconnector,DEV_LOGGER))
            element_list.append(running_elem)
        except Exception as ex:
            DEV_LOGGER.error('Detail="Error while retrieving status for Management Connector" '
                             'Error="%r %s"' % (ex, ex.__str__()))
            raise CafeStatusError('Error while retrieving status for Management Connector')

        return element_list

    # -------------------------------------------------------------------------

    def _get_additional_status(self, connector_name):
        """
        Get the connectors additional status element
        """

        DEV_LOGGER.debug('Detail="CafeStatusAdapter: Retrieving additional status for connector" '
                         'Connector="%s"' % connector_name)

        connector_additional_elem = ElementTree.Element('additional')

        # Need to spawn a new process to run the connectors xstatus python module.
        # This is needed so that we can run the module as the connector user rather than as root.
        # Running the module as the connector user will limit what the module can do, thus preventing the
        # module from executing malicious code such as wiping the filesystem

        child_process = None
        connector_elements_str_list = None
        try:
            # Queue to receive serialised data from the child process
            queue = Queue()

            DEV_LOGGER.debug('Detail="CafeStatusAdapter: Attempting to spawn child process for connecter xstatus execution" '
                             'Connector="%s"' % connector_name)
            child_process = Process(target=self._get_connector_status, args=(connector_name, queue))
            child_process.start()
            # Wait for a maximum of 5 minutes for the child process to put something on the queue
            try:
                connector_elements_str_list = queue.get(block=True, timeout=300)
            except Empty as ex:
                DEV_LOGGER.error('Detail="Timeout while attempting to read from child process queue" '
                                 'Connector="%s"' % connector_name)
                raise ex
            finally:
                # either the Queue timed-out or we got something from it. Either way we're done with this process.
                # If we got something from the queue then the process should exit naturally straight away. If the Queue
                # timed-out, then something has gone wrong and we should force the process to terminate, by specifying a
                # 1 second timeout in the join.
                child_process.join(1)
        except Exception as ex:
            DEV_LOGGER.error('Detail="Error while attempting to run XStatus" '
                             'Connector="%s" '
                             'Error="%r %s"' % (connector_name, ex, ex.__str__()))
            raise CafeStatusError('Internal Error while attempting to execute Cafe Connector XStatus')

        if not child_process.exitcode == 0:
            DEV_LOGGER.error('Detail="XStatus child process returned error code" '
                             'Connector="%s" '
                             'Error code="%d"' % (connector_name, child_process.exitcode))
            raise CafeStatusError('Internal Error while attempting to execute Cafe Connector XStatus')

        try:
            # reconstruct the elements from their strings and add them as subelements to the 'additional' element
            for connector_elem_str in connector_elements_str_list:
                sub_element = ElementTree.fromstring(connector_elem_str)
                connector_additional_elem.append(sub_element)
        except Exception as ex:
            DEV_LOGGER.error('Detail="Invalid XML returned from connector XStatus module" '
                             'Connector="%s" '
                             'XML List="%s" '
                             'Error="%r %s"' % (connector_name, connector_elements_str_list, ex, ex.__str__()))
            raise CafeStatusError('Invalid XML returned from connector XStatus module')

        return connector_additional_elem

    # -------------------------------------------------------------------------

    def _get_connector_status(self, connector_name, queue):
        """
        Run the connector xstatus module
        """
        # Try to load the python module for the connector
        module_dirpath = '/opt/' + connector_name + '/xstatus/'
        module_name = connector_name
        connector_xstatus_module = None
        module_user = '_' + connector_name

        try:
            DEV_LOGGER.debug('Detail="CafeStatusAdapter: Attempting to load xstatus module for connector" '
                             'Connector="%s"' % connector_name)
            connector_xstatus_module = CafeXUtils.load_connector_module(module_dirpath, module_name, CafeStatusError, DEV_LOGGER, module_type='XStatus')
        except CafeXUtils.CafeXModuleNotFound:
            DEV_LOGGER.debug('Detail="XStatus module not provided by connector. Ignoring" '
                             'Connector="%s" ' % connector_name)
            queue.put([])
            return
        except CafeStatusError as ex:
            DEV_LOGGER.error('Detail="Error while attempting to load XStatus module" '
                             'Connector="%s" ' % connector_name)
            queue.put([])
            raise ex

        # Run the connector python module
        if connector_xstatus_module:
            try:
                # To limit the scope of what the connector module can do,
                # run the connector module as the connector user.
                DEV_LOGGER.debug('Detail="CafeStatusAdapter: Attempting to execute xstatus module for connector" '
                                 'Connector="%s"' % connector_name)
                CafeXUtils.set_process_owner(module_user, DEV_LOGGER)
                connector_elements = connector_xstatus_module.get_status(self.rest_client, translate)
                connector_elements_str_list = list()
                for connector_element in connector_elements:
                    connector_elements_str_list.append(ElementTree.tostring(connector_element))
                queue.put(connector_elements_str_list)
            except Exception as ex:
                DEV_LOGGER.error('Detail="Error while attempting to execute Cafe Connector XStatus." '
                                 'Connector="%s" '
                                 'Error="%r %s"' % (connector_name, ex, ex.__str__()))
                queue.put([])
                raise CafeStatusError('Error while attempting to execute Cafe Connector XStatus.')
        else:
            DEV_LOGGER.error('Detail="Cafe Connector XStatus module was not loaded." '
                             'Connector="%s" '
                             'Module Path="%s" '
                             'Module Name="%s"' % (connector_name, module_dirpath, module_name))
            queue.put([])
            raise CafeStatusError('Cafe Connector XStatus module was not loaded.')

    # -------------------------------------------------------------------------
