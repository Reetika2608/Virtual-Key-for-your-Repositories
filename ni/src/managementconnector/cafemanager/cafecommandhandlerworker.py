"""
Command handler for CAFE
"""

from multiprocessing.process import Process
from multiprocessing import Queue
from Queue import Empty

import taacrypto

from ni.clusterdatabase import restclient
from ni.cafedynamic.cafexutil import CafeXUtils
from ni.managementframework.applications.commandhandler import CommandError
from ni.managementconnector.config.cafeproperties import CAFEProperties

try:
    # Initialise logging application handle for hybridservices, for XCommands
    from ni.managementconnector.platform.hybridlogsetup import initialise_logging_hybrid_services
    initialise_logging_hybrid_services("managementconnector")
except ImportError:
    # Backwards compatibility
    pass


DEV_LOGGER = CAFEProperties.get_dev_logger()
ADMIN_LOGGER = CAFEProperties.get_admin_logger()


# =============================================================================


class CafeCommandError(CommandError):
    """ Command Error """
    pass

# =============================================================================


class CafeCommandHandlerWorker(object):
    """ CAFE XCommand Handler"""

    def __init__(self):
        """ Cafe Command Initialiser """

        self.uuid = None
        self.emit_result = None
        DEV_LOGGER.debug('Detail="Cafe xcommand initialisation."')

    # -------------------------------------------------------------------------

    def output(self, info):
        """ Cafe Command callback """

        DEV_LOGGER.debug('Detail="Cafe xcommand output." '
                         'uuid="%s" '
                         'info="%s"' % (self.uuid, info))
        self.emit_result(self.uuid, {'info': info})

    # -------------------------------------------------------------------------

    def run(self, uuid, args, result_func, rest_client=None):  # pylint: disable=W0613
        """ run the command """

        self.uuid = uuid
        self.emit_result = result_func
        connector_name = args['connector']
        command_name = args['connector_cmd']
        parameters = args['parameters']

        DEV_LOGGER.debug('Detail="Cafe xcommand invoked. '
                         'uuid="%s" '
                         'Connector Name="%s"'
                         'Command Name="%s"' % (self.uuid, connector_name, command_name))

        # Validate input and decrypt parameters
        try:
            connector_name, command_name, parameters = self.validate_and_transform_input(connector_name, command_name, parameters)
        except CafeCommandError as ex:
            DEV_LOGGER.info('Detail="Error while attempting to process XCommand parameters"')
            raise ex

        # Need to spawn a new process to run the connectors xcommand python module.
        # This is needed so that we can run the module as the connector user rather than as root.
        # Running the module as the connector user will limit what the module can do, thus preventing the
        # module from executing malicious code such as wiping the filesystem

        child_process = None
        error_queue = None
        try:
            # Queue to receive serialised data from the child process
            queue = Queue()

            child_process = Process(target=self.run_connector_module, args=(connector_name, command_name, parameters, queue))
            child_process.start()
            # Wait for a maximum of 5 minutes for the child process the finish
            child_process.join(300)
            # Check if any errors are pushed on the queue
            try:
                error_queue = queue.get(block=False)
                # Got an error on the queue, raise exception
                raise CommandError(error_queue)

            except Empty:
                DEV_LOGGER.debug('Detail="Child Process returned with an empty queue, no errors'
                                 'Connector="%s"' % connector_name)
        except CommandError:
            # Catch and reraise specific Connector CommandErrors
            raise
        except Exception as ex:
            DEV_LOGGER.error('Detail="Error while attempting to run XCommand" '
                             'Error="%r %s"' % (ex, ex.__str__()))
            raise CafeCommandError('Internal Error while attempting to execute Cafe Connector XCommand')

        if not child_process.exitcode == 0:
            DEV_LOGGER.error('Detail="XCommand child process returned error code" '
                             'Error code ="%d"' % child_process.exitcode)
            raise CafeCommandError('Internal Error while attempting to execute Cafe Connector XCommand')

    # -------------------------------------------------------------------------

    @staticmethod
    def validate_and_transform_input(connector_name, command_name, parameters):
        """
        Validate the input, and transform/manipulate input
        """

        if connector_name == '':
            DEV_LOGGER.error('Detail="Connector name missing from Cafe xcommand."')
            raise CafeCommandError('Connector name missing from Cafe xcommand.')

        if not CafeXUtils.is_package_installed(connector_name):
            DEV_LOGGER.error('Detail="Cafe Connector is not installed." '
                             'Connector="%s" ' % connector_name)
            raise CafeCommandError('Cafe Connector "%s" is not installed.' % connector_name)

        if parameters != '':
            # decrypt the parameters
            try:
                parameters = taacrypto.decrypt_with_system_key(parameters)
                if parameters == '':
                    DEV_LOGGER.error('Detail="Parameters missing from Cafe xcommand."')
                    raise CafeCommandError('Parameters missing from Cafe xcommand.')
            except taacrypto.CryptoError as ex:
                DEV_LOGGER.error('Detail="Error decrypting xcommand parameters." '
                                 'Connector="%s" '
                                 'Error="%r %s"' % (connector_name, ex, ex.__str__()))
                raise CafeCommandError('Internal error while attempting to process XCommand parameters for Cafe Connector: "%s" ' % connector_name)

        return connector_name, command_name, parameters

    # -------------------------------------------------------------------------

    def run_connector_module(self, connector_name, command_name, parameters, queue):
        """
        Run the connector module
        """
        # Try to load the python module for the connector
        module_dirpath = '/opt/' + connector_name + '/xcommand/'
        module_name = connector_name
        connector_xcommand_module = None
        module_user = '_' + connector_name

        try:
            connector_xcommand_module = CafeXUtils.load_connector_module(module_dirpath,
                                                                         module_name,
                                                                         CafeCommandError,
                                                                         DEV_LOGGER,
                                                                         module_type='XCommand')
        except (CafeCommandError, CafeXUtils.CafeXModuleNotFound) as ex:
            DEV_LOGGER.error('Detail="Error while attempting to load XCommand module: module_dirpath=%s, module_name=%s"' %
                             (module_dirpath, module_name))
            raise ex

        # Run the connector python module
        if connector_xcommand_module:
            try:
                # To limit the scope of what the connector module can do,
                # run the connector module as the connector user.
                CafeXUtils.set_process_owner(module_user, DEV_LOGGER)
                connector_xcommand_module.run(command_name, parameters, restclient.ClusterDatabaseRestClient(), self.output, queue)
            except Exception as ex:
                DEV_LOGGER.error('Detail="Error while attempting to execute Cafe Connector XCommand." '
                                 'Connector="%s" '
                                 'command_name="%s" '
                                 'Error="%r %s"' % (connector_name, command_name, ex, ex.__str__()))
                raise CafeCommandError('Error while attempting to execute Cafe Connector XCommand.')
        else:
            DEV_LOGGER.error('Detail="Cafe Connector XCommand module was not loaded." '
                             'Connector="%s" '
                             'Command name="%s" '
                             'Module Path="%s" '
                             'Module Name="%s"' % (connector_name, command_name, module_dirpath, module_name))
            raise CafeCommandError('Cafe Connector XCommand module was not loaded.')


# =============================================================================
