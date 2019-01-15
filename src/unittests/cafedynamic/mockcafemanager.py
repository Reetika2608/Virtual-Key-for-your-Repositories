# Standard library imports

# Local application / library specific imports
from cafedynamic.cafemanager import CAFEManager
from unittests.cafedynamic.mockcafedatabase import MockCAFEDatabase
from managementconnector.config.cafeproperties import CAFEProperties


DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class MockCAFEManager(CAFEManager):
    """
        Mocking out pieces of CAFEManager
    """
    def __init__(self, options):
        """
            MockCAFEManager initialiser
        """
        CAFEManager.__init__(self, options)

    # -------------------------------------------------------------------------

    def _initialise_database(self):
        """
            Initialise the database for this plugin
        """
        DEV_LOGGER.debug('Detail="Mock initialising basic database for Mock CAFE Manager"')

        self.cafe_database = MockCAFEDatabase()

    # -------------------------------------------------------------------------

    def register_file_observer(self, filepath, callback):
        """
            Mock register for INotify's using the filepath & callback specified
        """
        DEV_LOGGER.debug('Detail="Mock registering for INotify " '
                         'File ="%s" '
                         'Callback = "%s"' % (filepath, callback))

    # -------------------------------------------------------------------------

    def unregister_file_observer(self, filepath, callback):
        """
            Mock unregister for INotify's using the filepath & callback specified
        """
        DEV_LOGGER.debug('Detail="Mock unregistering for INotify " '
                         'File ="%s" '
                         'Callback = "%s"' % (filepath, callback))

    # -------------------------------------------------------------------------

    def _register_directory_observer(self, directorypath, callback):
        """
            Mock register for INotify's using the directory path & callback specified
        """
        DEV_LOGGER.debug('Detail="Mock registering for INotify " '
                         'Directory ="%s" '
                         'Callback = "%s"' % (directorypath, callback))

    # -------------------------------------------------------------------------

    def _unregister_directory_observer(self, directorypath, callback):
        """
            Mock unregister for INotify's using the directory path & callback specified
        """
        DEV_LOGGER.debug('Detail="Mock unregistering for INotify " '
                         'Directory ="%s" '
                         'Callback = "%s"' % (directorypath, callback))
