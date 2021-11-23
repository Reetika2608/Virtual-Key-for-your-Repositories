"""
    Class providing convenience methods for component templates.
"""

# Standard library imports
import re

# Local application / library specific imports
from managementconnector.config.cafeproperties import CAFEProperties
from cafedynamic.cafedatabase import CAFEDatabase

DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class CAFEConvenience(object):
    """
        Class providing convenience methods for component templates.

        A convenience method should return a dictionary with two keys:
        1)  A 'data' key which points to the actual data that the method should return
        2)  A 'cdb_tables' key which points to a list of CDB tables, which if changed would effect the 'data' value
            i.e
            It should return what CDB tables the caller of this method should be listening to in order to pick up
            changes for the 'data' key value
            If a table has no inotify path, or a restart of expressway is required when the CDB table changes,
            then there is no need to return that table.
    """

    # -------------------------------------------------------------------------

    @staticmethod
    def get_ipv4_int_network_address(cafe_database):
        """
            Helper method to get internal ipv4 network address
        """
        if isinstance(cafe_database, CAFEDatabase):
            DEV_LOGGER.debug('Detail="CAFEConvenience method get_ipv4_int_network_address() called."')
            return cafe_database.get_internal_network_address()
        else:
            DEV_LOGGER.error('Detail="Programmer error. '
                             'Input parameter to CAFEConvenience method get_ipv4_int_network_address() should be an instance of CAFEDatabase"')

    # -------------------------------------------------------------------------

    @staticmethod
    def get_ipv6_int_network_address(cafe_database):
        """
            Helper method to get internal ipv6 network address
        """
        if isinstance(cafe_database, CAFEDatabase):
            DEV_LOGGER.debug('Detail="CAFEConvenience method get_ipv6_int_network_address() called."')
            return cafe_database.get_internal_network_address(ip_version='ipv6')
        else:
            DEV_LOGGER.error('Detail="Programmer error. '
                             'Input parameter to CAFEConvenience method get_ipv6_int_network_address() should be an instance of CAFEDatabase"')

    # -------------------------------------------------------------------------

    @staticmethod
    def get_convenience_method(keyword):
        """
            Returns convenience method which keyword maps to
        """
        if keyword in CAFEConvenience.convenience_method_map:
            return CAFEConvenience.convenience_method_map[keyword].__get__(CAFEConvenience, None)
        else:
            raise LookupError('Invalid CAFEConvenience keyword.')

    # -------------------------------------------------------------------------

    @staticmethod
    def print_convenience_method_map():
        """
            Prints a map of keywords to convenience methods
        """
        print("\nAvailable Component Template Convenience Methods: \n")
        for keyword, _ in CAFEConvenience.convenience_method_map.items():
            print("Template Keyword: '%s'\t|\tCAFE Manager Method: '%s()'\t|\tMethod DocString: '%s'" \
                  % (keyword,
                     CAFEConvenience.get_convenience_method(keyword).__name__,
                     re.sub(r"\s\s+", " ", CAFEConvenience.get_convenience_method(keyword).__doc__.translate(None, '\n'))))

    # -------------------------------------------------------------------------

    convenience_method_map = {
        'EXPRESSWAY_IPV4_INTERNAL_ADDRESS': get_ipv4_int_network_address,
        'EXPRESSWAY_IPV6_INTERNAL_ADDRESS': get_ipv6_int_network_address
    }


# =============================================================================
