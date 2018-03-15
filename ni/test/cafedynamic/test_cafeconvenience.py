import unittest

# Standard library imports
import logging

import ni.unittests.mock._platform
# Local application / library specific imports
from ni.unittests.cafedynamic.mockcafedatabase import MockCAFEDatabase
from ni.cafedynamic.cafeconvenience import CAFEConvenience
from ni.managementconnector.config.cafeproperties import CAFEProperties

DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class CAFEConvenienceTest(unittest.TestCase):
    """
        CAFE Convenience Test Class
    """

    def setUp(self):
        """
            CAFE Convenience Test Setup
        """

        DEV_LOGGER.info('***TEST CAFEConvenienceTest Setup***')

        self.cafe_database = MockCAFEDatabase()

        self.assertIsNotNone(self.cafe_database, 'CAFEDatabase instance was not successfully created')

    # -------------------------------------------------------------------------

    def tearDown(self):
        """
            CAFE Convenience Test TearDown
        """

        DEV_LOGGER.info('***TEST CAFEConvenienceTest TearDown***')
        self.cafe_database = None

    # -------------------------------------------------------------------------

    def test_cafe_convenience_valid_keywords(self):
        """
            Test CAFE Convenience Valid Keywords
        """

        DEV_LOGGER.info('***TEST*** test_cafe_convenience_valid_keywords')

        def get_keyword_data(test_object, keyword, expecting_cdb_tables=True):
            convenience = CAFEConvenience.get_convenience_method(keyword)(test_object.cafe_database)
            test_object.assertIsNotNone(convenience['data'], 'No "data" was return for convenience keyword "%s".' % keyword)
            if expecting_cdb_tables:
                test_object.assertIsNotNone(convenience['cdb_tables'], 'No "cdb_tables" was return for convenience keyword "%s".' % keyword)

            return convenience

        def validate_keyword_data(test_object, keyword, expected_data):
            DEV_LOGGER.debug('***TEST*** test_cafe_convenience_valid_keywords: Verifying convenience keyword "%s".' % keyword)

            return_data = get_keyword_data(self, keyword)
            test_object.assertEqual(return_data['data'], expected_data['data'],
                                    'Incorrect "data" returned. Expected data "%s" got "%s"' % (expected_data['data'], return_data['data']))
            test_object.assertListEqual(return_data['cdb_tables'], expected_data['cdb_tables'],
                                        'Incorrect "cdb_tables" returned. Expected tables "%s" got "%s"' % (expected_data['cdb_tables'], return_data['cdb_tables']))

        convenience_keyword = 'EXPRESSWAY_IPV4_INTERNAL_ADDRESS'
        convenience_expected_data = {'data': self.cafe_database.internal_ipv4_address,
                                     'cdb_tables': ['/configuration/network', '/configuration/networkinterface']}

        validate_keyword_data(self, convenience_keyword, convenience_expected_data)

        convenience_keyword = 'EXPRESSWAY_IPV6_INTERNAL_ADDRESS'
        convenience_expected_data = {'data': self.cafe_database.internal_ipv6_address,
                                     'cdb_tables': ['/configuration/network', '/configuration/networkinterface']}

        validate_keyword_data(self, convenience_keyword, convenience_expected_data)

    # -------------------------------------------------------------------------

    def test_cafe_convenience_invalid_keywords(self):
        """
            Test CAFE Convenience Invalid Keywords
        """

        DEV_LOGGER.info('***TEST*** test_cafe_convenience_invalid_keywords')

        invalid_convenience_keyword = 'MY_INVALID_CONVENIENCE_KEYWORD'
        DEV_LOGGER.debug('***TEST*** test_cafe_convenience_invalid_keywords: Verifying invalid convenience keyword "%s".' % invalid_convenience_keyword)

        with self.assertRaises(LookupError):
            CAFEConvenience.get_convenience_method(invalid_convenience_keyword)(self.cafe_database)


# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
