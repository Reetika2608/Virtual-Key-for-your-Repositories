import unittest

# Standard library imports
import logging
import shutil
import pyratemp
import os
import sys

sys.path.append("/opt/c_mgmt/src/")

# Local application / library specific imports
from cafedynamic.cafefilewriter import CAFEFileWriter
from cafedynamic.cafexutil import CafeXUtils
from managementconnector.config.cafeproperties import CAFEProperties


DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class CAFEFileWriterTest(unittest.TestCase):
    """
        CAFE File Writer Test Class
    """

    def setUp(self):
        """
            CAFE File Writer Test Setup
        """

        DEV_LOGGER.info('***TEST CAFEFileWriterTest Setup***')

        self.cafe_filewriter = None
        self.working_directory = '/tmp/test_cafefilewriter/'

        if os.path.exists(self.working_directory):
            shutil.rmtree(self.working_directory)
        CafeXUtils.make_path(self.working_directory)

    # -------------------------------------------------------------------------

    def tearDown(self):
        """
            CAFE File Writer Test TearDown
        """

        DEV_LOGGER.info('***TEST CAFEFileWriterTest TearDown***')
        self.cafe_filewriter = None

        if os.path.exists(self.working_directory):
            shutil.rmtree(self.working_directory)

    # -------------------------------------------------------------------------

    def create_file(self, filepath, content):
        """
            Write the template content to a filename
        """
        with open(filepath, 'w') as template_file:
            template_file.write(content)

    # -------------------------------------------------------------------------

    def test_cafe_filewriter_valid_template(self):
        """
            Test CAFE File Writer Valid Keywords
        """

        DEV_LOGGER.info('***TEST*** test_cafe_filewriter_valid_template')

        content = VALID_TEMPLATE
        filepath = self.working_directory + 'valid_template.txt'

        self.create_file(filepath, content)

        DEV_LOGGER.debug('***TEST*** test_cafe_filewriter_valid_template: Verifying valid template "%s".' % filepath)
        try:
            CAFEFileWriter.validate_template_file_content(filepath)
        except Exception as ex:
            self.assertIsNone(ex, 'Valid template was not returned')

    # -------------------------------------------------------------------------

    def test_cafe_filewriter_invalid_template(self):
        """
            Test CAFE File Writer Valid Keywords
        """

        DEV_LOGGER.info('***TEST*** test_cafe_filewriter_invalid_template')

        content = INVALID_TEMPLATE
        filepath = self.working_directory + 'invalid_template.txt'

        self.create_file(filepath, content)

        DEV_LOGGER.debug('***TEST*** test_cafe_filewriter_invalid_template: Verifying invalid template "%s".' % filepath)

        with self.assertRaises(pyratemp.TemplateParseError):
            CAFEFileWriter.validate_template_file_content(filepath)

# =============================================================================


VALID_TEMPLATE = """\
{
    "connector": {
        "ci_machine_account": "AppFusionSvc.machAcct",
        "ci_machine_password": "{cipher}xxxxxxxx",
        "ci_client_id": "Cd1e0aaac0b48762efe2a622351aaecd3d57d2944e4ec82ef237806d455279538",
        "ci_secret": "{cipher}xxxxx"
    },
    "expressway": {
        "ipv4_address": "@!EXPRESSWAY_IPV4_INTERNAL_ADDRESS!@",
        "ipv6_address": "@!EXPRESSWAY_IPV6_INTERNAL_ADDRESS!@"
    },
    "cucm_cluster_records": [#!
        $!setvar('cucm_publisher_records', '[cucm for cucm in CDB["/configuration/edgeconfigprovisioning/cucm"] if cucm["role"] == "Publisher"]')!$
        <!--(for cucm_publisher_records_index, cucm_publisher in enumerate(cucm_publisher_records))-->
        {
            "axl_username": "@!cucm_publisher['axl_username']!@",
            "axl_password": "@!cucm_publisher['axl_password']!@",
            "cucm_records": [#!
                $!setvar('cucm_records', '[cucm for cucm in CDB["/configuration/edgeconfigprovisioning/cucm"] if cucm["publisher"] == cucm_publisher["publisher"]]')!$
                <!--(for cucm_records_index, cucm in enumerate(cucm_records))-->
                {
                    "host": "@!cucm["address"]!@",#!
                    $!setvar('is_publisher', '"true" if cucm["role"] == "Publisher" else "false"')!$
                    "publisher": @!is_publisher!@#!
                    $!setvar('closing_bracket', '"}," if cucm_records_index < len(cucm_records) - 1 else "}"')!$
                @!closing_bracket!@
                <!--(end)-->
            ]#!
            $!setvar('closing_bracket', '"}," if cucm_publisher_records_index < len(cucm_publisher_records) - 1 else "}"')!$
        @!closing_bracket!@
        <!--(end)-->
    ],
    "sip_domains": [#!
        $!setvar('sip_domain_records', '[domain for domain in CDB["/configuration/sipdomain"]]')!$
        <!--(for sip_domain_records_index, domain in enumerate(sip_domain_records))-->
        {
            "name": "@!domain["name"]!@",
            "sip": @!domain["edgesip"]!@,
            "federation": @!domain["xmppfederation"]!@,
            "client": @!domain["edgexmpp"]!@#!
            $!setvar('closing_bracket', '"}," if sip_domain_records_index < len(sip_domain_records) - 1 else "}"')!$
        @!closing_bracket!@
        <!--(end)-->
    ]
}
"""

# Extra '-' on first for loop
INVALID_TEMPLATE = """\
{
    "connector": {
        "ci_machine_account": "AppFusionSvc.machAcct",
        "ci_machine_password": "{cipher}xxxxxxxx",
        "ci_client_id": "Cd1e0aaac0b48762efe2a622351aaecd3d57d2944e4ec82ef237806d455279538",
        "ci_secret": "{cipher}xxxxx"
    },
    "expressway": {
        "ipv4_address": "@!EXPRESSWAY_IPV4_INTERNAL_ADDRESS!@",
        "ipv6_address": "@!EXPRESSWAY_IPV6_INTERNAL_ADDRESS!@"
    },
    "cucm_cluster_records": [#!
        $!setvar('cucm_publisher_records', '[cucm for cucm in CDB["/configuration/edgeconfigprovisioning/cucm"] if cucm["role"] == "Publisher"]')!$
        <!---(for cucm_publisher_records_index, cucm_publisher in enumerate(cucm_publisher_records))-->
        {
            "axl_username": "@!cucm_publisher['axl_username']!@",
            "axl_password": "@!cucm_publisher['axl_password']!@",
            "cucm_records": [#!
                $!setvar('cucm_records', '[cucm for cucm in CDB["/configuration/edgeconfigprovisioning/cucm"] if cucm["publisher"] == cucm_publisher["publisher"]]')!$
                <!--(for cucm_records_index, cucm in enumerate(cucm_records))-->
                {
                    "host": "@!cucm["address"]!@",#!
                    $!setvar('is_publisher', '"true" if cucm["role"] == "Publisher" else "false"')!$
                    "publisher": @!is_publisher!@#!
                    $!setvar('closing_bracket', '"}," if cucm_records_index < len(cucm_records) - 1 else "}"')!$
                @!closing_bracket!@
                <!--(end)-->
            ]#!
            $!setvar('closing_bracket', '"}," if cucm_publisher_records_index < len(cucm_publisher_records) - 1 else "}"')!$
        @!closing_bracket!@
        <!--(end)-->
    ],
    "sip_domains": [#!
        $!setvar('sip_domain_records', '[domain for domain in CDB["/configuration/sipdomain"]]')!$
        <!--(for sip_domain_records_index, domain in enumerate(sip_domain_records))-->
        {
            "name": "@!domain["name"]!@",
            "sip": @!domain["edgesip"]!@,
            "federation": @!domain["xmppfederation"]!@,
            "client": @!domain["edgexmpp"]!@#!
            $!setvar('closing_bracket', '"}," if sip_domain_records_index < len(sip_domain_records) - 1 else "}"')!$
        @!closing_bracket!@
        <!--(end)-->
    ]
}
"""



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
