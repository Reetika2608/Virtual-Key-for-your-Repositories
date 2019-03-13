import os
import sys
import defusedxml.ElementTree


PRODUCT_INFO_FILE = '/info/product_info.xml'


class TaacryptoAppender(object):
    """ Dynamically load the correct taacrypto lib """

    @staticmethod
    def append_taacrypto_version():
        """get_taacrypto_version and append"""
        taacrypto_version = '8.11'
        if os.path.isfile(PRODUCT_INFO_FILE):
            tree = defusedxml.ElementTree.parse(PRODUCT_INFO_FILE)
            root = tree.getroot()
            version = root.find('version')
            major_ver = int(version.find('major').text)
            minor_ver = int(version.find('minor').text)

            # set expressway specific taa lib version based on the expressway version
            # this is due to the changes made in the taa libs in expressway 8.11
            if major_ver == 8:
                if minor_ver < 11:
                    taacrypto_version = '8.10'

        sys.path.append('/opt/c_mgmt/lib64/taacrypto/%s/' % taacrypto_version)
