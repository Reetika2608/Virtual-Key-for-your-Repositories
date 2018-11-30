"""
    Version checking code
"""
import xml.etree.ElementTree as ET

def get_expressway_version():
    """
        Gets the Expressway Major.Minor Version from product info xml file
    """
    root = ET.parse("/info/product_info.xml")
    major = root.findtext('version/major')
    minor = root.findtext('version/minor')
    version = "{}.{}".format(major, minor)

    return version

def get_expressway_full_version():
    """
       Gets the Full Expressway Version from product info XML file
    """
    root = ET.parse("/info/product_info.xml")
    major = root.findtext('version/major')
    minor = root.findtext('version/minor')
    maintenance = root.findtext('version/maintenance')
    release_type = root.findtext('version/release/type')
    release_version = root.findtext('version/release/version')

    if maintenance != '0':
        version = "X{}.{}.{}{}{}".format(major, minor, maintenance, release_type, release_version)
    else:
        version = "X{}.{}{}{}".format(major, minor, release_type, release_version)

    return version
