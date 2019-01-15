"""
    Class providing file writing template
"""

# Standard library imports
import os
import pyratemp

# Local application / library specific imports
from managementconnector.config.cafeproperties import CAFEProperties
from base_platform.expressway.filesystem.pyratempfilewriter import PyratempFileWriter

DEV_LOGGER = CAFEProperties.get_dev_logger()


# =============================================================================


class CAFEFileWriter(PyratempFileWriter):
    """
        Class providing file writing template
    """
    template = None
    strip_line_indentation = False

    def config_file_write(self, data, component_template):
        """
            Fill template parameters and write the template
        """

        self.template = component_template

        # Render the template
        try:
            PyratempFileWriter.write_file(self, data)
        except pyratemp.TemplateException as ex:
            raise SyntaxError(ex)

    # -------------------------------------------------------------------------

    def set_file_permissions(self):
        """
            set all read, mgmt write
        """

        try:
            os.chmod(self.get_file_path(), 0644)
        except KeyError as ex:
            raise OSError(ex)
    # -------------------------------------------------------------------------

    @staticmethod
    def validate_template_file_content(filename):
        """
            Taken from pyratemp_tool.py
            Attempt to parse the template file provided
            :returns parsed template
            :except pyratemp.TemplateParseError if template cannot be parsed
        """

        extension = os.path.splitext(filename)[1]
        if extension == ".htm" or extension == ".html":
            template = pyratemp.Template(filename=filename, escape=pyratemp.HTML)
        elif extension == ".tex":
            template = pyratemp.Template(filename=filename, escape=pyratemp.LATEX)
        else:
            template = pyratemp.Template(filename=filename)

        return template


# =============================================================================
