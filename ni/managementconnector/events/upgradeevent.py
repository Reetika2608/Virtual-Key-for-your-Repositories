""" Upgrade Event """

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class UpgradeEvent(object):
    """ Upgrade Event """

    _measurementName = "connectorUpgradeEvent"

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Management Connector Upgrade Event Class'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self, state, connector_type, download_duration, install_duration, file_size, url, version, expressway_version, reason, exception):
        """ Log push metrics init """
        self.state = state
        self.connector_type = connector_type
        self.download_duration = download_duration
        self.install_duration = install_duration
        self.file_size = file_size
        self.url = url
        self.version = version
        self.expressway_version = expressway_version
        self.reason = reason
        self.exception = exception

    def get_detailed_info(self):
        """ gets detailed info about the event """
        tags = dict()
        fields = dict()

        if self.state is not None:
            tags['state'] = self.state

        if self.connector_type is not None:
            tags['connectorType'] = self.connector_type

        if self.download_duration is not None:
            fields['downloadDuration'] = self.download_duration

        if self.install_duration is not None:
            fields['installDuration'] = self.install_duration

        if self.file_size is not None:
            fields['fileSize'] = self.file_size

        if self.url is not None:
            fields['url'] = self.url

        if self.version is not None:
            fields['connectorVersion'] = self.version

        if self.expressway_version is not None:
            fields['platformVersion'] = self.expressway_version

        # Error specific information
        if self.state == ManagementConnectorProperties.EVENT_FAILURE:
            tags['reason'] = self.reason
            if self.exception:
                fields['exception'] = str(self.exception)

        return {"tags": tags, "fields": fields, "measurementName": self._measurementName}