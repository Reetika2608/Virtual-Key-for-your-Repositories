""" Log push Event """

from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties

DEV_LOGGER = ManagementConnectorProperties.get_dev_logger()


class LogPushEvent(object):
    """ Log Push Event """

    _measurementName = "logPushEvent"

    # -------------------------------------------------------------------------

    def __str__(self):
        return 'Management Connector Log Push Event Class'

    # -------------------------------------------------------------------------

    __repr__ = __str__

    # -------------------------------------------------------------------------

    def __init__(self, state, log_search_id, archive_duration, upload_duration, file_size,
                 batch_size, reason, exception):
        """ Log push metrics init """
        self.state = state
        self.log_search_id = log_search_id
        self.archive_duration = archive_duration
        self.upload_duration = upload_duration
        self.file_size = file_size
        self.batch_size = batch_size
        self.reason = reason
        self.exception = exception

    def get_detailed_info(self):
        """ gets detailed info about an event """
        tags = dict()
        fields = dict()

        tags['state'] = self.state

        if self.file_size is not None:
            fields['fileSize'] = self.file_size

        if self.batch_size is not None:
            fields['batchSize'] = self.batch_size

        if self.state == ManagementConnectorProperties.EVENT_SUCCESS:
            fields['archiveDuration'] = self.archive_duration
            fields['uploadDuration'] = self.upload_duration
        else:
            tags['reason'] = self.reason
            if self.exception:
                fields['exception'] = self.exception

        fields['logsearchId'] = self.log_search_id

        return {"tags": tags, "fields": fields, "measurementName": self._measurementName}
