""" US22967: FMC: Introduce back-off logic in event sending if FMC can't download/install a connector """

from datetime import datetime, timedelta

from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties


class EventDampener:
    """ Class to manage back-off of Event Sending. """

    _total_failures = 0
    _fail_count = 0
    _fail_threshold = ManagementConnectorProperties.EVENT_DAMPENER_INTERVAL
    _fail_timestamp = None

    def __init__(self):
        pass

    def is_failure_event_permitted(self):
        """
            Method to decide whether or not to allow an action, based on a set interval (_fail_threshold).

            This method is called when has an Event failure has occurred (e.g: Upgrade Event failure). Each time the
            method is called, the _fail_count is incremented.  On the first failure, the event permitted.
            On subsequent failures, the event is suppressed. Once the _fail_count reaches the threshold, it resets.
            A repetitive event is only sent according the interval set for _fail_threshold.

            If a sufficient amount of time has passed since the last failure event (_fail_timestamp), the count resets.
            This allows infrequent, intermittent failures to be sent so they are not hidden by the suppression.
        """

        if self._fail_timestamp:
            if datetime.now() > self._fail_timestamp + timedelta(hours=6):
                self._fail_count = 0

        self._fail_count += 1
        self._total_failures += 1
        self._fail_timestamp = datetime.now()

        if self._fail_count == 1:
            return True

        if self._fail_count >= self._fail_threshold:
            self._fail_count = 0

        return False

    def reset_counters(self):
        """ Method to reset failure count. """
        self._total_failures = 0
        self._fail_count = 0

    def get_total_failures(self):
        """ Return total number of failures since last successful action """
        return self._total_failures
