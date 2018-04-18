import unittest

from datetime import datetime, timedelta

from ni.managementconnector.service.eventdampener import EventDampener
from ni.managementconnector.config.managementconnectorproperties import ManagementConnectorProperties


class EventDampenerTest(unittest.TestCase):

    _fail_threshold = ManagementConnectorProperties.EVENT_DAMPENER_INTERVAL

    def test_dampener_is_allowed(self):
        dampener = EventDampener()
        i = 0
        while i < 25:
            if i % self._fail_threshold == 0:
                self.assertTrue(dampener.is_failure_event_permitted(), "Action #{} should be allowed".format(i))
            else:
                self.assertFalse(dampener.is_failure_event_permitted(), "Action #{} should not be allowed".format(i))
            i += 1

    def test_sparse_failures_are_sent(self):
        dampener = EventDampener()

        dampener._fail_count = 2
        dampener._fail_timestamp = datetime.now() - timedelta(hours=12)

        self.assertTrue(dampener.is_failure_event_permitted(), "Late action should be allowed.")

    def test_close_failures_are_unsent(self):
        dampener = EventDampener()

        dampener._fail_count = 2
        dampener._fail_timestamp = datetime.now()

        self.assertFalse(dampener.is_failure_event_permitted(), "Late action should not be allowed.")
