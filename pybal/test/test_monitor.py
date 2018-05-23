# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitor`.

"""
import unittest, mock

import pybal.monitor
import pybal.util

import twisted.test.proto_helpers

from .fixtures import PyBalTestCase


class BaseMonitoringProtocolTestCase(PyBalTestCase):
    """
    Base test case class for pybal monitors, intended to
    be subclassed by (all) individual monitors.
    """

    monitorClass = pybal.monitor.MonitoringProtocol

    def setUp(self):
        super(BaseMonitoringProtocolTestCase, self).setUp()
        self.monitor = self.monitorClass(
            self.coordinator, self.server, self.config)
        self.monitor.reactor = self.reactor

    def tearDown(self):
        if self.monitor.active:
            self.monitor.stop()

    def assertDelayedCallInvoked(self, delayedCall, mockedMethod, reactor=None, interval=None):
        """
        Tests whether a reactor.callLater scheduled call is actually invoked.
        Requires reactor to be an instance of task.Clock
        """

        reactor = reactor or self.reactor
        if interval is None:
            interval = delayedCall.getTime() - delayedCall.seconds()

        self.assertTrue(delayedCall.active())
        reactor.advance(interval / 2)
        mockedMethod.assert_not_called()
        reactor.advance(interval / 2)
        self.assertFalse(delayedCall.active())
        mockedMethod.assert_called_once()

    def testRun(self):
        self.monitor.run()
        self.assertTrue(self.monitor.active)

    def testRunAlreadyActive(self):
        self.monitor.run()
        with self.assertRaises(AssertionError):
            self.monitor.run()
        self.assertTrue(self.monitor.active)

    def testStop(self):
        self.monitor.run()
        self.monitor.stop()
        self.assertFalse(self.monitor.active)


class MonitoringProtocolTestCase(PyBalTestCase):
    """
    Test case for `pybal.monitor.MonitoringProtocol`.
    This tests MonitoringProtocol methods in isolation.
    """

    def setUp(self):
        super(MonitoringProtocolTestCase, self).setUp()
        self.monitor = pybal.monitor.MonitoringProtocol(
            self.coordinator,
            self.server,
            self.config,
            reactor=self.reactor)
        self.monitor.__name__ = 'TestMonitor'

    def testReactor(self):
        self.assertIs(self.monitor.reactor, self.reactor)

        monitor = pybal.monitor.MonitoringProtocol(
            self.coordinator,
            self.server,
            self.config,
            reactor=mock.sentinel.reactor
        )
        self.assertIs(monitor.reactor, mock.sentinel.reactor)

        monitor = pybal.monitor.MonitoringProtocol(
            self.coordinator,
            self.server,
            self.config
        )
        self.assertIs(monitor.reactor, twisted.internet.reactor)


    def testRun(self):
        """Test `MonitoringProtocol.run`."""
        self.assertIsNone(self.monitor._shutdownTriggerID)

        self.monitor.run()
        self.assertTrue(self.monitor.active)
        self.assertIn((self.monitor.stop, (), {}),
                      self.monitor.reactor.triggers['before']['shutdown'])

        with self.assertRaises(AssertionError):
            self.monitor.run()

    def testStop(self):
        """Test `MonitoringProtocol.stop`."""
        self.monitor.run()
        self.monitor._shutdownTriggerID = mock.sentinel.shutdownTriggerID
        with mock.patch.object(self.monitor.reactor,
            'removeSystemEventTrigger') as mock_rSET:
            self.monitor.stop()
        self.assertFalse(self.monitor.active)
        mock_rSET.assert_called_once_with(mock.sentinel.shutdownTriggerID)

    def testName(self):
        """Test `MonitoringProtocol._resultUp`."""
        self.assertEquals(self.monitor.name(), 'TestMonitor')

    def testResultUp(self):
        """Test `MonitoringProtocol._resultUp`."""
        self.monitor._resultUp()
        self.assertTrue(self.coordinator.up)

    def testResultUpInactive(self):
        """`MonitoringProtocol._resultUp` should not change state when monitor
        is inactive, unless this is the first check."""
        self.monitor.firstCheck = False
        self.monitor._resultUp()
        self.assertIsNone(self.coordinator.up)

    def testResultDown(self):
        """Test `MonitoringProtocol._resultDown`."""
        self.monitor._resultDown()
        self.assertFalse(self.monitor.up)

    def testResultDownInactive(self):
        """`MonitoringProtocol._resultDown` should not change state when
        monitor is inactive, unless this is the first check."""
        self.monitor.firstCheck = False
        self.monitor._resultDown()
        self.assertIsNone(self.coordinator.up)

    def testGetConfigString(self):
        """Test `MonitoringProtocol._getConfigString`."""
        self.config['testmonitor.strValue'] = 'abc'
        self.assertEquals(self.monitor._getConfigString('strValue'), 'abc')

        self.config['testmonitor.badStrValue'] = 123
        with self.assertRaises(ValueError):
            self.monitor._getConfigString('badStrValue')

    def testGetConfigInt(self):
        """Test `MonitoringProtocol._getConfigInt`."""
        self.config['testmonitor.intValue'] = 123
        self.assertEquals(self.monitor._getConfigInt('intValue'), 123)

    def testGetConfigBool(self):
        """Test `MonitoringProtocol._getConfigBool`."""
        self.config['testmonitor.boolValue'] = 'false'
        self.assertFalse(self.monitor._getConfigBool('boolValue'))

    def testGetConfigStringList(self):
        """Test `MonitoringProtocol._getConfigStringList`."""
        self.config['testmonitor.strListValue'] = '"abc"'
        self.assertEquals(
            self.monitor._getConfigStringList('strListValue'), 'abc')

        self.config['testmonitor.strListValue'] = '["abc", "def"]'
        self.assertEquals(
            self.monitor._getConfigStringList('strListValue'), ['abc', 'def'])

        self.config['testmonitor.unicodeListValue'] = '["abc", u"def"]'
        self.assertEquals(
            self.monitor._getConfigStringList('unicodeListValue'), ['abc', 'def'])

        self.config['testmonitor.badStrListValue'] = '["abc", 123]'
        with self.assertRaises(ValueError):
            self.monitor._getConfigStringList('badStrListValue')

        self.config['testmonitor.emptyStrListValue'] = '[]'
        with self.assertRaises(ValueError):
            self.monitor._getConfigStringList('emptyStrListValue')
