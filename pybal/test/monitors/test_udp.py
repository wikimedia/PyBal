# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors.udp`.
"""

# Python imports
import mock

# Twisted imports
import twisted.test.proto_helpers

# Testing imports
from .. import test_monitor

# Pybal imports
import pybal.monitor
import pybal.util
from pybal.monitors.udp import UDPMonitoringProtocol


class UDPMonitoringProtocolTestCase(test_monitor.BaseLoopingCheckMonitoringProtocolTestCase):
    monitorClass = UDPMonitoringProtocol

    def setUp(self):
        super(UDPMonitoringProtocolTestCase, self).setUp()

        def startProtocol(*args, **kwargs):
            self.monitor.transport = mock.Mock()
            self.monitor.startProtocol()

        self.reactor.listenUDP = mock.Mock(side_effect=startProtocol)

    def testInit(self):
        self.assertEquals(self.monitor.intvCheck,
                          UDPMonitoringProtocol.INTV_CHECK)
        self.assertEquals(self.monitor.icmp_timeout,
                          UDPMonitoringProtocol.ICMP_TIMEOUT)

        config = pybal.util.ConfigDict()
        config['udp.interval'] = 5
        config['udp.icmp-timeout'] = 2
        monitor = UDPMonitoringProtocol(
            self.coordinator, self.server, config)
        self.assertEquals(monitor.intvCheck, 5)
        self.assertEquals(monitor.icmp_timeout, 2)

    def testRun(self):
        self.assertEquals(self.monitor.last_down_timestamp, 0)
        super(UDPMonitoringProtocolTestCase, self).testRun()
        self.reactor.listenUDP.assert_called_with(0, self.monitor)

    def testConnectionRefused(self):
        monitor = UDPMonitoringProtocol(
            self.coordinator, self.server, self.config)
        monitor.connectionRefused()
        self.assertFalse(monitor.up)
        self.assertNotEquals(monitor.last_down_timestamp, 0)
