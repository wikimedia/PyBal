# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors.udp`.
"""

# Testing imports
from .. import test_monitor

# Pybal imports
import pybal.monitor
import pybal.util
from pybal.monitors.udp import UDPMonitoringProtocol

# Twisted imports
import twisted.internet.reactor

class UDPMonitoringProtocolTestCase(test_monitor.BaseMonitoringProtocolTestCase):
    monitorClass = UDPMonitoringProtocol

    def setUp(self):
        super(UDPMonitoringProtocolTestCase, self).setUp()
        self.monitor.reactor = twisted.internet.reactor

    def testInit(self):
        self.assertEquals(self.monitor.interval,
                          UDPMonitoringProtocol.INTV_CHECK)
        self.assertEquals(self.monitor.icmp_timeout,
                          UDPMonitoringProtocol.ICMP_TIMEOUT)

        config = pybal.util.ConfigDict()
        config['udp.interval'] = 5
        config['udp.icmp-timeout'] = 2
        monitor = UDPMonitoringProtocol(
            self.coordinator, self.server, config)
        self.assertEquals(monitor.interval, 5)
        self.assertEquals(monitor.icmp_timeout, 2)

    def testRun(self):
        self.assertEquals(self.monitor.last_down_timestamp, 0)
        self.monitor.run()
        self.assertEquals(self.monitor.loop.running, True)
        self.assertTrue(self.monitor.up)

    def testConnectionRefused(self):
        monitor = UDPMonitoringProtocol(
            self.coordinator, self.server, self.config)
        monitor.connectionRefused()
        self.assertFalse(monitor.up)
        self.assertNotEquals(monitor.last_down_timestamp, 0)
