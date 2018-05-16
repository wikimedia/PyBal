# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors.runcommand`.
"""

# Testing imports
from .. import test_monitor

# Pybal imports
import pybal.monitor
from pybal.monitors.runcommand import RunCommandMonitoringProtocol


class RunCommandMonitoringProtocolTestCase(test_monitor.BaseMonitoringProtocolTestCase):
    """Test case for `pybal.monitors.RunCommandMonitoringProtocol`."""

    monitorClass = RunCommandMonitoringProtocol

    def setUp(self):
        self.config['runcommand.command'] = '/bin/true'
        super(RunCommandMonitoringProtocolTestCase, self).setUp()

    def testInit(self):
        self.config['runcommand.arguments'] = '[ "--help" ]'
        monitor = RunCommandMonitoringProtocol(
            self.coordinator, self.server, self.config)

        self.assertEquals(monitor.intvCheck,
                          RunCommandMonitoringProtocol.INTV_CHECK)
        self.assertEquals(monitor.timeout,
                          RunCommandMonitoringProtocol.TIMEOUT_RUN)
        self.assertEquals(monitor.arguments, ["--help",])

    def testInitNoArguments(self):
        monitor = RunCommandMonitoringProtocol(
            self.coordinator, self.server, self.config)
        self.assertEquals(monitor.arguments, [""])

    def testInitArgumentsNotStringList(self):
        self.config['runcommand.arguments'] = "[]"
        monitor = RunCommandMonitoringProtocol(
            self.coordinator, self.server, self.config)
        self.assertEquals(monitor.arguments, [""])
