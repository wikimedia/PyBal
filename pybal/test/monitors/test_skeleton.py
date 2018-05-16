# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors.__skeleton__`.
"""

# Testing imports
from .. import test_monitor

# Pybal imports
from pybal.monitors.__skeleton__ import SkeletonMonitoringProtocol


class SkeletonMonitoringProtocolTestCase(test_monitor.BaseMonitoringProtocolTestCase):
    """Test case for `pybal.monitors.SkeletonMonitoringProtocol`."""

    monitorClass = SkeletonMonitoringProtocol
