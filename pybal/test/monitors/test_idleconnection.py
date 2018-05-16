# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors.idleconnection`.
"""

# Testing imports
from .. import test_monitor

import mock

# Pybal imports
import pybal.monitor
from pybal.monitors.idleconnection import IdleConnectionMonitoringProtocol

# Twisted imports
import twisted.internet.tcp
from twisted.python import failure

# Python imports
import socket


class IdleConnectionMonitoringProtocolTestCase(test_monitor.BaseMonitoringProtocolTestCase):
    """Test case for `pybal.monitors.IdleConnectionMonitoringProtocol`."""

    monitorClass = IdleConnectionMonitoringProtocol

    def setUp(self):
        super(IdleConnectionMonitoringProtocolTestCase, self).setUp()
        self.monitor.reactor = self.reactor

    def testInit(self):
        """Test `IdleConnectionMonitoringProtocol.__init__`."""
        monitor = IdleConnectionMonitoringProtocol(None, self.server, self.config)
        IC = IdleConnectionMonitoringProtocol
        self.assertEqual(monitor.maxDelay, IC.MAX_DELAY)
        self.assertEqual(monitor.toCleanReconnect, IC.TIMEOUT_CLEAN_RECONNECT)
        self.assertEqual(monitor.keepAlive, IC.KEEPALIVE)
        self.assertEqual(monitor.keepAliveRetries, IC.KEEPALIVE_RETRIES)
        self.assertEqual(monitor.keepAliveIdle, IC.KEEPALIVE_IDLE)
        self.assertEqual(monitor.keepAliveInterval, IC.KEEPALIVE_INTERVAL)

        self.config.update({
            'idleconnection.max-delay': '123',
            'idleconnection.timeout-clean-reconnect': '456',
            'idleconnection.keepalive': 'true',
            'idleconnection.keepalive-retries': 5,
            'idleconnection.keepalive-idle': 8,
            'idleconnection.keepalive-interval': 60
        })
        monitor = IdleConnectionMonitoringProtocol(None, self.server, self.config)
        self.assertEqual(monitor.maxDelay, 123)
        self.assertEqual(monitor.toCleanReconnect, 456)
        self.assertTrue(monitor.keepAlive)
        self.assertEqual(monitor.keepAliveRetries, 5)
        self.assertEqual(monitor.keepAliveIdle, 8)
        self.assertEqual(monitor.keepAliveInterval, 60)

    def testRun(self):
        """Test `IdleConnectionMonitoringProtocol.run`."""
        super(IdleConnectionMonitoringProtocolTestCase, self).testRun()
        connector = self.reactor.connectors.pop()
        destination = connector.getDestination()
        self.assert_((destination.host, destination.port) == (self.server.host, self.server.port)
                     or (destination.host, destination.port) == (self.server.ip, self.server.port))

    def testStop(self):
        with mock.patch.object(self.monitor, 'stopTrying') as mock_stopTrying:
            super(IdleConnectionMonitoringProtocolTestCase, self).testStop()
        mock_stopTrying.assert_called()

    def testStartedConnecting(self):
        testConnector = mock.Mock(spec=twisted.internet.tcp.Connector)
        testConnector.transport = mock.sentinel.transport
        self.monitor.startedConnecting(testConnector)
        self.assertIs(self.monitor.transport, mock.sentinel.transport)

    def testClientConnectionFailed(self):
        self.monitor.active = True
        self.monitor.up = True
        testConnector = mock.Mock(spec=twisted.internet.tcp.Connector)
        testFailure = failure.Failure(
            twisted.internet.error.ConnectError("Testing a connect error"))
        with mock.patch.object(self.monitor, 'retry') as mock_retry:
            self.monitor.clientConnectionFailed(testConnector, testFailure)
        self.assertFalse(self.monitor.up)
        mock_retry.assert_called_once_with(testConnector)

    def testClientConnectionFailedNotActive(self):
        self.monitor.active = False
        testConnector = mock.Mock(spec=twisted.internet.tcp.Connector)
        testFailure = failure.Failure(
            twisted.internet.error.ConnectError("Testing a connect error"))
        with mock.patch.object(self.monitor, '_resultDown') as mock_resultDown:
            self.monitor.clientConnectionFailed(testConnector, testFailure)
        mock_resultDown.assert_not_called()

    def testClientConnectionLost(self):
        self.monitor.active = True
        self.monitor.up = True
        testConnector = mock.Mock(spec=twisted.internet.tcp.Connector)
        testFailure = failure.Failure(
            twisted.internet.error.ConnectionLost("Testing lost connection"))
        with mock.patch.object(self.monitor, 'retry') as mock_retry:
            self.monitor.clientConnectionLost(testConnector, testFailure)
        self.assertFalse(self.monitor.up)
        mock_retry.assert_called_once_with(testConnector)

    def testClientConnectionLostNotActive(self):
        self.monitor.active = False
        testConnector = mock.Mock(spec=twisted.internet.tcp.Connector)
        testFailure = failure.Failure(
            twisted.internet.error.ConnectionLost("Testing lost connection"))
        with mock.patch.object(self.monitor, '_resultDown') as mock_resultDown:
            self.monitor.clientConnectionLost(testConnector, testFailure)
        mock_resultDown.assert_not_called()

    def testClientConnectionLostCleanly(self):
        self.monitor.active = True
        self.monitor.up = True
        testConnector = mock.Mock(spec=twisted.internet.tcp.Connector)
        testFailure = failure.Failure(
            twisted.internet.error.ConnectionDone("Testing cleanly closed connection"))
        with mock.patch.object(self.monitor, '_connect') as mock_connect:
            self.monitor.clientConnectionLost(testConnector, testFailure)
        self.assertTrue(self.monitor.up)
        mock_connect.assert_called_once_with(timeout=self.monitor.toCleanReconnect)

    def testClientConnectionMade(self):
        """Test `IdleConnectionMonitoringProtocol.clientConnectionMade`."""
        self.monitor.run()
        self.monitor.up = False
        with mock.patch.object(self.monitor, 'resetDelay') as mock_resetDelay:
            self.monitor.clientConnectionMade()
        self.assertTrue(self.monitor.up)
        mock_resetDelay.assert_called_once()

    def testClientConnectionMadeKeepalive(self):
        self.monitor.transport = mock.Mock(spec=twisted.internet.tcp.Connection)
        self.monitor.active = True
        self.monitor.keepAlive = True
        self.monitor.clientConnectionMade()
        testSocket = self.monitor.transport.getHandle()
        testSocket.setsockopt.assert_called()
        setsockopt_args = {args[0] for args in testSocket.setsockopt.call_args_list}
        expected_args = {
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        }
        try:
            expected_args.update({
                (socket.SOL_TCP, socket.TCP_KEEPIDLE, self.monitor.keepAliveIdle),
                (socket.SOL_TCP, socket.TCP_KEEPCNT, self.monitor.keepAliveRetries),
                (socket.SOL_TCP, socket.TCP_KEEPINTVL, self.monitor.keepAliveInterval)
            })
        except AttributeError:
            pass    # Not Linux
        self.assertEqual(setsockopt_args, expected_args)

    def testclientConnectionMadeKeepaliveNotActive(self):
        self.monitor.active = False
        with mock.patch.object(self.monitor, '_resultUp') as mock_resultUp:
            self.monitor.clientConnectionMade()
        mock_resultUp.assert_not_called()

    def testBuildProtocol(self):
        """Test `IdleConnectionMonitoringProtocol.buildProtocol`."""
        self.monitor.run()
        self.monitor.up = False
        self.monitor.buildProtocol(None)
        self.assertTrue(self.monitor.up)

    def testConnect(self):
        with mock.patch.object(self.monitor, 'reactor') as mock_reactor:
            self.monitor._connect(mock.sentinel.arg1)
        mock_reactor.connectTCP.assert_called_with(
            self.monitor.server.ip,
            self.monitor.server.port,
            self.monitor,
            mock.sentinel.arg1)
