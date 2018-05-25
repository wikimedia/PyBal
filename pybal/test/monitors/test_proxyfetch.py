# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors.proxyfetch`.
"""

# Python imports
import unittest, mock

# Twisted imports
import twisted.internet.base
from twisted.internet import defer, reactor, task
from twisted.python import failure
from twisted.python.runtime import seconds

# Pybal imports
import pybal.monitor
from pybal.monitors.proxyfetch import ProxyFetchMonitoringProtocol

# Testing imports
from .. import test_monitor


class ProxyFetchMonitoringProtocolTestCase(test_monitor.BaseLoopingCheckMonitoringProtocolTestCase):
    """Test case for `pybal.monitors.ProxyFetchMonitoringProtocol`."""

    monitorClass = ProxyFetchMonitoringProtocol

    def setUp(self):
        self.config['proxyfetch.url'] = '["http://en.wikipedia.org/test.php"]'
        super(ProxyFetchMonitoringProtocolTestCase, self).setUp()

    def testInit(self):
        monitor = ProxyFetchMonitoringProtocol(None, self.server, self.config)
        self.assertEquals(monitor.intvCheck, ProxyFetchMonitoringProtocol.INTV_CHECK)
        self.assertEquals(monitor.toGET, ProxyFetchMonitoringProtocol.TIMEOUT_GET)
        self.assertEquals(monitor.expectedStatus, ProxyFetchMonitoringProtocol.HTTP_STATUS)
        self.assertEquals(monitor.URL, ["http://en.wikipedia.org/test.php"])
        self.assertIsNone(monitor.checkCall)
        self.assertIsNone(monitor.getPageDeferred)
        self.assertIsNone(monitor.checkStartTime)

        # cleanup
        monitor.stop()

    def testInitIncompleteConfig(self):
        del self.config['proxyfetch.url']
        with self.assertRaises(Exception):
            monitor = ProxyFetchMonitoringProtocol(None, self.server, self.config)

    def testStopCallsCancelled(self):
        self.monitor.run()
        with mock.patch.object(self.monitor, 'getPageDeferred',
            spec=defer.Deferred) as m_getPageDeferred:
            self.monitor.stop()
        m_getPageDeferred.cancel.assert_called()

    def testCheck(self):
        startSeconds = seconds()
        self.monitor.active = True
        with mock.patch.multiple(self.monitor,
                                 getProxyPage=mock.DEFAULT,
                                 _fetchSuccessful=mock.DEFAULT,
                                 _fetchFailed=mock.DEFAULT,
                                 _checkFinished=mock.DEFAULT) as mocks:
            mocks['getProxyPage'].return_value = defer.Deferred()
            d = self.monitor.check()

        self.assertIsInstance(d, defer.Deferred)
        self.assertGreaterEqual(self.monitor.checkStartTime, startSeconds)

        # Check getProxyPage keyword arguments
        kwargs = mocks['getProxyPage'].call_args[1]
        self.assertEqual(kwargs['method'], "GET")
        self.assertEqual(kwargs['host'], self.server.ip)
        self.assertEqual(kwargs['port'], self.server.port)
        self.assertEqual(kwargs['status'], self.monitor.expectedStatus)
        self.assertEqual(kwargs['timeout'], self.monitor.toGET)
        self.assertFalse(kwargs['followRedirect'])

        # Check whether the callback works
        testResult = "Test page"
        self.monitor.getPageDeferred.callback(testResult)

        mocks['_fetchSuccessful'].assert_called_once_with(testResult)
        mocks['_fetchFailed'].assert_not_called()
        mocks['_checkFinished'].assert_called()

    def testCheckFailure(self):
        self.monitor.active = True
        with mock.patch.multiple(self.monitor,
                                 getProxyPage=mock.DEFAULT,
                                 _fetchSuccessful=mock.DEFAULT,
                                 _fetchFailed=mock.DEFAULT,
                                 _checkFinished=mock.DEFAULT) as mocks:
            mocks['getProxyPage'].return_value = defer.Deferred()
            self.monitor.check()

        # Check whether the callback works
        testFailure = failure.Failure(defer.TimeoutError("Test failure"))
        self.monitor.getPageDeferred.errback(testFailure)

        mocks['_fetchFailed'].assert_called_once_with(testFailure)
        mocks['_fetchSuccessful'].assert_not_called()
        mocks['_checkFinished'].assert_called()

    def testCheckInactive(self):
        """
        Tests whether monitor.check doesn't do a check when inactive.
        """

        self.monitor.active = False
        self.monitor.getPageDeferred = mock.sentinel.someDeferred
        self.monitor.check()
        # Should still be the same (sentinel) deferred
        self.assertIs(self.monitor.getPageDeferred, mock.sentinel.someDeferred)

    def testFetchSuccessful(self):
        testResult = "Test page result"
        self.monitor.checkStartTime = seconds()
        with mock.patch.object(self.monitor, '_resultUp') as mock_resultUp:
            r = self.monitor._fetchSuccessful(testResult)
        mock_resultUp.assert_called_once()
        self.assertIs(r, testResult)

    def testFetchFailed(self):
        testMessage = "Testing failed fetches"
        testFailure = failure.Failure(defer.TimeoutError(testMessage))
        self.monitor.checkStartTime = seconds()
        with mock.patch.object(self.monitor, '_resultDown') as mock_resultDown:
            self.monitor._fetchFailed(testFailure)
        mock_resultDown.assert_called_once()

    def testFetchFailedCancelled(self):
        testFailure = failure.Failure(defer.CancelledError())
        with mock.patch.object(self.monitor, '_resultDown') as mock_resultDown:
            r = self.monitor._fetchFailed(testFailure)
        self.assertIsNone(r)
        mock_resultDown.assert_not_called()

    def testFetchFailedNotTrapped(self):
        testMessage = "Testing failed fetches"
        testFailure = failure.Failure(Exception(testMessage))
        self.monitor.checkStartTime = seconds()
        with mock.patch.object(self.monitor, '_resultDown') as mock_resultDown:
            # Twisted raises either the wrapped exception or the Failure itself
            with self.assertRaises((failure.Failure, testFailure.type)):
                self.monitor._fetchFailed(testFailure)
        mock_resultDown.assert_called_once()
        testFailure.trap(testFailure.type)

    def testCheckFinished(self):
        testResult = "Test page result"

        r = self.monitor._checkFinished(testResult)

        self.assertIs(r, testResult)
        self.assertIsNone(self.monitor.checkStartTime)

    def testCheckFinishedFailure(self):
        testFailure = twisted.internet.error.ConnectError("Testing a connect error")

        r = self.monitor._checkFinished(testFailure)

        self.assertIs(r, testFailure)
        self.assertIsNone(self.monitor.checkStartTime)

    def testGetProxyPageHTTP(self):
        testURL = "http://en.wikipedia.org/"
        host = "cp1001.eqiad.wmnet"
        port = 80
        r = ProxyFetchMonitoringProtocol.getProxyPage(
            testURL,
            host=host,
            port=port,
            reactor=self.reactor)
        self.assertIsInstance(r, defer.Deferred)
        # Test whether connectTCP has been called with at least
        # host and port args and the correct factory
        self.assertEqual(len(self.reactor.tcpClients), 1)
        tcpClient = self.reactor.tcpClients[0]
        self.assertEqual(tcpClient[:2], (host, port))
        self.assertIsInstance(tcpClient[2], twisted.web.client.HTTPClientFactory)
        self.assertEqual(tcpClient[2].url, testURL)

    def testGetProxyPageRedir(self):
        testURL = "http://en.wikipedia.org/"
        host = "cp1001.eqiad.wmnet"
        port = 80
        r = ProxyFetchMonitoringProtocol.getProxyPage(testURL,
            host=host,
            port=port,
            status=301,
            reactor=self.reactor)
        self.assertIsInstance(r, defer.Deferred)
        # Test whether connectTCP has been called with at least
        # host and port args and the correct factory
        self.assertEqual(len(self.reactor.tcpClients), 1)
        tcpClient = self.reactor.tcpClients[0]
        self.assertEqual(tcpClient[:2], (host, port))
        self.assertIsInstance(tcpClient[2], pybal.monitors.proxyfetch.RedirHTTPClientFactory)
        self.assertEqual(tcpClient[2].url, testURL)

    def testGetProxyPageHTTPS(self):
        testURL = "https://en.wikipedia.org/"
        host = "cp1001.eqiad.wmnet"
        port = 80
        r = ProxyFetchMonitoringProtocol.getProxyPage(testURL,
            host=host,
            port=port,
            reactor=self.reactor)
        self.assertIsInstance(r, defer.Deferred)
        # Test whether connectTCP has been called with at least
        # host and port args and the correct factory
        self.assertEqual(len(self.reactor.sslClients), 1)
        sslClient = self.reactor.sslClients[0]
        self.assertEqual(sslClient[:2], (host, port))
        self.assertIsInstance(sslClient[2], twisted.web.client.HTTPClientFactory)
        self.assertEqual(sslClient[2].url, testURL)


class RedirHTTPPageGetterTestCase(unittest.TestCase):
    def setUp(self):
        self.protocol = pybal.monitors.proxyfetch.RedirHTTPPageGetter()
        self.protocol.factory = mock.Mock(spec=pybal.monitors.proxyfetch.RedirHTTPClientFactory)
        self.protocol.headers = {}

    def testHandleStatus3xx(self):
        for status in range(301, 304):
            self.protocol.handleStatus(b'1.1', bytes(str(status)), b'Message')
            # handleEndHeaders calls the appropriate handleStatus_xxx method
            self.protocol.handleEndHeaders()
            # Ensure self.factory.failed is not 1 as set by handleStatusDefault
            self.assertEqual(self.protocol.failed, 0, "Status: {}".format(status))

    def testHandleStatus200(self):
        self.protocol.handleStatus(b'1.1', b'200', b'OK')
        # handleEndHeaders calls the appropriate handleStatus_xxx method
        self.protocol.handleEndHeaders()
        # Ensure self.factory.failed is 1 as set by handleStatusDefault
        self.assertEqual(self.protocol.failed, 1)
