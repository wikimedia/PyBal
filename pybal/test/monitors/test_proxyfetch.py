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
        self.assertEquals(monitor.URLs, ["http://en.wikipedia.org/test.php"])
        self.assertIsNone(monitor.checkCall)
        self.assertIsNone(monitor.getPageDeferredList)
        self.assertIsNone(monitor.checkStartTime)
        self.assertFalse(monitor.checkAllUrls)
        self.assertEqual(monitor.maxFailures, 0)

        # cleanup
        monitor.stop()

    def testInitIncompleteConfig(self):
        del self.config['proxyfetch.url']
        with self.assertRaises(Exception):
            monitor = ProxyFetchMonitoringProtocol(None, self.server, self.config)

    def testInitMultipleChecks(self):
        config = pybal.util.ConfigDict()
        config['proxyfetch.url'] = '["http://en.wikipedia.org/test.php", "http://de.wikipedia.org/test.php"]'
        config['proxyfetch.check_all'] = True
        monitor = ProxyFetchMonitoringProtocol(None, self.server, config)
        self.assertTrue(monitor.checkAllUrls)
        self.assertEqual(monitor.maxFailures, 0)
        monitor.stop()
        config['proxyfetch.max_failures'] = 1
        monitor = ProxyFetchMonitoringProtocol(None, self.server, config)
        self.assertEqual(monitor.maxFailures, 1)
        monitor.stop()
        del config['proxyfetch.check_all']
        monitor = ProxyFetchMonitoringProtocol(None, self.server, config)
        self.assertEqual(monitor.maxFailures, 0)
        monitor.stop()

    def testStopCallsCancelled(self):
        self.monitor.run()
        with mock.patch.object(self.monitor, 'getPageDeferredList',
                               spec=defer.DeferredList) as m_getPageDeferred:
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

        self.assertIsInstance(d, defer.DeferredList)
        self.assertGreaterEqual(self.monitor.checkStartTime.values()[0], startSeconds)

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
        self.monitor.getPageDeferredList._deferredList[0].callback(testResult)

        mocks['_fetchSuccessful'].assert_called_once_with(
            testResult,
            url='http://en.wikipedia.org/test.php'
        )
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
        self.monitor.getPageDeferredList._deferredList[0].errback(testFailure)

        mocks['_fetchFailed'].assert_called_once_with(
            testFailure,
            url='http://en.wikipedia.org/test.php'
        )
        mocks['_fetchSuccessful'].assert_not_called()
        mocks['_checkFinished'].assert_called()

    def testCheckInactive(self):
        """
        Tests whether monitor.check doesn't do a check when inactive.
        """

        self.monitor.active = False
        self.monitor.getPageDeferredList = mock.sentinel.someDeferred
        self.monitor.check()
        # Should still be the same (sentinel) deferred
        self.assertIs(self.monitor.getPageDeferredList,
                      mock.sentinel.someDeferred)

    def testCheckMultiSuccess(self):
        """If all urls are retrieved correctly, monitor is up."""
        self.monitor.checkAllUrls = True
        self.monitor.active = True
        self.monitor.URLs = [
            'http://www.example.com',
            'http://www1.example.com'
        ]
        clock = task.Clock()
        checkCall = task.LoopingCall(self.monitor.check)
        checkCall.clock = clock
        self.monitor.getProxyPage = mock.MagicMock(
            return_value=defer.Deferred()
        )
        self.assertTrue(self.monitor.firstCheck)
        checkCall.start(200)

        def to_test(result):
            self.assertEqual(self.monitor.currentFailures, [])
            self.assertEqual(self.monitor.getProxyPage.call_count, 2)
            self.assertTrue(self.monitor.up)
            return result
        checkCall.deferred.addCallback(to_test)
        checkCall.stop()

    def testCheckMultiFailure(self):
        self.monitor.checkAllUrls = True
        self.monitor.active = True
        self.monitor.URLs = [
            'http://www.example.com',
            'http://www1.example.com'
        ]
        clock = task.Clock()
        checkCall = task.LoopingCall(self.monitor.check)
        checkCall.clock = clock
        testFailure = defer.fail(defer.TimeoutError("Test failure"))
        self.monitor.getProxyPage = mock.MagicMock(
            side_effect=[defer.Deferred(), testFailure]
        )
        checkCall.start(200)
        # before _checkFinished is fired
        self.assertEqual(self.monitor.currentFailures, ["Test failure"])

        def to_test(result):
            self.assertEqual(self.monitor.getProxyPage.call_count, 2)
            self.assertFalse(self.monitor.up)
            self.assertEqual(self.monitor.currentFailures, [])
            return result
        checkCall.deferred.addCallback(
            to_test
        )
        checkCall.stop()

    def testCheckMultiMaxFailures(self):
        self.monitor.checkAllUrls = True
        self.monitor.active = True
        self.monitor.maxFailures = 1
        self.monitor.URLs = [
            'http://www.example.com',
            'http://www1.example.com'
        ]
        clock = task.Clock()
        checkCall = task.LoopingCall(self.monitor.check)
        checkCall.clock = clock
        testFailure = defer.fail(defer.TimeoutError("Test failure"))
        self.monitor.getProxyPage = mock.MagicMock(
            side_effect=[defer.Deferred(), testFailure]
        )
        checkCall.start(200)
        # before _checkFinished is fired
        self.assertEqual(self.monitor.currentFailures, ["Test failure"])

        def to_test(result):
            self.assertEqual(self.monitor.getProxyPage.call_count, 2)
            self.assertTrue(self.monitor.up)
            self.assertEqual(self.monitor.currentFailures, [])
            return result
        checkCall.deferred.addCallback(
            to_test
        )
        checkCall.stop()

    def testFetchSuccessful(self):
        testResult = "Test page result"
        url = 'http://en.wikipedia.org/wiki/Main_Page'
        self.monitor.checkStartTime = {
            self.monitor._keyFromUrl(url): seconds()
        }
        with mock.patch.object(self.monitor,
                               'report', mock.DEFAULT) as report:
            pm = self.monitor.proxyfetch_metrics['request_duration_seconds']
            pm.labels = mock.MagicMock()
            r = self.monitor._fetchSuccessful(testResult, url=url)
        report.assert_called_once()
        pm.labels.assert_called_with(
            result='successful',
            url=url,
            **self.monitor.metric_labels
        )
        self.assertIs(r, testResult)
        self.assertEqual(len(self.monitor.currentFailures), 0)

    def testFetchFailed(self):
        testMessage = "Testing failed fetches"
        url = 'http://en.wikipedia.org/wiki/Main_Page'
        testFailure = failure.Failure(defer.TimeoutError(testMessage))
        self.monitor.checkStartTime = {
            self.monitor._keyFromUrl(url): seconds()
        }
        self.assertEqual(len(self.monitor.currentFailures), 0)
        with mock.patch.object(self.monitor,
                                 'report',
                                 mock.DEFAULT) as report:
            pm = self.monitor.proxyfetch_metrics['request_duration_seconds']
            pm.labels = mock.MagicMock()
            self.monitor._fetchFailed(testFailure, url=url)
        report.assert_called_once()
        pm.labels.assert_called_with(
            result='failed',
            url=url,
            **self.monitor.metric_labels
        )
        self.assertEqual(self.monitor.currentFailures,
                         [testFailure.getErrorMessage()])

    def testFetchFailedCancelled(self):
        testFailure = failure.Failure(defer.CancelledError())
        url = 'http://en.wikipedia.org/wiki/Main_Page'
        r = self.monitor._fetchFailed(testFailure, url)
        self.assertIsNone(r)
        self.assertEqual(len(self.monitor.currentFailures), 0)

    def testFetchFailedNotTrapped(self):
        testMessage = "Testing failed fetches"
        url = 'http://en.wikipedia.org/wiki/Main_Page'
        testFailure = failure.Failure(Exception(testMessage))
        self.monitor.checkStartTime = {
            self.monitor._keyFromUrl(url): seconds()
        }
        self.assertEqual(self.monitor.currentFailures, [])
        # Twisted raises either the wrapped exception or the Failure itself
        with self.assertRaises((failure.Failure, testFailure.type)):
            self.monitor._fetchFailed(testFailure, url=url)
        testFailure.trap(testFailure.type)
        # Failure raise an exception, but still be recorded
        self.assertEqual(self.monitor.currentFailures,
                         [testFailure.getErrorMessage()])

    def testCheckFinished(self):
        testResult = "Test page result"
        with mock.patch.object(self.monitor, '_resultUp') as mock_up:
            r = self.monitor._checkFinished(testResult)
        mock_up.assert_called_once()
        self.assertIs(r, testResult)
        self.assertIsNone(self.monitor.checkStartTime)
        self.assertEqual(self.monitor.currentFailures, [])

    def testCheckFinishedFailure(self):
        testFailure = failure.Failure(twisted.internet.error.ConnectError("Testing a connect error"))
        self.monitor.currentFailures = [testFailure.getErrorMessage()]
        with mock.patch.object(self.monitor, '_resultDown') as mock_down:
            r = self.monitor._checkFinished(testFailure)
        mock_down.assert_called_with(reason=testFailure.getErrorMessage())
        self.assertIs(r, testFailure)
        self.assertIsNone(self.monitor.checkStartTime)
        self.assertEqual(self.monitor.currentFailures, [])

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
