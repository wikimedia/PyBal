# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors`.

"""

import pybal.util
import pybal.monitor
from pybal.monitors.__skeleton__ import SkeletonMonitoringProtocol
from pybal.monitors.proxyfetch import ProxyFetchMonitoringProtocol
from pybal.monitors.idleconnection import IdleConnectionMonitoringProtocol
from pybal.monitors.dnsquery import DNSQueryMonitoringProtocol
from pybal.monitors.runcommand import RunCommandMonitoringProtocol
from pybal.monitors.udp import UDPMonitoringProtocol

from twisted.internet import defer, reactor, base, task
from twisted.names.common import ResolverBase
from twisted.names import dns, error
from twisted.python.runtime import seconds
from twisted.python import failure
import twisted.test.proto_helpers
import twisted.internet.error
import twisted.web.client

import unittest, mock

from .fixtures import PyBalTestCase


class BaseMonitoringProtocolTestCase(PyBalTestCase):
    """Base test case for pybal monitors"""

    monitorClass = pybal.monitor.MonitoringProtocol

    def setUp(self):
        super(BaseMonitoringProtocolTestCase, self).setUp()
        self.monitor = self.monitorClass(
            self.coordinator, self.server, self.config)
        self.monitor.reactor = reactor

    def tearDown(self):
        if self.monitor.active:
            self.monitor.stop()

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


class SkeletonMonitoringProtocolTestCase(BaseMonitoringProtocolTestCase):
    """Test case for `pybal.monitors.SkeletonMonitoringProtocol`."""

    monitorClass = SkeletonMonitoringProtocol

class ProxyFetchMonitoringProtocolTestCase(BaseMonitoringProtocolTestCase):
    """Test case for `pybal.monitors.ProxyFetchMonitoringProtocol`."""

    monitorClass = ProxyFetchMonitoringProtocol

    def assertCheckScheduled(self, mock_callLater, mock_DC):
        """
        Tests whether a new check has been scheduled using reactor.mock_callLater
        Requires mocked callLater and DelayedCall as arguments
        """

        self.assertIs(self.monitor.checkCall, mock_DC)
        mock_callLater.assert_called_with(self.monitor.intvCheck, self.monitor.check)

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

    @mock.patch.object(reactor, 'callLater')
    def testRun(self, mock_callLater):
        mock_DC = mock.Mock(spec=twisted.internet.base.DelayedCall)
        mock_callLater.return_value = mock_DC
        super(ProxyFetchMonitoringProtocolTestCase, self).testRun()
        self.assertCheckScheduled(mock_callLater, mock_DC)
        # Don't upset self.tearDown
        self.monitor.checkCall = None

    @mock.patch.object(reactor, 'callLater')
    def testRunAlreadyActive(self, mock_callLater):
        mock_DC = mock.Mock(spec=twisted.internet.base.DelayedCall)
        mock_DC.active.return_value = True
        mock_callLater.return_value = mock_DC
        super(ProxyFetchMonitoringProtocolTestCase, self).testRun()
        # Make sure monitor.checkCall hasn't been replaced
        self.assertEqual(self.monitor.checkCall, mock_DC)
        # Don't upset self.tearDown
        self.monitor.checkCall = None

    @mock.patch.object(reactor, 'callLater')
    def testStopCallsCancelled(self, mock_callLater):
        self.monitor.run()
        cmCheckCall = mock.patch.object(self.monitor, 'checkCall',
            spec=twisted.internet.base.DelayedCall)
        cmGetPageDeferred = mock.patch.object(self.monitor, 'getPageDeferred',
            spec=defer.Deferred)
        with cmCheckCall as m_checkCall, cmGetPageDeferred as m_getPageDeferred:
            self.monitor.stop()
        m_checkCall.cancel.assert_called()
        m_getPageDeferred.cancel.assert_called()

    def testCheckInterval(self):
        with mock.patch('pybal.monitors.proxyfetch.reactor', new_callable=task.Clock) as reactor:
            with mock.patch.object(self.monitor, 'check') as mock_check:
                self.monitor.run()
        reactor.advance(self.monitor.intvCheck / 2)
        mock_check.assert_not_called()
        reactor.advance(self.monitor.intvCheck / 2)
        mock_check.assert_called_once()

    @mock.patch('pybal.monitors.proxyfetch.reactor',
        new_callable=twisted.test.proto_helpers.MemoryReactor)
    def testCheck(self, mock_reactor):
        startSeconds = seconds()
        self.monitor.active = True
        with mock.patch.multiple(self.monitor,
                                 getProxyPage=mock.DEFAULT,
                                 _fetchSuccessful=mock.DEFAULT,
                                 _fetchFailed=mock.DEFAULT,
                                 _checkFinished=mock.DEFAULT) as mocks:
            mocks['getProxyPage'].return_value = defer.Deferred()
            self.monitor.check()

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

    @mock.patch('pybal.monitors.proxyfetch.reactor',
        new_callable=twisted.test.proto_helpers.MemoryReactor)
    def testCheckFailure(self, mock_reactor):
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

    @mock.patch.object(reactor, 'callLater')
    def testCheckFinished(self, mock_callLater):
        self.monitor.active = True
        testResult = "Test page result"
        mock_DC = mock.Mock(spec=twisted.internet.base.DelayedCall)
        mock_callLater.return_value = mock_DC

        r = self.monitor._checkFinished(testResult)

        self.assertIs(r, testResult)
        self.assertIsNone(self.monitor.checkStartTime)
        self.assertCheckScheduled(mock_callLater, mock_DC)

    @mock.patch.object(reactor, 'callLater')
    def testCheckFinishedNotActive(self, mock_callLater):
        self.monitor.active = False
        testResult = "Test page result"
        self.monitor._checkFinished(testResult)
        mock_callLater.ensure_not_called()

    @mock.patch.object(reactor, 'callLater')
    def testCheckFinishedFailure(self, mock_callLater):
        self.monitor.active = True
        testFailure = twisted.internet.error.ConnectError("Testing a connect error")
        mock_DC = mock.Mock(spec=twisted.internet.base.DelayedCall)
        mock_callLater.return_value = mock_DC

        r = self.monitor._checkFinished(testFailure)

        self.assertIs(r, testFailure)
        self.assertIsNone(self.monitor.checkStartTime)
        self.assertCheckScheduled(mock_callLater, mock_DC)

    @mock.patch.object(reactor, 'connectTCP')
    def testGetProxyPageHTTP(self, mock_connectTCP):
        testURL = "http://en.wikipedia.org/"
        host = "cp1001.eqiad.wmnet"
        port = 80
        r = ProxyFetchMonitoringProtocol.getProxyPage(testURL, host=host, port=port)
        self.assertIsInstance(r, defer.Deferred)
        # Test whether connectTCP has been called with at least
        # host and port args and the correct factory
        mock_connectTCP.assert_called_once()
        self.assertEqual(mock_connectTCP.call_args[0][:2], (host, port))
        self.assertIsInstance(mock_connectTCP.call_args[0][2],
                              twisted.web.client.HTTPClientFactory)

    @mock.patch.object(reactor, 'connectTCP')
    def testGetProxyPageRedir(self, mock_connectTCP):
        testURL = "http://en.wikipedia.org/"
        host = "cp1001.eqiad.wmnet"
        port = 80
        r = ProxyFetchMonitoringProtocol.getProxyPage(testURL,
            host=host, port=port, status=301)
        self.assertIsInstance(r, defer.Deferred)
        # Test whether connectTCP has been called with at least
        # host and port args and the correct factory
        mock_connectTCP.assert_called_once()
        self.assertEqual(mock_connectTCP.call_args[0][:2], (host, port))
        self.assertIsInstance(mock_connectTCP.call_args[0][2],
                              pybal.monitors.proxyfetch.RedirHTTPClientFactory)

    @mock.patch.object(reactor, 'connectSSL')
    def testGetProxyPageHTTPS(self, mock_connectSSL):
        testURL = "https://en.wikipedia.org/"
        host = "cp1001.eqiad.wmnet"
        port = 80
        r = ProxyFetchMonitoringProtocol.getProxyPage(testURL, host=host, port=port)
        self.assertIsInstance(r, defer.Deferred)
        # Test whether connectTCP has been called with at least
        # host and port args and the correct factory
        mock_connectSSL.assert_called_once()
        self.assertEqual(mock_connectSSL.call_args[0][:2], (host, port))
        self.assertIsInstance(mock_connectSSL.call_args[0][2],
                              twisted.web.client.HTTPClientFactory)


class RedirHTTPPageGetterTestCase(unittest.TestCase):
    def setUp(self):
        self.protocol = pybal.monitors.proxyfetch.RedirHTTPPageGetter()
        self.protocol.factory = mock.Mock(spec=pybal.monitors.proxyfetch.RedirHTTPClientFactory)
        self.protocol.headers = {}

    @unittest.skip("Fails for status 302 and 303")
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


class IdleConnectionMonitoringProtocolTestCase(BaseMonitoringProtocolTestCase):
    """Test case for `pybal.monitors.IdleConnectionMonitoringProtocol`."""

    monitorClass = IdleConnectionMonitoringProtocol

    def setUp(self):
        super(IdleConnectionMonitoringProtocolTestCase, self).setUp()
        self.monitor.reactor = self.reactor

    def testInit(self):
        """Test `IdleConnectionMonitoringProtocol.__init__`."""
        monitor = IdleConnectionMonitoringProtocol(None, self.server, self.config)
        self.assertEquals(
            monitor.maxDelay, IdleConnectionMonitoringProtocol.MAX_DELAY)
        self.assertEquals(
            monitor.toCleanReconnect,
            IdleConnectionMonitoringProtocol.TIMEOUT_CLEAN_RECONNECT
        )
        self.config['idleconnection.max-delay'] = '123'
        self.config['idleconnection.timeout-clean-reconnect'] = '456'
        monitor = IdleConnectionMonitoringProtocol(None, self.server, self.config)
        self.assertEquals(monitor.maxDelay, 123)
        self.assertEquals(monitor.toCleanReconnect, 456)

    def testRun(self):
        """Test `IdleConnectionMonitoringProtocol.run`."""
        self.monitor.run()
        connector = self.reactor.connectors.pop()
        destination = connector.getDestination()
        self.assert_((destination.host, destination.port) == (self.server.host, self.server.port)
                     or (destination.host, destination.port) == (self.server.ip, self.server.port))

    def testClientConnectionMade(self):
        """Test `IdleConnectionMonitoringProtocol.clientConnectionMade`."""
        self.monitor.run()
        self.monitor.up = False
        self.monitor.clientConnectionMade()
        self.assertTrue(self.monitor.up)

    def testBuildProtocol(self):
        """Test `IdleConnectionMonitoringProtocol.buildProtocol`."""
        self.monitor.run()
        self.monitor.up = False
        self.monitor.buildProtocol(None)
        self.assertTrue(self.monitor.up)


class FakeResolverOK(ResolverBase):
    def _lookup(self, name, cls, qtype, timeout):
        if qtype == dns.A:
            payload = dns.Record_A(address='127.0.0.1', ttl=60)
        else:
            payload = dns.Record_AAAA(address='1::2', ttl=60)

        rr = dns.RRHeader(name=name, type=qtype, cls=cls, ttl=60,
                          payload=payload)

        results = [rr]
        authority = []
        additional = []
        return defer.succeed((results, authority, additional))


class FakeResolverTimeoutError(ResolverBase):
    def _lookup(self, name, cls, qtype, timeout):
        return defer.fail(error.DNSQueryTimeoutError([]))


class FakeResolverServerError(ResolverBase):
    def _lookup(self, name, cls, qtype, timeout):
        return defer.fail(error.DNSServerError([]))


class FakeResolverNameError(ResolverBase):
    def _lookup(self, name, cls, qtype, timeout):
        return defer.fail(error.DNSNameError([]))


class FakeResolverQueryRefusedError(ResolverBase):
    def _lookup(self, name, cls, qtype, timeout):
        return defer.fail(error.DNSQueryRefusedError([]))


class FakeResolverUnknownError(ResolverBase):
    def _lookup(self, name, cls, qtype, timeout):
        return defer.fail(error.DNSUnknownError([]))


class DNSQueryMonitoringProtocolTestCase(BaseMonitoringProtocolTestCase):
    """Test case for `pybal.monitors.DNSQueryMonitoringProtocol`."""

    monitorClass = DNSQueryMonitoringProtocol

    def setUp(self):
        self.config['dnsquery.hostnames'] = '["en.wikipedia.org"]'
        super(DNSQueryMonitoringProtocolTestCase, self).setUp()

    def tearDown(self):
        super(DNSQueryMonitoringProtocolTestCase, self).tearDown()
        # There doesn't seem to be any sane way to avoid the delayed call to
        # maybeParseConfig: https://twistedmatrix.com/trac/ticket/3745
        for call in reactor.getDelayedCalls():
            if call.func.func_name == 'maybeParseConfig':
                call.cancel()

    def testInit(self):
        """Test `DNSQueryMonitoringProtocol.__init__`."""
        monitor = DNSQueryMonitoringProtocol(None, self.server, self.config)

        self.assertEquals(monitor.intvCheck, monitor.INTV_CHECK)
        self.assertEquals(monitor.toQuery, monitor.TIMEOUT_QUERY)
        self.assertEquals(monitor.hostnames, ['en.wikipedia.org'])
        self.assertFalse(monitor.failOnNXDOMAIN)

    def testRun(self):
        """Test `DNSQueryMonitoringProtocol.run`."""
        self.assertIsNone(self.monitor.resolver)
        self.monitor.run()
        self.assert_(len(self.monitor.resolver.resolvers) > 0)

    def __testQuery(self, expectSuccess, fakeResolver):
        """Install a mocked resolver to test different lookup results"""
        self.monitor.resolver = fakeResolver()
        query = self.monitor.check()

        def test_dnsquery(results):
            if expectSuccess:
                self.assertTrue(self.monitor.up)
            else:
                self.assertFalse(self.monitor.up)

        # Check test outcome upon deferred query completion
        query.addCallback(test_dnsquery)
        return query

    def testQuerySuccessful(self):
        self.__testQuery(expectSuccess=True, fakeResolver=FakeResolverOK)

    def testQueryFailedTimeoutError(self):
        self.__testQuery(expectSuccess=False,
                         fakeResolver=FakeResolverTimeoutError)

    def testQueryFailedServerError(self):
        self.__testQuery(expectSuccess=False,
                         fakeResolver=FakeResolverServerError)

    def testQueryFailedNameErrorOK(self):
        # dnsquery.fail-on-nxdomain is set to false by default. Expect success.
        self.__testQuery(expectSuccess=True,
                         fakeResolver=FakeResolverNameError)

    def testQueryFailedNameErrorKO(self):
        # Set dnsquery.fail-on-nxdomain to true and expect failure.
        self.config['dnsquery.fail-on-nxdomain'] = 'true'
        self.monitor = DNSQueryMonitoringProtocol(
                self.coordinator, self.server, self.config)

        self.__testQuery(expectSuccess=False,
                         fakeResolver=FakeResolverNameError)

    def testQueryFailedQueryRefusedError(self):
        self.__testQuery(expectSuccess=False,
                         fakeResolver=FakeResolverQueryRefusedError)

    def testQueryFailedUnknownError(self):
        self.__testQuery(expectSuccess=False,
                         fakeResolver=FakeResolverUnknownError)


class RunCommandMonitoringProtocolTestCase(BaseMonitoringProtocolTestCase):
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


class UDPMonitoringProtocolTestCase(BaseMonitoringProtocolTestCase):
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
