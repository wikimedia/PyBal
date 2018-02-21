# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors`.

"""

import pybal.util
from pybal.monitors.idleconnection import IdleConnectionMonitoringProtocol
from pybal.monitors.dnsquery import DNSQueryMonitoringProtocol
from pybal.monitors.runcommand import RunCommandMonitoringProtocol
from pybal.monitors.udp import UDPMonitoringProtocol

from twisted.internet import defer
from twisted.internet.reactor import getDelayedCalls
from twisted.names.common import ResolverBase
from twisted.names import dns, error

from .fixtures import PyBalTestCase


class IdleConnectionMonitoringProtocolTestCase(PyBalTestCase):
    """Test case for `pybal.monitors.IdleConnectionMonitoringProtocol`."""

    def setUp(self):
        super(IdleConnectionMonitoringProtocolTestCase, self).setUp()
        self.config = pybal.util.ConfigDict()
        self.monitor = IdleConnectionMonitoringProtocol(
            self.coordinator, self.server, self.config)
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


class DNSQueryMonitoringProtocolTestCase(PyBalTestCase):
    """Test case for `pybal.monitors.DNSQueryMonitoringProtocol`."""

    def setUp(self):
        super(DNSQueryMonitoringProtocolTestCase, self).setUp()
        self.config = pybal.util.ConfigDict()
        self.config['dnsquery.hostnames'] = '["en.wikipedia.org"]'
        self.monitor = DNSQueryMonitoringProtocol(
            self.coordinator, self.server, self.config)

    def tearDown(self):
        # There doesn't seem to be any sane way to avoid the delayed call to
        # maybeParseConfig: https://twistedmatrix.com/trac/ticket/3745
        for call in getDelayedCalls():
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
        self.monitor.stop()

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


class RunCommandMonitoringProtocolTestCase(PyBalTestCase):
    """Test case for `pybal.monitors.RunCommandMonitoringProtocol`."""

    def setUp(self):
        super(RunCommandMonitoringProtocolTestCase, self).setUp()
        self.config = pybal.util.ConfigDict()
        self.config['runcommand.command'] = '/bin/true'

    def testInit(self):
        self.config['runcommand.arguments'] = '[ "--help" ]'
        self.monitor = RunCommandMonitoringProtocol(
            self.coordinator, self.server, self.config)

        self.assertEquals(self.monitor.intvCheck,
                          RunCommandMonitoringProtocol.INTV_CHECK)
        self.assertEquals(self.monitor.timeout,
                          RunCommandMonitoringProtocol.TIMEOUT_RUN)
        self.assertEquals(self.monitor.arguments, ["--help",])

    def testInitNoArguments(self):
        self.monitor = RunCommandMonitoringProtocol(
            self.coordinator, self.server, self.config)
        self.assertEquals(self.monitor.arguments, [""])

    def testInitArgumentsNotStringList(self):
        self.config['runcommand.arguments'] = "[]"
        self.monitor = RunCommandMonitoringProtocol(
            self.coordinator, self.server, self.config)
        self.assertEquals(self.monitor.arguments, [""])


class UDPMonitoringProtocolTestCase(PyBalTestCase):
    def setUp(self):
        super(UDPMonitoringProtocolTestCase, self).setUp()
        self.config = pybal.util.ConfigDict()
        self.monitor = UDPMonitoringProtocol(
            self.coordinator, self.server, self.config)

    def tearDown(self):
        self.monitor.stop()

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
