# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors.dnsquery`.
"""

# Twisted imports
from twisted.internet import defer, reactor
from twisted.names.common import ResolverBase
from twisted.names import dns, error

# Pybal imports
import pybal.monitor
from pybal.monitors.dnsquery import DNSQueryMonitoringProtocol

# Testing imports
from .. import test_monitor


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


class DNSQueryMonitoringProtocolTestCase(test_monitor.BaseLoopingCheckMonitoringProtocolTestCase):
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
        self.assertIsInstance(query, defer.Deferred)

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
