"""
dns.py
Copyright (C) 2012-2014 by Mark Bergsma <mark@nedworks.org>

DNS Monitor class implementation for PyBal
"""

# Python imports
import random, socket
import logging

# Twisted imports
from twisted.internet import defer
from twisted.names import client, dns, error
from twisted.python import runtime

# Pybal imports
from pybal import monitor
from pybal.metrics import Gauge


class DNSQueryMonitoringProtocol(monitor.LoopingCheckMonitoringProtocol):
    """
    Monitor that checks a DNS server by doing repeated DNS queries
    """

    __name__ = 'DNSQuery'

    TIMEOUT_QUERY = 5

    catchList = (defer.TimeoutError, error.DomainError,
                 error.AuthoritativeDomainError, error.DNSFormatError, error.DNSNameError,
                 error.DNSQueryRefusedError, error.DNSQueryTimeoutError,
                 error.DNSServerError, error.DNSUnknownError)

    metric_labelnames = ('service', 'host', 'monitor')
    metric_keywords = {
        'namespace': 'pybal',
        'subsystem': 'monitor_' + __name__.lower()
    }

    dnsquery_metrics = {
        'request_duration_seconds': Gauge(
            'request_duration_seconds',
            'DNS query duration',
            labelnames=metric_labelnames + ('result',),
            **metric_keywords)
    }

    def __init__(self, coordinator, server, configuration, reactor=None):
        """Constructor"""

        # Call ancestor constructor
        super(DNSQueryMonitoringProtocol, self).__init__(
            coordinator,
            server,
            configuration,
            reactor=reactor)

        self.toQuery = self._getConfigInt('timeout', self.TIMEOUT_QUERY)
        self.hostnames = self._getConfigStringList('hostnames')
        self.failOnNXDOMAIN = self._getConfigBool('fail-on-nxdomain', False)

        self.resolver = None
        self.DNSQueryDeferred = None
        self.checkStartTime = None

    def run(self):
        """Start the monitoring"""

        super(DNSQueryMonitoringProtocol, self).run()

        # Create a resolver. Use the DNS server IPv4 addresses instead of
        # self.server.ip as Twisted's createResolver (< 17.1.0) does not
        # support querying a nameserver over IPv6.
        self.resolver = client.createResolver([(ip, 53) for ip in self.server.ip4_addresses])

    def stop(self):
        """Stop the monitoring"""
        super(DNSQueryMonitoringProtocol, self).stop()

        if self.DNSQueryDeferred is not None:
            self.DNSQueryDeferred.cancel()

    def check(self):
        """Periodically called method that does a single uptime check."""

        hostname = random.choice(self.hostnames)
        query = dns.Query(hostname, type=random.choice([dns.A, dns.AAAA]))

        self.checkStartTime = runtime.seconds()

        if query.type == dns.A:
            self.DNSQueryDeferred = self.resolver.lookupAddress(hostname, timeout=[self.toQuery])
        elif query.type == dns.AAAA:
            self.DNSQueryDeferred = self.resolver.lookupIPV6Address(hostname, timeout=[self.toQuery])

        self.DNSQueryDeferred.addCallback(self._querySuccessful, query
                ).addErrback(self._queryFailed, query
                ).addBoth(self._checkFinished)
        return self.DNSQueryDeferred

    def _querySuccessful(self, (answers, authority, additional), query):
        """Called when the DNS query finished successfully."""

        if query.type in (dns.A, dns.AAAA):
            addressFamily = query.type == dns.A and socket.AF_INET or socket.AF_INET6
            addresses = " ".join([socket.inet_ntop(addressFamily, r.payload.address)
                                  for r in answers
                                  if r.type == query.type])
            resultStr = "%s %s %s" % (query.name, dns.QUERY_TYPES[query.type], addresses)
        else:
            resultStr = None

        duration = runtime.seconds() - self.checkStartTime
        self.report('DNS query successful, %.3f s' % (duration)
                    + (resultStr and (': ' + resultStr) or ""))
        self._resultUp()

        self.dnsquery_metrics['request_duration_seconds'].labels(
            result='successful',
            **self.metric_labels
            ).set(duration)

        return answers, authority, additional

    def _queryFailed(self, failure, query):
        """Called when the DNS query finished with a failure."""

        queryStr = ", query: %s %s" % (query.name, dns.QUERY_TYPES[query.type])

        # Don't act as if the check failed if we cancelled it
        if failure.check(defer.CancelledError):
            return None
        elif failure.check(error.DNSQueryTimeoutError):
            errorStr = "DNS query timeout" + queryStr
        elif failure.check(error.DNSServerError):
            errorStr = "DNS server error" + queryStr
        elif failure.check(error.DNSNameError):
            errorStr = "%s NXDOMAIN" % query.name
            if not self.failOnNXDOMAIN:
                self.report(errorStr, level=logging.INFO)
                self._resultUp()
                return None
        elif failure.check(error.DNSQueryRefusedError):
            errorStr = "DNS query refused" + queryStr
        else:
            errorStr = str(failure)

        duration = runtime.seconds() - self.checkStartTime
        self.report(
            'DNS query failed, %.3f s' % (duration),
            level=logging.ERROR
        )

        self._resultDown(errorStr)

        self.dnsquery_metrics['request_duration_seconds'].labels(
            result='failed',
            **self.metric_labels
            ).set(duration)

        failure.trap(*self.catchList)

    def _checkFinished(self, result):
        """
        Called when the DNS query finished with either success or failure,
        to do after-check cleanups.
        """

        self.checkStartTime = None

        return result
