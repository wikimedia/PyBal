"""
proxyfetch.py
Copyright (C) 2006 by Mark Bergsma <mark@nedworks.org>

Monitor class implementations for PyBal
"""

# Python imports
import hashlib
import logging
import random

# Twisted imports
from twisted.internet import defer
from twisted.web import client
from twisted.python.runtime import seconds
import twisted.internet.reactor

# Pybal imports
from pybal import monitor, util
from pybal.metrics import Gauge


log = util.log


class RedirHTTPPageGetter(client.HTTPPageGetter):
    """PageGetter that accepts redirects as valid responses"""

    # Handle 3xx (redirect) status as 200 OK
    handleStatus_301 = client.HTTPPageGetter.handleStatus_200
    handleStatus_302 = client.HTTPPageGetter.handleStatus_200
    handleStatus_303 = client.HTTPPageGetter.handleStatus_200

    # Fail on 200 (we're expecting a redirect here)
    handleStatus_200 = client.HTTPPageGetter.handleStatusDefault


class RedirHTTPClientFactory(client.HTTPClientFactory):
    """HTTPClientFactory that accepts redirects as valid responses"""
    protocol = RedirHTTPPageGetter


class ProxyFetchMonitoringProtocol(monitor.LoopingCheckMonitoringProtocol):
    """
    Monitor that checks server uptime by repeatedly fetching a certain URL
    """

    TIMEOUT_GET = 5

    HTTP_STATUS = 200

    CHECK_ALL = False

    __name__ = 'ProxyFetch'

    from twisted.internet import error
    from twisted.web import error as weberror
    catchList = ( defer.TimeoutError, weberror.Error, error.ConnectError, error.DNSLookupError )

    metric_labelnames = ('service', 'host', 'monitor')
    metric_keywords = {
        'namespace': 'pybal',
        'subsystem': 'monitor_' + __name__.lower()
    }

    proxyfetch_metrics = {
        'request_duration_seconds': Gauge(
            'request_duration_seconds',
            'HTTP(S) request duration',
            labelnames=metric_labelnames + ('result', 'url', ), # TODO: statuscode
            **metric_keywords)
    }

    def __init__(self, coordinator, server, configuration={}, reactor=None):
        """Constructor"""

        # Call ancestor constructor
        super(ProxyFetchMonitoringProtocol, self).__init__(
            coordinator,
            server,
            configuration,
            reactor=reactor)

        self.toGET = self._getConfigInt('timeout', self.TIMEOUT_GET)
        self.expectedStatus = self._getConfigInt('http_status',
                                                 self.HTTP_STATUS)
        self.URLs = self._getConfigStringList('url')
        self.checkAllUrls = self._getConfigBool('check_all', self.CHECK_ALL)
        self.getPageDeferredList = None

        self.checkStartTime = None
        self.currentFailures = []
        # Maximum number of failures to tolerate:
        if self.checkAllUrls:
            self.maxFailures = self._getConfigInt('max_failures', 0)
        else:
            self.maxFailures = 0

    def stop(self):
        """Stop all running and/or upcoming checks"""

        super(ProxyFetchMonitoringProtocol, self).stop()

        if self.getPageDeferredList is not None:
            self.getPageDeferredList.cancel()

    def check(self):
        """Periodically called method that does a single uptime check."""

        if not self.active:
            log.warn("ProxyFetchMonitoringProtocol.check() called while active == False")
            return

        # FIXME: Use GET as a workaround for a Twisted bug with HEAD/Content-length
        # where it expects a body and throws a PartialDownload failure
        if not self.checkAllUrls:
            urls = [random.choice(self.URLs)]
        else:
            urls = self.URLs
        self.checkStartTime = {self._keyFromUrl(url): None for url in self.URLs}
        self.currentFailures = []

        deferreds = []
        for url in urls:
            self.checkStartTime[self._keyFromUrl(url)] = seconds()
            deferred = self.getProxyPage(
                url,
                method='GET',
                host=self.server.ip,
                port=self.server.port,
                status=self.expectedStatus,
                timeout=self.toGET,
                followRedirect=False,
                reactor=self.reactor
            ).addCallback(
                self._fetchSuccessful,
                url=url
            ).addErrback(
                self._fetchFailed,
                url=url
            )
            deferreds.append(deferred)
        self.getPageDeferredList = defer.DeferredList(deferreds).addBoth(
            self._checkFinished)
        return self.getPageDeferredList

    def _fetchSuccessful(self, result, url=None):
        """Called when getProxyPage is finished successfully."""
        # Here we don't add anything to self.currentFailures.
        duration = seconds() - self.checkStartTime[self._keyFromUrl(url)]
        self.report('Fetch successful (%s), %.3f s' % (url, duration))

        self.proxyfetch_metrics['request_duration_seconds'].labels(
            result='successful',
            url=url,
            **self.metric_labels
            ).set(duration)

        return result

    def _fetchFailed(self, failure, url=None):
        """Called when getProxyPage finished with a failure."""

        # Don't act as if the check failed if we cancelled it
        if failure.check(defer.CancelledError):
            return None

        duration = seconds() - self.checkStartTime[self._keyFromUrl(url)]
        self.report('Fetch failed (%s), %.3f s' % (url, duration),
                    level=logging.WARN)

        self.currentFailures.append(failure.getErrorMessage())

        self.proxyfetch_metrics['request_duration_seconds'].labels(
            result='failed',
            url=url,
            **self.metric_labels
            ).set(duration)

        failure.trap(*self.catchList)

    def _checkFinished(self, result):
        """
        Called when all getProxyPage finished with either success or failure,
        to do after-check cleanups and fire reportDown or reportUp.
        """
        self.checkStartTime = None
        if len(self.currentFailures) <= self.maxFailures:
            self._resultUp()
        else:
            self._resultDown(reason="\n".join(self.currentFailures))
        self.currentFailures = []
        return result

    @staticmethod
    def getProxyPage(url, contextFactory=None, host=None, port=None,
                     status=None, reactor=twisted.internet.reactor, *args, **kwargs):
        """Download a web page as a string. (modified from twisted.web.client.getPage)

        Download a page. Return a deferred, which will callback with a
        page (as a string) or errback with a description of the error.

        See HTTPClientFactory to see what extra args can be passed.
        """
        if status > 300 and status < 304:
            factory = RedirHTTPClientFactory(url, *args, **kwargs)
        else:
            factory = client.HTTPClientFactory(url, *args, **kwargs)

        host = host or factory.host
        port = port or factory.port

        if factory.scheme == 'https':
            from twisted.internet import ssl
            if contextFactory is None:
                contextFactory = ssl.ClientContextFactory()
            reactor.connectSSL(host, port, factory, contextFactory)
        else:
            reactor.connectTCP(host, port, factory)
        return factory.deferred

    @staticmethod
    def _keyFromUrl(url):
        """Create a dict key from a url."""
        return hashlib.md5(url).hexdigest()
