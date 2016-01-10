"""
proxyfetch.py
Copyright (C) 2006 by Mark Bergsma <mark@nedworks.org>

Monitor class implementations for PyBal
"""

from pybal import monitor, util

from twisted.internet import reactor, defer
from twisted.web import client
from twisted.python.runtime import seconds
import logging, random

log = util.log


class RedirHTTPPageGetter(client.HTTPPageGetter):
    """PageGetter that accepts redirects as valid responses"""

    def handleStatus_301(self):
        """If we get a redirect, that's ok"""
        # Twisted uses old-style classes, yuck
        return client.HTTPPageGetter.handleStatus_200(self)

    def handleStatus_200(self):
        """Fail on 200 (we're expecting a redirect here)"""
        return self.handleStatusDefault()


class RedirHTTPClientFactory(client.HTTPClientFactory):
    """HTTPClientFactory that accepts redirects as valid responses"""
    protocol = RedirHTTPPageGetter


class ProxyFetchMonitoringProtocol(monitor.MonitoringProtocol):
    """
    Monitor that checks server uptime by repeatedly fetching a certain URL
    """

    INTV_CHECK = 10

    TIMEOUT_GET = 5

    HTTP_STATUS = 200

    __name__ = 'ProxyFetch'

    from twisted.internet import error
    from twisted.web import error as weberror
    catchList = ( defer.TimeoutError, weberror.Error, error.ConnectError, error.DNSLookupError )

    def __init__(self, coordinator, server, configuration={}):
        """Constructor"""

        # Call ancestor constructor
        super(ProxyFetchMonitoringProtocol, self).__init__(coordinator, server, configuration)

        self.intvCheck = self._getConfigInt('interval', self.INTV_CHECK)
        self.toGET = self._getConfigInt('timeout', self.TIMEOUT_GET)
        self.expectedStatus = self._getConfigInt('http_status',
                                                 self.HTTP_STATUS)

        self.checkCall = None
        self.getPageDeferred = defer.Deferred()

        self.checkStartTime = None

        self.URL = self._getConfigStringList('url')

    def run(self):
        """Start the monitoring"""

        super(ProxyFetchMonitoringProtocol, self).run()

        if not self.checkCall or not self.checkCall.active():
            self.checkCall = reactor.callLater(self.intvCheck, self.check)

    def stop(self):
        """Stop all running and/or upcoming checks"""

        super(ProxyFetchMonitoringProtocol, self).stop()

        if self.checkCall and self.checkCall.active():
            self.checkCall.cancel()

        self.getPageDeferred.cancel()

    def check(self):
        """Periodically called method that does a single uptime check."""

        if not self.active:
            log.warn("ProxyFetchMonitoringProtocol.check() called while active == False")
            return

        # FIXME: Use GET as a workaround for a Twisted bug with HEAD/Content-length
        # where it expects a body and throws a PartialDownload failure

        url = random.choice(self.URL)

        self.checkStartTime = seconds()
        self.getPageDeferred = self.getProxyPage(
            url,
            method='GET',
            host=self.server.ip,
            port=self.server.port,
            status=self.expectedStatus,
            timeout=self.toGET,
            followRedirect=False
        ).addCallbacks(
            self._fetchSuccessful,
            self._fetchFailed
        ).addBoth(self._checkFinished)

    def _fetchSuccessful(self, result):
        """Called when getProxyPage is finished successfully."""

        self.report('Fetch successful, %.3f s' % (seconds() - self.checkStartTime))
        self._resultUp()

        return result

    def _fetchFailed(self, failure):
        """Called when getProxyPage finished with a failure."""

        # Don't act as if the check failed if we cancelled it
        if failure.check(defer.CancelledError):
            return None

        self.report('Fetch failed, %.3f s' % (seconds() - self.checkStartTime),
                    level=logging.WARN)

        self._resultDown(failure.getErrorMessage())

        failure.trap(*self.catchList)

    def _checkFinished(self, result):
        """
        Called when getProxyPage finished with either success or failure,
        to do after-check cleanups.
        """

        self.checkStartTime = None

        # Schedule the next check
        if self.active:
            self.checkCall = reactor.callLater(self.intvCheck, self.check)

        return result

    def getProxyPage(url, contextFactory=None, host=None, port=None,
                     status=None, *args, **kwargs):
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
    getProxyPage = staticmethod(getProxyPage)
