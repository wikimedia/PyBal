"""
dns.py
Copyright (C) 2012 by Mark Bergsma <mark@nedworks.org>

DNS Monitor class implementation for PyBal
"""

from pybal import monitor

from twisted.internet import reactor, defer
from twisted.names import client, dns, error
from twisted.python import runtime

import random, socket

class DNSMonitoringProtocol(monitor.MonitoringProtocol):
    """
    Monitor that checks a DNS server by doing repeated DNS queries
    """
    
    __name__ = 'DNS'
    
    INTV_CHECK = 10
    TIMEOUT_QUERY = 5
    
    catchList = (defer.TimeoutError, error.DomainError,
                 error.AuthoritativeDomainError, error.DNSFormatError, error.DNSNameError,
                 error.DNSQueryRefusedError, error.DNSQueryTimeoutError,
                 error.DNSServerError, error.DNSUnknownError)

    
    def __init__(self, coordinator, server, configuration):
        """Constructor"""

        # Call ancestor constructor        
        super(DNSMonitoringProtocol, self).__init__(coordinator, server, configuration)

        self.intvCheck = self._getConfigInt('interval', self.INTV_CHECK)
        self.toQuery = self._getConfigInt('timeout', self.TIMEOUT_QUERY)
        self.hostnames = self._getConfigStringList('hostnames')
        
        self.resolver = None
        self.checkCall = None
        self.DNSQueryDeferred = defer.Deferred()
        self.checkStartTime = None
    
    def run(self):
        """Start the monitoring""" 
        
        super(DNSMonitoringProtocol, self).run()
        
        # Create a resolver
        self.resolver = client.createResolver([(self.server.ip, 53)])

        if not self.checkCall or not self.checkCall.active():
            self.checkCall = reactor.callLater(self.intvCheck, self.check)
    
    def stop(self):
        """Stop the monitoring"""
        super(DNSMonitoringProtocol, self).stop()

        if self.checkCall and self.checkCall.active():
            self.checkCall.cancel()
        
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

    
    def _querySuccessful(self, (answers, authority, additional), query):
        """Called when the DNS query finished successfully."""        
        
        if query.type in (dns.A, dns.AAAA):
            addressFamily = query.type == dns.A and socket.AF_INET or socket.AF_INET6
            addresses = " ".join([socket.inet_ntop(addressFamily, r.payload.address)
                                  for r in answers
                                  if r.name == query.name and r.type == query.type])
            resultStr = "%s %s %s" % (query.name, dns.QUERY_TYPES[query.type], addresses)
        else:
            resultStr = None
        
        self.report('DNS query successful, %.3f s' % (runtime.seconds() - self.checkStartTime)
                    + (resultStr and (': ' + resultStr) or ""))
        self._resultUp()
        
        return answers, authority, additional
    
    def _queryFailed(self, failure, query):
        """Called when the DNS query finished with a failure."""        

        # Don't act as if the check failed if we cancelled it
        if failure.check(defer.CancelledError):
            return None
        elif failure.check(error.DNSQueryTimeoutError):
            errorStr = "DNS query timeout"
        elif failure.check(error.DNSServerError):
            errorStr = "DNS server error"
        elif failure.check(error.DNSNameError):
            self.report("DNS server reports %s NXDOMAIN" % query.name)
            self._resultUp()
            return None
        elif failure.check(error.DNSQueryRefusedError):
            errorStr = "DNS query refused"
        else:
            errorStr = str(failure)
                         
        self.report('DNS query failed, %.3f s' % (runtime.seconds() - self.checkStartTime))
    
        self._resultDown(errorStr)
        
        failure.trap(*self.catchList)

    def _checkFinished(self, result):
        """
        Called when the DNS query finished with either success or failure,
        to do after-check cleanups.
        """
        
        self.checkStartTime = None
        
        # Schedule the next check
        if self.active:
            self.checkCall = reactor.callLater(self.intvCheck, self.check)
        
        return result
