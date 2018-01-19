"""
PyBal
Copyright (C) 2006-2018 by Mark Bergsma <mark@nedworks.org>

LVS balancer/monitor
"""

import importlib
import random
import socket

from twisted.internet import defer, reactor
from twisted.names import client, dns
from twisted.names.error import AuthoritativeDomainError
from twisted.python import failure

from pybal import util

log = util.log

class Server:
    """
    Class that maintains configuration and state of a single (real)server
    """

    # Defaults
    DEF_STATE = True
    DEF_WEIGHT = 10

    # Set of attributes allowed to be overridden in a server list
    allowedConfigKeys = { ('host', str), ('weight', int), ('enabled', bool) }

    def __init__(self, host, lvsservice, addressFamily=None):
        """Constructor"""

        self.host = host
        self.lvsservice = lvsservice
        if addressFamily:
            self.addressFamily = addressFamily
        else:
            self.addressFamily = (':' in self.lvsservice.ip) and socket.AF_INET6 or socket.AF_INET
        self.ip = None
        self.port = 80
        self.ip4_addresses = set()
        self.ip6_addresses = set()
        self.monitors = set()

        # A few invariants that SHOULD be maintained (but currently may not be):
        # P0: pooled => enabled /\ ready
        # P1: up => pooled \/ !enabled \/ !ready
        # P2: pooled => up \/ !canDepool

        self.weight = self.DEF_WEIGHT
        self.up = False
        self.pooled = False
        self.enabled = True
        self.ready = False
        self.modified = None

    def __eq__(self, other):
        return isinstance(other, Server) and self.host == other.host and self.lvsservice == other.lvsservice

    def __hash__(self):
        return hash(self.host)

    def addMonitor(self, monitor):
        """Adds a monitor instance to the set"""

        self.monitors.add(monitor)

    def removeMonitors(self):
        """Removes all monitors"""

        for monitor in self.monitors:
            monitor.stop()

        self.monitors.clear()

    def resolveHostname(self):
        """Attempts to resolve the server's hostname to an IP address for better reliability."""

        timeout = [1, 2, 5]
        lookups = []

        query = dns.Query(self.host, dns.A)
        lookups.append(client.lookupAddress(self.host, timeout
            ).addCallback(self._lookupFinished, socket.AF_INET, query))

        query = dns.Query(self.host, dns.AAAA)
        lookups.append(client.lookupIPV6Address(self.host, timeout
            ).addCallback(self._lookupFinished, socket.AF_INET6, query))

        return defer.DeferredList(lookups, consumeErrors=True
            ).addCallback(self._allLookupsCompleted)

    def _lookupFinished(self, (answers, authority, additional), addressFamily, query):
        ips = set([socket.inet_ntop(addressFamily, r.payload.address)
                   for r in answers
                   if r.name == query.name and r.type == query.type])

        if query.type == dns.A:
            self.ip4_addresses = ips
        elif query.type == dns.AAAA:
            self.ip6_addresses = ips

        # TODO: expire TTL
        #if self.ip:
        #    minTTL = min([r.ttl for r in answers
        #          if r.name == query.name and r.type == query.type])

        return ips

    def _allLookupsCompleted(self, results):
        # Pick *1* main ip address to use. Prefer any existing one
        # if still available.

        addr = " ".join(
            list(self.ip4_addresses) + list(self.ip6_addresses))
        msg = "Resolved {} to addresses {}".format(self.host, addr)
        log.debug(msg)

        ip_addresses = {
            socket.AF_INET:
                self.ip4_addresses,
            socket.AF_INET6:
                self.ip6_addresses
            }[self.addressFamily]

        try:
            if not self.ip or self.ip not in ip_addresses:
                self.ip = random.choice(list(ip_addresses))
        except IndexError:
            errmsg = "Could not resolve {} to IP addresses for AF {})".format(
                self.host, self.addressFamily)
            raise AuthoritativeDomainError(errmsg)
        else:
            return self.ip

    def destroy(self):
        self.enabled = False
        self.removeMonitors()

    def initialize(self, coordinator):
        """
        Initializes this server instance and fires a Deferred
        when ready for use (self.ready == True)
        """

        d = self.resolveHostname()

        return d.addCallbacks(self._ready, self._initFailed, callbackArgs=[coordinator])

    def _ready(self, result, coordinator):
        """
        Called when initialization has finished.
        """

        self.ready = True
        self.up = self.DEF_STATE
        self.pooled = self.DEF_STATE
        self.maintainState()

        self.createMonitoringInstances(coordinator)

        return True

    def _initFailed(self, fail):
        """
        Called when initialization failed
        """
        log.error("Initialization failed for server {}".format(self.host))

        assert self.ready == False
        self.maintainState()

        return False # Continue on success callback chain

    def createMonitoringInstances(self, coordinator):
        """Creates and runs monitoring instances for this Server"""

        lvsservice = self.lvsservice

        try:
            monitorlist = eval(lvsservice.configuration['monitors'])
        except KeyError:
            log.critical(
                "LVS service {} does not have a 'monitors' configuration option set.".format(
                    lvsservice.name)
            )
            raise

        if type(monitorlist) != list:
            msg = "option 'monitors' in LVS service section {} is not a python list"
            log.err(msg.format(lvsservice.name))
        else:
            for monitorname in monitorlist:
                try:
                    monitormodule = importlib.import_module(
                        "pybal.monitors.{}".format(monitorname.lower()))
                except ImportError:
                    log.err("Monitor {} does not exist".format(monitorname))
                except Exception:
                    log.critical("Cannot import pybal.monitors.{}".format(monitorname))
                    # An exception was raised importing the given monitor
                    # module. Instead of just logging the problem, stop PyBal
                    # as the admin might think everything is fine and all
                    # checks are green, while in fact no check is being
                    # performed.
                    reactor.stop()
                else:
                    monitorclass = getattr(monitormodule, monitorname + 'MonitoringProtocol')
                    monitor = monitorclass(coordinator, self, lvsservice.configuration)
                    self.addMonitor(monitor)
                    monitor.run()

    def calcStatus(self):
        """AND quantification of monitor.up over all monitoring instances of a single Server"""

        # Global status is up iff all monitors report up
        return reduce(lambda b,monitor: b and monitor.up, self.monitors, len(self.monitors) != 0)

    def calcPartialStatus(self):
        """OR quantification of monitor.up over all monitoring instances of a single Server"""

        # Partial status is up iff one of the monitors reports up
        return reduce(lambda b,monitor: b or monitor.up, self.monitors, len(self.monitors) == 0)

    def textStatus(self):
        return "%s/%s/%s" % (self.enabled and "enabled" or "disabled",
                             self.up and "up" or (self.calcPartialStatus() and "partially up" or "down"),
                             self.pooled and "pooled" or "not pooled")

    def maintainState(self):
        """Maintains a few invariants on configuration changes"""

        # P0
        if not self.enabled or not self.ready:
            self.pooled = False
        # P1
        if not self.pooled and self.enabled:
            self.up = False

    def merge(self, configuration):
        """Merges in configuration from a dictionary of (allowed) attributes"""

        # Ensure only known attributes of the right type can be set
        # in the server object. (Some config parsing formats currently
        # have no input validation.)
        filteredConfig = {k:v
            for (k,v)
            in configuration.iteritems()
            if (k, type(v)) in self.allowedConfigKeys}
        # Overwrite configuration
        self.__dict__.update(filteredConfig)
        self.maintainState()
        self.modified = True    # Indicate that this instance previously existed

    def dumpState(self):
        """Dump current state of the server"""
        return {'pooled': self.pooled, 'weight': self.weight,
                'up': self.up, 'enabled': self.enabled}

    @classmethod
    def buildServer(cls, hostName, configuration, lvsservice):
        """
        Factory method which builds a Server instance from a
        dictionary of (allowed) configuration attributes
        """

        server = cls(hostName, lvsservice) # create a new instance...
        server.merge(configuration)        # ...and override attributes
        server.modified = False

        return server
