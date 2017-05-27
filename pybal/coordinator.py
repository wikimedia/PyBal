#!/usr/bin/python

"""
PyBal
Copyright (C) 2006-2017 by Mark Bergsma <mark@nedworks.org>

LVS Squid balancer/monitor for managing the Wikimedia Squid servers using LVS
"""
import random
import socket

from twisted.internet import defer
from twisted.names import client, dns
from twisted.python import failure

from pybal import config, util

log = util.log


class Server:
    """
    Class that maintains configuration and state of a single (real)server
    """

    # Defaults
    DEF_STATE = True
    DEF_WEIGHT = 10

    # Set of attributes allowed to be overridden in a server list
    allowedConfigKeys = [ ('host', str), ('weight', int), ('enabled', bool) ]

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
        lookups.append(
            client.lookupAddress(self.host, timeout).addCallback(self._lookupFinished, socket.AF_INET, query)
        )

        query = dns.Query(self.host, dns.AAAA)
        lookups.append(
            client.lookupIPV6Address(self.host, timeout).addCallback(self._lookupFinished, socket.AF_INET6, query)
        )

        return defer.DeferredList(lookups).addBoth(self._hostnameResolved)

    def _lookupFinished(self, (answers, authority, additional), addressFamily, query):
        ips = set([socket.inet_ntop(addressFamily, r.payload.address)
                   for r in answers
                   if r.name == query.name and r.type == query.type])

        if query.type == dns.A:
            self.ip4_addresses = ips
        elif query.type == dns.AAAA:
            self.ip6_addresses = ips

        # TODO: expire TTL
        # if self.ip:
        #    minTTL = min([r.ttl for r in answers
        #          if r.name == query.name and r.type == query.type])

        return ips

    def _hostnameResolved(self, result):
        # Pick *1* main ip address to use. Prefer any existing one
        # if still available.

        addr = " ".join(
            list(self.ip4_addresses) + list(self.ip6_addresses))
        msg = "Resolved {} to addresses {}".format(self.host, addr)
        log.debug(msg)

        ip_addresses = {
            socket.AF_INET: self.ip4_addresses,
            socket.AF_INET6: self.ip6_addresses
        }[self.addressFamily]

        try:
            if not self.ip or self.ip not in ip_addresses:
                self.ip = random.choice(list(ip_addresses))
                # TODO: (re)pool
        except IndexError:
            return failure.Failure()  # TODO: be more specific?
        else:
            return True

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

        assert self.ready is False
        self.maintainState()

        return False  # Continue on success callback chain

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
                    monitormodule = getattr(
                        __import__('pybal.monitors', fromlist=[monitorname.lower()], level=0), monitorname.lower())
                except AttributeError:
                    log.err("Monitor {} does not exist".format(monitorname))
                else:
                    monitorclass = getattr(monitormodule, monitorname + 'MonitoringProtocol')
                    monitor = monitorclass(coordinator, self, lvsservice.configuration)
                    self.addMonitor(monitor)
                    monitor.run()

    def calcStatus(self):
        """AND quantification of monitor.up over all monitoring instances of a single Server"""

        # Global status is up if all monitors report up
        return reduce(lambda b, monitor: b and monitor.up, self.monitors, len(self.monitors) != 0)

    def calcPartialStatus(self):
        """OR quantification of monitor.up over all monitoring instances of a single Server"""

        # Partial status is up if one of the monitors reports up
        return reduce(lambda b, monitor: b or monitor.up, self.monitors, len(self.monitors) == 0)

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

        for key, value in configuration.iteritems():
            if (key, type(value)) not in self.allowedConfigKeys:
                del configuration[key]

        # Overwrite configuration
        self.__dict__.update(configuration)
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

        server = cls(hostName, lvsservice)  # create a new instance...
        server.merge(configuration)         # ...and override attributes
        server.modified = False

        return server


class Coordinator:
    """
    Class that coordinates the configuration, state and status reports
    for a single LVS instance
    """

    serverConfigUrl = 'file:///etc/pybal/squids'

    intvLoadServers = 60

    def __init__(self, lvsservice, configUrl):
        """Constructor"""

        self.servers = {}
        self.lvsservice = lvsservice
        self.pooledDownServers = set()
        self.configHash = None
        self.serverConfigUrl = configUrl
        self.serverInitDeferredList = defer.Deferred()
        self.configObserver = config.ConfigurationObserver.fromUrl(self, configUrl)
        self.configObserver.startObserving()

    def __str__(self):
        return "[%s]" % self.lvsservice.name

    def assignServers(self):
        """
        Takes a new set of servers (as a host->Server dict) and
        hands them over to LVSService
        """

        # Hand over enabled servers to LVSService
        self.lvsservice.assignServers(
            set([server for server in self.servers.itervalues() if server.pooled]))

    def refreshModifiedServers(self):
        """
        Calculates the status of every server that existed before the config change.
        """

        for server in self.servers.itervalues():
            if not server.modified:
                continue

            server.up = server.calcStatus()
            server.pooled = server.enabled and server.up

    def resultDown(self, monitor, reason=None):
        """
        Accepts a 'down' notification status result from a single monitoring instance
        and acts accordingly.
        """

        server = monitor.server

        data = {'service': self, 'monitor': monitor.name(),
                'host': server.host, 'status': server.textStatus(),
                'reason': (reason or '(reason unknown)')}
        msg = "Monitoring instance {monitor} " \
              "reports server {host} ({status}) down: {reason}"
        log.error(msg.format(**data), system=self.lvsservice.name)

        if server.up:
            server.up = False
            if server.pooled:
                self.depool(server)

    def resultUp(self, monitor):
        """
        Accepts a 'up' notification status result from a single monitoring instance
        and acts accordingly.
        """

        server = monitor.server

        if not server.up and server.calcStatus():
            log.info("Server {} ({}) is up".format(server.host,
                                                   server.textStatus()),
                     system=self.lvsservice.name)
            server.up = True
            if server.enabled and server.ready:
                self.repool(server)

    def depool(self, server):
        """Depools a single Server, if possible"""

        assert server.pooled

        if self.canDepool():
            self.lvsservice.removeServer(server)
            self.pooledDownServers.discard(server)
        else:
            self.pooledDownServers.add(server)
            msg = "Could not depool server " \
                  "{} because of too many down!".format(server.host)
            log.error(msg, system=self.lvsservice.name)

    def repool(self, server):
        """
        Repools a single server. Also depools previously downed Servers that could
        not be depooled then because of too many hosts down.
        """

        assert server.enabled and server.ready

        if not server.pooled:
            self.lvsservice.addServer(server)
        else:
            msg = "Leaving previously pooled but down server {} pooled"
            log.info(msg.format(server.host), system=self.lvsservice.name)

        # If it had been pooled in down state before, remove it from the list
        self.pooledDownServers.discard(server)

        # See if we can depool any servers that could not be depooled before
        while len(self.pooledDownServers) > 0 and self.canDepool():
            self.depool(self.pooledDownServers.pop())

    def canDepool(self):
        """Returns a boolean denoting whether another server can be depooled"""

        # Construct a list of servers that have status 'down'
        downServers = [server for server in self.servers.itervalues() if not server.up]

        # The total amount of pooled servers may never drop below a configured threshold
        return len(self.servers) - len(downServers) >= len(self.servers) * self.lvsservice.getDepoolThreshold()

    def onConfigUpdate(self, config):
        """Parses the server list and changes the state accordingly."""

        delServers = self.servers.copy()    # Shallow copy

        initList = []

        for hostName, hostConfig in config.items():
            if hostName in self.servers:
                # Existing server. merge
                server = delServers.pop(hostName)
                server.merge(hostConfig)
                data = {'status': (server.enabled and "enabled" or "disabled"),
                        'host': hostName, 'weight': server.weight}
                log.info(
                    "Merged {status} server {host}, weight {weight}".format(**data),
                    system=self.lvsservice.name
                )
            else:
                # New server
                server = Server.buildServer(hostName, hostConfig, self.lvsservice)
                data = {'status': (server.enabled and "enabled" or "disabled"),
                        'host': hostName, 'weight': server.weight}
                # Initialize with LVS service specific configuration
                self.lvsservice.initServer(server)
                self.servers[hostName] = server
                initList.append(server.initialize(self))
                log.info(
                    "New {status} server {host}, weight {weight}".format(**data),
                    system=self.lvsservice.name
                )

        # Remove old servers
        for hostName, server in delServers.iteritems():
            log.info("{} Removing server {} (no longer found in new configuration)".format(self, hostName))
            server.destroy()
            del self.servers[hostName]

        # Calculate up status for previously existing, modified servers
        self.refreshModifiedServers()

        # Wait for all new servers to finish initializing
        self.serverInitDeferredList = defer.DeferredList(initList).addCallback(self._serverInitDone)

    def _serverInitDone(self, result):
        """Called when all (new) servers have finished initializing"""

        log.info("{} Initialization complete".format(self))

        # Assign the updated list of enabled servers to the LVSService instance
        self.assignServers()
