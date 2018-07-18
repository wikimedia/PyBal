#!/usr/bin/python

"""
PyBal
Copyright (C) 2006-2017 by Mark Bergsma <mark@nedworks.org>

LVS Squid balancer/monitor for managing the Wikimedia Squid servers using LVS
"""

import logging
from twisted.internet import defer

from pybal import config, util
from pybal.metrics import Counter, Gauge
import pybal.server

log = util.log

class Coordinator:
    """
    Class that coordinates the configuration, state and status reports
    for a single LVS instance
    """

    serverConfigUrl = 'file:///etc/pybal/squids'

    intvLoadServers = 60

    metric_keywords = {
        'labelnames': ('service', ),
        'namespace': 'pybal',
        'subsystem': 'service'
    }

    metrics = {
        'servers': Gauge(
            'servers',
            'Amount of servers',
            **metric_keywords),
        'servers_enabled': Gauge(
            'servers_enabled',
            'Amount of enabled servers',
            **metric_keywords),
        'servers_up': Gauge(
            'servers_up',
            'Amount of up servers',
            **metric_keywords),
        'servers_pooled': Gauge(
            'servers_pooled',
            'Amount of pooled servers',
            **metric_keywords),
        'can_depool': Gauge(
            'can_depool',
            'Can depool more servers',
            **metric_keywords),
        'pooled_down_servers': Gauge(
            'pooled_down_servers',
            'Amount of down servers pooled because too many down',
            **metric_keywords),
        'could_not_depool_total': Counter(
            'could_not_depool_total',
            'Pybal could not depool a server because too many down',
            **metric_keywords),
        'depool_threshold': Gauge(
            'depool_threshold',
            "Threshold of up servers vs total servers below which pybal can't depool any more",
            **metric_keywords),
    }

    def __init__(self, lvsservice, configUrl):
        """Constructor"""

        self.servers = {}
        self.lvsservice = lvsservice
        self.metric_labels = {
            'service': self.lvsservice.name
        }
        self.pooledDownServers = set()
        self.configHash = None
        self.serverConfigUrl = configUrl
        self.serverInitDeferredList = defer.Deferred()
        self.configObserver = config.ConfigurationObserver.fromUrl(self, configUrl)
        self.configObserver.startObserving()

        self.metrics['depool_threshold'].labels(
            **self.metric_labels
            ).set(self.lvsservice.getDepoolThreshold())

    def __str__(self):
        return "[%s]" % self.lvsservice.name

    def assignServers(self):
        """
        Takes a new set of servers (as a host->Server dict) and
        hands them over to LVSService
        """

        # Hand over enabled servers to LVSService
        self.lvsservice.assignServers(
            set([server for server in self.servers.itervalues() if server.pool]))

    def refreshPreexistingServer(self, server):
        """
        Takes a preexisting server and calculates its .pool and .up status.
        """

        assert server.up == server.calcStatus(), "{} up status inconsistent".format(server.host)
        server.pool = server.enabled and server.up

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
            if server.pool: self.depool(server)

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
            if server.enabled and server.ready: self.repool(server)

    def depool(self, server):
        """Depools a single Server, if possible"""

        assert server.pool

        if self.canDepool():
            server.pool = False
            self.lvsservice.removeServer(server)
            self.pooledDownServers.discard(server)
            self.metrics['servers_pooled'].labels(**self.metric_labels).dec()
        else:
            self.pooledDownServers.add(server)
            msg = "Could not depool server " \
                  "{} because of too many down!".format(server.host)
            log.error(msg, system=self.lvsservice.name)
            self.metrics['could_not_depool_total'].labels(**self.metric_labels).inc()
        self._updatePooledDownMetrics()

    def repool(self, server):
        """
        Repools a single server. Also depools previously downed Servers that could
        not be depooled then because of too many hosts down.
        """

        assert server.enabled and server.ready

        if not server.pool:
            server.pool = True
            self.lvsservice.addServer(server)
            self.metrics['servers_pooled'].labels(**self.metric_labels).inc()
        else:
            msg = "Leaving previously pooled but down server {} pooled"
            log.info(msg.format(server.host), system=self.lvsservice.name)

        # If it had been pooled in down state before, remove it from the list
        self.pooledDownServers.discard(server)
        self._updatePooledDownMetrics()

        # See if we can depool any servers that could not be depooled before
        while len(self.pooledDownServers) > 0 and self.canDepool():
            self.depool(self.pooledDownServers.pop())

    def canDepool(self):
        """Returns a boolean denoting whether another server can be depooled"""

        # Total number of servers
        totalServerCount = len(self.servers)

        # Number of hosts considered to be up by PyBal's monitoring and
        # administratively enabled. Under normal circumstances, they would be
        # the hosts serving traffic.
        # However, a host can go down after PyBal has reached the depool
        # threshold for the service the host belongs to. In that case, the
        # misbehaving server is kept pooled. This count does not include such
        # hosts.
        upServerCount = len([server for server in self.servers.itervalues() if server.up and server.enabled])

        # The total amount of hosts serving traffic may never drop below a
        # configured threshold
        return upServerCount >= totalServerCount * self.lvsservice.getDepoolThreshold()

    def onConfigUpdate(self, config):
        """
        Takes a dictionary of server hostnames to configuration dicts as the
        complete set of new servers, and updates the state of the coordinator
        accordingly.
        """

        delServers = self.servers.copy()    # Shallow copy

        initList = []

        # Let's keep pybal logging not too chatty by summarizing
        # the number of added servers on new configurations (pybal start-up)
        new_config = not self.servers
        if new_config:
            lvl = logging.DEBUG
        else:
            lvl = logging.INFO

        for hostName, hostConfig in config.items():
            if hostName in self.servers:
                # Existing server. merge
                server = delServers.pop(hostName)
                server.merge(hostConfig)
                # Calculate up status for the previously existing server
                self.refreshPreexistingServer(server)
                data = {'status': (server.enabled and "enabled" or "disabled"),
                        'host': hostName, 'weight': server.weight}
                log.info(
                    "Merged {status} server {host}, weight {weight}".format(**data),
                    system=self.lvsservice.name
                )
            else:
                # New server
                server = pybal.server.Server.buildServer(hostName, hostConfig, self.lvsservice)
                data = {'status': (server.enabled and "enabled" or "disabled"),
                        'host': hostName, 'weight': server.weight}
                # Initialize with LVS service specific configuration
                self.lvsservice.initServer(server)
                self.servers[hostName] = server
                initList.append(server.initialize(self))
                util._log(
                          "New {status} server {host}, weight {weight}".format(**data),
                          lvl,
                          system=self.lvsservice.name
                )

        if new_config:
            enabled_servers = len([server for server in self.servers.itervalues() if server.enabled is True])
            disabled_servers = len(self.servers) - enabled_servers
            util._log("Added {total} server(s): {enabled} enabled server(s) and {disabled} disabled server(s)".format(
                        total=len(self.servers),
                        enabled=enabled_servers,
                        disabled=disabled_servers),
                      logging.INFO,
                      system=self.lvsservice.name
            )

        # Remove old servers
        for hostName, server in delServers.iteritems():
            log.info("{} Removing server {} (no longer found in new configuration)".format(self, hostName),
                     system=self.lvsservice.name)
            server.destroy()
            del self.servers[hostName]

        # Wait for all new servers to finish initializing
        self.serverInitDeferredList = defer.DeferredList(initList).addCallback(self._serverInitDone)

        # Update metrics
        self._updateServerMetrics()
        self._updatePooledDownMetrics()

    def _serverInitDone(self, result):
        """Called when all (new) servers have finished initializing"""

        log.info("{} Initialization complete".format(self))

        # Assign the updated list of enabled servers to the LVSService instance
        self.assignServers()

        self.metrics['servers_pooled'].labels(
            **self.metric_labels
            ).set(
                len([s for s in self.servers.itervalues() if s.pool]))
        self._updatePooledDownMetrics()

    def _updateServerMetrics(self):
        """Update gauge metrics for servers on config change"""
        self.metrics['servers'].labels(
            **self.metric_labels
            ).set(
                len(self.servers))
        self.metrics['servers_enabled'].labels(
            **self.metric_labels
            ).set(
                len([s for s in self.servers.itervalues() if s.enabled]))
        self.metrics['servers_up'].labels(
            **self.metric_labels
            ).set(
                len([s for s in self.servers.itervalues() if s.up]))

    def _updatePooledDownMetrics(self):
        """Update gauge metrics for pooled-but-down servers"""
        self.metrics['pooled_down_servers'].labels(
            **self.metric_labels
            ).set(len(self.pooledDownServers))
        self.metrics['can_depool'].labels(
            **self.metric_labels
            ).set(self.canDepool() and 1 or 0)
