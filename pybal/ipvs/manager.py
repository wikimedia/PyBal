from __future__ import absolute_import

from twisted.internet import defer
from gnlpy.ipvs import IpvsClient

from pybal.ipvs import LVSService
import pybal.ipvs.service

from pybal.bgpfailover import BGPFailover


class NetlinkServiceManager(LVSService):
    """Service manager that uses the netlink-based state machines"""

    Debug = False

    DryRun = False

    def __init__(self, name, (protocol, ip, port, scheduler), configuration):
        self.name = name
        # Logical server state within pybal itself
        self.servers = set()
        # FSM to manage the IPVS state of every server
        self.destinations = {}

        if protocol not in self.SVC_PROTOS:
            raise ValueError(
                "Service {srv} has invalid protocol '{pr}', valid values are '{val}'".format(
                    srv=self.name,
                    pr=protocol,
                    val=", ".join(self.SVC_PROTOS)
                )
            )
        if scheduler not in self.SVC_SCHEDULERS:
            raise ValueError(
                "Service {srv} has invalid scheduler '{sc}', valid values are '{val}'".format(
                    srv=self.name,
                    sc=scheduler,
                    val=", ".join(self.SVC_SCHEDULERS)
                )
            )

        self.protocol = protocol
        self.ip = ip
        self.port = port
        self.scheduler = scheduler

        self.configuration = configuration
        self.Debug = configuration.getboolean('debug', False)
        self.DryRun = configuration.getboolean('dryrun', False)

        self.nlClient = IpvsClient(verbose=self.Debug)

        if self.configuration.getboolean('bgp', True):
            # Add service ip to the BGP announcements
            BGPFailover.addPrefix(self.ip)

        self.fsm = pybal.ipvs.service.Service(
            self.nlClient,
            (self.protocol, self.ip, self.port, self.scheduler)
        )
        self.createService()

    def createService(self):
        """Initializes this LVS instance in LVS."""
        self.fsm.toState('present')

    def assignServers(self, newServers):
        """Takes a (new) set of servers (as a host->Server dictionary)
        and updates the LVS state accordingly."""
        to_remove = self.servers - newServers
        to_add = newServers
        # All of these are actually blocking as they'll make a call to
        # netlink. Still, it's formally correct to return a deferredlist
        dl = []
        for server in to_remove:
            dl.append(self.removeServer(server))
        for server in to_add:
            dl.append(self.addServer(server))
        return defer.DeferredList(dl)

    def _to_ipvs(self, server):
        # TODO: check that server.host is always defined
        if server.host not in self.destinations:
            self.destinations[server.host] = pybal.ipvs.server.Server(
                self.nlClient, server, self.fsm)
        return self.destinations[server.host]

    def removeServer(self, server):
        def depool(*args):
            server.pooled = False
            self.servers.remove(server) # May raise KeyError
            # We also want to remove the host from destinations
            # this is not strictly needed but will avoid this to
            # expand forever if we add/remove servers.
            del self.destinations[server.host]

        ipvsserver = self._to_ipvs(server)
        # For now this is blocking,
        # might not be such in the future
        d = ipvsserver.toState('unknown')
        d.addCallback(depool)
        return d

    def addServer(self, server):
        def pool(*args):
            server.pooled = True
            self.servers.add(server)
        ipvsserver = self._to_ipvs(server)
        # We need to check if the server needs
        # refreshing.
        desired_weight = server.weight or 1
        if ipvsserver.weight_ != desired_weight:
            ipvsserver.currentState = ipvsserver.states['refresh']
        d = ipvsserver.toState('up')
        d.addCallback(pool)
        return d
