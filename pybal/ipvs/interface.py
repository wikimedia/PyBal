from pybal.bgpfailover import BGPFailover
from pybal.ipvs.ipvsadm import IPVSADMManager
from pybal.util import log


class LVSService:
    """Class that maintains the state of a single LVS service
    instance."""

    ipvsManager = IPVSADMManager

    SVC_PROTOS = ('tcp', 'udp')
    SVC_SCHEDULERS = ('rr', 'wrr', 'lc', 'wlc', 'lblc', 'lblcr', 'dh', 'sh',
                      'sed', 'nq')

    def __init__(self, name, (protocol, ip, port, scheduler), configuration):
        """Constructor"""

        self.name = name
        self.servers = set()

        if (protocol not in self.SVC_PROTOS or
                scheduler not in self.SVC_SCHEDULERS):
            raise ValueError('Invalid protocol or scheduler')

        self.protocol = protocol
        self.ip = ip
        self.port = port
        self.scheduler = scheduler

        self.configuration = configuration

        self.ipvsManager.DryRun = configuration.getboolean('dryrun', False)
        self.ipvsManager.Debug = configuration.getboolean('debug', False)

        if self.configuration.getboolean('bgp', True):
            # Add service ip to the BGP announcements
            BGPFailover.addPrefix(self.ip)

        self.createService()

    def service(self):
        """Returns a tuple (protocol, ip, port, scheduler) that
        describes this LVS instance."""

        return (self.protocol, self.ip, self.port, self.scheduler)

    def createService(self):
        """Initializes this LVS instance in LVS."""

        # Remove a previous service and add the new one
        cmdList = [self.ipvsManager.commandRemoveService(self.service()),
                   self.ipvsManager.commandAddService(self.service())]
        self.ipvsManager.modifyState(cmdList)

    def assignServers(self, newServers):
        """Takes a (new) set of servers (as a host->Server dictionary)
        and updates the LVS state accordingly."""

        cmdList = (
            [self.ipvsManager.commandAddServer(self.service(), server)
             for server in newServers - self.servers] +
            [self.ipvsManager.commandEditServer(self.service(), server)
             for server in newServers & self.servers] +
            [self.ipvsManager.commandRemoveServer(self.service(), server)
             for server in self.servers - newServers]
        )

        self.servers = newServers
        self.ipvsManager.modifyState(cmdList)

    def addServer(self, server):
        """Adds (pools) a single Server to the LVS state."""

        if server not in self.servers:
            cmdList = [self.ipvsManager.commandAddServer(self.service(),
                                                         server)]
        else:
            log.warn('bug: adding already existing server to LVS')
            cmdList = [self.ipvsManager.commandEditServer(self.service(),
                                                          server)]

        self.servers.add(server)

        self.ipvsManager.modifyState(cmdList)
        server.pooled = True

    def removeServer(self, server):
        """Removes (depools) a single Server from the LVS state."""

        cmdList = [self.ipvsManager.commandRemoveServer(self.service(),
                                                        server)]

        self.servers.remove(server)  # May raise KeyError

        server.pooled = False
        self.ipvsManager.modifyState(cmdList)

    def initServer(self, server):
        """Initializes a server instance with LVS service specific
        configuration."""

        server.port = self.port

    def getDepoolThreshold(self):
        """Returns the threshold below which no more down servers will
        be depooled."""

        return self.configuration.getfloat('depool-threshold', .5)
