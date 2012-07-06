#!/usr/bin/python

"""
PyBal
Copyright (C) 2006-20012 by Mark Bergsma <mark@nedworks.org>

LVS Squid balancer/monitor for managing the Wikimedia Squid servers using LVS
"""

from __future__ import absolute_import

import os, sys, signal, socket, random
from pybal import ipvs, monitor, util

from twisted.python import failure
from twisted.internet import reactor, defer
from twisted.names import client, dns

try:
    from pybal import bgp
except ImportError:
    pass

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
        lookups.append(client.lookupAddress(self.host, timeout
            ).addCallback(self._lookupFinished, socket.AF_INET, query))

        query = dns.Query(self.host, dns.AAAA)
        lookups.append(client.lookupIPV6Address(self.host, timeout
            ).addCallback(self._lookupFinished, socket.AF_INET6, query))

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
        #if self.ip:
        #    minTTL = min([r.ttl for r in answers
        #          if r.name == query.name and r.type == query.type])
        
        return ips   

    def _hostnameResolved(self, result):
        # Pick *1* main ip address to use. Prefer any existing one
        # if still available.
        
        print "Resolved", self.host, "to addresses", " ".join(
            list(self.ip4_addresses) + list(self.ip6_addresses)) 
        
        ip_addresses = {
            socket.AF_INET:
                self.ip4_addresses,
            socket.AF_INET6:
                self.ip6_addresses
            }[self.addressFamily]
        
        try:
            if not self.ip or self.ip not in ip_addresses:
                self.ip = random.choice(list(ip_addresses))
                # TODO: (re)pool
        except IndexError:
            return failure.Failure() # TODO: be more specific?
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
        
        print "Initialization failed for server", self.host
        
        assert self.ready == False
        self.maintainState()
        
        return False # Continue on success callback chain

    def createMonitoringInstances(self, coordinator):
        """Creates and runs monitoring instances for this Server"""        
        
        lvsservice = self.lvsservice
        
        try:
            monitorlist = eval(lvsservice.configuration['monitors'])
        except KeyError:
            print "LVS service", lvsservice.name, "does not have a 'monitors' configuration option set."
            raise

        if type(monitorlist) != list:
            print "option 'monitors' in LVS service section", lvsservice.name, \
                "is not a Python list."
        else:                
            for monitorname in monitorlist:
                try:
                    monitormodule = getattr(__import__('pybal.monitors', fromlist=[monitorname.lower()], level=0), monitorname.lower())
                except AttributeError:
                    print "Monitor", monitorname, "does not exist."
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

        for key, value in configuration.iteritems():
            if (key, type(value)) not in self.allowedConfigKeys:
                del configuration[key]
        
        # Overwrite configuration
        self.__dict__.update(configuration)
        self.maintainState()        
        self.modified = True    # Indicate that this instance previously existed  
    
    @classmethod
    def buildServer(cls, configuration, lvsservice):
        """
        Factory method which builds a Server instance from a
        dictionary of (allowed) configuration attributes
        """

        server = cls(configuration['host'], lvsservice) # create a new instance...
        server.merge(configuration)                     # ...and override attributes
        server.modified = False
        
        return server

class Coordinator:
    """
    Class that coordinates the configuration, state and status reports
    for a single LVS instance
    """
    
    serverConfigURL = 'file:///etc/pybal/squids'
    
    intvLoadServers = 60
    
    def __init__(self, lvsservice, configURL):
        """Constructor"""
        
        self.lvsservice = lvsservice
        self.servers = {}
        self.pooledDownServers = set()
        self.configHash = None
        self.serverConfigURL = configURL

        self.serverInitDeferredList = defer.Deferred()
        
        # Start a periodic server list update task
        from twisted.internet import task
        task.LoopingCall(self.loadServers).start(self.intvLoadServers)
    
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
            if not server.modified: continue
            
            server.up = server.calcStatus()
            server.pooled = server.enabled and server.up

    def resultDown(self, monitor, reason=None):
        """
        Accepts a 'down' notification status result from a single monitoring instance
        and acts accordingly.
        """
        
        server = monitor.server
        
        print self, "Monitoring instance %s reports server %s (%s) down:" % (monitor.name(), server.host, server.textStatus()), (reason or '(reason unknown)')
        
        if server.up:
            server.up = False
            if server.pooled: self.depool(server)

    def resultUp(self, monitor):
        """
        Accepts a 'up' notification status result from a single monitoring instance
        and acts accordingly.
        """
        
        server = monitor.server
    
        if not server.up and server.calcStatus():
            print self, "Server %s (%s) is up" % (server.host, server.textStatus())
            server.up = True
            if server.enabled and server.ready: self.repool(server)    

    def depool(self, server):
        """Depools a single Server, if possible"""
        
        assert server.pooled
        
        if self.canDepool():
            self.lvsservice.removeServer(server)
            self.pooledDownServers.discard(server)
        else:
            self.pooledDownServers.add(server)
            print self, 'Could not depool server', server.host, 'because of too many down!'
    
    def repool(self, server):
        """
        Repools a single server. Also depools previously downed Servers that could
        not be depooled then because of too many hosts down.
        """
        
        assert server.enabled and server.ready
        
        if not server.pooled:
            self.lvsservice.addServer(server)
        else:
            print self, "Leaving previously pooled but down server", server.host, "pooled"
        
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
    
    def loadServers(self, configURL=None):
        """Periodic task to load a new server list/configuration file from a specified URL."""
        
        configURL = configURL or self.serverConfigURL
        
        if configURL.startswith('http://'):
            # Retrieve file over HTTP
            from twisted.web import client
            client.getPage(configURL
                ).addCallback(self._configReceived
                ).addErrback(self._configLoadError, configURL)
        elif configURL.startswith('file://'):
            # Read the text file
            try:
                self._configReceived(open(configURL[7:], 'r').read())
            except IOError, e:
                print e
        else:
            raise ValueError, "Invalid configuration URL"

    def _configLoadError(self, fail, configURL):
        """
        Called when client.getPage could not load the configuration file.
        """
        
        print self, "Could not load configuration URL %s:" % configURL, fail.getErrorMessage()

    def _configReceived(self, configuration):
        """
        Compares the MD5 hash of the new configuration vs. the old one,
        and calls _parseConfig if it's different.
        """
        
        import hashlib
        newHash = hashlib.md5()
        newHash.update(configuration)
        if not self.configHash or self.configHash.digest() != newHash.digest():
            print self, 'New configuration received'
            
            self.configHash = newHash        
            self._parseConfig(configuration.splitlines())
    
    def _parseConfig(self, lines):
        """Parses the server list and changes the state accordingly."""
        
        delServers = self.servers.copy()    # Shallow copy
        
        initList = []
             
        for line in lines:
            line = line.rstrip('\n').strip()
            if line.startswith('#') or line == '': continue
            
            serverdict = eval(line)
            if type(serverdict) == dict and 'host' in serverdict:
                host = serverdict['host']
                if host in self.servers:
                    # Existing server. merge
                    server = delServers.pop(host)
                    server.merge(serverdict)            
                    print self, "Merged %s server %s, weight %d" % (server.enabled and "enabled" or "disabled", host, server.weight)
                else:
                    # New server
                    server = Server.buildServer(serverdict, self.lvsservice)
                    # Initialize with LVS service specific configuration 
                    self.lvsservice.initServer(server)
                    self.servers[host] = server
                    initList.append(server.initialize(self))
                    print self, "New %s server %s, weight %d" % (server.enabled and "enabled" or "disabled", host, server.weight )
                
        # Remove old servers
        for host, server in delServers.iteritems():
            print self, "Removing server %s (no longer found in new configuration)" % host
            server.destroy()
            del self.servers[host]
        
        # Calculate up status for previously existing, modified servers
        self.refreshModifiedServers()
        
        # Wait for all new servers to finish initializing
        self.serverInitDeferredList = defer.DeferredList(initList).addCallback(self._serverInitDone)
    
    def _serverInitDone(self, result):
        """Called when all (new) servers have finished initializing"""

        print self, "Initialization complete"
        
        # Assign the updated list of enabled servers to the LVSService instance
        self.assignServers()

class BGPFailover:
    """Class for maintaining a BGP session to a router for IP address failover"""

    prefixes = {}
    peerings = []

    def __init__(self, globalConfig):
        self.globalConfig = globalConfig
        
        if self.globalConfig.getboolean('bgp', False):
            self.setup()

    def setup(self):        
        try:
            self.bgpPeering = bgp.NaiveBGPPeering(myASN=self.globalConfig.getint('bgp-local-asn'),
                                                  peerAddr=self.globalConfig.get('bgp-peer-address'))
            
            asPath = [int(asn) for asn in self.globalConfig.get('bgp-as-path', str(self.bgpPeering.myASN)).split()]
            attributes = {}

            try:                
                attributes[(bgp.AFI_INET, bgp.SAFI_UNICAST)] = bgp.FrozenAttributeDict([
                    bgp.OriginAttribute(),
                    bgp.ASPathAttribute(asPath),
                    bgp.NextHopAttribute(self.globalConfig['bgp-nexthop-ipv4'])])
            except KeyError:
                if (bgp.AFI_INET, bgp.SAFI_UNICAST) in BGPFailover.prefixes:
                    raise ValueError("IPv4 BGP NextHop (global configuration variable 'bgp-nexthop-ipv4') not set")
            
            try:
                attributes[(bgp.AFI_INET6, bgp.SAFI_UNICAST)] = bgp.FrozenAttributeDict([
                    bgp.OriginAttribute(),
                    bgp.ASPathAttribute(asPath),
                    bgp.MPReachNLRIAttribute((bgp.AFI_INET6, bgp.SAFI_UNICAST,
                                             bgp.IPv6IP(self.globalConfig['bgp-nexthop-ipv6']), []))])
            except KeyError:
                if (bgp.AFI_INET6, bgp.SAFI_UNICAST) in BGPFailover.prefixes:
                    raise ValueError("IPv6 BGP NextHop (global configuration variable 'bgp-nexthop-ipv6') not set")

            advertisements = set([bgp.Advertisement(prefix, attributes[af], af)
                                  for af in attributes.keys()
                                  for prefix in BGPFailover.prefixes.get(af, set())])
            
            self.bgpPeering.setEnabledAddressFamilies(set(attributes.keys()))
            self.bgpPeering.setAdvertisements(advertisements)
            self.bgpPeering.automaticStart()
        except Exception:
            print "Could not set up BGP peering instance."
            raise
        else:
            BGPFailover.peerings.append(self.bgpPeering)
            reactor.addSystemEventTrigger('before', 'shutdown', self.closeSession, self.bgpPeering)
            try:
                # Try to listen on the BGP port, not fatal if fails
                reactor.listenTCP(bgp.PORT, bgp.BGPServerFactory({self.bgpPeering.peerAddr: self.bgpPeering}))
            except Exception:
                pass
    
    def closeSession(self, peering):
        print "Clearing session to", peering.peerAddr
        # Withdraw all announcements
        peering.setAdvertisements(set())
        return peering.manualStop()
    
    @classmethod
    def addPrefix(cls, prefix):
        try:
            if ':' not in prefix: 
                cls.prefixes.setdefault((bgp.AFI_INET, bgp.SAFI_UNICAST), set()).add(bgp.IPv4IP(prefix))
            else:
                cls.prefixes.setdefault((bgp.AFI_INET6, bgp.SAFI_UNICAST), set()).add(bgp.IPv6IP(prefix))
        except NameError:
            # bgp not imported
            pass
                
def parseCommandLine(configuration):
    """
    Parses the command line arguments, and sets configuration options
    in dictionary configuration.
    """
    
    import sys, getopt

    options = 'hnd'
    long_options = [ 'help', 'dryrun', 'debug' ]
    
    for o, a in getopt.gnu_getopt(sys.argv, options, long_options)[0]:
        if o in ('-h', '--help'):
            printHelp()
            sys.exit(0)
        elif o in ('-n', '--dryrun'):
            configuration['dryrun'] = True
        elif o in ('-d', '--debug'):
            configuration['debug'] = True

def printHelp():
    """Prints a help screen"""
    
    print "Usage:"
    print "\tpybal [ options ]"
    print "\t\t-h\t--help\t\tThis help message"
    print "\t\t-n\t--dryrun\tDry Run mode, do not actually update"
    print "\t\t-d\t--debug\tDebug mode, do not daemonize, log to stdout"
    print "\t\t\t\t\tLVS configuration/state, but print commands"

def createDaemon():
    """
    Detach a process from the controlling terminal and run it in the
    background as a daemon.
    """

    try:
        # Fork a child process so the parent can exit.  This will return control
        # to the command line or shell.  This is required so that the new process
        # is guaranteed not to be a process group leader.  We have this guarantee
        # because the process GID of the parent is inherited by the child, but
        # the child gets a new PID, making it impossible for its PID to equal its
        # PGID.
        pid = os.fork()
    except OSError, e:
        return( ( e.errno, e.strerror ) )     # ERROR (return a tuple)

    if ( pid == 0 ):       # The first child.
        # Next we call os.setsid() to become the session leader of this new
        # session.  The process also becomes the process group leader of the
        # new process group.  Since a controlling terminal is associated with a
        # session, and this new session has not yet acquired a controlling
        # terminal our process now has no controlling terminal.  This shouldn't
        # fail, since we're guaranteed that the child is not a process group
        # leader.
        os.setsid()

        # When the first child terminates, all processes in the second child
        # are sent a SIGHUP, so it's ignored.
        #signal.signal( signal.SIGHUP, signal.SIG_IGN )

        try:
            # Fork a second child to prevent zombies.  Since the first child is
            # a session leader without a controlling terminal, it's possible for
            # it to acquire one by opening a terminal in the future.  This second
            # fork guarantees that the child is no longer a session leader, thus
            # preventing the daemon from ever acquiring a controlling terminal.
            pid = os.fork()        # Fork a second child.
        except OSError, e:
            return( ( e.errno, e.strerror ) )  # ERROR (return a tuple)

        if ( pid == 0 ):      # The second child.
            # Ensure that the daemon doesn't keep any directory in use.  Failure
            # to do this could make a filesystem unmountable.
            os.chdir( "/" )
            os.umask( 022 )
        else:
            os._exit( 0 )      # Exit parent (the first child) of the second child.
    else:
        os._exit( 0 )         # Exit parent of the first child.

    # Close all open files.  Try the system configuration variable, SC_OPEN_MAX,
    # for the maximum number of open files to close.  If it doesn't exist, use
    # the default value (configurable).
    try:
        maxfd = os.sysconf( "SC_OPEN_MAX" )
    except ( AttributeError, ValueError ):
        maxfd = 256       # default maximum

    #for fd in range( 0, maxfd ):
    #    try:
    #        os.close( fd )
    #    except OSError:   # ERROR (ignore)
    #        pass

    # Redirect the standard file descriptors to /dev/null.
    os.open( "/dev/null", os.O_RDONLY )    # standard input (0)
    os.open( "/dev/null", os.O_RDWR )       # standard output (1)
    os.open( "/dev/null", os.O_RDWR )       # standard error (2)

    return( 0 )

def writePID(): 
    """
    Writes the current processes's PID into /var/run/pybal.pid
    """
    
    try:
        file('/var/run/pybal.pid', 'w').write(str(os.getpid()) + '\n')
    except Exception:
        raise

def terminate():
    """
    Cleans up on exit
    """
        
    # Remove any PID file
    print "Removing PID file /var/run/pybal.pid"
    try:
        os.unlink('/var/run/pybal.pid')
    except OSError:
        pass
    
    print "Exiting..."

def sighandler(signum, frame):
    """
    Signal handler
    """
    
    if signum == signal.SIGTERM:
        terminate()
    elif signum == signal.SIGHUP:
        # Cycle logfiles
        if isinstance(sys.stdout, util.LogFile):
            print "Cycling log file..."
            sys.stdout.reopen()

def installSignalHandlers():
    """
    Installs Unix signal handlers, e.g. to run terminate() on TERM
    """
    
    signals = [signal.SIGTERM, signal.SIGHUP]
    
    for sig in signals:
        signal.signal(sig, sighandler)

def main():
    from ConfigParser import SafeConfigParser
   
    # Read the configuration file
    configFile = '/etc/pybal/pybal.conf'
    
    config = SafeConfigParser()
    config.read(configFile)
    
    services, cliconfig = {}, {}
    
    # Parse the command line
    parseCommandLine(cliconfig)

    try:
        if not cliconfig.get('debug', False):
            # Become a daemon
            createDaemon()
            
            # Write PID file
            writePID()
            
            # Open a logfile
            try:
                logfile = '/var/log/pybal.log'
                sys.stdout = sys.stderr = util.LogFile(logfile)
            except Exception:
                print "Unable to open logfile %s, using stdout" % logfile  

        # Install signal handlers
        installSignalHandlers()

        globalConfig = {}
        for section in config.sections():
            if section != 'global':
                cfgtuple = (
                    config.get(section, 'protocol'),
                    config.get(section, 'ip'),
                    config.getint(section, 'port'),
                    config.get(section, 'scheduler'))
                
            # Read the custom configuration options of the LVS section
            configdict = util.ConfigDict(config.items(section))
            
            # Override with command line options
            configdict.update(cliconfig)
            
            if section != 'global':
                services[section] = ipvs.LVSService(section, cfgtuple, configuration=configdict)
                crd = Coordinator(services[section],
                    configURL=config.get(section, 'config'))
                print "Created LVS service '%s'" % section
        
        
        # Set up BGP
        try:
            configdict = util.ConfigDict(config.items('global'))
        except Exception:
            configdict = util.ConfigDict()
        configdict.update(cliconfig)
        bgpannouncement = BGPFailover(configdict)

        reactor.run()
    finally:
        terminate()

if __name__ == '__main__':
    main()
