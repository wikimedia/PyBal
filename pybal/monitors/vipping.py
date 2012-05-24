"""
vipping.py
Copyright (C) 2008 by Mark Bergsma <mark@nedworks.org>

Monitor class implementations for PyBal

$Id$
"""

from pybal import monitor

from twisted.internet import reactor, protocol, udp, interfaces, error
from twisted.python import log, reflect, failure

from zope.interface import implements

import socket, struct

try:
    import fcntl
except ImportError:
    fcntl = None
    
from errno import EWOULDBLOCK, EINTR, EMSGSIZE, ECONNREFUSED, EAGAIN

try:
    from eunuchs.sendmsg import sendmsg
except ImportError:
    pass

class VIPPingMonitoringProtocol(monitor.MonitoringProtocol):
    """
    The VIPPing monitor attempts to reach a real server on its Virtual IP (VIP)
    using ICMP echo-request/echo-reply.
    """
    
    __name__ = 'VIPPing'
    
    def __init__(self, coordinator, server, configuration):
        """Constructor"""

        # Call ancestor constructor        
        super(VIPPingMonitoringProtocol, self).__init__(coordinator, server, configuration)
        
        # Install cleanup handler
        reactor.addSystemEventTrigger('before', 'shutdown', self.stop)
    
    def run(self):
        """Start the monitoring""" 
        
        self.protocol = ICMPPing()
        p = RawICMPPort(0, self.protocol, reactor=reactor)
        p.startListening()

    def stop(self):
        """Stop the monitoring"""
        pass

class ICMPPing(protocol.DatagramProtocol):
    """
    A quick and dirty implementation of ICMP echo-request & echo-reply.
    """
    
    def startProtocol(self):
        self.sendDatagram(1)
        pass
    
    def stopProtocol(self):
        pass
        
    def datagramReceived(self, datagram, addr=None):
        print addr, [ord(c) for c in datagram]
    
    def sendDatagram(self, ip):
        msg = self._constructEthernetII('\x00\x04\x75\x7B\xEE\xDF', '\x00\x1F\xF3\x55\x00\x04', 0x800,
                                        self._constructIPv4(socket.IPPROTO_ICMP, '\x01\x14\xA8\xC0', '\x0B\x14\xA8\xC0',
                                                            self._constructICMP(8, 0, 1, 1, ' ' * 40)))
        print "sending:", [hex(ord(c)) for c in msg]
        self.transport.write(msg)

    def _constructEthernetII(self, srcmac, dstmac, ethertype, data):
        return dstmac + srcmac + struct.pack('!H', ethertype) + data

    def _constructIPv4(self, proto, src, dst, data, ttl=64):
        return struct.pack('!BBHIBBH', 0x45, 0, 20 + len(data), 0, ttl, proto, 0) + src + dst + data

    def _constructICMP(self, type, code, id, sequence, data):
        msg = struct.pack('!BBHHH', type, code, 0, id, sequence) + data
        
        # FIXME: checksum
        
        return msg

class RawICMPPort(udp.Port):
    """
    Raw ICMPPort, for sending and reading ICMP packets including transport header.
    Only works on Linux.
    """
    
    implements(interfaces.IUDPTransport, interfaces.ISystemHandle)
    
    # Constants not in socket module
    SOL_RAW = 255
    ICMP_FILTER = 1
    PF_PACKET = 17

    ICMP_ECHOREPLY = 0
    ICMP_DEST_UNREACH = 3
    ICMP_SOURCE_QUENCH = 4
    ICMP_REDIRECT = 5
    ICMP_ECHO = 8
    ICMP_TIME_EXCEEDED = 11
    ICMP_PARAMETERPROB = 12
    ICMP_TIMESTAMP = 13
    ICMP_TIMESTAMPREPLY = 14
    ICMP_INFO_REQUEST = 15
    ICMP_INFO_REPLY = 16
    ICMP_ADDRESS = 17
    ICMP_ADDRESSREPLY = 18
    
    addressFamily = PF_PACKET #socket.AF_INET
    socketType = socket.SOCK_RAW
    socketProto = 0x800 #socket.IPPROTO_ICMP
    maxThroughput = 256 * 1024 # max bytes we read in one eventloop iteration
    
    def createInternetSocket(self):
        s = socket.socket(self.addressFamily, self.socketType, self.socketProto)
        s.setblocking(0)
        if fcntl and hasattr(fcntl, 'FD_CLOEXEC'):
            old = fcntl.fcntl(s.fileno(), fcntl.F_GETFD)
            fcntl.fcntl(s.fileno(), fcntl.F_SETFD, old | fcntl.FD_CLOEXEC)
        return s

    def write(self, datagram, addr=None):
        """Write a datagram.

        @param addr: should be None.
        """

        assert addr is None
        try:
            return sendmsg(fd=self.socket.fileno(),
                                   data=datagram,
                                   ancillary=[
                                              (SOL_IP, IP_PKTINFO, (10, #interface index
                                                                    '0.0.0.0',
                                                                    '255.255.255.255',
                                                                    )),
                                                                    #(SOL_IP, IP_RETOPTS, ''),
                                            ])
        except socket.error, se:
            no = se.args[0]
            if no == EINTR:
                return self.write(datagram, addr)
            elif no == EMSGSIZE:
                raise error.MessageLengthError, "message too long"
            elif no == ECONNREFUSED:
                # in non-connected UDP ECONNREFUSED is platform dependent, I think
                # and the info is not necessarily useful. Nevertheless maybe we
                # should call connectionRefused? XXX
                return
            else:
                raise


    def _bindSocket(self):       
        #try:
        skt = self.createInternetSocket()
        
        #try:
        #    skt.setsockopt(self.SOL_RAW, self.ICMP_FILTER, 
        #               ~(self.ICMP_ECHOREPLY)) #|self.ICMP_DEST_UNREACH|self.ICMP_SOURCE_QUENCH|self.ICMP_REDIRECT|self.ICMP_TIME_EXCEEDED|self.ICMP_PARAMETERPROB))
        #except: raise
        #except socket.error, le:
        #    raise error.CannotListenError, (self.interface, self.port, le)

        # Make sure that if we listened on port 0, we update that to
        # reflect what the OS actually assigned us.
        self._realPortNumber = skt.getsockname()[1]

        log.msg("%s starting on %s"%(self.protocol.__class__, self._realPortNumber))

        self.connected = 1
        self.socket = skt
        self.fileno = self.socket.fileno

    def setLogStr(self):
        self.logstr = reflect.qual(self.protocol.__class__) + " (ICMP)"

    def logPrefix(self):
        """Returns the name of my class, to prefix log entries with.
        """
        return self.logstr

    def getHost(self):
        """
        Returns an IPv4Address.

        This indicates the address from which I am connecting.
        """
        return address.IPv4Address('ICMP', *(self.socket.getsockname() + ('INET_ICMP',)))
        

