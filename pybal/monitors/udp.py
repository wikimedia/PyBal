"""
udp.py
Copyright (C) 2018 by Valentin Gutierrez <vgutierrez@wikimedia.org>

UDP Monitor class implementation for PyBal
"""

import logging

from twisted.internet import protocol
from twisted.internet.task import LoopingCall
from twisted.python import runtime
from pybal import monitor

class UDPMonitoringProtocol(monitor.MonitoringProtocol, protocol.DatagramProtocol):
    """
    Monitor that sends a Len=0 UDP packet to the server.
    As long as it doesn't get an ICMP destination unreachable it will
    keep the state set to up.
    """

    __name__ = 'UDP'

    INTV_CHECK = 10
    # After ICMP_TIMEOUT seconds it will consider the monitor up again
    ICMP_TIMEOUT = 20

    def __init__(self, coordinator, server, configuration):
        """Constructor"""

        super(UDPMonitoringProtocol, self).__init__(coordinator, server, configuration)

        self.loop = None
        self.port = None
        self.last_down_timestamp = 0
        self.interval = self._getConfigInt('interval', self.INTV_CHECK)
        self.icmp_timeout = self._getConfigInt('icmp-timeout', self.ICMP_TIMEOUT)

    def __report_prefix(self):
        return '{}:{}:'.format(self.server.ip, self.server.port)

    def startProtocol(self):
        self.transport.connect(self.server.ip, self.server.port)
        self.loop = LoopingCall(self.check)
        self.loop.start(self.interval)

    def run(self):
        """Start the monitoring"""

        super(UDPMonitoringProtocol, self).run()

        self.port = self.reactor.listenUDP(0, self)

    def stop(self):
        """Stop the monitoring"""

        super(UDPMonitoringProtocol, self).stop()

        if self.loop and self.loop.running:
            self.loop.stop()

        if self.port:
            self.port.loseConnection()

    def check(self):
        "Periodically called method that does a single check"

        if not self.active:
            return

        self.transport.write("")
        self.is_up()

    def is_up(self):
        """
        Mark the monitor as up iff no ICMP errors were received
        self.icmp_timeout seconds after the last error
        """
        if not self.active:
            return

        if (runtime.seconds() - self.last_down_timestamp) > self.icmp_timeout:
            self._resultUp()
            self.report("{} marked as UP".format(self.__report_prefix()))

    def connectionRefused(self):
        """Called if an ICMP destination unreachable is received"""

        self.last_down_timestamp = runtime.seconds()
        self._resultDown()
        self.report("{} ICMP destination unreachable received".format(self.__report_prefix()),
                    level=logging.WARN)
