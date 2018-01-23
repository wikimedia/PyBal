# bgp.py
# Copyright (c) 2007-2018 by Mark Bergsma <mark@nedworks.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
A (partial) implementation of the BGP 4 protocol (RFC4271).

Supported features:

- RFC 3392 (Capabilities Advertisement with BGP-4) [rudimentary]
- RFC 4760 (Multi-protocol Extensions for BGP-4)
"""

# Constants
VERSION = 4
PORT = 179

HDR_LEN = 19
MAX_LEN = 4096

# BGP messages
MSG_OPEN = 1
MSG_UPDATE = 2
MSG_NOTIFICATION = 3
MSG_KEEPALIVE = 4

# BGP FSM states
ST_IDLE, ST_CONNECT, ST_ACTIVE, ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED = range(6)

stateDescr = {
    ST_IDLE:        "IDLE",
    ST_CONNECT:     "CONNECT",
    ST_ACTIVE:      "ACTIVE",
    ST_OPENSENT:    "OPENSENT",
    ST_OPENCONFIRM: "OPENCONFIRM",
    ST_ESTABLISHED: "ESTABLISHED"
}

# Notification error codes
ERR_MSG_HDR = 1
ERR_MSG_OPEN = 2
ERR_MSG_UPDATE = 3
ERR_HOLD_TIMER_EXPIRED = 4
ERR_FSM = 5
ERR_CEASE = 6

# Notification suberror codes
ERR_MSG_HDR_CONN_NOT_SYNC = 1
ERR_MSG_HDR_BAD_MSG_LEN = 2
ERR_MSG_HDR_BAD_MSG_TYPE = 3

ERR_MSG_OPEN_UNSUP_VERSION = 1
ERR_MSG_OPEN_BAD_PEER_AS = 2
ERR_MSG_OPEN_BAD_BGP_ID = 3
ERR_MSG_OPEN_UNSUP_OPT_PARAM = 4
ERR_MSG_OPEN_UNACCPT_HOLD_TIME = 6

ERR_MSG_UPDATE_MALFORMED_ATTR_LIST = 1
ERR_MSG_UPDATE_UNRECOGNIZED_WELLKNOWN_ATTR = 2
ERR_MSG_UPDATE_MISSING_WELLKNOWN_ATTR = 3
ERR_MSG_UPDATE_ATTR_FLAGS = 4
ERR_MSG_UPDATE_ATTR_LEN = 5
ERR_MSG_UPDATE_INVALID_ORIGIN = 6
ERR_MSG_UPDATE_INVALID_NEXTHOP = 8
ERR_MSG_UPDATE_OPTIONAL_ATTR = 9
ERR_MSG_UPDATE_INVALID_NETWORK_FIELD = 10
ERR_MSG_UPDATE_MALFORMED_ASPATH = 11

# BGP Open optional parameter codes
OPEN_PARAM_CAPABILITIES = 2

# BGP Capability codes
CAP_MP_EXT = 1
CAP_ROUTE_REFRESH = 2
CAP_ORF = 3

AFI_INET = 1
AFI_INET6 = 2
SUPPORTED_AFI = [AFI_INET, AFI_INET6]

SAFI_UNICAST = 1
SAFI_MULTICAST = 2
SUPPORTED_SAFI = [SAFI_UNICAST, SAFI_MULTICAST]


# System imports
import logging
import struct

# Zope imports
from zope.interface import implements, Interface

# Twisted imports
from twisted import copyright
from twisted.internet import reactor, protocol, base, interfaces, error, defer

# BGP imports
from attributes import Attribute, MPReachNLRIAttribute, MPUnreachNLRIAttribute
from attributes import AttributeDict, FrozenAttributeDict
from attributes import ATTR_EXTENDED_LEN
from exceptions import BGPException, NotificationSent, BadMessageLength, AttributeException
from ip import IPv4IP, IPv6IP, IPPrefix

# Pybal imports :-(
from pybal.metrics import Gauge
from pybal.util import _log

# Interfaces

class IBGPPeering(Interface):
    """
    Interface for notifications from the BGP protocol / FSM
    """

    def notificationSent(self, protocol, error, suberror, data):
        """
        Called when a BGP Notification message was sent.
        """

    def connectionClosed(self, protocol):
        """
        Called when the BGP connection has been closed (in error or not).
        """

    def completeInit(self, protocol):
        """
        Called when BGP resources should be initialized.
        """

    def sessionEstablished(self, protocol):
        """
        Called when the BGP session has reached the Established state
        """

    def connectRetryEvent(self, protocol):
        """
        Called when the connect-retry timer expires. A new connection should
        be initiated.
        """


class Advertisement(object):
    """
    Class that represents a single BGP advertisement, consisting of an IP network prefix,
    BGP attributes and optional extra information
    """

    def __init__(self, prefix, attributes, addressfamily=(AFI_INET, SAFI_UNICAST)):
        self.prefix = prefix
        self.attributes = attributes
        self.addressfamily = addressfamily

    def __repr__(self):
        return repr(self.__dict__)


class FSM(object):
    class BGPTimer(object):
        """
        Timer class with a slightly different Timer interface than the
        Twisted DelayedCall interface
        """

        def __init__(self, callable):
            self.delayedCall = None
            self.callable = callable

        def cancel(self):
            """Cancels the timer if it was running, does nothing otherwise"""

            try:
                self.delayedCall.cancel()
            except (AttributeError, error.AlreadyCalled, error.AlreadyCancelled):
                pass

        def reset(self, secondsFromNow):
            """Resets an already running timer, or starts it if it wasn't running."""

            try:
                self.delayedCall.reset(secondsFromNow)
            except (AttributeError, error.AlreadyCalled, error.AlreadyCancelled):
                self.delayedCall = reactor.callLater(secondsFromNow, self.callable)

        def active(self):
            """Returns True if the timer was running, False otherwise."""

            try:
                return self.delayedCall.active()
            except AttributeError:
                return False

    protocol = None

    state = ST_IDLE

    largeHoldTime = 4*60
    sendNotificationWithoutOpen = True    # No bullshit

    eventMethods = {
        1:  'manualStart',
        2:  'manualStop',
        3:  'automaticStart',

        9:  'connectRetryTimeEvent',
        10: 'holdTimeEvent',
        11: 'keepAliveEvent',
        12: 'delayOpenEvent',
        13: 'idleHoldTimeEvent',

        17: 'connectionMade',
        18: 'connectionFailed',
        19: 'openReceived',
        20: 'openReceived',
        21: 'headerError',
        22: 'openMessageError',
        23: 'openCollisionDump',
        24: 'versionError',

        26: 'keepAliveReceived',
        27: 'updateReceived',
        28: 'updateError'
    }

    bgpTimers = { 'connectRetryTimer', 'holdTimer', 'keepAliveTimer',
        'delayOpenTimer', 'idleHoldTimer' }

    metric_labelnames = {'local_asn', 'state', 'local_ip', 'remote_ip', 'side'}
    metric_keywords = {
        'labelnames': metric_labelnames,
        'namespace': 'pybal',
        'subsystem': 'bgp'
    }

    metrics = {
        'bgp_session_state_count': Gauge('session_state_count',
                                   'Number of sessions in the specified state',
                                   **metric_keywords)
    }

    def __init__(self, bgpPeering=None, protocol=None):
        self.bgpPeering = bgpPeering
        self.protocol = protocol

        self.connectRetryCounter = 0
        self.connectRetryTime = 30
        self.connectRetryTimer = FSM.BGPTimer(self.connectRetryTimeEvent)
        self.holdTime = 3 * 60
        self.holdTimer = FSM.BGPTimer(self.holdTimeEvent)
        self.keepAliveTime = self.holdTime / 3
        self.keepAliveTimer = FSM.BGPTimer(self.keepAliveEvent)

        self.allowAutomaticStart = True
        self.allowAutomaticStop = False
        self.delayOpen = False
        self.delayOpenTime = 30
        self.delayOpenTimer = FSM.BGPTimer(self.delayOpenEvent)

        self.dampPeerOscillations = True
        self.idleHoldTime = 30
        self.idleHoldTimer = FSM.BGPTimer(self.idleHoldTimeEvent)

        self.metric_labels = {
            'state': stateDescr[self.state],
            'local_asn': None,
            'local_ip': None,
            'remote_ip': None,
            'side': None
        }
        if self.bgpPeering:
            self.metric_labels['local_asn'] = self.bgpPeering.myASN

        self.initial_idle_state = True

    def log(self, msg, lvl=logging.DEBUG):
        s = "bgp.FSM@{}".format(hex(id(self)))
        if self.protocol is not None:
            s += " peer {}".format(self.protocol.peerAddrStr())
        elif self.bgpPeering is not None:
            s += " peer {}".format(self.bgpPeering.peerAddr)
        _log(msg, lvl, s)

    def __setattr__(self, name, value):
        if name == 'state' and value != getattr(self, name):
            self.log("State is now: %s" % stateDescr[value], logging.INFO)
            self.__update_metrics(value)
        super(FSM, self).__setattr__(name, value)

    def __update_metrics(self, new_state):
        if self.metric_labels['local_ip'] and self.metric_labels['remote_ip']:
                if not self.initial_idle_state:
                    self.metrics['bgp_session_state_count'].labels(**self.metric_labels).dec()
                else:
                    self.initial_idle_state = False
                self.metric_labels['state'] = stateDescr[new_state]
                self.metrics['bgp_session_state_count'].labels(**self.metric_labels).inc()

    def manualStart(self):
        """
        Should be called when a BGP ManualStart event (event 1) is requested.
        Note that a protocol instance does not yet exist at this point,
        so this method requires some support from BGPPeering.manualStart().
        """

        if self.state == ST_IDLE:
            self.connectRetryCounter = 0
            self.connectRetryTimer.reset(self.connectRetryTime)

    def manualStop(self):
        """Should be called when a BGP ManualStop event (event 2) is requested."""

        if self.state != ST_IDLE:
            self.protocol.sendNotification(ERR_CEASE, 0)
            # Stop all timers
            for timer in (self.connectRetryTimer, self.holdTimer, self.keepAliveTimer,
                          self.delayOpenTimer, self.idleHoldTimer):
                timer.cancel()
            if self.bgpPeering is not None: self.bgpPeering.releaseResources(self.protocol)
            self._closeConnection()
            self.connectRetryCounter = 0
            self.state = ST_IDLE
            raise NotificationSent(self.protocol, ERR_CEASE, 0)

    def automaticStart(self, idleHold=False):
        """
        Should be called when a BGP Automatic Start event (event 3) is requested.
        Returns True or False to indicate BGPPeering whether a connection attempt
        should be initiated.
        """

        if self.state == ST_IDLE:
            if idleHold:
                self.idleHoldTimer.reset(self.idleHoldTime)
                return False
            else:
                self.connectRetryCounter = 0
                self.connectRetryTimer.reset(self.connectRetryTime)
                return True

    def connectionMade(self):
        """Should be called when a TCP connection has successfully been
        established with the peer. (events 16, 17)
        """

        self.metric_labels['local_ip'] = self.protocol.transport.getHost().host
        self.metric_labels['remote_ip'] = self.protocol.transport.getPeer().host
        if self.protocol.transport.getPeer().port == PORT:
            self.metric_labels['side'] = 'active'
        else:
            self.metric_labels['side'] = 'passive'

        if self.state in (ST_CONNECT, ST_ACTIVE):
            # State Connect, Event 16 or 17
            if self.delayOpen:
                self.connectRetryTimer.cancel()
                self.delayOpenTimer.reset(self.delayOpenTime)
            else:
                self.connectRetryTimer.cancel()
                if self.bgpPeering: self.bgpPeering.completeInit(self.protocol)
                self.protocol.sendOpen()
                self.holdTimer.reset(self.largeHoldTime)
                self.state = ST_OPENSENT

    def connectionFailed(self):
        """Should be called when the associated TCP connection failed, or
        was lost. (event 18)"""

        if self.state == ST_CONNECT:
            # State Connect, event 18
            if self.delayOpenTimer.active():
                 self.connectRetryTimer.reset(self.connectRetryTime)
                 self.delayOpenTimer.cancel()
                 self.state = ST_ACTIVE
            else:
                self.connectRetryTimer.cancel()
                self._closeConnection()
                if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
                self.state = ST_IDLE
        elif self.state == ST_ACTIVE:
            # State Active, event 18
            self.connectRetryTimer.reset(self.connectRetryTime)
            self.delayOpenTimer.cancel()
            if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
            self.connectRetryCounter += 1
            # TODO: osc damping
            self.state = ST_IDLE
        elif self.state == ST_OPENSENT:
            # State OpenSent, event 18
            if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
            self._closeConnection()
            self.connectRetryTimer.reset(self.connectRetryTime)
            self.state = ST_ACTIVE
        elif self.state in (ST_OPENCONFIRM, ST_ESTABLISHED):
            self._errorClose()


    def openReceived(self):
        """Should be called when a BGP Open message was received from
        the peer. (events 19, 20)
        """

        if self.state in (ST_CONNECT, ST_ACTIVE):
            if self.delayOpenTimer.active():
                # State Connect, event 20
                self.connectRetryTimer.cancel()
                if self.bgpPeering: self.bgpPeering.completeInit(self.protocol)
                self.delayOpenTimer.cancel()
                self.protocol.sendOpen()
                self.protocol.sendKeepAlive()
                if self.holdTime != 0:
                    self.keepAliveTimer.reset(self.keepAliveTime)
                    self.holdTimer.reset(self.holdTime)
                else:    # holdTime == 0
                    self.keepAliveTimer.cancel()
                    self.holdTimer.cancel()

                self.state = ST_OPENCONFIRM
            else:
                # State Connect, event 19
                self._errorClose()

        elif self.state == ST_OPENSENT:
            if not self.delayOpen:
                # State OpenSent, event 19
                self.delayOpenTimer.cancel()
                self.connectRetryTimer.cancel()
                self.protocol.sendKeepAlive()
                if self.holdTime > 0:
                    self.keepAliveTimer.reset(self.keepAliveTime)
                    self.holdTimer.reset(self.holdTime)
                self.state = ST_OPENCONFIRM
            else:
                # State OpenSent, event 20
                self.protocol.sendNotification(ERR_FSM, 0)
                self._errorClose()
                raise NotificationSent(self.protocol, ERR_FSM, 0)

        elif self.state == ST_OPENCONFIRM:
            if not self.delayOpen:
                # State OpenConfirm, events 19
                self.log("Running collision detection")

                # Perform collision detection
                self.protocol.collisionDetect()
            else:
                # State OpenConfirm, event 20
                self.protocol.sendNotification(ERR_FSM, 0)
                self._errorClose()
                raise NotificationSent(self.protocol, ERR_FSM, 0)

        elif self.state == ST_ESTABLISHED:
            # State Established, event 19 or 20
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def headerError(self, suberror, data=''):
        """
        Should be called when an invalid BGP message header was received.
        (event 21)
        """

        self.protocol.sendNotification(ERR_MSG_HDR, suberror, data)
        # Note: RFC4271 states that we should send ERR_FSM in the
        # Established state, which contradicts earlier statements.
        self._errorClose()
        raise NotificationSent(self.protocol, ERR_MSG_HDR, suberror, data)

    def openMessageError(self, suberror, data=''):
        """
        Should be called when an invalid BGP Open message was received.
        (event 22)
        """

        self.protocol.sendNotification(ERR_MSG_OPEN, suberror, data)
        # Note: RFC4271 states that we should send ERR_FSM in the
        # Established state, which contradicts earlier statements.
        self._errorClose()
        raise NotificationSent(self.protocol, ERR_MSG_OPEN, suberror, data)

    def keepAliveReceived(self):
        """
        Should be called when a BGP KeepAlive packet was received
        from the peer. (event 26)
        """

        if self.state == ST_OPENCONFIRM:
            # State OpenSent, event 26
            self.holdTimer.reset(self.holdTime)
            self.state = ST_ESTABLISHED
            self.protocol.deferred.callback(self.protocol)
        elif self.state == ST_ESTABLISHED:
            # State Established, event 26
            self.holdTimer.reset(self.holdTime)
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            # States Connect, Active, event 26
            self._errorClose()
        elif self.state == ST_OPENSENT:
            # State OpenSent, event 26
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def versionError(self):
        """
        Should be called when a BGP Notification Open Version Error
        message was received from the peer. (event 24)
        """

        if self.state in (ST_OPENSENT, ST_OPENCONFIRM):
            # State OpenSent/OpenConfirm, event 24
            self.connectRetryTimer.cancel()
            if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
            self._closeConnection()
            self.state = ST_IDLE
        elif self.state in (ST_CONNECT, ST_ACTIVE, ST_ESTABLISHED):
            # State Connect/Active/Established, event 24
            self._errorClose()

    def notificationReceived(self, error, suberror):
        """
        Should be called when a BGP Notification message was
        received from the peer. (events 24, 25)
        """

        if error == ERR_MSG_OPEN and suberror == 1:
            # Event 24
            self.versionError()
        else:
            if self.state != ST_IDLE:
                # State != Idle, events 24, 25
                self._errorClose()

    def updateReceived(self, update):
        """Called when a valid BGP Update message was received. (event 27)"""

        if self.state == ST_ESTABLISHED:
            # State Established, event 27
            if self.holdTime != 0:
                self.holdTimer.reset(self.holdTime)

            self.bgpPeering.update(update)
        elif self.state in (ST_ACTIVE, ST_CONNECT):
            # States Active, Connect, event 27
            self._errorClose()
        elif self.state in (ST_OPENSENT, ST_OPENCONFIRM):
            # States OpenSent, OpenConfirm, event 27
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def updateError(self, suberror, data=''):
        """Called when an invalid BGP Update message was received. (event 28)"""

        if self.state == ST_ESTABLISHED:
            # State Established, event 28
            self.protocol.sendNotification(ERR_MSG_UPDATE, suberror, data)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_MSG_UPDATE, suberror, data)
        elif self.state in (ST_ACTIVE, ST_CONNECT):
            # States Active, Connect, event 28
            self._errorClose()
        elif self.state in (ST_OPENSENT, ST_OPENCONFIRM):
            # States OpenSent, OpenConfirm, event 28
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def openCollisionDump(self):
        """
        Called when the collision detection algorithm determined
        that the associated connection should be dumped.
        (event 23)
        """

        self.log("Collided, closing")

        if self.state == ST_IDLE:
            return
        elif self.state in (ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED):
            self.protocol.sendNotification(ERR_CEASE, 0)

        self._errorClose()
        raise NotificationSent(self.protocol, ERR_CEASE, 0)

    def delayOpenEvent(self):
        """Called when the DelayOpenTimer expires. (event 12)"""

        assert(self.delayOpen)

        self.log("Delay Open event")

        if self.state == ST_CONNECT:
            # State Connect, event 12
            self.protocol.sendOpen()
            self.holdTimer.reset(self.largeHoldTime)
            self.state = ST_OPENSENT
        elif self.state == ST_ACTIVE:
            # State Active, event 12
            self.connectRetryTimer.cancel()
            self.delayOpenTimer.cancel()
            if self.bgpPeering: self.bgpPeering.completeInit(self.protocol)
            self.sendOpen()
            self.holdTimer.reset(self.largeHoldTime)
            self.state = ST_OPENSENT
        elif self.state != ST_IDLE:
            # State OpenSent, OpenConfirm, Established, event 12
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def keepAliveEvent(self):
        """Called when the KeepAliveTimer expires. (event 11)"""

        if self.state in (ST_OPENCONFIRM, ST_ESTABLISHED):
            # State OpenConfirm, Established, event 11
            self.protocol.sendKeepAlive()
            if self.holdTime > 0:
                self.keepAliveTimer.reset(self.keepAliveTime)
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            self._errorClose()
        elif self.state == ST_OPENSENT:
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def holdTimeEvent(self):
        """Called when the HoldTimer expires. (event 10)"""

        if self.state in (ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED):
            # States OpenSent, OpenConfirm, Established, event 10
            self.protocol.sendNotification(ERR_HOLD_TIMER_EXPIRED, 0)
            self._errorClose()
            # TODO: peer osc damping
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            self._errorClose()

    def connectRetryTimeEvent(self):
        """Called when the ConnectRetryTimer expires. (event 9)"""

        if self.state in (ST_CONNECT, ST_ACTIVE):
            # State Connect, event 9
            self._closeConnection()
            self.connectRetryTimer.reset(self.connectRetryTime)
            self.delayOpenTimer.cancel()
            # Initiate TCP connection
            if self.bgpPeering: self.bgpPeering.connectRetryEvent(self.protocol)
        elif self.state != ST_IDLE:
            # State OpenSent, OpenConfirm, Established, event 12
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def idleHoldTimeEvent(self):
        """Called when the IdleHoldTimer expires. (event 13)"""

        if self.state == ST_IDLE:
            if self.bgpPeering: self.bgpPeering.automaticStart(idleHold=False)
        else:
            fsmError = False
            if self.state in (ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED):
                fsmError = True
                self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            if fsmError:
                raise NotificationSent(self.protocol, ERR_FSM, 0)

    def updateSent(self):
        """Called by the protocol instance when it just sent an Update message."""

        if self.holdTime > 0:
            self.keepAliveTimer.reset(self.keepAliveTime)

    def _errorClose(self):
        """Internal method that closes a connection and returns the state
        to IDLE.
        """

        # Stop the timers
        for timer in (self.connectRetryTimer, self.delayOpenTimer, self.holdTimer,
            self.keepAliveTimer):
            timer.cancel()

        # Release BGP resources (routes, etc)
        if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)

        self._closeConnection()

        self.connectRetryCounter += 1
        self.state = ST_IDLE

    def _closeConnection(self):
        """Internal method that close the connection if a valid BGP protocol
        instance exists.
        """

        if self.protocol is not None:
            self.protocol.closeConnection()
        # Remove from connections list
        if self.bgpPeering: self.bgpPeering.connectionClosed(self.protocol)

class BGPMessage(object):
    msgtype = None
    msgLenOffset = 16

    def __init__(self):
        self.msg = (bytearray(HDR_LEN), )
        self.constructHeader()

    def __repr__(self):
        msgType = {
            MSG_OPEN: "OPEN",
            MSG_UPDATE: "UPDATE",
            MSG_NOTIFICATION: "NOTIFICATION",
            MSG_KEEPALIVE: "KEEPALIVE",

        }.get(self.msgtype, "Invalid")
        return "<BGP %s, len %d>" % (msgType, len(self))

    def __str__(self):
        return "".join([str(part) for part in self.msg])

    def __len__(self):
        return sum([len(part) for part in self.msg])

    def __getitem__(self, i):
        return buffer(self.msg[i])

    @staticmethod
    def prependHeader(message, type):
        """Prepends the mandatory header to a constructed BGP message"""

        return struct.pack('!16sHB',
                           chr(255)*16,
                           len(message)+HDR_LEN,
                           type) + message

    def constructHeader(self, buffer=None):
        struct.pack_into('!16sHB', (buffer or self.msg[0]), 0,
            chr(255)*16,
            len(self),
            self.msgtype)

    def freeSpace(self):
        """
        Returns the available free space in the packet
        """
        return MAX_LEN - len(self)

    def _updateRecordLen(self, buf, offset=None, length=None):
        """
        Updates the length of the variable length field at the given
        offset in the provided buffer
        """

        struct.pack_into('!H', buf, offset, length)

    def _updateMsgLen(self):
        """
        Updates the length of the message in the message header
        """

        struct.pack_into('!H', self.msg[0], self.msgLenOffset, len(self))

    def _appendAll(self, buf, data, lenOffset=None):
        """
        Appends variable records (e.g. NLRI, attributes) and updates
        the variable length and total message size.
        """

        newSize = len(self) + len(data)
        if newSize <= MAX_LEN:
            buf.extend(data)
            if lenOffset is not None:
                self._updateRecordLen(buf, lenOffset, len(buf) - lenOffset - 2)
            self._updateMsgLen()
        else:
            raise ValueError("New message size %s would exceed MAX_LEN %d" %
                (newSize, MAX_LEN))

class BGPUpdateMessage(BGPMessage):
    msgtype = MSG_UPDATE

    def __init__(self):
        super(BGPUpdateMessage, self).__init__()
        self.msg = (self.msg[0], bytearray(2), bytearray(2), bytearray())
        self.withdrCount, self.attrCount, self.nlriCount = 0, 0, 0

    def __repr__(self):
        return (super(BGPUpdateMessage, self).__repr__()[:-1]
            + ", [%d:%d] withdrawals" % (self.withdrCount, len(self.msg[1]))
            + ", [%d:%d] attributes" % (self.attrCount, len(self.msg[2]))
            + ", [%d:%d] NLRI>" % (self.nlriCount, len(self.msg[3])))


    def addSomeWithdrawals(self, withdrawalSet):
        """
        Incrementally adds as many withdrawals to the UPDATE message as will
        fit in the remainder of the packet, removing added prefixes from the set
        Returns the number of withdrawals added.
        """
        added = BGP.encodeSomePrefixes(
            prefixSet=withdrawalSet,
            bArray=self.msg[1],
            offset=len(self.msg[1]),
            maxLen=self.freeSpace())
        self._updateRecordLen(self.msg[1], 0, len(self.msg[1]) - 2)
        self._updateMsgLen()
        self.withdrCount += added
        return added

    def addAttributes(self, attributes):
        """
        Incrementally adds NLRI attributes to the UPDATE message.
        """

        self._appendAll(self.msg[2], BGP.encodeAttributes(attributes), lenOffset=0)
        self.attrCount += len(attributes)

    def clearAttributes(self):
        """
        Removes all previously added attributes from the packet.
        """

        del self.msg[2][2:]
        self.msg[2][0:2] = 0, 0
        self._updateMsgLen()

    def addSomeNLRI(self, nlriSet):
        """
        Incrementally adds as many nlri to the UPDATE message as will
        fit in the remainder of the packet, removing added prefixes from the set
        Returns the number of nlri added.
        """

        added = BGP.encodeSomePrefixes(
            prefixSet=nlriSet,
            bArray=self.msg[3],
            offset=len(self.msg[3]),
            maxLen=self.freeSpace())
        self._updateMsgLen()
        self.nlriCount += added
        return added


class BGP(protocol.Protocol):
    """Protocol class for BGP 4"""

    def __init__(self):
        self.deferred = defer.Deferred()
        self.fsm = None

        self.disconnected = False
        self.receiveBuffer = ''

    def peerAddrStr(self):
        if self.transport:
            peer = self.transport.getPeer()
            return "{}:{}".format(peer.host, peer.port)
        else:
            return "(none)"

    def log(self, msg, lvl=logging.DEBUG):

        s = "bgp.BGP@{} peer {}".format(hex(id(self)), self.peerAddrStr())
        _log(msg, lvl, s)

    def connectionMade(self):
        """
        Starts the initial negotiation of the protocol
        """

        # Set transport socket options
        self.transport.setTcpNoDelay(True)

        self.log("Connection established")

        # Set the local BGP id from the local IP address if it's not set
        if self.factory.bgpId is None:
            self.factory.bgpId = IPv4IP(self.transport.getHost().host).ipToInt()  # FIXME: IPv6

        try:
            self.fsm.connectionMade()
        except NotificationSent, e:
            self.deferred.errback(e)

    def connectionLost(self, reason):
        """Called when the associated connection was lost."""

        # Don't do anything if we closed the connection explicitly ourselves
        if self.disconnected:
            # Callback sessionEstablished shouldn't be called, especially not
            # with an argument protocol = True. Calling errback doesn't seem
            # appropriate either. Just do nothing?
            #self.deferred.callback(True)
            self.factory.connectionClosed(self)
            return

        self.log("Connection lost: %s" % reason.getErrorMessage(), logging.INFO)

        try:
            self.fsm.connectionFailed()
        except NotificationSent, e:
            self.deferred.errback(e)

    def dataReceived(self, data):
        """
        Appends newly received data to the receive buffer, and
        then attempts to parse as many BGP messages as possible.
        """

        # Buffer possibly incomplete data first
        self.receiveBuffer += data

        # Attempt to parse as many messages as possible
        while(self.parseBuffer()): pass

    def closeConnection(self):
        """Close the connection"""

        if self.transport.connected:
            self.transport.loseConnection()
            self.disconnected = True

    def sendOpen(self):
        """Sends a BGP Open message to the peer"""

        self.log("Sending Open")

        self.transport.write(self.constructOpen())

    def sendUpdate(self, withdrawnPrefixes, attributes, nlri):
        """Sends a BGP Update message to the peer"""
        self.log("Sending Update", logging.INFO)
        self.log("Withdrawing: %s" % withdrawnPrefixes, logging.INFO)
        self.log("Attributes: %s" % attributes, logging.INFO)
        self.log("NLRI: %s" % nlri, logging.INFO)

        self.transport.write(self.constructUpdate(withdrawnPrefixes, attributes, nlri))
        self.fsm.updateSent()

    def sendKeepAlive(self):
        """Sends a BGP KeepAlive message to the peer"""

        self.transport.write(self.constructKeepAlive())

    def sendNotification(self, error, suberror, data=''):
        """Sends a BGP Notification message to the peer
        """

        self.transport.write(self.constructNotification(error, suberror, data))

    def sendMessage(self, bgpMessage):
        """
        Sends a bgpMessage
        """
        self.log("Sending BGP message: %s" % repr(bgpMessage))

        # FIXME: Twisted on Python 2 doesn't support bytearrays
        self.transport.writeSequence(bytes(bgpMessage))

    def constructOpen(self):
        """Constructs a BGP Open message"""

        # Construct optional parameters
        capabilities = self.constructCapabilities(self._capabilities())
        optParams = self.constructOpenOptionalParameters(
                parameters=(capabilities and [capabilities] or []))

        msg = struct.pack('!BHHI',
                          VERSION,
                          self.factory.myASN,
                          self.fsm.holdTime,
                          self.factory.bgpId) + optParams

        return BGPMessage.prependHeader(msg, MSG_OPEN)

    def constructUpdate(self, withdrawnPrefixes, attributes, nlri):
        """Constructs a BGP Update message"""

        withdrawnPrefixesData = BGP.encodePrefixes(withdrawnPrefixes)
        attributesData = BGP.encodeAttributes(attributes)
        nlriData = BGP.encodePrefixes(nlri)

        msg = (struct.pack('!H', len(withdrawnPrefixesData))
               + withdrawnPrefixesData
               + struct.pack('!H', len(attributesData))
               + attributesData
               + nlriData)

        return BGPMessage.prependHeader(msg, MSG_UPDATE)

    def constructKeepAlive(self):
        """Constructs a BGP KeepAlive message"""

        return BGPMessage.prependHeader('', MSG_KEEPALIVE)

    def constructNotification(self, error, suberror=0, data=''):
        """Constructs a BGP Notification message"""

        msg = struct.pack('!BB', error, suberror) + data
        return BGPMessage.prependHeader(msg, MSG_NOTIFICATION)

    def constructOpenOptionalParameters(self, parameters):
        """Constructs the OptionalParameters fields of a BGP Open message"""

        params = "".join(parameters)
        return struct.pack('!B', len(params)) + params

    def constructCapabilities(self, capabilities):
        """Constructs a Capabilities optional parameter of a BGP Open message"""

        if len(capabilities) > 0:
            caps = "".join([struct.pack('!BB', capCode, len(capValue)) + capValue
                            for capCode, capValue
                            in capabilities])
            return struct.pack('!BB', OPEN_PARAM_CAPABILITIES, len(caps)) + caps
        else:
            return None

    def parseBuffer(self):
        """Parse received data in receiveBuffer"""

        buf = self.receiveBuffer

        if len(buf) < HDR_LEN:
            # Every BGP message is at least 19 octets. Maybe the rest
            # hasn't arrived yet.
            return False

        # Check whether the first 16 octets of the buffer consist of
        # the BGP marker (all bits one)
        if buf[:16] != chr(255)*16:
            self.fsm.headerError(ERR_MSG_HDR_CONN_NOT_SYNC)

        # Parse the header
        try:
            marker, length, type = struct.unpack('!16sHB', buf[:HDR_LEN])
        except struct.error:
            self.fsm.headerError(ERR_MSG_HDR_CONN_NOT_SYNC)

        # Check the length of the message
        if length < HDR_LEN or length > MAX_LEN:
            self.fsm.headerError(ERR_MSG_HDR_BAD_MSG_LEN, struct.pack('!H', length))

        # Check whether the entire message is already available
        if len(buf) < length: return False

        message = buf[HDR_LEN:length]
        try:
            try:
                if type == MSG_OPEN:
                    self.openReceived(*self.parseOpen(message))
                elif type == MSG_UPDATE:
                    self.updateReceived(*self.parseUpdate(message))
                elif type == MSG_KEEPALIVE:
                    self.parseKeepAlive(message)
                    self.keepAliveReceived()
                elif type == MSG_NOTIFICATION:
                    self.notificationReceived(*self.parseNotification(message))
                else:    # Unknown message type
                    self.fsm.headerError(ERR_MSG_HDR_BAD_MSG_TYPE, chr(type))
            except BadMessageLength:
                self.fsm.headerError(ERR_MSG_HDR_BAD_MSG_LEN, struct.pack('!H', length))
        except NotificationSent, e:
            self.deferred.errback(e)

        # Message successfully processed, jump to next message
        self.receiveBuffer = self.receiveBuffer[length:]
        return True

    def parseOpen(self, message):
        """Parses a BGP Open message"""

        try:
            peerVersion, peerASN, peerHoldTime, peerBgpId, paramLen = struct.unpack('!BHHIB', message[:10])
        except struct.error:
            raise BadMessageLength(self)

        # Check whether these values are acceptable

        if peerVersion != VERSION:
            self.fsm.openMessageError(ERR_MSG_OPEN_UNSUP_VERSION,
                                      struct.pack('!B', VERSION))

        if peerASN in (0, 2**16-1):
            self.fsm.openMessageError(ERR_MSG_OPEN_BAD_PEER_AS)

        # Hold Time is negotiated and/or rejected later

        if peerBgpId in (0, 2**32-1, self.bgpPeering.bgpId):
            self.fsm.openMessageError(ERR_MSG_OPEN_BAD_BGP_ID)

        # TODO: optional parameters

        return peerVersion, peerASN, peerHoldTime, peerBgpId

    def parseUpdate(self, message):
        """Parses a BGP Update message"""

        try:
            withdrawnLen = struct.unpack('!H', message[:2])[0]
            withdrawnPrefixesData = message[2:withdrawnLen+2]
            attrLen = struct.unpack('!H', message[withdrawnLen+2:withdrawnLen+4])[0]
            attributesData = message[withdrawnLen+4:withdrawnLen+4+attrLen]
            nlriData = message[withdrawnLen+4+attrLen:]

            withdrawnPrefixes = BGP.parseEncodedPrefixList(withdrawnPrefixesData)
            attributes = BGP.parseEncodedAttributes(attributesData)
            nlri = BGP.parseEncodedPrefixList(nlriData)
        except BGPException, e:
            if (e.error, e.suberror) == (ERR_MSG_UPDATE, ERR_MSG_UPDATE_INVALID_NETWORK_FIELD):
                self.fsm.updateError(e.suberror)
            else:
                raise
        except Exception:
            # RFC4271 dictates that we send ERR_MSG_UPDATE Malformed Attribute List
            # in this case
            self.fsm.updateError(ERR_MSG_UPDATE_MALFORMED_ATTR_LIST)

            # updateError may have raised an exception. If not, we'll do it here.
            raise
        else:
            return withdrawnPrefixes, attributes, nlri

    def parseKeepAlive(self, message):
        """Parses a BGP KeepAlive message"""

        # KeepAlive body must be empty
        if len(message) != 0: raise BadMessageLength(self)

    def parseNotification(self, message):
        """Parses a BGP Notification message"""

        try:
            error, suberror = struct.unpack('!BB', message[:2])
        except struct.error:
            raise BadMessageLength(self)

        return error, suberror, message[2:]

    def openReceived(self, version, ASN, holdTime, bgpId):
        """Called when a BGP Open message was received."""

        msg = "OPEN: version: %s ASN: %s hold time: %s id: %s" % (version,
            ASN, holdTime, bgpId)
        self.log(msg, logging.INFO)

        self.peerId = bgpId
        self.bgpPeering.setPeerId(bgpId)

        # Perform collision detection
        self.collisionDetect()

        self.negotiateHoldTime(holdTime)
        self.fsm.openReceived()

    def updateReceived(self, withdrawnPrefixes, attributes, nlri):
        """Called when a BGP Update message was received."""

        try:
            attrSet = AttributeDict(attributes, checkMissing=(len(nlri)>0))
        except AttributeException, e:
            if type(e.data) is tuple:
                self.fsm.updateError(e.suberror, (e.data[2] and self.encodeAttribute(e.data) or chr(e.data[1])))
            else:
                self.fsm.updateError(e.suberror)
        else:
            self.fsm.updateReceived((withdrawnPrefixes, attrSet, nlri))

    def keepAliveReceived(self):
        """Called when a BGP KeepAlive message was received.
        """

        assert self.fsm.holdTimer.active()
        self.fsm.keepAliveReceived()

    def notificationReceived(self, error, suberror, data=''):
        """Called when a BGP Notification message was received.
        """
        self.log("NOTIFICATION: %s %s %s" % (
            error, suberror, [ord(d) for d in data]),
            logging.INFO)

        self.fsm.notificationReceived(error, suberror)

    def negotiateHoldTime(self, holdTime):
        """Negotiates the hold time"""

        self.fsm.holdTime = min(self.fsm.holdTime, holdTime)
        if self.fsm.holdTime != 0 and self.fsm.holdTime < 3:
            self.fsm.openMessageError(ERR_MSG_OPEN_UNACCPT_HOLD_TIME)

        # Derived times
        self.fsm.keepAliveTime = self.fsm.holdTime / 3

        self.log("Hold time: %s Keepalive time: %s" % (
            self.fsm.holdTime, self.fsm.keepAliveTime), logging.INFO)

    def collisionDetect(self):
        """Performs collision detection. Outsources to factory class BGPPeering."""

        return self.bgpPeering.collisionDetect(self)

    def isOutgoing(self):
        """Returns True when this protocol represents an outgoing connection,
        and False otherwise."""

        return (self.transport.getPeer().port == PORT)


    def _capabilities(self):
        # Determine capabilities
        capabilities = []
        for afi, safi in list(self.factory.addressFamilies):
            capabilities.append((CAP_MP_EXT, struct.pack('!HBB', afi, 0, safi)))

        return capabilities

    @staticmethod
    def parseEncodedPrefixList(data, addressFamily=AFI_INET):
        """Parses an RFC4271 encoded blob of BGP prefixes into a list"""

        prefixes = []
        postfix = data
        while len(postfix) > 0:
            prefixLen = ord(postfix[0])
            if (addressFamily == AFI_INET and prefixLen > 32
                ) or (addressFamily == AFI_INET6 and prefixLen > 128):
                raise BGPException(ERR_MSG_UPDATE, ERR_MSG_UPDATE_INVALID_NETWORK_FIELD)

            octetLen, remainder = prefixLen / 8, prefixLen % 8
            if remainder > 0:
                # prefix length doesn't fall on octet boundary
                octetLen += 1

            prefixData = map(ord, postfix[1:octetLen+1])
            # Zero the remaining bits in the last octet if it didn't fall
            # on an octet boundary
            if remainder > 0:
                prefixData[-1] = prefixData[-1] & (255 << (8-remainder))

            prefixes.append(IPPrefix((prefixData, prefixLen), addressFamily))

            # Next prefix
            postfix = postfix[octetLen+1:]

        return prefixes

    @staticmethod
    def parseEncodedAttributes(data):
        """Parses an RFC4271 encoded blob of BGP prefixes into a list"""

        attributes = []
        postfix = data
        while len(postfix) > 0:
            flags, typeCode = struct.unpack('!BB', postfix[:2])

            if flags & ATTR_EXTENDED_LEN:
                attrLen = struct.unpack('!H', postfix[2:4])[0]
                value = postfix[4:4+attrLen]
                postfix = postfix[4+attrLen:]    # Next attribute
            else:    # standard 1-octet length
                attrLen = ord(postfix[2])
                value = postfix[3:3+attrLen]
                postfix = postfix[3+attrLen:]    # Next attribute

            attribute = (flags, typeCode, value)
            attributes.append(attribute)

        return attributes

    @staticmethod
    def encodeAttribute(attrTuple):
        """Encodes a single attribute"""

        flags, typeCode, value = attrTuple
        if flags & ATTR_EXTENDED_LEN:
            fmtString = '!BBH'
        else:
            fmtString = '!BBB'

        return struct.pack(fmtString, flags, typeCode, len(value)) + value

    @staticmethod
    def encodeAttributes(attributes):
        """Encodes a set of attributes"""

        attrData = ""
        for attr in attributes.itervalues():
            if isinstance(attr, Attribute):
                attrData += attr.encode()
            else:
                attrData += BGP.encodeAttribute(attr)

        return attrData

    @staticmethod
    def encodeSomePrefixes(prefixSet, bArray, offset, maxLen):
        """
        Encodes as many IPPrefix prefixes from set prefixSet as will fit
        within maxLen. Removes prefixes from the set as they are added,
        so leaves any remaining prefixes didn't fit.
        Returns the number of prefixes added.
        """

        if not isinstance(prefixSet, set):
            raise TypeError("prefixSet needs to be instance of set()")

        bytesWritten = 0
        prefixesAdded = 0
        while True:
            try:
                prefix = prefixSet.pop()
            except KeyError:
                # Set is empty
                break
            else:
                octetLen, remainder = len(prefix) / 8, len(prefix) % 8
                if remainder > 0:
                    # prefix length doesn't fall on octet boundary
                    octetLen += 1
                if maxLen - bytesWritten >= octetLen + 1:
                    if len(bArray) - offset - bytesWritten < octetLen + 1:
                        # Make space
                        bArray.extend(b'\0' * (octetLen + 1
                            - (len(bArray) - offset- bytesWritten)))
                    struct.pack_into(
                        ("!B%ds" % octetLen),
                        bArray, (offset + bytesWritten),
                        len(prefix), prefix.packed()[:octetLen])
                    bytesWritten += (octetLen+1)
                    prefixesAdded += 1
                else:
                    # We didn't have space, put the prefix back
                    prefixSet.add(prefix)
                    break

        return prefixesAdded

    @staticmethod
    def encodePrefixes(prefixes):
        """Encodes a list of IPPrefix"""

        prefixData = bytearray()
        for prefix in prefixes:
            octetLen, remainder = len(prefix) / 8, len(prefix) % 8
            if remainder > 0:
                # prefix length doesn't fall on octet boundary
                octetLen += 1

            prefixData.extend(struct.pack('!B', len(prefix)) + prefix.packed()[:octetLen])

        return bytes(prefixData)


class BGPFactory(protocol.Factory):
    """Base factory for creating BGP protocol instances"""

    protocol = BGP
    FSM = FSM

    myASN = None
    bgpId = None

    def log(self, msg, lvl=logging.DEBUG):
        s = "bgp.BGPFactory@{}".format(hex(id(self)))
        _log(msg, lvl, s)

    def buildProtocol(self, addr):
        """Builds a BGPProtocol instance"""

        assert self.myASN is not None

        return protocol.Factory.buildProtocol(self, addr)

    def startedConnecting(self, connector):
        """Called when a connection attempt has been initiated."""
        pass

    def clientConnectionLost(self, connector, reason):
        self.log("Client connection lost: %s" % reason.getErrorMessage(),
                 logging.INFO)

class BGPServerFactory(BGPFactory):
    """Class managing the server (listening) side of the BGP
    protocol. Hands over the factory work to a specific BGPPeering
    (factory) instance.
    """

    def __init__(self, peers, myASN=None):
        self.peers = peers
        self.myASN = myASN

    def buildProtocol(self, addr):
        """Builds a BGPProtocol instance by finding an appropriate
        BGPPeering factory instance to hand over to.
        """
        self.log("Connection received from %s" % addr.host, logging.INFO)

        try:
            bgpPeering = self.peers[addr.host]
        except KeyError:
            # This peer is unknown. Reject the incoming connection.
            return None

        return bgpPeering.takeServerConnection(addr)


class BGPPeering(BGPFactory):
    """Class managing a BGP session with a peer"""

    implements(IBGPPeering, interfaces.IPushProducer)

    metric_labelnames = {'local_asn', 'peer'}
    metric_keywords = {
        'labelnames': metric_labelnames,
        'namespace': 'pybal',
        'subsystem': 'bgp'
    }

    metrics = {
        'bgp_session_established': Gauge('session_established',
                                         'BGP session established',
                                         **metric_keywords)
    }

    def __init__(self, myASN=None, peerAddr=None):
        self.myASN = myASN
        self.peerAddr = peerAddr
        self.peerId = None
        self.fsm = BGPFactory.FSM(self)
        self.addressFamilies = set(( AFI_INET, SAFI_UNICAST ))
        self.inConnections = []
        self.outConnections = []
        self.estabProtocol = None    # reference to the BGPProtocol instance in ESTAB state
        self.consumers = set()

        self.metric_labels = {
            'local_asn': self.myASN,
            'peer': self.peerAddr
        }
        self.metrics = BGPPeering.metrics
        self.metrics['bgp_session_established'].labels(**self.metric_labels).set(0)

    def __setattr__(self, name, value):
        if name == 'estabProtocol' and name in self.__dict__ and getattr(self, name) != value:
            if value:
                msg = 'established'
                metric_value = 1
            else:
                msg = 'gone'
                metric_value = 0
            self.log("BGP session %s for ASN %s peer %s" %
                     (msg, self.myASN, self.peerAddr),
                     logging.INFO)
            self.metrics['bgp_session_established'].labels(**self.metric_labels).set(metric_value)
        #  old style class, super().__setattr__() doesn't work
        #  https://docs.python.org/2/reference/datamodel.html#customizing-attribute-access
        self.__dict__[name] = value

    def buildProtocol(self, addr):
        """Builds a BGP protocol instance"""

        self.log("Building a new BGP protocol instance")

        p = BGPFactory.buildProtocol(self, addr)
        if p is not None:
            self._initProtocol(p, addr)
            self.outConnections.append(p)

        return p

    def takeServerConnection(self, addr):
        """Builds a BGP protocol instance for a server connection"""

        p = BGPFactory.buildProtocol(self, addr)
        if p is not None:
            self._initProtocol(p, addr)
            self.inConnections.append(p)

        return p

    def _initProtocol(self, protocol, addr):
        """Initializes a BGPProtocol instance"""

        protocol.bgpPeering = self

        # Hand over the FSM
        protocol.fsm = self.fsm
        protocol.fsm.protocol = protocol

        # Create a new fsm for internal use for now
        self.fsm = BGPFactory.FSM(self)
        self.fsm.state = protocol.fsm.state

        if addr.port == PORT:
            protocol.fsm.state = ST_CONNECT
        else:
            protocol.fsm.state = ST_ACTIVE

        # Set up callback and error handlers
        protocol.deferred.addCallbacks(self.sessionEstablished, self.protocolError)

    def clientConnectionFailed(self, connector, reason):
        """Called when the outgoing connection failed."""

        self.log("Client connection failed: %s" % reason.getErrorMessage(), logging.INFO)

        # There is no protocol instance yet at this point.
        # Catch a possible NotificationException
        try:
            self.fsm.connectionFailed()
        except NotificationSent, e:
            # TODO: error handling
            pass

    def manualStart(self):
        """BGP ManualStart event (event 1)"""

        if self.fsm.state == ST_IDLE:
            self.fsm.manualStart()
            # Create outbound connection
            self.connect()
            self.fsm.state = ST_CONNECT

    def manualStop(self):
        """BGP ManualStop event (event 2) Returns a Deferred that will fire once the connection(s) have closed"""

        # This code is currently synchronous, so no need to actually wait

        for c in self.inConnections + self.outConnections:
            # Catch a possible NotificationSent exception
            try:
                c.fsm.manualStop()
            except NotificationSent, e:
                pass

        return defer.succeed(True)

    def automaticStart(self, idleHold=False):
        """BGP AutomaticStart event (event 3)"""

        if self.fsm.state == ST_IDLE:
            if self.fsm.automaticStart(idleHold):
                # Create outbound connection
                self.connect()
                self.fsm.state = ST_CONNECT

    def releaseResources(self, protocol):
        """
        Called by FSM when BGP resources (routes etc.) should be released
        prior to ending a session.
        """
        pass

    def connectionClosed(self, protocol, disconnect=False):
        """
        Called by FSM or Protocol when the BGP connection has been closed.
        """

        self.log("Connection closed")

        if protocol is not None:
            # Connection succeeded previously, protocol exists
            # Remove the protocol, if it exists
            try:
                if protocol.isOutgoing():
                    self.outConnections.remove(protocol)
                else:
                    self.inConnections.remove(protocol)
            except ValueError:
                pass

            if protocol is self.estabProtocol:
                self.estabProtocol = None

        if self.fsm.allowAutomaticStart: self.automaticStart(idleHold=True)

    def completeInit(self, protocol):
        """
        Called by FSM when BGP resources should be initialized.
        """

    def sessionEstablished(self, protocol):
        """Called when the BGP session was established"""

        # The One True protocol
        self.estabProtocol = protocol
        self.fsm = protocol.fsm

        # Create a new deferred for later possible errors
        protocol.deferred = defer.Deferred()
        protocol.deferred.addErrback(self.protocolError)

        # Kill off all other possibly running protocols
        for p in self.inConnections + self.outConnections:
            if p != protocol:
                try:
                    p.fsm.openCollisionDump()
                except NotificationSent, e:
                    pass

        # BGP announcements / UPDATE messages can be sent now
        self.sendAdvertisements()

    def connectRetryEvent(self, protocol):
        """Called by FSM when we should reattempt to connect."""

        self.connect()

    def protocolError(self, failure):
        failure.trap(BGPException)

        self.log("BGP exception %s" % failure, logging.ERROR)

        e = failure.check(NotificationSent)
        try:
            # Raise the original exception
            failure.raiseException()
        except NotificationSent, e:
            if (e.error, e.suberror) == (ERR_MSG_UPDATE, ERR_MSG_UPDATE_ATTR_FLAGS):
                self.log("exception on flags: %s" % BGP.parseEncodedAttributes(e.data), logging.ERROR)
            else:
                self.log("%s %s %s" % (e.error, e.suberror, e.data), logging.ERROR)

        # FIXME: error handling

    def setPeerId(self, bgpId):
        """
        Should be called when an Open message was received from a peer.
        Sets the BGP identifier of the peer if it wasn't set yet. If the
        new peer id is unequal to the existing one, CEASE all connections.
        """

        if self.peerId is None:
            self.peerId = bgpId
        elif self.peerId != bgpId:
            # Ouch, schizophrenia. The BGP id of the peer is unequal to
            # the ids of current and/or previous sessions. Close all
            # connections.
            self.peerId = None
            for c in self.inConnections + self.outConnections:
                try:
                    c.fsm.openCollisionDump()
                except NotificationSent, e:
                    c.deferred.errback(e)

    def collisionDetect(self, protocol):
        """
        Runs the collision detection algorithm as defined in the RFC.
        Returns True if the requesting protocol has to CEASE
        """

        # Construct a list of other connections to examine
        openConfirmConnections = [c
             for c
             in self.inConnections + self.outConnections
             if c != protocol and c.fsm.state in (ST_OPENCONFIRM, ST_ESTABLISHED)]

        # We need at least 1 other connections to have a collision
        if len(openConfirmConnections) < 1:
            return False

        # A collision exists at this point.

        # If one of the other connections is already in ESTABLISHED state,
        # it wins
        if ST_ESTABLISHED in [c.fsm.state for c in openConfirmConnections]:
            protocol.fsm.openCollisionDump()
            return True

        # Break the tie
        assert self.bgpId != protocol.peerId
        if self.bgpId < protocol.peerId:
            dumpList = self.outConnections
        elif self.bgpId > protocol.peerId:
            dumpList = self.inConnections

        for c in dumpList:
            try:
                c.fsm.openCollisionDump()
            except NotificationSent, e:
                c.deferred.errback(e)

        return (protocol in dumpList)

    def connect(self):
        """Initiates a TCP connection to the peer. Should only be called from
        BGPPeering or FSM, otherwise use manualStart() instead.
        """

        self.log("(Re)connect to %s" % self.peerAddr, logging.INFO)

        if self.fsm.state != ST_ESTABLISHED:
            reactor.connectTCP(self.peerAddr, PORT, self)
            return True
        else:
            return False

    def pauseProducing(self):
        """IPushProducer method - noop"""
        pass

    def resumeProducing(self):
        """IPushProducer method - noop"""
        pass

    def registerConsumer(self, consumer):
        """Subscription interface to BGP update messages"""

        consumer.registerProducer(self, streaming=True)
        self.consumers.add(consumer)

    def unregisterConsumer(self, consumer):
        """Unsubscription interface to BGP update messages"""

        consumer.unregisterProducer()
        self.consumers.remove(consumer)

    def update(self, update):
        """Called by FSM when a BGP Update message is received."""

        # Write to all BGPPeering consumers
        for consumer in self.consumers:
            consumer.write(update)

    def sendAdvertisements(self):
        """Called when the BGP session is established, and announcements can be sent."""
        pass

    def setEnabledAddressFamilies(self, addressFamilies):
        """
        Expects a dict with address families to be enabled,
        containing iterables with Sub-AFIs
        """

        for afi, safi in list(addressFamilies):
            if afi not in SUPPORTED_AFI or safi not in SUPPORTED_SAFI:
                raise ValueError("Address family (%d, %d) not supported" % (afi, safi))

        self.addressFamilies = addressFamilies

class NaiveBGPPeering(BGPPeering):
    """
    "Naive" class managing a simple BGP session, not optimized for very many
    announced prefixes.
    """

    def __init__(self, myASN=None, peerAddr=None):
        BGPPeering.__init__(self, myASN, peerAddr)

        # Dicts of sets per (AFI, SAFI) combination
        self.advertised = {}
        self.toAdvertise = {}

    def completeInit(self, protocol):
        """
        Called by FSM when BGP resources should be initialized.
        """

        BGPPeering.completeInit(self, protocol)

        # (Re)init the existing set, they may get reused
        self.advertised = {}

    def sendAdvertisements(self):
        """
        Called when the BGP session has been established and is
        ready for sending announcements.
        """

        self._sendUpdates(self.advertised, self.toAdvertise)

    def setAdvertisements(self, advertisements):
        """
        Takes a set of Advertisements that will be announced.
        """

        self.toAdvertise = {}
        for af in self.addressFamilies:
            self.advertised.setdefault(af, set())
            self.toAdvertise[af] = {ad for ad in iter(advertisements) if ad.addressfamily == af}

        # Try to send
        self._sendUpdates(*self._calculateChanges())

    def _calculateChanges(self):
        """Calculates the needed updates (for all address (sub)families)
        between previous advertisements (self.advertised) and to be
        advertised NLRI (in self.toAdvertise)
        """

        withdrawals, updates = {}, {}
        for af in set(self.advertised.keys() + self.toAdvertise.keys()):
            withdrawals[af] = self.advertised[af] - self.toAdvertise[af]
            updates[af] = self.toAdvertise[af] - self.advertised[af]

        return withdrawals, updates


    def _sendUpdates(self, withdrawals, updates):
        """
        Takes a dict of sets of withdrawals and a dict of sets of
        updates (both per (AFI, SAFI) combination), sorts them to
        equal attributes and sends the advertisements if possible.
        Assumes that self.toAdvertise reflects the advertised state
        after withdrawals and updates.
        """

        # This may have to wait for another time...
        if not self.estabProtocol or self.fsm.state != ST_ESTABLISHED:
            return

        # Process per (AFI, SAFI) pair
        for af in set(withdrawals.keys() + updates.keys()):
            withdrawals.setdefault(af, set())
            updates.setdefault(af, set())

            # Map equal attributes to advertisements
            attributeMap = {}
            for advertisement in updates[af]:
                attributeMap.setdefault(advertisement.attributes, set()).add(advertisement)

            # Send
            if af == (AFI_INET, SAFI_UNICAST):
                self._sendInetUnicastUpdates(withdrawals[af], attributeMap)
            else:
                # NLRI for address families other than inet unicast should
                # get sent in MP Reach NLRI and MP Unreach NLRI attributes
                self._sendMPUpdates(af, withdrawals[af], attributeMap)

            self.advertised[af] = self.toAdvertise[af]

    def _sendInetUnicastUpdates(self, withdrawals, attributeMap):
        """
        Sends (multiple) UPDATE messages for the inet-unicast way,
        i.e. the straightforward way.

        Arguments:
        - withdrawals: a set of advertisements to withdraw
        - attributeMap: a dict of FrozenAttributeDict to updates sets
        """

        for attributes, advertisements in attributeMap.iteritems():
            withdrawalPrefixSet = {w.prefix for w in withdrawals}
            adPrefixSet = {ad.prefix for ad in advertisements}

            bgpupdate = BGPUpdateMessage()
            # Start with withdrawals, if there are any
            while len(withdrawals) > 0:
                prefixesAdded = bgpupdate.addSomeWithdrawals(withdrawalPrefixSet)
                if prefixesAdded == 0:
                    raise ValueError("Could not add any withdrawals")
                if len(withdrawals) > 0:
                    # We overflowed the packet
                    self.estabProtocol.sendMessage(bgpupdate)
                    bgpupdate = BGPUpdateMessage()

            # Attempt to add all attributes and (some) NLRI to the existing
            # packet, to optimize for the common case of small updates.
            # The same prefix SHOULD NOT be sent in both withdrawals
            # and updated NLRI, but NaiveBGPPeering should have already
            # taken care of that.
            try:
                bgpupdate.addAttributes(attributes)
            except ValueError:
                # Alas, didn't fit. Just send out.
                self.estabProtocol.sendMessage(bgpupdate)
            else:
                prefixesAdded = bgpupdate.addSomeNLRI(adPrefixSet)
                if prefixesAdded == 0:
                    # Packet was full, no NLRI added. Nevermind, let's send
                    # this one without attributes & NLRI.
                    bgpupdate.clearAttributes()
                self.estabProtocol.sendMessage(bgpupdate)

            # Start with a clean slate
            while len(adPrefixSet) > 0:
                bgpupdate = BGPUpdateMessage()
                # For inet-unicast, we need to add the complete set of
                # attributes to every packet.
                try:
                    bgpupdate.addAttributes(attributes)
                except ValueError:
                    # Too many attributes to fit an empty packet. That's a
                    # problem we can't solve.
                    raise
                else:
                    prefixesAdded = bgpupdate.addSomeNLRI(adPrefixSet)
                    if prefixesAdded == 0:
                        raise ValueError("Could not add any NLRI prefixes")
                    self.estabProtocol.sendMessage(bgpupdate)

    def _sendMPUpdates(self, addressfamily, withdrawals, attributeMap):
        """
        Sends (multiple) UPDATE messages the RFC4760 way.

        Arguments:
        - addressfamily: (AFI, SAFI) tuple
        - withdrawals: a set of advertisements to withdraw
        - attributeMap: a dict of FrozenAttributeDict to updates sets
        """

        afi, safi = addressfamily

        # Construct MPUnreachNLRI for withdrawals and send them

        withdrawalPrefixSet = {w.prefix for w in withdrawals}

        while len(withdrawalPrefixSet) > 0:
            bgpupdate = BGPUpdateMessage()
            unreachAttr = MPUnreachNLRIAttribute((afi, safi, []))

            prefixesAdded = unreachAttr.addSomePrefixes(
                prefixSet=withdrawalPrefixSet,
                maxLen=bgpupdate.freeSpace())
            if prefixesAdded == 0:
                raise ValueError("Could not add any prefixes to MPUnreachNLRI attribute")
            bgpupdate.addAttributes(FrozenAttributeDict([unreachAttr]))
            self.estabProtocol.sendMessage(bgpupdate)

        # Move NLRI into MPReachNLRI attributes and send them

        for attributes, advertisements in attributeMap.iteritems():
            newAttributes = AttributeDict(attributes)   # Shallow copy
            # Filter existing MPReachNLRIAttribute from the existing map
            try:
                origReachAttr = newAttributes.pop(MPReachNLRIAttribute)
            except KeyError:
                raise ValueError("Missing MPReachNLRIAttribute")

            adPrefixSet = {ad.prefix for ad in advertisements}
            while len(adPrefixSet) > 0:
                bgpupdate = BGPUpdateMessage()
                # We need to add the complete set of attributes besides
                # MPReachNLRI to every packet.
                try:
                    bgpupdate.addAttributes(newAttributes)
                except ValueError:
                    # Too many attributes to fit an empty packet. That's a
                    # problem we can't solve.
                    raise
                else:
                    # FIXME: MPReachNLRIAttribute.fromTuple(origReachAttr.tuple()) doesn't work
                    # as tuple() returns a decoded tuple, not an encoded tuple. Attribute classes
                    # overload self.value for both.
                    reachAttr = MPReachNLRIAttribute(value=origReachAttr.tuple()[2])
                    prefixesAdded = reachAttr.addSomePrefixes(
                        adPrefixSet, maxLen=bgpupdate.freeSpace())
                    if prefixesAdded == 0:
                        raise ValueError("Could not add any prefixes to MPReachNLRI attribute")
                    bgpupdate.addAttributes(FrozenAttributeDict([reachAttr]))
                    self.estabProtocol.sendMessage(bgpupdate)
