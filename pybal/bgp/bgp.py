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

# System imports
import logging
import struct

# Zope imports
from zope.interface import implements, Interface

# Twisted imports
from twisted import copyright
from twisted.internet import protocol, base, interfaces, defer
import twisted.internet.reactor

# BGP imports
from constants import *
from attributes import Attribute, MPReachNLRIAttribute, MPUnreachNLRIAttribute
from attributes import AttributeDict, FrozenAttributeDict
from attributes import ATTR_EXTENDED_LEN
from exceptions import BGPException, NotificationSent, BadMessageLength, AttributeException
from ip import IPv4IP, IPv6IP, IPPrefix
from fsm import FSM

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

        # Update FSM metric labels with this connection's info
        self.fsm.metric_labels['local_ip'] = self.transport.getHost().host
        self.fsm.metric_labels['remote_ip'] = self.transport.getPeer().host
        if self.transport.getPeer().port == PORT:
            self.fsm.metric_labels['side'] = 'active'
        else:
            self.fsm.metric_labels['side'] = 'passive'

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

        self.bgpPeering.setPeerId(bgpId)

        # Perform collision detection
        if self.bgpPeering.peerId == bgpId and not self.collisionDetect():
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

    reactor = twisted.internet.reactor

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
        """
        Builds a BGPProtocol instance by finding the appropriate
        BGPPeering factory instance to hand over to.

        If incoming connection (addr) is not registered as a peers,
        returns None to indicate the connection should be closed.
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
        """Builds a BGP protocol instance for an outgoing connection"""

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
        collidingConns = {c
             for c
             in self.inConnections + self.outConnections
             if c != protocol and c.fsm.state in (ST_OPENCONFIRM, ST_ESTABLISHED)}

        # We need at least 1 other connections to have a collision
        if not collidingConns:
            return False

        # A collision exists at this point.

        # If one of the other connections is already in ESTABLISHED state,
        # it wins
        if ST_ESTABLISHED in (c.fsm.state for c in collidingConns):
            protocol.fsm.openCollisionDump()
            return True

        # Break the tie
        assert protocol.factory is self
        assert self.bgpId != self.peerId
        dumpList = self.outConnections if self.bgpId < self.peerId else self.inConnections

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
            self.reactor.connectTCP(self.peerAddr, PORT, self)
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
        Expects a set of tuples of (AF, AFI) to be enabled
        """

        for afi, safi in addressFamilies:
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
