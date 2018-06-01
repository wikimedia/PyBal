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

# Twisted imports
from twisted import copyright
from twisted.internet import protocol, defer

# BGP imports
from constants import *
from attributes import Attribute, MPReachNLRIAttribute, MPUnreachNLRIAttribute
from attributes import AttributeDict
from attributes import ATTR_EXTENDED_LEN
from exceptions import BGPException, NotificationSent, BadMessageLength, AttributeException
from ip import IPv4IP, IPPrefix

# Pybal imports :-(
from pybal.util import _log


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
