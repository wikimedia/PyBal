# peering.py

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


# Python imports
import logging

# Zope imports
from zope.interface import implements, Interface

# Twisted imports
from twisted.internet import protocol, interfaces, defer
import twisted.internet.reactor

# BGP imports
from constants import *
from attributes import AttributeDict, FrozenAttributeDict
from attributes import MPReachNLRIAttribute, MPUnreachNLRIAttribute
from exceptions import BGPException, NotificationSent
from bgp import BGP, BGPUpdateMessage
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

    def __init__(self, myASN=None, peerAddr=None, **kwargs):
        self.myASN = myASN
        self.peerAddr = peerAddr
        self.peerId = None
        self.passiveStart = kwargs.get('passiveStart', False)
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

    def buildProtocol(self, peerAddr):
        """Builds a BGP protocol instance for an outgoing connection"""

        self.log("Building a new BGP protocol instance")

        p = BGPFactory.buildProtocol(self, peerAddr)
        if p is not None:
            self._initProtocol(p, peerAddr)
            self.outConnections.append(p)

        return p

    def takeServerConnection(self, peerAddr):
        """Builds a BGP protocol instance for a server connection"""

        # Ask the FSM if this connection should be accepted in this state
        if not self.fsm.tcpConnectionValid():
            # We're not taking connections in IDLE state
            return None

        p = BGPFactory.buildProtocol(self, peerAddr)
        if p is not None:
            self._initProtocol(p, peerAddr)
            self.inConnections.append(p)

        return p

    def _initProtocol(self, protocol, peerAddr):
        """Initializes a BGPProtocol instance"""

        protocol.bgpPeering = self

        # Hand over the FSM
        protocol.fsm = self.fsm
        protocol.fsm.protocol = protocol

        # Create a new fsm for internal use for now
        self.fsm = BGPFactory.FSM(self)
        self.fsm.state = protocol.fsm.state

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
        """BGP ManualStart event (event 1 or 4)"""

        if self.passiveStart:
            self.fsm.manualStartPassive()
        else:
            self.fsm.manualStart()

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
        """BGP AutomaticStart event (event 3 or 5)"""

        if self.passiveStart:
            self.fsm.automaticStartPassive()
        else:
            self.fsm.automaticStart(idleHold)

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

        # If attributeMap is empty, i.e there are no UPDATEs,
        # create an entry with no attributes to be used for withdrawals only
        if not attributeMap:
            attributeMap[FrozenAttributeDict([])] = set()

        withdrawalPrefixSet = {w.prefix for w in withdrawals}

        for attributes, advertisements in attributeMap.iteritems():
            adPrefixSet = {ad.prefix for ad in advertisements}

            bgpupdate = BGPUpdateMessage()
            # Start with withdrawals, if there are any
            while withdrawalPrefixSet:
                prefixesAdded = bgpupdate.addSomeWithdrawals(withdrawalPrefixSet)
                if prefixesAdded == 0:
                    raise ValueError("Could not add any withdrawals")
                if withdrawalPrefixSet:
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
            while adPrefixSet:
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

        assert not withdrawalPrefixSet

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
