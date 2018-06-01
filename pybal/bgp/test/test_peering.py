# -*- coding: utf-8 -*-
"""
  bgp.peering unit tests
  ~~~~~~~~~~~~~~~~~~~~~~

  This module contains tests for `bgp.peering`.
"""

# Python imports
import unittest, mock

# Twisted imports
from twisted.internet.address import IPv4Address
from twisted.python import failure
import twisted.internet.base
import twisted.internet.error
import twisted.test.proto_helpers

# BGP imports
from ..bgp import BGP, BGPUpdateMessage
from ..bgp import BGPFactory, BGPServerFactory, BGPPeering
from ..constants import *
from .. import fsm, exceptions, bgp, attributes, ip


class BGPFactoryTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(BGPFactoryTestCase, self).__init__(*args, **kwargs)
        self.testASN = 64600
        self.testAddr = IPv4Address('TCP', '127.0.0.2', PORT)

    def setUp(self):
        self.factory = BGPFactory()
        self.factory.reactor = twisted.test.proto_helpers.MemoryReactorClock()
        self.factory.protocol = BGP
        self.factory.myASN = 64600

        # Mock factory.log for less noisy output
        self._log_patcher = mock.patch.object(bgp.BGPFactory, 'log')
        self._log_patcher.start()

    def tearDown(self):
        self._log_patcher.stop()

    def testBuildProtocol(self):
        p = self.factory.buildProtocol(self.testAddr)
        self.assertIsInstance(p, self.factory.protocol)


class BGPServerFactoryTestCase(BGPFactoryTestCase):
    def setUp(self):
        self.testPeers = {
            '127.0.0.2': mock.Mock(spec=BGPPeering)
        }
        self.factory = BGPServerFactory(self.testPeers, self.testASN)
        self.factory.reactor = twisted.test.proto_helpers.MemoryReactorClock()

        self._log_patcher = mock.patch.object(bgp.BGPFactory, 'log')
        self._log_patcher.start()

    def testBuildProtocol(self):
        mock_peer = self.testPeers[self.testAddr.host]
        mock_peer.takeServerConnection.return_value = mock.sentinel.peering
        p = self.factory.buildProtocol(self.testAddr)
        mock_peer.takeServerConnection.assert_called_with(self.testAddr)
        self.assertIs(p, mock.sentinel.peering)

    def testBuildProtocolUnknownPeer(self):
        """
        Tests whether the incoming connection gets rejected for unknown peers
        """

        unknownAddr = IPv4Address('TCP', '127.0.0.99', PORT)
        p = self.factory.buildProtocol(unknownAddr)
        self.assertIsNone(p)


class BGPPeeringTestCase(BGPFactoryTestCase):
    def setUp(self):
        self.factory = BGPPeering(self.testASN, peerAddr='127.0.0.2')
        self.factory.reactor = twisted.test.proto_helpers.MemoryReactorClock()

        # Mock factory.log and fsm.FSM.log for less noisy output
        self.factory.log = mock.Mock()
        self._log_patcher = mock.patch.object(fsm.FSM, 'log')
        self._log_patcher.start()

        # Assume ACTIVE state for most tests as IDLE does very little
        self.factory.fsm.state = fsm.ST_ACTIVE

    def testInit(self):
        self.assertEqual(self.factory.myASN, self.testASN)
        self.assertEqual(self.factory.peerAddr, '127.0.0.2')
        self.assertIsNone(self.factory.peerId)
        self.assertFalse(self.factory.passiveStart)
        self.assertIsInstance(self.factory.fsm, BGPFactory.FSM)
        self.assertTrue(self.factory.addressFamilies)   # Not empty
        self.assertEqual(self.factory.inConnections, [])
        self.assertEqual(self.factory.outConnections, [])
        self.assertIsNone(self.factory.estabProtocol)
        self.assertIsInstance(self.factory.consumers, set)

    def testInitPassiveStart(self):
        factory = BGPPeering(self.testASN, peerAddr='127.0.0.2', passiveStart=True)
        self.assertTrue(factory.passiveStart)

    def testBuildProtocol(self):
        with mock.patch.object(self.factory, '_initProtocol') as mock_initProtocol:
            p = self.factory.buildProtocol(self.testAddr)
        self.assertIsInstance(p, self.factory.protocol)
        mock_initProtocol.assert_called_with(p, self.testAddr)
        self.assertIn(p, self.factory.outConnections)

    def testTakeServerConnection(self):
        self.testAddr.port = 10001
        p = self.factory.takeServerConnection(self.testAddr)
        self.assertIsInstance(p, self.factory.protocol)
        self.assertIn(p, self.factory.inConnections)
        self.assertIs(p.bgpPeering, self.factory)

    def testInitProtocol(self):
        testProtocol = BGPFactory.buildProtocol(self.factory, self.testAddr)
        origFSM = self.factory.fsm
        origState = origFSM.state

        self.factory._initProtocol(testProtocol, self.testAddr)

        self.assertIs(testProtocol.bgpPeering, self.factory)
        # Test FSM handover
        self.assertIs(testProtocol.fsm, origFSM)
        self.assertIs(origFSM.protocol, testProtocol)
        self.assertIsInstance(self.factory.fsm, BGPFactory.FSM)
        self.assertEqual(self.factory.fsm.state, origState)

    def testInitProtocolCallback(self):
        testProtocol = BGPFactory.buildProtocol(self.factory, self.testAddr)
        with mock.patch.object(self.factory, 'sessionEstablished') as mock_sE:
            self.factory._initProtocol(testProtocol, self.testAddr)
            testProtocol.deferred.callback(True)
        mock_sE.assert_called()

    def testInitProtocolErrback(self):
        testProtocol = BGPFactory.buildProtocol(self.factory, self.testAddr)
        with mock.patch.object(self.factory, 'protocolError') as mock_pE:
            self.factory._initProtocol(testProtocol, self.testAddr)
            testProtocol.deferred.errback(failure.Failure(Exception("Testing errback")))
        mock_pE.assert_called()

    def testClientConnectionFailed(self):
        testConnector = mock.Mock(spec=twisted.internet.base.BaseConnector)
        testFailure = failure.Failure(
            twisted.internet.error.ConnectionClosed("Testing connection failure"))
        with mock.patch.object(self.factory, 'fsm') as mock_fsm:
            self.factory.clientConnectionFailed(testConnector, testFailure)
        mock_fsm.connectionFailed.assert_called_once()

    def testManualStart(self):
        self.assertFalse(self.factory.passiveStart)
        with mock.patch.object(self.factory, 'fsm') as mock_fsm:
            self.factory.manualStart()
        mock_fsm.manualStart.assert_called_once()
        mock_fsm.manualStartPassive.assert_not_called()

    def testManualStartPassive(self):
        self.factory.passiveStart = True
        with mock.patch.object(self.factory, 'fsm') as mock_fsm:
            self.factory.manualStart()
        mock_fsm.manualStartPassive.assert_called_once()
        mock_fsm.manualStart.assert_not_called()

    def testManualStop(self):
        testProtocol = self.factory.buildProtocol(self.testAddr)
        allConnections = self.factory.inConnections + self.factory.outConnections
        # Mock each connection's FSM
        for c in allConnections:
            c.fsm = mock.Mock(spec=fsm.FSM)
        self.assertTrue(allConnections)

        deferred = self.factory.manualStop()

        def testAllStopped(result, testCase, allConnections):
            for c in allConnections:
                c.fsm.manualStop.assert_called_once()

        return deferred.addCallback(testAllStopped, self, allConnections)

    def testAutomaticStart(self):
        self.assertFalse(self.factory.passiveStart)
        with mock.patch.object(self.factory, 'fsm') as mock_fsm:
            self.factory.automaticStart()
        mock_fsm.automaticStart.assert_called_once()
        mock_fsm.automaticStartPassive.assert_not_called()

    def testAutomaticStartPassive(self):
        self.factory.passiveStart = True
        with mock.patch.object(self.factory, 'fsm') as mock_fsm:
            self.factory.automaticStart()
        mock_fsm.automaticStartPassive.assert_called_once()
        mock_fsm.automaticStart.assert_not_called()

    def testConnectionClosed(self):
        self.factory.fsm.allowAutomaticStart = True
        testProtocol = self.factory.buildProtocol(self.testAddr)
        testProtocol.isOutgoing = mock.Mock(return_value=True)
        self.assertIn(testProtocol, self.factory.outConnections)
        self.factory.estabProtocol = testProtocol

        with mock.patch.object(self.factory, 'automaticStart') as mock_automaticStart:
            self.factory.connectionClosed(testProtocol)
        mock_automaticStart.assert_called_once_with(idleHold=True)
        self.assertNotIn(testProtocol, self.factory.outConnections)
        self.assertIsNone(self.factory.estabProtocol)

    def testSessionEstablished(self):
        testProtocol = self.factory.buildProtocol(self.testAddr)
        testProtocol.fsm = mock.Mock(spec=fsm.FSM)
        testProtocol.fsm.state = fsm.ST_ESTABLISHED
        origDeferred = testProtocol.deferred

        # Create another protocol for collision dumping test
        otherProtocol = self.factory.takeServerConnection(self.testAddr)
        otherProtocol.fsm = mock.Mock(spec=fsm.FSM)

        with mock.patch.multiple(self.factory,
                                 sendAdvertisements=mock.DEFAULT,
                                 protocolError=mock.DEFAULT
                                ) as mocks:
            testProtocol.deferred.callback(testProtocol)    # Calls sessionEstablished
        self.assertIs(self.factory.estabProtocol, testProtocol)
        self.assertIs(self.factory.fsm, testProtocol.fsm)
        self.assertIsNot(testProtocol.deferred, origDeferred)
        self.assertFalse(testProtocol.deferred.called)   # New deferred?

        # Verify collision dump was performed
        testProtocol.fsm.openCollisionDump.assert_not_called()
        otherProtocol.fsm.openCollisionDump.assert_called_once()

        mocks['sendAdvertisements'].assert_called_once()

        # Test deferred errback
        f = failure.Failure(Exception("Testing errback"))
        testProtocol.deferred.errback(f)
        mocks['protocolError'].assert_called_with(f)

    def testConnectRetryEvent(self):
        with mock.patch.object(self.factory, 'connect') as mock_connect:
            self.factory.connectRetryEvent(mock.Mock(spec=BGP))
        mock_connect.assert_called_once()

    # FIXME: protocolError code seems odd
    def testProtocolErrorNotificationSent(self):
        testFailure = failure.Failure(
            exceptions.NotificationSent(
                None,
                bgp.ERR_MSG_UPDATE,
                bgp.ERR_MSG_UPDATE_ATTR_FLAGS))
        try:
            self.factory.protocolError(testFailure)
        except exceptions.NotificationSent as e:
            # Should have been trapped...
            self.fail("Exception {} should have been trapped".format(e))

    def testProtocolErrorOtherException(self):
        testFailure = failure.Failure(Exception("Any other exception"))
        with self.assertRaises((failure.Failure, testFailure.type)):
            self.factory.protocolError(testFailure)

    def testSetPeerId(self):
        self.factory.setPeerId(666)
        self.assertEqual(self.factory.peerId, 666)

        # Test schizophrenia
        testProtocol = self.factory.buildProtocol(self.testAddr)
        testProtocol.fsm = mock.Mock(spec=fsm.FSM)
        otherProtocol = self.factory.takeServerConnection(self.testAddr)
        otherProtocol.fsm = mock.Mock(spec=fsm.FSM)
        otherProtocol.fsm.openCollisionDump.side_effect = exceptions.NotificationSent(
            None,
            bgp.ERR_MSG_OPEN,
            bgp.ERR_MSG_OPEN_BAD_BGP_ID
        )

        self.factory.setPeerId(667)
        testProtocol.fsm.openCollisionDump.assert_called()
        otherProtocol.fsm.openCollisionDump.assert_called()
        self.assertTrue(otherProtocol.deferred.called)  # Fired errback?
        self.assertIsNone(self.factory.peerId)

    def testCollisionDetect(self):
        requestingProtocol = self.factory.buildProtocol(self.testAddr)
        requestingProtocol.fsm = mock.Mock(spec=fsm.FSM)

        # First, without other connections there can be no collision
        self.assertFalse(self.factory.collisionDetect(requestingProtocol))
        requestingProtocol.fsm.openCollisionDump.assert_not_called()

        # Create 2 other protocols to test collisions with
        outgoingConnection = self.factory.buildProtocol(self.testAddr)
        incomingConnection = self.factory.takeServerConnection(self.testAddr)
        otherProtocols = {outgoingConnection, incomingConnection}
        for p in otherProtocols:
            p.fsm = mock.Mock(spec=fsm.FSM)

        def reset_mocks():
            requestingProtocol.fsm.reset_mock()
            for p in otherProtocols:
                p.fsm.reset_mock()

        # The other protocols are IDLE, so won't collide
        self.assertFalse(self.factory.collisionDetect(requestingProtocol))
        requestingProtocol.fsm.openCollisionDump.assert_not_called()

        # Set an arbitrary other protocol to ESTABLISHED, the rest OPENCONFIRM
        estabProtocol = next(iter(otherProtocols))
        estabProtocol.fsm.state = fsm.ST_ESTABLISHED

        # The established protocol should win.
        self.assertTrue(self.factory.collisionDetect(requestingProtocol))
        requestingProtocol.fsm.openCollisionDump.assert_called_once()
        estabProtocol.fsm.openCollisionDump.assert_not_called()

        # Set all other protocols to state OPENCONFIRM, and a high BGP id
        for p in otherProtocols:
            p.fsm.state = fsm.ST_OPENCONFIRM
        self.factory.setPeerId(200)

        # Set a lower BGP id than the peers
        self.factory.bgpId = 100

        reset_mocks()

        # Peer's initiating connection should win
        self.assertTrue(self.factory.collisionDetect(requestingProtocol))
        requestingProtocol.fsm.openCollisionDump.assert_called_once()
        incomingConnection.fsm.openCollisionDump.assert_not_called()

        reset_mocks()

        self.assertFalse(self.factory.collisionDetect(incomingConnection))
        incomingConnection.fsm.openCollisionDump.assert_not_called()
        requestingProtocol.fsm.openCollisionDump.assert_called_once()
        outgoingConnection.fsm.openCollisionDump.assert_called_once()

        reset_mocks()

        # Swap sides. Our initiating connection should win.
        self.factory.bgpId = 300
        self.assertFalse(self.factory.collisionDetect(requestingProtocol))
        requestingProtocol.fsm.openCollisionDump.assert_not_called()
        incomingConnection.fsm.openCollisionDump.assert_called_once()

    def testConnect(self):
        b = self.factory.connect()
        self.assertTrue(b)
        self.assertTrue(self.factory.reactor.tcpClients)
        clientTuple = (self.factory.peerAddr, bgp.PORT, self.factory)
        self.assertEqual(self.factory.reactor.tcpClients[0][:len(clientTuple)], clientTuple)

        self.factory.reactor.tcpClients = []

        self.factory.fsm.state = fsm.ST_ESTABLISHED
        b = self.factory.connect()
        self.assertFalse(b)
        self.assertFalse(self.factory.reactor.tcpClients)

    def testRegisterUnregisterConsumer(self):
        consumer = mock.Mock()
        self.factory.registerConsumer(consumer)
        consumer.registerProducer.assert_called_with(self.factory, streaming=True)
        self.assertIn(consumer, self.factory.consumers)

        self.factory.unregisterConsumer(consumer)
        consumer.unregisterProducer.assert_called()
        self.assertNotIn(consumer, self.factory.consumers)

    def testUpdate(self):
        # Register 3 consumers
        for i in range(3):
            self.factory.registerConsumer(mock.Mock())

        # Test whether the same update is written to all consumers
        self.factory.update(mock.sentinel.update_message)
        for consumer in self.factory.consumers:
            consumer.write.assert_called_with(mock.sentinel.update_message)

    def testSendAdvertisements(self):
        self.factory.sendAdvertisements()

    def testSetEnabledAddressFamilies(self):
        af = {
            (AFI_INET, SAFI_UNICAST),
            (AFI_INET, SAFI_MULTICAST),
            (AFI_INET6, SAFI_UNICAST),
            (AFI_INET6, SAFI_MULTICAST)
        }
        self.factory.setEnabledAddressFamilies(af)

        # Test with unknown AF
        af.add((66, SAFI_UNICAST))
        with self.assertRaises(ValueError):
            self.factory.setEnabledAddressFamilies(af)


class PeeringSessionToOpenSentTestCase(unittest.TestCase):
    """
    Base class with shared code for PeeringClientSessionToOpenSentTestCase
    and PeeringServerSessionToOpenSentTestCase
    """

    def assertState(self, *states):
        self.assertIn(self.fsm.state, states,
            "State is {} instead of expected {}".format(
                bgp.stateDescr[self.fsm.state],
                "|".join([bgp.stateDescr[state] for state in states])))

    def setUp(self):
        self.myASN = 64601
        self.peerAddr =  IPv4Address('TCP', '127.0.0.1', PORT)
        self.enabledAddressFamilies = {(AFI_INET, SAFI_UNICAST)}

    def tearDown(self):
        # The BGPPeering factory keeps its own separate FSM
        for fsm in [self.peering.fsm, self.protocol.fsm]:
            for timer in (fsm.connectRetryTimer, fsm.holdTimer, fsm.keepAliveTimer,
                          fsm.delayOpenTimer, fsm.idleHoldTimer):
                timer.cancel()

    def _setupPeering(self):
        self.peering = BGPPeering(myASN=self.myASN, peerAddr=self.peerAddr.host)
        self.peering.reactor = twisted.test.proto_helpers.MemoryReactorClock()
        self.peering.setEnabledAddressFamilies(self.enabledAddressFamilies)

        # Mock logging for less noisy output
        self.peering.log = mock.Mock()
        self.peering.fsm.log = mock.Mock()

    def _setupTransport(self):
        self.transport = twisted.test.proto_helpers.StringTransport(peerAddress=self.peerAddr)
        self.transport.setTcpNoDelay = mock.Mock()

    def _testSession(self):
        self._setupPeering()

        # There's no protocol yet, track BGPPeering's FSM
        self.fsm = self.peering.fsm

        self.assertState(fsm.ST_IDLE)

        self._startSession()

        # A connection has been made. Call buildProtocol
        self._setupProtocol()

        self.assertProtocolInitialized()

        # peering.fsm has been replaced, start tracking the protocol's FSM
        # instead
        self.fsm = self.protocol.fsm

        # Create a test transport
        self._setupTransport()

        # Connect the transport to the protocol
        # It will call protocol.connectionMade() to start the protocol

        self.protocol.makeConnection(self.transport)

        self.assertState(fsm.ST_OPENSENT)
        self.assertIsNotNone(self.peering.bgpId)

        # Read the OPEN data that has been sent

        openData = self.transport.value()
        self.assertGreaterEqual(len(openData), 16)
        self.transport.clear()


class PeeringClientSessionToOpenSentTestCase(PeeringSessionToOpenSentTestCase):
    """
    Test case that sets up a BGPPeering instance and emulates a client session
    up to state OpenSent
    """

    @mock.patch.object(fsm.FSM, 'log')
    def _setupProtocol(self, mock_log):
        # A client connection has been made. Call buildProtocol

        self.protocol = self.peering.buildProtocol(self.peerAddr)

    def _startSession(self):
        self.peering.automaticStart()

        self.assertState(fsm.ST_CONNECT)
        self.assertTrue(self.peering.reactor.tcpClients)

        # Pretend we're starting a connection

        self.peering.startedConnecting(mock.Mock())

    def assertProtocolInitialized(self):
        self.assertIn(self.protocol, self.peering.outConnections)
        self.assertState(fsm.ST_CONNECT)

    def testSession(self):
        self._testSession()


class PeeringServerSessionToOpenSentTestCase(PeeringSessionToOpenSentTestCase):
    """
    Test case that sets up a BGPPeering instance and BGPServerFactory, and
    emulates a server session up to state OpenSent
    """

    def setUp(self):
        super(PeeringServerSessionToOpenSentTestCase, self).setUp()
        # Set a high (client) port for peerAddr
        self.peerAddr.port = 1000 + PORT

    def _setupPeering(self):
        super(PeeringServerSessionToOpenSentTestCase, self)._setupPeering()
        # Start passively
        self.peering.passiveStart = True
        self._setupServerFactory()

    def _setupServerFactory(self):
        """
        Sets up a BGPServerFactory instance and pretend it's listening
        """

        peers = {
            self.peerAddr.host: self.peering
        }
        self.serverFactory = BGPServerFactory(peers, myASN=self.myASN)
        self.serverFactory.reactor = twisted.test.proto_helpers.MemoryReactorClock()

    def _startSession(self):
        """
        For a server session test case, starting the session consists of
        listening passively in ACTIVE state.
        """

        self.peering.automaticStart()   # may be passive start

        expectedState = fsm.ST_ACTIVE if self.peering.passiveStart else fsm.ST_CONNECT
        self.assertState(expectedState)

    @mock.patch.object(fsm.FSM, 'log')
    def _setupProtocol(self, mock_log):
        # A client connection has been made.
        # Call takeServerConnection to build a protocol

        self.protocol = self.peering.takeServerConnection(self.peerAddr)

    def assertProtocolInitialized(self):
        self.assertIn(self.protocol, self.peering.inConnections)
        self.assertState(fsm.ST_ACTIVE, fsm.ST_CONNECT)

    def testSession(self):
        self._testSession()


class NaiveBGPPeeringTestCase(unittest.TestCase):

    def setUp(self):
        self.peering = bgp.NaiveBGPPeering(myASN=64600, peerAddr='10.0.0.1')
        self.peering.setEnabledAddressFamilies({
            (AFI_INET, SAFI_UNICAST),
            (AFI_INET6, SAFI_UNICAST)})
        self.peering.fsm.state = fsm.ST_ESTABLISHED

        proto = bgp.BGP()
        proto.transport = twisted.test.proto_helpers.StringTransportWithDisconnection()
        self.peering.estabProtocol = proto

        self.peering.setAdvertisements(set())

        med = attributes.MEDAttribute(50)
        aspath = attributes.ASPathAttribute([(2, [64496])])
        origin = attributes.OriginAttribute((0))

        self.attrs = attributes.AttributeDict({med, aspath, origin})

        self.emptyAFs = {
            (AFI_INET, SAFI_UNICAST): set(),
            (AFI_INET6, SAFI_UNICAST): set()
        }

    @mock.patch.object(BGPPeering, 'completeInit')
    def testCompleteInit(self, mock_completeInit):
        self.peering.completeInit(self.peering.estabProtocol)

        mock_completeInit.assert_called_with(self.peering, self.peering.estabProtocol)
        self.assertFalse(self.peering.advertised)

    def testSendAdvertisements(self):
        with mock.patch.object(self.peering, '_sendUpdates') as mock_sendUpdates:
            self.peering.sendAdvertisements()
        # Test whether existing advertisements are withdrawn, outstanding
        # advertisements are announced
        mock_sendUpdates.assert_called_with(
            self.peering.advertised, self.peering.toAdvertise)

    def testSetAdvertisements(self):
        self.assertEqual(self.peering.toAdvertise, self.emptyAFs)

    def testSetV4Advertisements(self):
        nexthop = attributes.NextHopAttribute('10.192.16.139')

        self.attrs[attributes.NextHopAttribute] = nexthop

        adv_v4 = bgp.Advertisement(
            prefix=ip.IPv4IP('10.2.1.18'),
            attributes=attributes.FrozenAttributeDict(self.attrs),
            addressfamily=(AFI_INET, SAFI_UNICAST))

        self.peering.setAdvertisements({ adv_v4 })

        self.assertEqual(self.peering.toAdvertise, {
            (AFI_INET, SAFI_UNICAST): { adv_v4 },
            (AFI_INET6, SAFI_UNICAST): set()
        })
        self.assertEqual(self.peering.advertised, self.peering.toAdvertise)

        self.peering.setAdvertisements(set())

        self.assertEqual(self.peering.advertised, self.emptyAFs)
        self.assertEqual(self.peering.advertised, self.peering.toAdvertise)

    def testSetV6Advertisements(self):
        nlri = attributes.MPReachNLRIAttribute((AFI_INET6, SAFI_UNICAST,
            ip.IPv6IP('2620:0:860:101:10:192:1:3'), []))

        self.attrs[attributes.MPReachNLRIAttribute] = nlri

        adv_v6 = bgp.Advertisement(
            prefix=ip.IPv6IP('2620:0:860:ed1a:0:0:0:1'),
            attributes=attributes.FrozenAttributeDict(self.attrs),
            addressfamily=(AFI_INET6, SAFI_UNICAST))

        self.peering.setAdvertisements({ adv_v6 })

        self.assertEqual(self.peering.toAdvertise, {
            (AFI_INET, SAFI_UNICAST): set(),
            (AFI_INET6, SAFI_UNICAST): { adv_v6 }
        })
        self.assertEqual(self.peering.advertised, self.peering.toAdvertise)

        self.peering.setAdvertisements(set())

        self.assertEqual(self.peering.toAdvertise, self.emptyAFs)
        self.assertEqual(self.peering.advertised, self.peering.toAdvertise)


class NaiveConstructAndSendTestCase(unittest.TestCase):

    def setUp(self):
        # Mock factory.log for less noisy output
        self._log_patcher = mock.patch.object(bgp.BGPFactory, 'log')
        self._log_patcher.start()

        self.peering = bgp.NaiveBGPPeering(myASN=64600, peerAddr='10.0.0.1')
        self.peering.setEnabledAddressFamilies({
            (AFI_INET, SAFI_UNICAST),
            (AFI_INET6, SAFI_UNICAST)})

        proto = bgp.BGP()
        proto.transport = twisted.test.proto_helpers.StringTransportWithDisconnection()
        self.peering.estabProtocol = proto

        med = attributes.MEDAttribute(50)
        aspath = attributes.ASPathAttribute([(2, [64496])])
        origin = attributes.OriginAttribute((0))

        self.attrs = attributes.AttributeDict({med, aspath, origin})

    def tearDown(self):
        self._log_patcher.stop()

    def _createAdvertisements(self, count=1, attrs=None):
        """
        Returns a set with count IPv4 prefix advertisements, along with
        mandatory attributes
        """

        frozenAttributes = attributes.FrozenAttributeDict(
            attrs if attrs is not None else self.attrs)
        return {
            bgp.Advertisement(
                prefix=prefix,
                attributes=frozenAttributes,
                addressfamily=self.addressFamily
            )
            for prefix in self._generatePrefixes(count) }

    def _createAttributeMap(self, advertisements, attrs=None):
        return {
            attributes.FrozenAttributeDict(attrs or self.attrs): advertisements
        }

@mock.patch.object(BGP, 'sendMessage')
class NaiveInetConstructAndSendTestCase(NaiveConstructAndSendTestCase):

    addressFamily = (AFI_INET, SAFI_UNICAST)

    @staticmethod
    def _generatePrefixes(count=1):
        for i in range(count):
            yield ip.IPPrefix( (i, 32), addressfamily=ip.AFI_INET )

    @unittest.skip("Bug: withdrawals handling is broken")
    def test_FewWithdrawals_NoUpdates(self, mock_sendMessage):
        """
        Tests Inet Unicast sending, 10 withdrawals and no updates.
        This should fit in a single UPDATE message.
        """

        withdrawals = self._createAdvertisements(count=10)
        attributeMap = {}
        self.peering._sendInetUnicastUpdates(withdrawals, attributeMap)

        mock_sendMessage.assert_called_once()   # A single message

        # Test constructed BGP update field lengths
        bgpupdate = mock_sendMessage.call_args[0][0]
        self.assertEqual(len(bgpupdate[1]), 52)
        self.assertEqual(len(bgpupdate[2]), 2)
        self.assertEqual(len(bgpupdate[3]), 0)

    @unittest.skip("Bug: withdrawals handling is broken")
    def test_ManyWithdrawals_NoUpdates(self, mock_sendMessage):
        """
        Tests Inet Unicast sending, 2000 withdrawals and no updates.
        This should fit in 3 UPDATE messages.
        """

        withdrawals = self._createAdvertisements(count=2000)
        attributeMap = {}
        self.peering._sendInetUnicastUpdates(withdrawals, attributeMap)

        # Should fit in 3 messages
        self.assertEqual(mock_sendMessage.call_count, 3)

        # Test constructed BGP updates field lengths
        bgpupdates = [args[0] for args, kwargs in mock_sendMessage.call_args_list]
        self.assertEqual(len(bgpupdates[0][1]), 4072)   # first packet full
        self.assertEqual(len(bgpupdates[0][2]), 2)
        self.assertEqual(len(bgpupdates[0][3]), 0)

        self.assertEqual(len(bgpupdates[1][1]), 4072)   # second packet full
        self.assertEqual(len(bgpupdates[1][2]), 2)
        self.assertEqual(len(bgpupdates[1][3]), 0)

        self.assertEqual(len(bgpupdates[2][1]), 1862)   # third packet half full
        self.assertEqual(len(bgpupdates[2][2]), 2)
        self.assertEqual(len(bgpupdates[2][3]), 0)

    @unittest.skip("Bug: withdrawals handling is broken")
    def test_FewWithdrawals_FewUpdates_SingleMessage(self, mock_sendMessage):
        """
        Tests Inet Unicast sending, 10 withdrawals and 20 updates.
        This should fit in a single update message.
        """

        withdrawals = self._createAdvertisements(count=10)
        advertisements = self._createAdvertisements(count=20)
        attributeMap = self._createAttributeMap(advertisements)
        self.peering._sendInetUnicastUpdates(withdrawals, attributeMap)

        mock_sendMessage.assert_called_once()   # A single message

        # Test constructed BGP update field lengths
        bgpupdate = mock_sendMessage.call_args[0][0]
        self.assertEqual(len(bgpupdate[1]), 52)
        self.assertEqual(len(bgpupdate[2]), 20)
        self.assertEqual(len(bgpupdate[3]), 100)

    @unittest.skip("Bug: withdrawals handling is broken")
    def test_ManyWithdrawals_FewUpdates_TwoMessages(self, mock_sendMessage):
        """
        Tests Inet Unicast sending, enough withdrawals to just fill a single
        message. Subsequent updates (with their attributes) won't fit and
        should be sent in a 2nd message.
        """

        withdrawals = self._createAdvertisements(count=814)
        advertisements = self._createAdvertisements(count=10)
        attributeMap = self._createAttributeMap(advertisements)
        self.peering._sendInetUnicastUpdates(withdrawals, attributeMap)

        self.assertEqual(mock_sendMessage.call_count, 2)

        # Test constructed BGP updates field lengths
        bgpupdates = [args[0] for args, kwargs in mock_sendMessage.call_args_list]
        self.assertEqual(len(bgpupdates[0][1]), 4072)   # first packet withdrawals
        self.assertEqual(len(bgpupdates[0][2]), 2)
        self.assertEqual(len(bgpupdates[0][3]), 0)

        self.assertEqual(len(bgpupdates[1][1]), 2)      # second packet, just updates
        self.assertEqual(len(bgpupdates[1][2]), 20)
        self.assertEqual(len(bgpupdates[1][3]), 50)

    def test_NoWithdrawals_FewUpdates(self, mock_sendMessage):
        """
        Tests Inet Unicast sending, with no withdrawals and a few updates
        which fit in a single message.
        """

        advertisements = self._createAdvertisements(count=20)
        attributeMap = self._createAttributeMap(advertisements)
        self.peering._sendInetUnicastUpdates(set(), attributeMap)

        mock_sendMessage.assert_called_once()

        # Test constructed BGP update field lengths
        bgpupdate = mock_sendMessage.call_args[0][0]
        self.assertEqual(len(bgpupdate[1]), 2)
        self.assertEqual(len(bgpupdate[2]), 20)
        self.assertEqual(len(bgpupdate[3]), 100)

    @unittest.skip("Bug: withdrawals handling is broken")
    def test_ManyWithdrawals_ManyUpdates(self, mock_sendMessage):
        """
        Tests Inet Unicast sending, enough withdrawals and updates to fill
        multiple messages each.
        """

        withdrawals = self._createAdvertisements(count=1000)
        advertisements = self._createAdvertisements(count=1200)
        attributeMap = self._createAttributeMap(advertisements)
        self.peering._sendInetUnicastUpdates(withdrawals, attributeMap)

        self.assertEqual(mock_sendMessage.call_count, 3)

        # Test constructed BGP updates field lengths
        bgpupdates = [args[0] for args, kwargs in mock_sendMessage.call_args_list]
        self.assertEqual(len(bgpupdates[0][1]), 4072)   # 1st packet withdrawals
        self.assertEqual(len(bgpupdates[0][2]), 2)
        self.assertEqual(len(bgpupdates[0][3]), 0)

        self.assertEqual(len(bgpupdates[1][1]), 932)    # 2nd packet, some withdrawals
        self.assertEqual(len(bgpupdates[1][2]), 20)
        self.assertEqual(len(bgpupdates[1][3]), 3125)   # updates fill the rest

        self.assertEqual(len(bgpupdates[2][1]), 2)      # 3rd packet, no withdrawals
        self.assertEqual(len(bgpupdates[2][2]), 20)
        self.assertEqual(len(bgpupdates[2][3]), 2875)   # some updates

@mock.patch.object(BGP, 'sendMessage')
class NaiveInet6ConstructAndSendTestCase(NaiveConstructAndSendTestCase):

    addressFamily = (AFI_INET, SAFI_UNICAST)

    def setUp(self):
        super(NaiveInet6ConstructAndSendTestCase, self).setUp()

        # Add a template MPReachNLRI with a sample nexthop and
        self.attrs[attributes.MPReachNLRIAttribute] = attributes.MPReachNLRIAttribute(
            (AFI_INET, AFI_INET6, ip.IPv6IP("::1"), [])
        )

    @staticmethod
    def _generatePrefixes(count=1):
        for i in range(count):
            yield ip.IPPrefix(([i >> o for o in range(120, -8, -8)], 128),
                              addressfamily=ip.AFI_INET6 )

    def test_FewWithdrawals_NoUpdates(self, mock_sendMessage):
        """
        Tests Inet6 Unicast sending, 10 withdrawals and no updates.
        This should fit in a single UPDATE message.
        """

        withdrawals = self._createAdvertisements(count=10, attrs={})
        attributeMap = {}
        self.peering._sendMPUpdates((AFI_INET6, SAFI_UNICAST), withdrawals, attributeMap)

        mock_sendMessage.assert_called_once()   # A single message

        # Test constructed BGP update field lengths
        bgpupdate = mock_sendMessage.call_args[0][0]
        self.assertEqual(len(bgpupdate[1]), 2)      # No IPv4 withdrawals
        self.assertEqual(len(bgpupdate[2]), 179)    # MPUnreach attributes
        self.assertEqual(len(bgpupdate[3]), 0)      # No IPv4 updates

    def test_FewWithdrawals_FewUpdates(self, mock_sendMessage):
        """
        Tests Inet Unicast sending, 10 withdrawals and 20 updates.
        This should fit in a single update message.
        """

        withdrawals = self._createAdvertisements(count=10, attrs={})
        advertisements = self._createAdvertisements(count=20)
        attributeMap = self._createAttributeMap(advertisements)
        self.peering._sendMPUpdates((AFI_INET6, SAFI_UNICAST), withdrawals, attributeMap)

        self.assertEqual(mock_sendMessage.call_count, 2)

        # Test constructed BGP updates field lengths
        bgpupdates = [args[0] for args, kwargs in mock_sendMessage.call_args_list]
        self.assertEqual(len(bgpupdates[0][1]), 2)      # No IPv4 withdrawals
        self.assertEqual(len(bgpupdates[0][2]), 179)    # MPUnreach attributes
        self.assertEqual(len(bgpupdates[0][3]), 0)      # No IPv4 updates

        self.assertEqual(len(bgpupdates[1][1]), 2)      # No IPv4 withdrawals
        self.assertEqual(len(bgpupdates[1][2]), 385)    # MPReach attributes
        self.assertEqual(len(bgpupdates[1][3]), 0)      # No IPv4 updates

    def test_FewUpdates_MPReachNLRIAttributeMissing(self, mock_sendMessage):
        """
        sendMPUpdates needs a template MPReachNLRI attribute for nexthop info
        Test whether it raises an exception if it's missing
        """

        del self.attrs[attributes.MPReachNLRIAttribute]

        advertisements = self._createAdvertisements(count=20)
        attributeMap = self._createAttributeMap(advertisements)
        with self.assertRaises(ValueError):
            self.peering._sendMPUpdates((AFI_INET6, SAFI_UNICAST), {}, attributeMap)
