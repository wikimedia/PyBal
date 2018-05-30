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
from ..bgp import BGP
from ..bgp import BGPFactory, BGPServerFactory, BGPPeering
from .. import constants, fsm, exceptions, bgp


class BGPFactoryTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(BGPFactoryTestCase, self).__init__(*args, **kwargs)
        self.testASN = 64600
        self.testAddr = IPv4Address('TCP', '127.0.0.2', constants.PORT)

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

        unknownAddr = IPv4Address('TCP', '127.0.0.99', constants.PORT)
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
            (constants.AFI_INET, constants.SAFI_UNICAST),
            (constants.AFI_INET, constants.SAFI_MULTICAST),
            (constants.AFI_INET6, constants.SAFI_UNICAST),
            (constants.AFI_INET6, constants.SAFI_MULTICAST)
        }
        self.factory.setEnabledAddressFamilies(af)

        # Test with unknown AF
        af.add((66, constants.SAFI_UNICAST))
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
        self.peerAddr =  IPv4Address('TCP', '127.0.0.1', constants.PORT)
        self.enabledAddressFamilies = {(constants.AFI_INET, constants.SAFI_UNICAST)}

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
        self.peerAddr.port = 1000 + constants.PORT

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
