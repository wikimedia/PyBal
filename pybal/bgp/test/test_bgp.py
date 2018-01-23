# -*- coding: utf-8 -*-
"""
  bgp.bgp unit tests
  ~~~~~~~~~~~~~~~~~~

  This module contains tests for `bgp.bgp`.

"""

from .. import ip, bgp, exceptions, attributes

import unittest, mock, struct

from twisted.test import proto_helpers
from twisted.python.failure import Failure
from twisted.internet import task
from twisted.internet.error import ConnectionLost
from twisted.internet.address import IPv4Address, IPv6Address

class BGPUpdateMessageTestCase(unittest.TestCase):
    attrs = attributes.FrozenAttributeDict(
                [attributes.OriginAttribute(),
                attributes.ASPathAttribute([64600, 64601]),
                attributes.NextHopAttribute("192.0.2.1"),
                attributes.MEDAttribute(100)])

    def setUp(self):
        self.msg = bgp.BGPUpdateMessage()
        self.assertEqual(self.msg.msgLenOffset, 16)
        self.assertEqual(len(self.msg.msg), 4)
        self.assertEqual(len(self.msg), 23)
        self.assertIn("UPDATE", repr(self.msg))

    def testAddSomeWithdrawals(self):
        self.assertEqual(self.msg.addSomeWithdrawals(set()), 0)

        prefixset = set([ip.IPv4IP('127.0.0.1'),])
        self.assertEqual(self.msg.addSomeWithdrawals(prefixset), 1)

        # The prefix should have been removed from the set
        self.assertEqual(len(prefixset), 0)

        prefixset = set([ ip.IPv4IP(idx) for idx in range(1024) ])
        # Not all prefixes will fit within maxLen
        self.assertEqual(self.msg.addSomeWithdrawals(prefixset), 813)
        self.assertEqual(len(prefixset), 211)

    def testAttributes(self):
        self.msg.addAttributes(attributes.FrozenAttributeDict({}))
        self.assertEqual(len(self.msg), 23)
        self.msg.addAttributes(self.attrs)
        self.assertEqual(len(self.msg), 50)
        self.msg.clearAttributes()
        self.assertEqual(len(self.msg), 23)

        prefixset = set([ ip.IPv4IP(idx) for idx in range(810) ])
        self.assertEqual(self.msg.addSomeWithdrawals(prefixset), 810)
        self.assertRaises(ValueError, self.msg.addAttributes, self.attrs)

    def testAddSomeNLRI(self):
        self.assertEqual(self.msg.addSomeNLRI(set()), 0)

        prefixset = set([ip.IPv6IP('::1'),])
        self.assertEqual(self.msg.addSomeNLRI(prefixset), 1)

        # The prefix should have been removed from the set
        self.assertEqual(len(prefixset), 0)

        prefixset = set([ ip.IPv6IP(hex(idx)) for idx in range(1024) ])
        # Not all prefixes will fit within maxLen
        self.assertEqual(self.msg.addSomeNLRI(prefixset), 238)
        self.assertEqual(len(prefixset), 1024-238)

    def testFreeSpace(self):
        self.assertEqual(self.msg.freeSpace(), bgp.MAX_LEN-len(self.msg))

class BGPTestCase(unittest.TestCase):
    MSG_DATA_OPEN = (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' +
                     b'\x00+\x01\x04\xfcX\x00\xb4\x7f\x7f\x7f\x7f\x0e\x02\x0c\x01\x04' +
                     b'\x00\x01\x00\x01\x01\x04\x00\x02\x00\x01')

    def setUp(self):
        self.factory = bgp.BGPPeering(myASN=64600, peerAddr='127.0.0.1')
        # FIXME: Should configure this in a better way in bgp.FSM
        self.factory.fsm.allowAutomaticStart = False

        # FIXME: Make Factory param
        af = [(bgp.AFI_INET, bgp.SAFI_UNICAST), (bgp.AFI_INET6, bgp.SAFI_UNICAST)]
        self.factory.setEnabledAddressFamilies(af)
        # FIXME: make Factory param
        self.factory.bgpId = ip.IPv4IP('127.127.127.127').ipToInt()

        self.proto = self.factory.buildProtocol(IPv4Address('TCP', '127.0.0.1', 0))
        self.proto.fsm.allowAutomaticStart = False
        self.tr = proto_helpers.StringTransportWithDisconnection()
        self.tr.protocol = self.proto
        self.assertRaises(AttributeError, self.proto.makeConnection, self.tr)

    def tearDown(self):
        # The BGPPeering factory keeps its own separate FSM
        for fsm in [self.factory.fsm, self.proto.fsm]:
            for timer in (fsm.connectRetryTimer, fsm.holdTimer, fsm.keepAliveTimer,
                          fsm.delayOpenTimer, fsm.idleHoldTimer):
                timer.cancel()

    def testConnectionLost(self):
        failure = Failure(ConnectionLost("Unit test"))

        with mock.patch.object(self.proto.fsm, 'connectionFailed') as mock_method:
            self.proto.connectionLost(failure)
            mock_method.assert_called()

            mock_method.reset_mock()
            self.proto.disconnected = True
            self.proto.connectionLost(failure)
            mock_method.assert_not_called()

    def testDataReceived(self):
        d = b"Unit testing data"
        self.proto.dataReceived(d)
        self.assertIn(d, self.proto.receiveBuffer)

    def testCloseConnection(self):
        with mock.patch.object(self.proto.fsm, 'connectionFailed') as mock_method:
            self.tr.connected = True
            self.proto.closeConnection()
            self.assertTrue(self.proto.disconnected)
            self.assertTrue(self.tr.disconnecting or not self.tr.connected)
            mock_method.assert_called()

    def testSendOpen(self):
        self.proto.sendOpen()
        self.assertEqual(self.tr.value(), self.MSG_DATA_OPEN)

    def testSendUpdate(self):
        withdrawals = [ip.IPPrefix('192.168.99.0/24')]
        nlri = [ip.IPPrefix('172.24.0.0/17')]

        self.proto.sendUpdate(withdrawals, BGPUpdateMessageTestCase.attrs, nlri)
        self.assertEqual(self.tr.value()[:19],
            b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' +
            b'\x00:\x02')
        self.assertEqual(len(self.tr.value()), 58)
        # TODO: test prefix & attribute fields, cross test against BGPUpdateMessage

    def testSendKeepAlive(self):
        self.proto.sendKeepAlive()
        self.assertEqual(self.tr.value(),
            b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x13\x04')

    def testSendNotification(self):
        self.proto.sendNotification(
            bgp.ERR_MSG_UPDATE,
            bgp.ERR_MSG_UPDATE_MALFORMED_ASPATH,
            "Arbitrary data")
        self.assertEqual(self.tr.value(),
            b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' +
            b'\x00#\x03\x03\x0bArbitrary data')

    def testParseOpen(self):
        # parseOpen rejects our own bgpId in MSG_DATA_OPEN,
        # replace with some other IP
        msgdata = bytearray(self.MSG_DATA_OPEN[bgp.HDR_LEN:])
        bgpId = ip.IPv4IP('1.2.3.4').ipToInt()
        struct.pack_into('!I', msgdata, 5, bgpId)

        # Verify whether parseOpen returns the correct Open parameters
        t = self.proto.parseOpen(str(msgdata))
        self.assertEqual(t, (bgp.VERSION, self.factory.myASN, self.proto.fsm.holdTime, bgpId))

        # Verify whether a truncated message raises BadMessageLength
        self.assertRaises(exceptions.BadMessageLength, self.proto.parseOpen, str(msgdata[:3]))

        with mock.patch.object(self.proto.fsm, 'openMessageError') as mock_method:
            # Verify whether any BGP version other than bgp.VERSION (4) raises
            # ERR_MSG_OPEN_UNSUP_VERSION
            msgdata[0] = 66
            self.proto.parseOpen(str(msgdata))
            mock_method.assert_called_with(bgp.ERR_MSG_OPEN_UNSUP_VERSION, chr(bgp.VERSION))
            msgdata[0] = bgp.VERSION
            mock_method.reset_mock()

            # Verify whether invalid ASN 0 raises ERR_MSG_OPEN_BAD_PEER_AS
            msgdata[1:3] = [0, 0]
            self.proto.parseOpen(str(msgdata))
            mock_method.assert_called_with(bgp.ERR_MSG_OPEN_BAD_PEER_AS)
            mock_method.reset_mock()
            msgdata[1:3] = [2, 3]

            # Verify whether invalid BGP id 0 raises ERR_MSG_OPEN_BAD_BGP_ID
            msgdata[5:9] = [0]*4
            self.proto.parseOpen(str(msgdata))
            mock_method.assert_called_with(bgp.ERR_MSG_OPEN_BAD_BGP_ID)
            mock_method.reset_mock()

            # MSG_DATA_OPEN is constructed using our own bgpId,
            # Verify parseOpen rejects it
            self.proto.parseOpen(self.MSG_DATA_OPEN[bgp.HDR_LEN:])
            mock_method.assert_called_with(bgp.ERR_MSG_OPEN_BAD_BGP_ID)

    def testParseUpdate(self):
        # Test empty UPDATE
        update = bgp.BGPUpdateMessage()
        self.assertEqual(self.proto.parseUpdate(bytes(update)[bgp.HDR_LEN:]), ([], [], []))

        # Add withdrawals
        withdrawals = [ip.IPPrefix("192.168.{0}.0/24".format(i)) for i in range(100)]
        update.addSomeWithdrawals(set(withdrawals))
        r = self.proto.parseUpdate(bytes(update)[bgp.HDR_LEN:])
        self.assertListEqual(sorted(r[0]), withdrawals)
        self.assertEqual(r[1:], ([], []))

        # Add some attributes
        update.addAttributes(BGPUpdateMessageTestCase.attrs)
        r = self.proto.parseUpdate(bytes(update)[bgp.HDR_LEN:])
        self.assertListEqual(sorted(r[0]), withdrawals)
        self.assertEqual(len(r[1]), len(BGPUpdateMessageTestCase.attrs))
        self.assertEqual(r[2:], ([], ))

        # ...and some NLRI
        nlri = [ip.IPPrefix("10.{0}.3.0/24".format(i)) for i in range(100)]
        update.addSomeNLRI(set(nlri))
        r = self.proto.parseUpdate(bytes(update)[bgp.HDR_LEN:])
        self.assertListEqual(sorted(r[0]), withdrawals)
        self.assertEqual(len(r[1]), len(BGPUpdateMessageTestCase.attrs))
        self.assertListEqual(sorted(r[2]), nlri)

        # Test a malformed message
        # FIXME: Test for specific struct.unpack exception
        # FIXME: fix parseUpdate string slicing code to catch truncated message
        msgdata = bytearray(bytes(update)[bgp.HDR_LEN:])
        msgdata[0] += 66
        self.assertRaises(Exception, self.proto.parseUpdate, msgdata)

    def testParseKeepAlive(self):
        self.assertRaises(exceptions.BadMessageLength, self.proto.parseKeepAlive, b' ')

    def testParseNotification(self):
        # Verify whether a valid NOTIFICATION parses correctly
        msg = (struct.pack('!BB', bgp.ERR_MSG_UPDATE,
            bgp.ERR_MSG_UPDATE_MALFORMED_ASPATH) + b"Unit test")
        self.assertEqual(self.proto.parseNotification(msg),
            (bgp.ERR_MSG_UPDATE, bgp.ERR_MSG_UPDATE_MALFORMED_ASPATH, b"Unit test"))
        # Verify a truncated message raises BadMessageLength
        self.assertRaises(exceptions.BadMessageLength, self.proto.parseNotification, b' ')

class NaiveBGPPeeringTestCase(unittest.TestCase):

    def setUp(self):
        self.peering = bgp.NaiveBGPPeering(myASN=64600, peerAddr='10.0.0.1')
        self.peering.addressFamilies = set([(1, 1), (2, 1)])
        self.peering.fsm.state = bgp.ST_ESTABLISHED

        proto = bgp.BGP()
        proto.transport = proto_helpers.StringTransportWithDisconnection()
        self.peering.estabProtocol = proto

        self.peering.toAdvertise = {(1, 1): set([]),
                                    (2, 1): set([])}

        med = attributes.MEDAttribute(50)
        aspath = attributes.ASPathAttribute([(2, [64496])])
        origin = attributes.OriginAttribute((0))

        self.attrs = {
            attributes.MEDAttribute: med,
            attributes.ASPathAttribute: aspath,
            attributes.OriginAttribute: origin,
        }

    def testSetV4Advertisements(self):
        nexthop = attributes.NextHopAttribute('10.192.16.139')

        self.attrs[attributes.NextHopAttribute] = nexthop

        adv_v4 = bgp.Advertisement(prefix=ip.IPv4IP('10.2.1.18'),
                                   attributes=self.attrs,
                                   addressfamily=(1, 1))

        self.peering.advertised = { (1, 1): set([ adv_v4 ]),
                                    (2, 1): set([]) }

        self.peering.setAdvertisements(set())

    def testSetV6Advertisements(self):
        nlri = attributes.MPReachNLRIAttribute((bgp.AFI_INET6, bgp.SAFI_UNICAST,
            ip.IPv6IP('2620:0:860:101:10:192:1:3'), []))

        self.attrs[attributes.MPReachNLRIAttribute] = nlri

        adv_v6 = bgp.Advertisement(prefix=ip.IPv6IP('2620:0:860:ed1a:0:0:0:1'),
                                   attributes=self.attrs,
                                   addressfamily=(2, 1))

        self.peering.advertised = { (1, 1): set([]),
                                    (2, 1): set([ adv_v6 ]) }

        self.peering.setAdvertisements(set())


class BGPOpenParserTestCase(unittest.TestCase):

    MSG_OPEN = (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' +
                b'\xff\xff\xff\xff\xff\xff\x00\x2d\x01\x04\xff\x14\x00\xb4\x04\x04' +
                b'\x04\x04\x10\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02' +
                b'\x02\x02\x00')
    MSG_OPEN_VERSION = 4
    MSG_OPEN_PEER_ASN = 65300
    MSG_OPEN_HOLD_TIME = 180
    MSG_OPEN_BGP_ID = ip.IPv4IP('4.4.4.4').ipToInt()
    def setUp(self):
        self.bgp = bgp.BGP()
        self.bgp.bgpPeering = bgp.BGPPeering(myASN=65300, peerAddr='4.4.4.4')
        self.bgp.openReceived = mock.MagicMock()

    def testParseOpen(self):
        self.bgp.receiveBuffer = BGPOpenParserTestCase.MSG_OPEN
        self.assertTrue(self.bgp.parseBuffer())
        self.bgp.openReceived.assert_called_with(BGPOpenParserTestCase.MSG_OPEN_VERSION,
                                                 BGPOpenParserTestCase.MSG_OPEN_PEER_ASN,
                                                 BGPOpenParserTestCase.MSG_OPEN_HOLD_TIME,
                                                 BGPOpenParserTestCase.MSG_OPEN_BGP_ID)


class BGPKeepAliveParserTestCase(unittest.TestCase):
    MSG_KEEPALIVE = (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' +
                     b'\xff\xff\xff\xff\xff\xff\x00\x13\x04')
    MSG_BOGUS_KEEPALIVE = (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' +
                           b'\xff\xff\xff\xff\xff\xfe\x00\x13\x04')
    def setUp(self):
        self.bgp = bgp.BGP()
        self.bgp.keepAliveReceived = mock.MagicMock()
        self.bgp.fsm = mock.MagicMock()
        self.bgp.fsm.headerError = mock.MagicMock()

    def testParseKeepAlive(self):
        self.bgp.receiveBuffer = BGPKeepAliveParserTestCase.MSG_KEEPALIVE
        self.assertTrue(self.bgp.parseBuffer())
        self.bgp.keepAliveReceived.assert_called()

    def testParseBogusKeepAlive(self):
        self.bgp.receiveBuffer = BGPKeepAliveParserTestCase.MSG_BOGUS_KEEPALIVE
        self.assertTrue(self.bgp.parseBuffer())
        self.bgp.fsm.headerError.assert_called_with(bgp.ERR_MSG_HDR_CONN_NOT_SYNC)


class BGPUpdateParserTestCase(unittest.TestCase):
    MSG_UPDATE = (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' +
                  b'\xff\xff\xff\xff\xff\xff\x00\x3f\x02\x00\x00\x00\x1c\x40\x01\x01' +
                  b'\x00\x40\x02\x00\x40\x03\x04\x03\x03\x03\x03\x80\x04\x04\x00\x00' +
                  b'\x00\x00\x40\x05\x04\x00\x00\x00\x64\x18\x0a\x1e\x03\x18\x0a\x1e' +
                  b'\x02\x18\x0a\x1e\x01')

    MSG_UPDATE_WITHDRAWN_PREFIXES = []
    MSG_UPDATE_ATTRIBUTES = [
        attributes.BaseOriginAttribute(value='\x00').tuple(),
        (64, 2, ''),  #  attributes.BaseASPathAttribute(value='').tuple()
        (64, 3, '\x03\x03\x03\x03'),  # attributes.NextHopAttribute(value='3.3.3.3').tuple(),
        attributes.BaseMEDAttribute(value='\x00\x00\x00\x00').tuple(),
        (64, 5, '\x00\x00\x00d') # attributes.BaseLocalPrefAttribute(value=100).tuple()
    ]
    MSG_UPDATE_NLRI = [ip.IPPrefix('10.30.3.0/24'), ip.IPPrefix('10.30.2.0/24'),
                       ip.IPPrefix('10.30.1.0/24')]

    def setUp(self):
        self.bgp = bgp.BGP()
        self.bgp.updateReceived = mock.MagicMock()

    def testParseUpdate(self):
        self.bgp.receiveBuffer = BGPUpdateParserTestCase.MSG_UPDATE
        self.assertTrue(self.bgp.parseBuffer())
        self.bgp.updateReceived.assert_called_with(
            BGPUpdateParserTestCase.MSG_UPDATE_WITHDRAWN_PREFIXES,
            BGPUpdateParserTestCase.MSG_UPDATE_ATTRIBUTES,
            BGPUpdateParserTestCase.MSG_UPDATE_NLRI)


class BGPNotificationParserTestCase(unittest.TestCase):
    MSG_NOTIFICATION = (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' +
                        b'\xff\xff\xff\xff\xff\xff\x00\x17\x03\x02\x02\xfe\xb0')
    MSG_NOTIFICATION_MAJOR_ERROR = bgp.ERR_MSG_OPEN
    MSG_NOTIFICATION_MINOR_ERROR = bgp.ERR_MSG_OPEN_BAD_PEER_AS
    MSG_NOTIFICATION_ERROR_VALUE = struct.pack('!H', 65200)

    def setUp(self):
        self.bgp = bgp.BGP()
        self.bgp.notificationReceived = mock.MagicMock()

    def testParseNotification(self):
        self.bgp.receiveBuffer = BGPNotificationParserTestCase.MSG_NOTIFICATION
        self.assertTrue(self.bgp.parseBuffer())
        self.bgp.notificationReceived.assert_called_with(
            BGPNotificationParserTestCase.MSG_NOTIFICATION_MAJOR_ERROR,
            BGPNotificationParserTestCase.MSG_NOTIFICATION_MINOR_ERROR,
            BGPNotificationParserTestCase.MSG_NOTIFICATION_ERROR_VALUE
        )


class BGPNonSupportedMsgParserTestCase(unittest.TestCase):
    MSG_ROUTE_REFRESH = (b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' +
                         b'\xff\xff\xff\xff\xff\xff\x00\x17\x05\x00\x01\x00\x01')

    def setUp(self):
        self.bgp = bgp.BGP()
        self.bgp.fsm = mock.MagicMock()
        self.bgp.fsm.headerError = mock.MagicMock()

    def testParseRouteRefresh(self):
        self.bgp.receiveBuffer = BGPNonSupportedMsgParserTestCase.MSG_ROUTE_REFRESH
        self.assertTrue(self.bgp.parseBuffer())
        self.bgp.fsm.headerError.assert_called_with(bgp.ERR_MSG_HDR_BAD_MSG_TYPE, chr(5))


class BGPTimerTestCase(unittest.TestCase):
    def setUp(self):
        self.reactor_patcher = mock.patch('pybal.bgp.bgp.reactor', new_callable=task.Clock)
        self.reactor = self.reactor_patcher.start()

    def tearDown(self):
        self.reactor_patcher.stop()

    def testTriggeredTimer(self):
        called_function = mock.MagicMock()
        timer = bgp.FSM.BGPTimer(called_function)
        self.assertFalse(timer.active())
        timer.reset(bgp.FSM.largeHoldTime)
        self.assertTrue(timer.active())
        self.reactor.advance(bgp.FSM.largeHoldTime)
        called_function.assert_called_once()

    def testCancelledTimer(self):
        called_function = mock.MagicMock()
        timer = bgp.FSM.BGPTimer(called_function)
        timer.reset(bgp.FSM.largeHoldTime)
        self.reactor.advance(bgp.FSM.largeHoldTime-1)
        self.assertTrue(timer.active())
        timer.cancel()
        self.assertFalse(timer.active())
        self.reactor.advance(2)
        called_function.assert_not_called()

class BGPUniqueLoggingTestCase(unittest.TestCase):
    def testLogImplementations(self):
        classes = ['BGP', 'FSM', 'BGPFactory']
        for c in classes:
            logger_patch = mock.patch('pybal.bgp.bgp._log')
            logger = logger_patch.start()

            class_ = getattr(bgp, c)
            instanceA = class_()
            instanceB = class_()

            instanceA.log("MSG")
            instanceB.log("MSG")

            self.assertNotEquals(logger.mock_calls[-1],
                                 logger.mock_calls[-2])

            logger_patch.stop()
