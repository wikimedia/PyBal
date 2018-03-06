# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.bgpfailover`.

"""

import pybal.bgpfailover
import pybal.util

from pybal.bgp import bgp

from twisted.internet.error import CannotListenError

import mock
from .fixtures import PyBalTestCase

class TestBGPFailover(PyBalTestCase):
    """Test case for `pybal.ipvs.IPVSManager`."""

    def setUp(self):
        # Reset class attributes
        pybal.bgpfailover.BGPFailover.prefixes = {}
        pybal.bgpfailover.BGPFailover.ipServices = {}
        pybal.bgpfailover.BGPFailover.peerings = {}
        self.config = pybal.util.ConfigDict({
            'bgp': "yes",
            'bgp-local-asn': "64666",
            'bgp-as-path': "64666 64667",
            'bgp-peer-address': "[ \"127.255.255.255\", \"::1\" ]"
        })
        self.bgpfailover = pybal.bgpfailover.BGPFailover(self.config)

    def testConstructor(self):
        config = self.config
        bgpfailover = self.bgpfailover
        self.assertEqual(bgpfailover.globalConfig, config)

        # Test config parsing
        self.assertEqual(bgpfailover.myASN, 64666)
        self.assertListEqual(bgpfailover.asPath, [64666, 64667])

        self.assertEqual(bgpfailover.defaultMED, 0)

        config['bgp-peer-address'] = "127.255.255.255"
        bgpfailover = pybal.bgpfailover.BGPFailover(config)
        self.assertListEqual(bgpfailover.peerAddresses, ["127.255.255.255"])
        config['bgp-peer-address'] = "[ \"127.255.255.255\" ]"
        bgpfailover = pybal.bgpfailover.BGPFailover(config)
        self.assertListEqual(bgpfailover.peerAddresses, ["127.255.255.255"])
        config['bgp-peer-address'] = "[ \"127.255.255.255\", \"::1\" ]"
        bgpfailover = pybal.bgpfailover.BGPFailover(config)
        self.assertListEqual(bgpfailover.peerAddresses, ["127.255.255.255", "::1"])

        config['bgp-med'] = "10"
        bgpfailover = pybal.bgpfailover.BGPFailover(config)
        self.assertEqual(bgpfailover.defaultMED, 10)

        # Test whether missing IPv4/IPv6 nexthops are detected
        pybal.bgpfailover.BGPFailover.prefixes[(1, 1)] = None
        self.assertRaises(ValueError, pybal.bgpfailover.BGPFailover, config)
        config['bgp-nexthop-ipv4'] = "127.1.1.1"
        pybal.bgpfailover.BGPFailover.prefixes[(2, 1)] = None
        self.assertRaises(ValueError, pybal.bgpfailover.BGPFailover, config)
        config['bgp-nexthop-ipv6'] = "::1"
        pybal.bgpfailover.BGPFailover(config)

    @mock.patch('pybal.bgpfailover.reactor.listenTCP')
    @mock.patch('pybal.bgpfailover.bgp.NaiveBGPPeering')
    def testSetup(self, mock_peering, mock_listenTCP):
        # Test whether setup creates peerings
        self.bgpfailover.setup()
        mock_peering.assert_called()
        mock_listenTCP.assert_called()
        self.assertSetEqual(set(self.bgpfailover.peerings.keys()), {"127.255.255.255", "::1"})

    @mock.patch('pybal.bgpfailover.reactor.addSystemEventTrigger')
    @mock.patch('pybal.bgpfailover.bgp.NaiveBGPPeering')
    def testSetupStartException(self, mock_peering, mock_addSystemEventTrigger):
        # Test exception handling
        mock_addSystemEventTrigger.side_effect = ValueError("Mock")
        self.assertRaises(ValueError, self.bgpfailover.setup)

    @mock.patch('pybal.bgpfailover.reactor.listenTCP')
    @mock.patch('pybal.bgpfailover.bgp.NaiveBGPPeering')
    def testSetupCannotListen(self, mock_peering, mock_listenTCP):
        mock_listenTCP.side_effect = CannotListenError(None, None, "Mocked")
        self.assertRaises(CannotListenError, self.bgpfailover.setup)
        mock_peering.assert_called()

    def testSetupDisabled(self):
        # setup should do nothing if bgp is disabled
        self.config['bgp'] = 'no'
        bgpfailover = pybal.bgpfailover.BGPFailover(self.config)
        bgpfailover.setup()
        self.assertEquals(len(bgpfailover.peerings), 0)

    def testBuildAdvertisements(self):
        config = self.config
        config['bgp-nexthop-ipv4'] = "127.1.1.1"
        config['bgp-nexthop-ipv6'] = "::1"
        config['bgp-med'] = "10"
        bgpfailover = pybal.bgpfailover.BGPFailover(config)
        bgpfailover.associateService('192.168.1.1', None, med=None)
        bgpfailover.associateService('::1', None, med=20)
        # bgpfailover.prefixes = {(1, 1): {bgp.IPv4IP('192.168.1.1')},
        #                         (2, 1): {bgp.IPv6IP('fe80::1')}}
        advertisements = bgpfailover.buildAdvertisements()
        self.assertEquals(len(advertisements), 2)
        self.assertTrue(all([isinstance(ad, bgp.Advertisement) for ad in advertisements]))
        # Check whether the right prefixes are being advertised
        self.assertSetEqual(
            {ad.prefix for ad in advertisements},
            {bgp.IPv4IP('192.168.1.1'), bgp.IPv6IP('::1')})
        # Test whether the correct MEDs are present in advertisements
        self.assertSetEqual(
            {ad.attributes[bgp.MEDAttribute].value for ad in advertisements},
            {10, 20})
        # Test whether required attributes are present
        for ad in advertisements:
            # ensure the generated attributes are hashable
            for attribute in ad.attributes.itervalues():
                self.assertIsInstance(hash(attribute), int)
            if ad.addressfamily[0] == bgp.AFI_INET:
                self.assertTrue(set(ad.attributes.keys()).issuperset(
                    {bgp.OriginAttribute, bgp.ASPathAttribute, bgp.NextHopAttribute}))
            elif ad.addressfamily[0] == bgp.AFI_INET6:
                self.assertTrue(set(ad.attributes.keys()).issuperset(
                    {bgp.OriginAttribute, bgp.ASPathAttribute, bgp.MPReachNLRIAttribute}))

        bgpfailover.prefixes[(6, 66)] = bgp.IPv6IP('6:66')
        self.assertRaises(ValueError, bgpfailover.buildAdvertisements)

    def testCloseSession(self):
        mockPeering = mock.MagicMock(spec=bgp.NaiveBGPPeering)
        mockPeering.peerAddr = "127.66.66.66"
        mockPeering.setAdvertisements = mock.MagicMock()
        mockPeering.manualStop = mock.MagicMock()
        self.bgpfailover.closeSession(mockPeering)
        mockPeering.setAdvertisements.assert_called()
        mockPeering.manualStop.assert_called()

    def testAssociateService(self):
        bgpfailover = self.bgpfailover
        mockService = mock.MagicMock()

        ip = bgp.IPv4IP("1.2.3.4")
        bgpfailover.associateService('1.2.3.4', mockService, None)
        self.assertSetEqual(bgpfailover.prefixes[(1, 1)], {ip})
        self.assertEqual(bgpfailover.ipServices[ip][0]['af'], (1, 1))
        self.assertEqual(bgpfailover.ipServices[ip][0]['med'], None)

        ip = bgp.IPv6IP("1:2:3:4:5:6:7:8")
        bgpfailover.associateService('1:2:3:4:5:6:7:8', mockService, 66)
        self.assertSetEqual(bgpfailover.prefixes[(2, 1)], {ip})
        self.assertEqual(bgpfailover.ipServices[ip][0]['af'], (2, 1))
        self.assertEqual(bgpfailover.ipServices[ip][0]['med'], 66)

        ip = bgp.IPv4IP("1.2.3.4")
        bgpfailover.associateService('1.2.3.4', mockService, None)
        self.assertSetEqual(bgpfailover.prefixes[(1, 1)], {ip})
        self.assertEqual(bgpfailover.ipServices[ip][1]['af'], (1, 1))
        self.assertEqual(bgpfailover.ipServices[ip][1]['med'], None)

        # Test whether inequal MED fails
        self.assertRaises(ValueError,
            bgpfailover.associateService, "1.2.3.4", mockService, med=99)
