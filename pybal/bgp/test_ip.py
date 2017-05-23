# -*- coding: utf-8 -*-
"""
  bgp.ip unit tests
  ~~~~~~~~~~~~~~~~~

  This module contains tests for `bgp.ip`.

"""
import ip

from unittest import TestCase


class IPv4IPTestCase(TestCase):

    def testPrefixStr(self):
        prefix = ip.IPv4IP('91.198.174.192')

        self.assertEquals(prefix.addressfamily, ip.AFI_INET)
        self.assertEquals(prefix.prefixlen, 32)
        self.assertEquals(len(prefix), 32)

    def testPrefixInt(self):
        prefix = ip.IPv4IP(2130706433)
        self.assertEquals(prefix.prefixlen, 32)
        self.assertEquals(len(prefix), 32)
        self.assertEquals(str(prefix), '127.0.0.1')

    def testPrefixOctets(self):
        prefix = ip.IPv4IP((0x7f, 0x0, 0x0, 0x1))
        self.assertEquals(prefix.prefixlen, 32)
        self.assertEquals(len(prefix), 32)
        self.assertEquals(str(prefix), '127.0.0.1')

    def testComparisons(self):
        p1, p2 = ip.IPv4IP('127.0.0.1'), ip.IPv4IP('127.0.0.2')
        self.assertNotEqual(p1, p2)
        self.assertLess(p1, p2)
        self.assertEquals(p1, ip.IPv4IP(2130706433))
        self.assertLessEqual(p1, p2)
        self.assertLessEqual(p1, ip.IPv4IP(2130706433))
        self.assertNotEqual(hash(p1), hash(p2))

    def testIPToInt(self):
        prefix = ip.IPv4IP('127.0.0.1')
        self.assertEquals(prefix.ipToInt(), 2130706433)

    def testNetmask(self):
        prefix = ip.IPv4IP('127.0.0.1')
        self.assertEquals(prefix.netmask(), -1)

    def testPacked(self):
        prefix = ip.IPv4IP('127.0.0.1')
        self.assertEquals(prefix.packed(pad=True), b'\x7F\0\0\x01')

class IPv6IPTestCase(TestCase):

    def testOK(self):
        prefix = ip.IPv6IP('2620:0:862:ed1a::1')

        self.assertEquals(prefix.addressfamily, ip.AFI_INET6)
        self.assertEquals(prefix.prefixlen, 128)
        self.assertEquals(len(prefix), 128)
        self.assertEquals(str(prefix), '2620:0:862:ed1a:0:0:0:1')

    def testComparisons(self):
        p1, p2 = ip.IPv6IP('fe80::1'), ip.IPv6IP('2620:0:862:ed1a::1')
        self.assertNotEqual(p1, p2)
        self.assertGreater(p1, p2)
        self.assertGreaterEqual(p1, p2)
        self.assertNotEqual(hash(p1), hash(p2))

    def testPacked(self):
        self.assertEquals(ip.IPv6IP('2620:0:862:ed1a::1').packed(pad=True),
            b'\x26\x20\0\0\x08\x62\xed\x1a\0\0\0\0\0\0\0\x01')

    def testValueError(self):
        with self.assertRaises(ValueError):
            ip.IPv6IP()

class IPPrefixTestCase(TestCase):

    def testPrefixStr(self):
        prefix = ip.IPPrefix('91.198.174.192/32')

        self.assertEquals(prefix.addressfamily, ip.AFI_INET)
        self.assertEquals(prefix.prefixlen, 32)
        self.assertEquals(len(prefix), 32)
        self.assertEquals(prefix, ip.IPv4IP('91.198.174.192'))
        self.assertEquals(str(prefix), '91.198.174.192/32')

        prefix = ip.IPPrefix('192.168.1.2/24')
        self.assertEquals(len(prefix), 24)
        prefix.mask(len(prefix))
        self.assertEquals(prefix, ip.IPPrefix('192.168.1.0/24'))

        prefix = ip.IPPrefix('2620:0:863::/46')
        self.assertEquals(len(prefix), 46)
        self.assertEquals(str(prefix), '2620:0:863:0:0:0:0:0/46')

    def testPrefixUnicode(self):
        prefix = ip.IPPrefix(u'192.168.1.2/24')
        self.assertEquals(len(prefix), 24)
        prefix.mask(len(prefix))
        self.assertEquals(prefix, ip.IPPrefix('192.168.1.0/24'))

    def testIPUnicode(self):
        prefix = ip.IPv4IP(u'192.168.1.2')
        self.assertEquals(len(prefix), 32)
        prefix.mask(len(prefix))

    def testComparisons(self):
        p1, p2 = ip.IPPrefix('1.2.3.4/8'), ip.IPPrefix('1.2.3.4/16')
        self.assertNotEqual(p1, p2)
        self.assertLess(p1, p2)
        self.assertLessEqual(p1, p2)
        self.assertNotEqual(hash(p1), hash(p2))
