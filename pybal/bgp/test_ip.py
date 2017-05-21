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

    def testPrefixInt(self):
        prefix = ip.IPv4IP(2130706433)
        self.assertEquals(prefix.prefixlen, 32)
        self.assertEquals(str(prefix), '127.0.0.1')

    def testPrefixOctets(self):
        prefix = ip.IPv4IP((0x7f, 0x0, 0x0, 0x1))
        self.assertEquals(prefix.prefixlen, 32)
        self.assertEquals(str(prefix), '127.0.0.1')

class IPv6IPTestCase(TestCase):

    def testOK(self):
        prefix = ip.IPv6IP('2620:0:862:ed1a::1')

        self.assertEquals(prefix.addressfamily, ip.AFI_INET6)
        self.assertEquals(prefix.prefixlen, 128)

    def testValueError(self):
        with self.assertRaises(ValueError):
            ip.IPv6IP()
