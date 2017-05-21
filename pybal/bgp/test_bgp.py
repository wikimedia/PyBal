# -*- coding: utf-8 -*-
"""
  bgp.bgp unit tests
  ~~~~~~~~~~~~~~~~~~

  This module contains tests for `bgp.bgp`.

"""

import ip
import bgp

import unittest


class AttributeTestCase(unittest.TestCase):

    def testOriginAttribute(self):
        attr = bgp.OriginAttribute()
        self.assertFalse(attr.optional)
        self.assertTrue(attr.transitive)
        self.assertEquals(attr.value, attr.ORIGIN_IGP)

    def testBaseASPathAttribute(self):
        attr = bgp.BaseASPathAttribute()
        self.assertEquals(attr.value, [(2, [])])

class BGPUpdateMessageTestCase(unittest.TestCase):

    def setUp(self):
        self.msg = bgp.BGPUpdateMessage()
        self.assertEquals(self.msg.msgLenOffset, 16)
        self.assertEquals(len(self.msg.msg), 4)

    def testAddSomeWithdrawals(self):
        self.assertEquals(self.msg.addSomeWithdrawals(set()), 0)

        prefixset = set([ip.IPv4IP('127.0.0.1'),])
        self.assertEquals(self.msg.addSomeWithdrawals(prefixset), 1)

        # The prefix should have been removed from the set
        self.assertEquals(len(prefixset), 0)

        prefixset = set([ ip.IPv4IP(idx) for idx in range(1024) ])
        # Not all prefixes will fit within maxLen
        self.assertEquals(self.msg.addSomeWithdrawals(prefixset), 813)
        self.assertEquals(len(prefixset), 211)
