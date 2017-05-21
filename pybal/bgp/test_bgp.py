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
        self.assertEquals(len(self.msg), 23)
        self.assertIn("UPDATE", repr(self.msg))

        self.attrs = bgp.FrozenAttributeDict(
                    [bgp.OriginAttribute(),
                    bgp.ASPathAttribute([64600, 64601]),
                    bgp.NextHopAttribute("192.0.2.1"),
                    bgp.MEDAttribute(100)])

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

    def testAttributes(self):
        self.msg.addAttributes(bgp.FrozenAttributeDict({}))
        self.assertEqual(len(self.msg), 23)
        self.msg.addAttributes(self.attrs)
        self.assertEqual(len(self.msg), 50)
        self.msg.clearAttributes()
        self.assertEquals(len(self.msg), 23)

        prefixset = set([ ip.IPv4IP(idx) for idx in range(810) ])
        self.assertEquals(self.msg.addSomeWithdrawals(prefixset), 810)
        self.assertRaises(ValueError, self.msg.addAttributes, self.attrs)

    def testAddSomeNLRI(self):
        self.assertEquals(self.msg.addSomeNLRI(set()), 0)

        prefixset = set([ip.IPv6IP('::1'),])
        self.assertEquals(self.msg.addSomeNLRI(prefixset), 1)

        # The prefix should have been removed from the set
        self.assertEquals(len(prefixset), 0)

        prefixset = set([ ip.IPv6IP(hex(idx)) for idx in range(1024) ])
        # Not all prefixes will fit within maxLen
        self.assertEquals(self.msg.addSomeNLRI(prefixset), 238)
        self.assertEquals(len(prefixset), 1024-238)

    def testFreeSpace(self):
        self.assertEquals(self.msg.freeSpace(), bgp.MAX_LEN-len(self.msg))
