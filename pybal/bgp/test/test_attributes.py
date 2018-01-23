# -*- coding: utf-8 -*-
"""
  bgp.attributes unit tests
  ~~~~~~~~~~~~~~~~~~~~~~~~~

  This module contains tests for `bgp.attributes`.

"""

import unittest, mock
import struct

from .. import exceptions, attributes, bgp, ip

class AttributeTestCase(unittest.TestCase):
    # Device Under Test
    DUT = None

    def setUp(self):
        if self.DUT is None:
            return

        self.attr = self.DUT(self.sampleValue)
        self.typeCode = self.DUT.typeCode

    def _encodeValue(self, value):
        """
        Encode value into the format expected for an attrTuple.
        Meant to be overridden in child test classes
        """
        return value

    def _testValue(self):
        self.assertEquals(self.attr.value, self.sampleValue)

    def _testInvalidTruncatedValue(self, truncCount=1):
        truncatedValue = self._encodeValue(self.sampleValue)[:-truncCount]
        with self.assertRaises(exceptions.AttributeException):
            self.DUT(attrTuple=(self.flags, self.typeCode, truncatedValue))

    def testConstructor(self):
        if self.DUT is None:
            return

        self.assertEquals(self.attr.type, self.DUT)
        self.assertEquals(self.attr.typeCode, self.DUT.typeCode)

        self._testFlags()
        self._testValue()

    def testConstructorFromTuple(self):
        if self.DUT is None:   # Attribute itself
            # Test creating an unknown optional Attribute
            flags = attributes.ATTR_OPTIONAL | attributes.ATTR_TRANSITIVE
            typeCode = 99
            attr = attributes.Attribute(attrTuple=(flags, typeCode, None))
            self.assertEquals(attr.typeCode, typeCode)
            self.assertTrue(attr.partial)

            # Test creating a required unknown Attribute
            with self.assertRaises(exceptions.AttributeException) as arcm:
                attributes.Attribute(attrTuple=(0, 99, None))
            self.assertEquals(arcm.exception.suberror, bgp.ERR_MSG_UPDATE_UNRECOGNIZED_WELLKNOWN_ATTR)
        else:
            # Common code for inheritors
            value = self._encodeValue(self.sampleValue)
            self.attr = self.DUT(attrTuple=(self.flags, self.typeCode, value))
            self._testFlags()
            self._testValue()

    def testConstructorFromInvalidTuple(self):
        if self.DUT is None:
            return

        value = self._encodeValue(self.sampleValue)

        # Test invalid flags
        with self.assertRaises(exceptions.AttributeException):
            self.DUT(attrTuple=(0, self.typeCode, value))

    def testEncode(self):
        if self.DUT is None or self.sampleValue is None:
            return

        # FIXME: make Attribute.encode() and Attribute.tuple() work here
        value = self._encodeValue(self.sampleValue)
        self.assertEquals(
            self.attr.encode(),
            bgp.BGP.encodeAttribute((self.flags, self.typeCode, value)))

    def testStr(self):
        if self.DUT is None:
            return

        s = str(self.attr)
        self.assertTrue(isinstance(s, str))

    @unittest.skip("Bug: exceptions.RuntimeError: maximum recursion depth exceeded")
    def testEquality(self):
        if self.DUT is None:
            return
        otherAttr = self.DUT(self.sampleValue)
        self.assertTrue(self.attr == otherAttr)
        self.assertFalse(self.attr != otherAttr)

    def testHash(self):
        if not self.DUT:
            return

        h = hash(self.attr)
        self.assertTrue(isinstance(h, int))

    def testFlagStr(self):
        if not self.DUT:
            return

        flagsStr = self.attr.flagsStr()
        self.assertTrue(isinstance(flagsStr, str))
        self.assertEquals('O' in flagsStr, self.attr.optional)
        self.assertEquals('T' in flagsStr, self.attr.transitive)
        self.assertEquals('P' in flagsStr, self.attr.partial)
        self.assertEquals('E' in flagsStr, self.attr.extendedLength)

class OriginAttributeTestCase(AttributeTestCase):
    DUT = attributes.OriginAttribute
    sampleValue = attributes.OriginAttribute.ORIGIN_EGP
    flags = attributes.ATTR_TRANSITIVE

    def _encodeValue(self, value):
        return chr(value)

    def _testFlags(self):
        self.assertFalse(self.attr.optional)
        self.assertTrue(self.attr.transitive)
        self.assertFalse(self.attr.extendedLength)

    def testConstructorFromInvalidTuple(self):
        super(OriginAttributeTestCase, self).testConstructorFromInvalidTuple()

        # Test invalid values
        self._testInvalidTruncatedValue()
        with self.assertRaises(exceptions.AttributeException):
            self.DUT(attrTuple=(self.flags, self.typeCode, "test"))
        with self.assertRaises(exceptions.AttributeException):
            self.DUT(attrTuple=(self.flags, self.typeCode, chr(99)))

class ASPathAttributeTestCase(AttributeTestCase):
    DUT = attributes.ASPathAttribute
    sampleValue = [(2, [])]
    flags = attributes.ATTR_TRANSITIVE

    def _encodeValue(self, value):
        return ASPathAttributeTestCase.encodeValueExample(value)

    def _testFlags(self):
        self.assertFalse(self.attr.optional)
        self.assertTrue(self.attr.transitive)
        self.assertFalse(self.attr.extendedLength)

    @staticmethod
    def encodeValueExample(value):
        # TODO: implement packed path encoding as a separate (static) method
        # in BaseASPathAttribute
        return "".join([
            struct.pack('!BB{}H'.format(len(asPath)), segType, len(asPath), *asPath)
            for segType, asPath
            in value])

    def testConstructorFromInvalidTuple(self):
        super(ASPathAttributeTestCase, self).testConstructorFromInvalidTuple()
        # Test invalid values
        self._testInvalidTruncatedValue()
        value = ASPathAttributeTestCase.encodeValueExample([])
        with self.assertRaises(exceptions.AttributeException):
            self.DUT(attrTuple=(self.flags, self.typeCode, value))

class NextHopAttributeTestCase(AttributeTestCase):
    DUT = attributes.NextHopAttribute
    sampleValue = "1.2.3.4"
    flags = attributes.ATTR_TRANSITIVE

    def _encodeValue(self, value):
        return ip.IPv4IP(value).packed()

    def _testFlags(self):
        self.assertFalse(self.attr.optional)
        self.assertTrue(self.attr.transitive)
        self.assertFalse(self.attr.extendedLength)

    def _testValue(self):
        # FIXME: value handling is not very consistent
        self.assertEquals(self.attr.value, ip.IPv4IP(self.sampleValue))

    def testConstructorFromInvalidTuple(self):
        super(NextHopAttributeTestCase, self).testConstructorFromInvalidTuple()
        # Test invalid values
        self._testInvalidTruncatedValue()
        # FIXME: handling of values in NextHopAttribute is rather inconsistent
        # No real point in testing that code more rather than fixing it up.

class MEDAttributeTestCase(AttributeTestCase):
    DUT = attributes.MEDAttribute
    sampleValue = 50
    flags = attributes.ATTR_OPTIONAL

    def _encodeValue(self, value):
        return struct.pack('!I', value)

    def _testFlags(self):
        self.assertTrue(self.attr.optional)
        self.assertFalse(self.attr.transitive)
        self.assertFalse(self.attr.extendedLength)

    def testConstructorFromInvalidTuple(self):
        super(MEDAttributeTestCase, self).testConstructorFromInvalidTuple()
        # Test invalid values
        self._testInvalidTruncatedValue()

class LocalPrefAttributeTestCase(AttributeTestCase):
    DUT = attributes.LocalPrefAttribute
    sampleValue = 100
    flags = attributes.ATTR_OPTIONAL

    def _encodeValue(self, value):
        return struct.pack('!I', value)

    def _testFlags(self):
        self.assertTrue(self.attr.optional)
        self.assertFalse(self.attr.transitive)
        self.assertFalse(self.attr.extendedLength)

    def testConstructorFromInvalidTuple(self):
        super(LocalPrefAttributeTestCase, self).testConstructorFromInvalidTuple()
        # Test invalid values
        self._testInvalidTruncatedValue()

class AtomicAggregateAttributeTestCase(AttributeTestCase):
    DUT = attributes.AtomicAggregateAttribute
    sampleValue = None
    flags = 0

    def _encodeValue(self, value):
        return b''

    def _testFlags(self):
        self.assertFalse(self.attr.optional)
        self.assertFalse(self.attr.extendedLength)

    def _testValue(self):
        # FIXME: handling of values by AtomicAggregate is inconsistent
        if self.attr.value == b'' and self.sampleValue is None:
            self.skipTest("Handling of values by AtomicAggregate is inconsistent")

    def testConstructorFromInvalidTuple(self):
        value = self._encodeValue(self.sampleValue)
        # Test invalid flags
        with self.assertRaises(exceptions.AttributeException):
            self.DUT(attrTuple=(attributes.ATTR_OPTIONAL, self.typeCode, value))

        # Test with a value (which should not exist)
        with self.assertRaises(exceptions.AttributeException):
            self.DUT(attrTuple=(self.flags, self.typeCode, b' '))

    def testEncode(self):
        self.assertEquals(
            self.attr.encode(),
            struct.pack('!BBB', 0, attributes.ATTR_TYPE_ATOMIC_AGGREGATE, 0))

    def testStr(self):
        pass

class AggregatorAttributeTestCase(AttributeTestCase):
    DUT = attributes.AggregatorAttribute
    sampleValue = (14907, ip.IPv4IP("1.2.3.4"))
    flags = attributes.ATTR_OPTIONAL | attributes.ATTR_TRANSITIVE

    def _encodeValue(self, value):
        return struct.pack(b'!H', value[0]) + value[1].packed()

    def _testFlags(self):
        self.assertTrue(self.attr.optional)
        self.assertTrue(self.attr.transitive)
        self.assertFalse(self.attr.extendedLength)

    def testConstructorFromInvalidTuple(self):
        super(AggregatorAttributeTestCase, self).testConstructorFromInvalidTuple()
        # Test invalid values
        self._testInvalidTruncatedValue()

class CommunityAttributeTestCase(AttributeTestCase):
    DUT = attributes.CommunityAttribute
    # Generate two communities 14907:200 and 43821:301
    sampleValue = [(14907<<16)+200, (43821<<16)+301]
    flags = attributes.ATTR_OPTIONAL | attributes.ATTR_TRANSITIVE

    def _encodeValue(self, value):
        return struct.pack(b"!{}I".format(len(value)), *value)

    def _testFlags(self):
        self.assertTrue(self.attr.optional)
        self.assertTrue(self.attr.transitive)
        self.assertFalse(self.attr.extendedLength)

    def testConstructorFromInvalidTuple(self):
        super(CommunityAttributeTestCase, self).testConstructorFromInvalidTuple()
        # Test invalid values
        self._testInvalidTruncatedValue()

class MPReachNLRIAttributeTestCase(AttributeTestCase):
    DUT = attributes.MPReachNLRIAttribute
    sampleValue = (
        bgp.AFI_INET6,
        bgp.SAFI_UNICAST,
        ip.IPv6IP(b"a:b:c:d:e:f:0:1"),
        [ip.IPv6IP(b"fe80::")])
    flags = attributes.ATTR_OPTIONAL | attributes.ATTR_EXTENDED_LEN

    def _encodeValue(self, value):
        # FIXME: duplication with MPReachNLRIAttribute.encode
        afi, safi, nexthop, nlri = value
        pnh = nexthop.packed()
        return struct.pack(
            b"!HBB{}sB".format(len(pnh)),
            afi,
            safi,
            len(pnh),
            pnh,
            0) + bgp.BGP.encodePrefixes(nlri)

    def _testFlags(self):
        self.assertTrue(self.attr.optional)
        self.assertFalse(self.attr.transitive)
        self.assertTrue(self.attr.extendedLength)

    def testConstructorFromTuple(self):
        super(MPReachNLRIAttributeTestCase, self).testConstructorFromTuple()

        # Add another prefix and create again
        self.attr.addPrefixes([ip.IPv6IP(b"fe80::1")])
        value = self._encodeValue(self.sampleValue)
        self.attr = self.DUT(attrTuple=(self.flags, self.typeCode, value))
        self._testFlags()
        self._testValue()

    # FIXME
    @unittest.skip("Bug in MPReachNLRIAttribute.initFromTuple: IPv4IP doesn't accept packed= argument ")
    def testConstructorFromTupleAFI_INET(self):
        # AFI_INET test case
        encValue = self._encodeValue((bgp.AFI_INET,
            bgp.SAFI_UNICAST,
            ip.IPv4IP(b"127.0.0.1"),
            []))
        attr = self.DUT(attrTuple=(self.flags, self.typeCode, encValue))

    def testConstructorFromInvalidTuple(self):
        super(MPReachNLRIAttributeTestCase, self).testConstructorFromInvalidTuple()
        # Test invalid values
        # Empty value
        with self.assertRaises(exceptions.AttributeException):
            self.DUT(attrTuple=(self.flags, self.typeCode, b''))
        # Invalid AFI/SAFI
        with self.assertRaises(exceptions.AttributeException):
            encValue = self._encodeValue((66, 6) + self.sampleValue[2:])
            self.DUT(attrTuple=(self.flags, self.typeCode, encValue))
        # Prefix too long
        with self.assertRaises(exceptions.AttributeException):
            with mock.patch.object(bgp.BGP, 'parseEncodedPrefixList') as mock_pEPL:
                mock_pEPL.side_effect = bgp.BGPException()
                self.DUT(attrTuple=
                    (self.flags, self.typeCode, self._encodeValue(self.sampleValue)))
        # Truncated value
        self._testInvalidTruncatedValue(20)

class MPUnreachNLRIAttributeTestCase(AttributeTestCase):
    DUT = attributes.MPUnreachNLRIAttribute
    sampleValue = (
        bgp.AFI_INET6,
        bgp.SAFI_UNICAST,
        [ip.IPv6IP(b"fe80::")])
    flags = attributes.ATTR_OPTIONAL | attributes.ATTR_EXTENDED_LEN

    def _testFlags(self):
        self.assertTrue(self.attr.optional)
        self.assertFalse(self.attr.transitive)
        self.assertTrue(self.attr.extendedLength)

    def _encodeValue(self, value):
        # FIXME: duplication with MPUnreachNLRIAttribute.encode
        afi, safi, nlri = value
        return struct.pack(b"!HB", afi, safi) + bgp.BGP.encodePrefixes(nlri)

    def testConstructorFromTuple(self):
        super(MPUnreachNLRIAttributeTestCase, self).testConstructorFromTuple()

        # Add another prefix and create again
        self.attr.addPrefixes([ip.IPv6IP(b"fe80::1")])
        value = self._encodeValue(self.sampleValue)
        self.attr = self.DUT(attrTuple=(self.flags, self.typeCode, value))
        self._testFlags()
        self._testValue()

    def testConstructorFromInvalidTuple(self):
        super(MPUnreachNLRIAttributeTestCase, self).testConstructorFromInvalidTuple()
        # Test invalid values
        # Empty value
        with self.assertRaises(exceptions.AttributeException):
            self.DUT(attrTuple=(self.flags, self.typeCode, b''))
        # Invalid AFI/SAFI
        with self.assertRaises(exceptions.AttributeException):
            encValue = self._encodeValue((66, 6) + self.sampleValue[2:])
            self.DUT(attrTuple=(self.flags, self.typeCode, encValue))
        # Prefix too long
        with self.assertRaises(exceptions.AttributeException):
            with mock.patch.object(bgp.BGP, 'parseEncodedPrefixList') as mock_pEPL:
                mock_pEPL.side_effect = bgp.BGPException()
                self.DUT(attrTuple=
                    (self.flags, self.typeCode, self._encodeValue(self.sampleValue)))
        # Truncated value
        self._testInvalidTruncatedValue(20)

class LastUpdateIntAttributeTestCase(AttributeTestCase):
    DUT = attributes.LastUpdateIntAttribute
    sampleValue = None
    flags = 0

    def _testFlags(self):
        pass

    def testConstructorFromInvalidTuple(self):
        pass


class AttributeDictTestCase(unittest.TestCase):
    def setUp(self):
        self.attributeDict = attributes.AttributeDict({})
        self.testAttributes = {
            (attributes.ATTR_OPTIONAL,              # Flags
            attributes.ATTR_TYPE_MULTI_EXIT_DISC,   # typeCode
            b'\x00\x00\x00\xA0'                     # Value
            ),

            attributes.OriginAttribute(attributes.OriginAttribute.ORIGIN_EGP)
        }

    def testConstructor(self):
        # Test constructing from another AttributeDict
        ad = attributes.AttributeDict(self.attributeDict)
        self.assertEquals(ad, self.attributeDict)

        # Test attrTuples and Attribute inheritors
        attrs = self.testAttributes
        ad = attributes.AttributeDict(attrs)
        self.assertIn(attributes.MEDAttribute, ad)
        self.assertIn(attributes.OriginAttribute, ad)

        # Other types should fail
        with self.assertRaises(exceptions.AttributeException):
            attributes.AttributeDict({"test string"})

        # Some attributes are missing
        with self.assertRaises(exceptions.AttributeException) as arcm:
            attributes.AttributeDict(attrs, checkMissing=True)
        self.assertEquals(arcm.exception.suberror, bgp.ERR_MSG_UPDATE_MISSING_WELLKNOWN_ATTR)

        # ...add them
        attrs.add(attributes.ASPathAttribute([(2, [64600])]))
        attrs.add(attributes.NextHopAttribute(b"127.0.0.1"))
        ad = attributes.AttributeDict(attrs)

    def testAdd(self):
        for attr in iter(self.testAttributes):
            if isinstance(attr, attributes.Attribute):  # Skip attrTuples
                self.assertNotIn(type(attr), self.attributeDict)
                self.attributeDict.add(attr)
                self.assertIn(type(attr), self.attributeDict)

                # Adding again should raise an exception
                with self.assertRaises(exceptions.AttributeException) as arcm:
                    self.attributeDict.add(attr)
                self.assertEquals(arcm.exception.suberror, bgp.ERR_MSG_UPDATE_MALFORMED_ATTR_LIST)

    def testStr(self):
        ad = attributes.AttributeDict(self.testAttributes)
        self.assertTrue(str(ad))
        self.assertTrue(isinstance(str(ad), str))

class FrozenAttributeDictTestCase(unittest.TestCase):
    def setUp(self):
        self.testAttributes = {
            (attributes.ATTR_OPTIONAL,              # Flags
            attributes.ATTR_TYPE_MULTI_EXIT_DISC,   # typeCode
            b'\x00\x00\x00\xA0'                     # Value
            ),

            attributes.OriginAttribute(attributes.OriginAttribute.ORIGIN_EGP)
        }
        self.frAttributeDict = attributes.FrozenAttributeDict(self.testAttributes)

    def testModifications(self):
        with self.assertRaises(Exception):
            sefl.frAttributeDict.add(attributes.OriginAttribute(attributes.OriginAttribute.ORIGIN_EGP))

    def testEq(self):
        otherFAD = attributes.FrozenAttributeDict(self.testAttributes)
        self.assertTrue(self.frAttributeDict == otherFAD)
