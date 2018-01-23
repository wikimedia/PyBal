# attributes.py
# Copyright (c) 2007-2018 by Mark Bergsma <mark@nedworks.org>

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


# System imports
import struct

# BGP imports
from exceptions import BGPException, AttributeException
from ip import IPv4IP, IPv6IP, IPPrefix
import bgp

# BGP attribute flags
ATTR_OPTIONAL = 1 << 7
ATTR_TRANSITIVE = 1 << 6
ATTR_PARTIAL = 1 << 5
ATTR_EXTENDED_LEN = 1 << 4

# BGP attribute types
ATTR_TYPE_ORIGIN = 1
ATTR_TYPE_AS_PATH = 2
ATTR_TYPE_NEXT_HOP = 3
ATTR_TYPE_MULTI_EXIT_DISC = 4
ATTR_TYPE_LOCAL_PREF = 5
ATTR_TYPE_ATOMIC_AGGREGATE = 6
ATTR_TYPE_AGGREGATOR = 7
ATTR_TYPE_COMMUNITY = 8

# RFC4760 attribute types
ATTR_TYPE_MP_REACH_NLRI = 14
ATTR_TYPE_MP_UNREACH_NLRI = 15

ATTR_TYPE_INT_LAST_UPDATE = 256 + 1


class Attribute(object):
    """
    Base class for all BGP attribute classes

    Attribute instances are (meant to be) immutable once initialized.
    """

    typeToClass = {}
    name = 'Attribute'
    typeCode = None

    def __init__(self, attrTuple=None):
        super(Attribute, self).__init__()

        if attrTuple is None:
            self.optional = False
            self.transitive = False
            self.partial = False
            self.extendedLength = False

            self.value = None
        else:
            flags, typeCode, value = attrTuple
            self.optional = (flags & ATTR_OPTIONAL != 0)
            self.transitive = (flags & ATTR_TRANSITIVE != 0)
            self.partial = (flags & ATTR_PARTIAL != 0)
            self.extendedLength = (flags & ATTR_EXTENDED_LEN != 0)

            self.value = value

            if typeCode not in self.typeToClass:
                if self.optional and self.transitive:
                    # Unrecognized optional, transitive attribute, set partial bit
                    self.typeCode = typeCode
                    self.partial = True
                elif not self.optional:
                    raise AttributeException(bgp.ERR_MSG_UPDATE_UNRECOGNIZED_WELLKNOWN_ATTR, attrTuple)

            self._initFromTuple(attrTuple)

        self.type = self.__class__

    def __eq__(self, other):
        return self is other or \
            (type(self) is type(other) and self.flags == other.flags and self.value == other.value)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.tuple())

    def __repr__(self):
        return repr(self.tuple())

    def __str__(self):
        return self.__repr__()

    def flagsStr(self):
        """Returns a string with characters symbolizing the flags
        set to True"""

        s = ''
        for c, f in [('O', self.optional), ('T', self.transitive),
                     ('P', self.partial), ('E', self.extendedLength)]:
            if f: s += c
        return s

    def flags(self):
        return ((self.optional and ATTR_OPTIONAL or 0)
                | (self.transitive and ATTR_TRANSITIVE or 0)
                | (self.partial and ATTR_PARTIAL or 0)
                | (self.extendedLength and ATTR_EXTENDED_LEN or 0))

    def tuple(self):
        return (self.flags(), self.typeCode, self.value)

    def _initFromTuple(self, attrTuple):
        pass

    @classmethod
    def fromTuple(cls, attrTuple):
        """Instantiates an Attribute inheritor of the right type for a
        given attribute tuple.
        """

        return cls.typeToClass.get(attrTuple[1], cls)(attrTuple=attrTuple)

    def encode(self):
        return bgp.BGP.encodeAttribute(self.flags(), self.typeCode, self.value)

class BaseOriginAttribute(Attribute):
    name = 'Origin'
    typeCode = ATTR_TYPE_ORIGIN

    ORIGIN_IGP = 0
    ORIGIN_EGP = 1
    ORIGIN_INCOMPLETE = 2

    def __init__(self, value=None, attrTuple=None):
        super(BaseOriginAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = False
            self.transitive = True
            self.value = value or self.ORIGIN_IGP

    def _initFromTuple(self, attrTuple):
        value = attrTuple[2]

        if self.optional or not self.transitive:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 1:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_LEN, attrTuple)
        if ord(value) not in (self.ORIGIN_IGP, self.ORIGIN_EGP, self.ORIGIN_INCOMPLETE):
            raise AttributeException(bgp.ERR_MSG_UPDATE_INVALID_ORIGIN, attrTuple)

        self.value = ord(value)

    def encode(self):
        return struct.pack('!BBBB', self.flags(), self.typeCode, 1, self.value)

class OriginAttribute(BaseOriginAttribute): pass

class BaseASPathAttribute(Attribute):
    name = 'AS Path'
    typeCode = ATTR_TYPE_AS_PATH

    def __init__(self, value=None, attrTuple=None):
        super(BaseASPathAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = False
            self.transitive = True

            if value and type(value) is list and reduce(lambda r,n: r and type(n) is int, value, True):
                # Flat sequential path of ASNs
                value = [(2, value)]
            self.value = value or [(2, [])] # One segment with one AS path sequence

    def _initFromTuple(self, attrTuple):
        value = attrTuple[2]

        if self.optional or not self.transitive:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) == 0:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

        self.value = []
        postfix = value
        try:
            # Loop over all path segments
            while len(postfix) > 0:
                segType, length = struct.unpack('!BB', postfix[:2])
                asPath = list(struct.unpack('!%dH' % length, postfix[2:2+length*2]))

                postfix = postfix[2+length*2:]
                self.value.append( (segType, asPath) )
        except Exception:
            raise AttributeException(bgp.ERR_MSG_UPDATE_MALFORMED_ASPATH)

    def encode(self):
        packedPath = "".join([struct.pack('!BB%dH' % len(asPath), segType, len(asPath), *asPath) for segType, asPath in self.value])
        return struct.pack('!BBB', self.flags(), self.typeCode, len(packedPath)) + packedPath

    def __str__(self):
        return " ".join([" ".join([str(asn) for asn in path]) for type, path in self.value])

    def __hash__(self):
        return hash(tuple([(segtype, tuple(path)) for segtype, path in self.value]))

class ASPathAttribute(BaseASPathAttribute): pass

class BaseNextHopAttribute(Attribute):
    name = 'Next Hop'
    typeCode = ATTR_TYPE_NEXT_HOP

    def __init__(self, value=None, attrTuple=None):
        super(BaseNextHopAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = False
            self.transitive = True
            self._set(value)

    def _initFromTuple(self, attrTuple):
        value = attrTuple[2]

        if self.optional or not self.transitive:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 4:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

        self._set(value)

    def encode(self):
        return struct.pack('!BBB', self.flags(), self.typeCode, len(self.value.packed())) + self.value.packed()

    def _set(self, value):
        if value:
            if value in (0, 2**32-1):
                raise AttributeException(bgp.ERR_MSG_UPDATE_INVALID_NEXTHOP)
            self.value = IPv4IP(value)
        else:
            self.value = IPv4IP('0.0.0.0')

class NextHopAttribute(BaseNextHopAttribute):
    set = BaseNextHopAttribute._set

class BaseMEDAttribute(Attribute):
    name = 'MED'
    typeCode = ATTR_TYPE_MULTI_EXIT_DISC

    def __init__(self, value=None, attrTuple=None):
        super(BaseMEDAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = True
            self.transitive = False
            self.value = value or 0

    def _initFromTuple(self, attrTuple):
        value = attrTuple[2]

        if not self.optional or self.transitive:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 4:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

        self.value = struct.unpack('!I', value)[0]

    def encode(self):
        return struct.pack('!BBBI', self.flags(), self.typeCode, 4, self.value)

class MEDAttribute(BaseMEDAttribute): pass

class BaseLocalPrefAttribute(Attribute):
    name = 'Local Pref'
    typeCode = ATTR_TYPE_LOCAL_PREF

    def __init__(self, value=None, attrTuple=None):
        super(BaseLocalPrefAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = True
            self.transitive = False
            self.value = value or 0

    def _initFromTuple(self, attrTuple):
        value = attrTuple[2]

        if not self.optional or self.transitive:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 4:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

        self.value = struct.unpack('!I', value)[0]

    def encode(self):
        return struct.pack('!BBBI', self.flags(), self.typeCode, 4, self.value)

class LocalPrefAttribute(BaseLocalPrefAttribute): pass

class BaseAtomicAggregateAttribute(Attribute):
    name = 'Atomic Aggregate'
    typeCode = ATTR_TYPE_ATOMIC_AGGREGATE

    def __init__(self, value=None, attrTuple=None):
        super(BaseAtomicAggregateAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = False
            self.value = None

    def _initFromTuple(self, attrTuple):
        if self.optional:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(attrTuple[2]) != 0:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

    def encode(self):
        return struct.pack('!BBB', self.flags(), self.typeCode, 0)

class AtomicAggregateAttribute(BaseAtomicAggregateAttribute): pass

class BaseAggregatorAttribute(Attribute):
    name = 'Aggregator'
    typeCode = ATTR_TYPE_AGGREGATOR

    def __init__(self, value=None, attrTuple=None):
        super(BaseAggregatorAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = True
            self.transitive = True
            self.value = value or (0, IPv4IP('0.0.0.0')) # TODO: IPv6

    def _initFromTuple(self, attrTuple):
        value = attrTuple[2]

        if not self.optional or not self.transitive:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 6:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

        asn = struct.unpack('!H', value[:2])[0]
        aggregator = IPv4IP(value[2:]) # TODO: IPv6
        self.value = (asn, aggregator)

    def encode(self):
        return struct.pack('!BBBH', self.flags(), self.typeCode, 6, self.value[0]) + self.value[1].packed()

class AggregatorAttribute(BaseAggregatorAttribute): pass

class BaseCommunityAttribute(Attribute):
    name = 'Community'
    typeCode = ATTR_TYPE_COMMUNITY

    def __init__(self, value=None, attrTuple=None):
        super(BaseCommunityAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = True
            self.transitive = True
            self.value = value or []

    def _initFromTuple(self, attrTuple):
        value = attrTuple[2]

        if not self.optional or not self.transitive:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) % 4 != 0:
            raise AttributeException(bgp.ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

        length = len(value) / 4
        self.value = list(struct.unpack('!%dI' % length, value))

    def encode(self):
        return struct.pack('!BBB%dI' % len(self.value), self.flags(), self.typeCode, len(self.value) * 4, *self.value)

    def __str__(self):
        return str(["%d:%d" % (c / 2**16, c % 2**16) for c in self.value])

    def __hash__(self):
        return hash(tuple(self.value))

class CommunityAttribute(BaseCommunityAttribute): pass

# RFC4760 attributes

class BaseMPAttribute(Attribute):
    def __init__(self, value=(bgp.AFI_INET, bgp.SAFI_UNICAST), attrTuple=None):
        super(BaseMPAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = True
            self.transitive = False
            self.extendedLength = True
            self.afi, self.safi = value[0:2]

    def _initFromTuple(self, attrTuple):
        if not self.optional or self.transitive:
            raise AttributeException(bgp.ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)

    def _unpackAFI(self, attrTuple):
        try:
            self.afi, self.safi = struct.unpack('!HB', attrTuple[2][:3])
        except struct.error:
            raise AttributeException(bgp.ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)
        else:
            if self.afi not in bgp.SUPPORTED_AFI or self.safi not in bgp.SUPPORTED_SAFI:
                raise AttributeException(bgp.ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)

    def _parseNLRI(self, attrTuple, value):
        try:
            return bgp.BGP.parseEncodedPrefixList(value, self.afi)
        except BGPException:
            raise AttributeException(bgp.ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)

    def addSomePrefixes(self, prefixSet, maxLen):
        """
        Add as many prefixes from prefixSet as will fit within maxLen,
        removing added prefixes from prefixSet.
        Returns the number of prefixes added.
        """
        # FIXME: Optimize to prevent double encoding

        bArray = bytearray()
        origPrefixSet = frozenset(prefixSet)
        count = bgp.BGP.encodeSomePrefixes(
            prefixSet=prefixSet,
            bArray=bArray,
            offset=0,
            maxLen=maxLen)
        self.value = self.value[0:-1] + (list(origPrefixSet - prefixSet), )
        return count


    @staticmethod
    def afiStr(afi, safi):
        return ({
                 bgp.AFI_INET:   "inet",
                 bgp.AFI_INET6:  "inet6"
            }[afi],
            {
                 bgp.SAFI_UNICAST:   "unicast",
                 bgp.SAFI_MULTICAST: "multicast"
            }[safi])

    def __str__(self):
        return "%s %s NLRI %s" % (BaseMPAttribute.afiStr(self.afi, self.safi) + (self.value[2], ))

class MPReachNLRIAttribute(BaseMPAttribute):
    name = 'MP Reach NLRI'
    typeCode = ATTR_TYPE_MP_REACH_NLRI

    # Tuple encoding of self.value:
    # (AFI, SAFI, NH, [NLRI])

    def __init__(self, value=None, attrTuple=None):
        super(MPReachNLRIAttribute, self).__init__(value=value, attrTuple=attrTuple)

        if not attrTuple:
            self.value = value or (bgp.AFI_INET6, bgp.SAFIUNICAST, IPv6IP(), [])

    def _initFromTuple(self, attrTuple):
        super(MPReachNLRIAttribute, self)._initFromTuple(attrTuple)

        self._unpackAFI(attrTuple)

        value = attrTuple[2]
        try:
            nhlen = struct.unpack('!B', value[3])[0]
            pnh = struct.unpack('!%ds' % nhlen, value[4:4+nhlen])[0]
        except struct.error:
            raise AttributeException(bgp.ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)

        if self.afi == bgp.AFI_INET:
            nexthop = IPv4IP(packed=pnh)
        elif self.afi == bgp.AFI_INET6:
            nexthop = IPv6IP(packed=pnh)

        nlri = self._parseNLRI(attrTuple, value[5+nhlen:])

        self.value = (self.afi, self.safi, nexthop, nlri)

    def encode(self):
        afi, safi, nexthop, nlri = self.value
        pnh = nexthop.packed()
        encodedNLRI = bgp.BGP.encodePrefixes(nlri)
        length = 5 + len(pnh) + len(encodedNLRI)

        return struct.pack('!BBHHBB%dsB' % len(pnh), self.flags(), self.typeCode, length, afi, safi, len(pnh), pnh, 0) + encodedNLRI

    def __str__(self):
        return "%s %s NH %s NLRI %s" % (BaseMPAttribute.afiStr(self.afi, self.safi) + self.value[2:4])

    def __hash__(self):
        return hash((self.value[0:3] + (frozenset(self.value[3]), )))

    def addPrefixes(self, prefixes):
        """
        Adds a (copied) list of prefixes to this attribute's NLRI
        """
        self.value = self.value[0:3] + (list(prefixes), )

class MPUnreachNLRIAttribute(BaseMPAttribute):
    name = 'MP Unreach NLRI'
    typeCode = ATTR_TYPE_MP_UNREACH_NLRI

    # Tuple encoding of self.value:
    # (AFI, SAFI, [NLRI])

    def __init__(self, value=None, attrTuple=None):
        super(MPUnreachNLRIAttribute, self).__init__(value=value, attrTuple=attrTuple)

        if not attrTuple:
            self.value = value or (bgp.AFI_INET6, bgp.SAFIUNICAST, [])

    def _initFromTuple(self, attrTuple):
        super(MPUnreachNLRIAttribute, self)._initFromTuple(attrTuple)

        self._unpackAFI(attrTuple)

        nlri = self._parseNLRI(attrTuple, attrTuple[2][3:])

        self.value = (self.afi, self.safi, nlri)

    def encode(self):
        afi, safi, nlri = self.value
        encodedNLRI = bgp.BGP.encodePrefixes(nlri)
        length = 3 + len(encodedNLRI)

        return struct.pack('!BBHHB', self.flags(), self.typeCode, length, afi, safi) + encodedNLRI

    def addPrefixes(self, prefixes):
        """
        Adds a (copied) list of prefixes to this attribute's NLRI
        """
        self.value = self.value[0:2] + (list(prefixes), )

    def __hash__(self):
        return hash(self.value[0:2]) ^ hash(frozenset(self.value[2]))


class LastUpdateIntAttribute(Attribute):
    name = 'Last Update'
    typeCode = ATTR_TYPE_INT_LAST_UPDATE

    def _initFromTuple(self, attrTuple):
        self.value = attrTuple[2]

Attribute.typeToClass = {
    ATTR_TYPE_ORIGIN:            OriginAttribute,
    ATTR_TYPE_AS_PATH:           ASPathAttribute,
    ATTR_TYPE_NEXT_HOP:          NextHopAttribute,
    ATTR_TYPE_MULTI_EXIT_DISC:   MEDAttribute,
    ATTR_TYPE_LOCAL_PREF:        LocalPrefAttribute,
    ATTR_TYPE_ATOMIC_AGGREGATE:  AtomicAggregateAttribute,
    ATTR_TYPE_AGGREGATOR:        AggregatorAttribute,
    ATTR_TYPE_COMMUNITY:         CommunityAttribute,

    ATTR_TYPE_MP_REACH_NLRI:     MPReachNLRIAttribute,
    ATTR_TYPE_MP_UNREACH_NLRI:   MPUnreachNLRIAttribute,

    ATTR_TYPE_INT_LAST_UPDATE:   LastUpdateIntAttribute
}


class AttributeDict(dict):
    def __init__(self, attributes, checkMissing=False):
        """
        Expects another AttributeDict object, or a sequence of
        either unparsed attribute tuples, or parsed Attribute inheritors.
        """

        if isinstance(attributes, AttributeDict):
            return dict.__init__(self, attributes)

        dict.__init__(self)

        for attr in iter(attributes):
            if isinstance(attr, tuple):
                self._add(Attribute.fromTuple(attr))
            elif isinstance(attr, Attribute):
                self._add(attr)
            else:
                raise AttributeException(bgp.ERR_MSG_UPDATE_MALFORMED_ATTR_LIST)

        if checkMissing:
            # Check whether all mandatory well-known attributes are present
            for attr in [OriginAttribute, ASPathAttribute, NextHopAttribute]:
                if attr not in self:
                    raise AttributeException(bgp.ERR_MSG_UPDATE_MISSING_WELLKNOWN_ATTR,
                                             (0, attr.typeCode, None))


    def _add(self, attribute):
        """Adds attribute attr to the dict, raises AttributeException if already present"""

        if attribute.__class__ == Attribute:
            key = attribute.typeCode
        else:
            key = attribute.__class__

        if key in self:
            # Attribute was already present
            raise AttributeException(bgp.ERR_MSG_UPDATE_MALFORMED_ATTR_LIST)
        else:
            super(AttributeDict, self).__setitem__(key, attribute)

    add = _add

    def __str__(self):
        return "{%s}" % ", ".join(["%s: %s" % (attrType.__name__, str(attr)) for attrType, attr in self.iteritems()])

class FrozenAttributeDict(AttributeDict):
    __delitem__ = None
    __setitem__ = None
    clear = None
    fromkeys = None
    pop = None
    popitem = None
    setdefault = None
    update = None
    add = None


    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        import operator
        return reduce(operator.xor, map(hash, self.itervalues()), 0)
