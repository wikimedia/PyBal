# bgp.py
# Copyright (c) 2007-2017 by Mark Bergsma <mark@nedworks.org>

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

"""
A (partial) implementation of the BGP 4 protocol (RFC4271).

Supported features:

- RFC 3392 (Capabilities Advertisement with BGP-4) [rudimentary]
- RFC 4760 (Multi-protocol Extensions for BGP-4)
"""

# System imports
import struct

# Zope imports
from zope.interface import implements, Interface

# Twisted imports
from twisted import copyright
from twisted.internet import reactor, protocol, base, interfaces, error, defer

# Constants
VERSION = 4
PORT = 179

HDR_LEN = 19
MAX_LEN = 4096

# BGP messages
MSG_OPEN = 1
MSG_UPDATE = 2
MSG_NOTIFICATION = 3
MSG_KEEPALIVE = 4

# BGP FSM states
ST_IDLE, ST_CONNECT, ST_ACTIVE, ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED = range(6)

stateDescr = {
    ST_IDLE:        "IDLE",
    ST_CONNECT:     "CONNECT",
    ST_ACTIVE:      "ACTIVE",
    ST_OPENSENT:    "OPENSENT",
    ST_OPENCONFIRM: "OPENCONFIRM",
    ST_ESTABLISHED: "ESTABLISHED"
}

# Notification error codes
ERR_MSG_HDR = 1
ERR_MSG_OPEN = 2
ERR_MSG_UPDATE = 3
ERR_HOLD_TIMER_EXPIRED = 4
ERR_FSM = 5
ERR_CEASE = 6

# Notification suberror codes
ERR_MSG_HDR_CONN_NOT_SYNC = 1
ERR_MSG_HDR_BAD_MSG_LEN = 2
ERR_MSG_HDR_BAD_MSG_TYPE = 3

ERR_MSG_OPEN_UNSUP_VERSION = 1
ERR_MSG_OPEN_BAD_PEER_AS = 2
ERR_MSG_OPEN_BAD_BGP_ID = 3
ERR_MSG_OPEN_UNSUP_OPT_PARAM = 4
ERR_MSG_OPEN_UNACCPT_HOLD_TIME = 6

ERR_MSG_UPDATE_MALFORMED_ATTR_LIST = 1
ERR_MSG_UPDATE_UNRECOGNIZED_WELLKNOWN_ATTR = 2
ERR_MSG_UPDATE_MISSING_WELLKNOWN_ATTR = 3
ERR_MSG_UPDATE_ATTR_FLAGS = 4
ERR_MSG_UPDATE_ATTR_LEN = 5
ERR_MSG_UPDATE_INVALID_ORIGIN = 6
ERR_MSG_UPDATE_INVALID_NEXTHOP = 8
ERR_MSG_UPDATE_OPTIONAL_ATTR = 9
ERR_MSG_UPDATE_INVALID_NETWORK_FIELD = 10
ERR_MSG_UPDATE_MALFORMED_ASPATH = 11

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

# BGP Open optional parameter codes
OPEN_PARAM_CAPABILITIES = 2

# BGP Capability codes
CAP_MP_EXT = 1
CAP_ROUTE_REFRESH = 2
CAP_ORF = 3

AFI_INET = 1
AFI_INET6 = 2
SUPPORTED_AFI = [AFI_INET, AFI_INET6]

SAFI_UNICAST = 1
SAFI_MULTICAST = 2
SUPPORTED_SAFI = [SAFI_UNICAST, SAFI_MULTICAST]

# Exception classes

class BGPException(Exception):
    def __init__(self, protocol=None):
        self.protocol = protocol

class NotificationSent(BGPException):
    def __init__(self, protocol, error, suberror, data=''):
        BGPException.__init__(self, protocol)

        self.error = error
        self.suberror = suberror
        self.data = data

    def __str__(self):
        return repr((self.error, self.suberror, self.data))

class BadMessageLength(BGPException):
    pass

class AttributeException(BGPException):
    def __init__(self, suberror, data=''):
        BGPException.__init__(self)

        self.error = ERR_MSG_UPDATE
        self.suberror = suberror
        self.data = data

# Interfaces

class IBGPPeering(Interface):
    """
    Interface for notifications from the BGP protocol / FSM
    """

    def notificationSent(self, protocol, error, suberror, data):
        """
        Called when a BGP Notification message was sent.
        """

    def connectionClosed(self, protocol):
        """
        Called when the BGP connection has been closed (in error or not).
        """

    def completeInit(self, protocol):
        """
        Called when BGP resources should be initialized.
        """

    def sessionEstablished(self, protocol):
        """
        Called when the BGP session has reached the Established state
        """

    def connectRetryEvent(self, protocol):
        """
        Called when the connect-retry timer expires. A new connection should
        be initiated.
        """

# TODO: Replace by some better third party classes or rewrite
class IPPrefix(object):
    """Class that represents an IP prefix"""

    def __init__(self, ipprefix, addressfamily=None):
        self.prefix = None # packed ip string

        if isinstance(ipprefix, IPPrefix):
            self.prefix, self.prefixlen, self.addressfamily = ipprefix.prefix, ipprefix.prefixlen, ipprefix.addressfamily
        elif type(ipprefix) is tuple:
            # address family must be specified
            if not addressfamily:
                raise ValueError()

            self.addressfamily = addressfamily

            prefix, self.prefixlen = ipprefix
            if type(prefix) is str:
                # tuple (ipstr, prefixlen)
                self.prefix = prefix
            elif type(prefix) is int:
                if self.addressfamily == AFI_INET:
                    # tuple (ipint, prefixlen)
                    self.prefix = struct.pack('!I', prefix)
                else:
                    raise ValueError()
            else:
                # Assume prefix is a sequence of octets
                self.prefix = b"".join(map(chr, prefix))
        elif type(ipprefix) is str:
            # textual form
            prefix, prefixlen = ipprefix.split('/')
            self.addressfamily = addressfamily or (':' in prefix and AFI_INET6 or AFI_INET)

            if self.addressfamily == AFI_INET:
                self.prefix = b"".join([chr(int(o)) for o in prefix.split('.')])
            elif self.addressfamily == AFI_INET6:
                self.prefix = bytearray()
                hexlist = prefix.split(":")
                if len(hexlist) > 8:
                    raise ValueError()

                for hexstr in hexlist:
                    if hexstr is not "":
                        self.prefix += struct.pack('!H', int(hexstr, 16))
                    else:
                        zeroCount = 8 - len(hexlist) + 1
                        self.prefix += struct.pack('!%dH' % zeroCount, *((0,) * zeroCount))
                self.prefix = bytes(self.prefix)

            self.prefixlen = int(prefixlen)
        else:
            raise ValueError()

    def __repr__(self):
        return repr(str(self))

    def __str__(self):
        if self.addressfamily == AFI_INET:
            return '.'.join([str(ord(o)) for o in self.packed(pad=True)]) + '/%d' % self.prefixlen
        elif self.addressfamily == AFI_INET6:
            return ':'.join([hex(o)[2:] for o in struct.unpack('!8H', self.packed(pad=True))]) + '/%d' % self.prefixlen

    def __eq__(self, other):
        # FIXME: masked ips
        return isinstance(other, IPPrefix) and self.prefixlen == other.prefixlen and self.prefix == other.prefix

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.prefix < other.prefix or \
            (self.prefix == other.prefix and self.prefixlen < other.prefixlen)

    def __le__(self, other):
        return self.__lt__(other) or self.__eq__(other)

    def __gt__(self, other):
        return self.prefix > other.prefix or \
            (self.prefix == other.prefix and self.prefixlen > other.prefixlen)

    def __ge__(self, other):
        return self.__gt__(other) or self.__eq__(other)

    def __hash__(self):
        return hash(self.prefix) ^ hash(self.prefixlen)

    def __len__(self):
        return self.prefixlen

    def _packedMaxLen(self):
        return (self.addressfamily == AFI_INET6 and 16 or 4)

    def ipToInt(self):
        return reduce(lambda x, y: x * 256 + y, map(ord, self.prefix))

    def netmask(self):
        return ~( (1 << (len(self.prefix)*8 - self.prefixlen)) - 1)

    def mask(self, prefixlen, shorten=False):
        # DEBUG
        assert len(self.prefix) == self._packedMaxLen()

        masklen = len(self.prefix) * 8 - prefixlen
        self.prefix = struct.pack('!I', self.ipToInt() >> masklen << masklen)
        if shorten: self.prefixlen = prefixlen
        return self

    def packed(self, pad=False):
        if pad:
            return self.prefix + '\0' * (self._packedMaxLen() - len(self.prefix))
        else:
            return self.prefix

class IPv4IP(IPPrefix):
    """Class that represents a single non-prefix IPv4 IP."""

    def __init__(self, ip):
        if type(ip) is str and len(ip) > 4:
            super(IPv4IP, self).__init__(ip + '/32', AFI_INET)
        else:
            super(IPv4IP, self).__init__((ip, 32), AFI_INET)

    def __str__(self):
        return ".".join([str(ord(o)) for o in self.prefix])

class IPv6IP(IPPrefix):
    """Class that represents a single non-prefix IPv6 IP."""

    def __init__(self, ip=None, packed=None):
        if not ip and not packed:
            raise ValueError()

        if packed:
            super(IPv6IP, self).__init__((packed, 128), AFI_INET6)
        else:
            super(IPv6IP, self).__init__(ip + '/128', AFI_INET6)

    def __str__(self):
        return ':'.join([hex(o)[2:] for o in struct.unpack('!8H', self.packed(pad=True))])

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
                    raise AttributeException(ERR_MSG_UPDATE_UNRECOGNIZED_WELLKNOWN_ATTR, attrTuple)

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
        return BGP.encodeAttribute(self.flags(), self.typeCode, self.value)

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
            raise AttributeException(ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 1:
            raise AttributeException(ERR_MSG_UPDATE_ATTR_LEN, attrTuple)
        if ord(value) not in (self.ORIGIN_IGP, self.ORIGIN_EGP, self.ORIGIN_INCOMPLETE):
            raise AttributeException(ERR_MSG_UPDATE_INVALID_ORIGIN, attrTuple)

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
            raise AttributeException(ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) == 0:
            raise AttributeException(ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

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
            raise AttributeException(ERR_MSG_UPDATE_MALFORMED_ASPATH)

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
            raise AttributeException(ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 4:
            raise AttributeException(ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

        self._set(value)

    def encode(self):
        return struct.pack('!BBB', self.flags(), self.typeCode, len(self.value.packed())) + self.value.packed()

    def _set(self, value):
        if value:
            if value in (0, 2**32-1):
                raise AttributeException(ERR_MSG_UPDATE_INVALID_NEXTHOP)
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
            raise AttributeException(ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 4:
            raise AttributeException(ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

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
            raise AttributeException(ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 4:
            raise AttributeException(ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

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
            raise AttributeException(ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(attrTuple[2]) != 0:
            raise AttributeException(ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

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
            raise AttributeException(ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) != 6:
            raise AttributeException(ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

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
            raise AttributeException(ERR_MSG_UPDATE_ATTR_FLAGS, attrTuple)
        if len(value) % 4 != 0:
            raise AttributeException(ERR_MSG_UPDATE_ATTR_LEN, attrTuple)

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
    def __init__(self, value=(AFI_INET, SAFI_UNICAST), attrTuple=None):
        super(BaseMPAttribute, self).__init__(attrTuple=attrTuple)

        if not attrTuple:
            self.optional = True
            self.transitive = False
            self.extendedLength = True
            self.afi, self.safi = value[0:2]

    def _initFromTuple(self, attrTuple):
        if not self.optional or self.transitive:
            raise AttributeException(ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)

    def _unpackAFI(self, attrTuple):
        try:
            self.afi, self.safi = struct.unpack('!HB', attrTuple[2][:3])
        except struct.error:
            raise AttributeException(ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)
        else:
            if self.afi not in SUPPORTED_AFI or self.safi not in SUPPORTED_SAFI:
                raise AttributeException(ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)

    def _parseNLRI(self, attrTuple, value):
        try:
            return BGP.parseEncodedPrefixList(value, self.afi)
        except BGPException:
            raise AttributeException(ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)

    def addSomePrefixes(self, prefixSet, maxLen):
        """
        Add as many prefixes from prefixSet as will fit within maxLen,
        removing added prefixes from prefixSet.
        Returns the number of prefixes added.
        """
        # FIXME: Optimize to prevent double encoding

        bArray = bytearray()
        origPrefixSet = frozenset(prefixSet)
        count = BGP.encodeSomePrefixes(
            prefixSet=prefixSet,
            bArray=bArray,
            offset=0,
            maxLen=maxLen)
        self.value = self.value[0:-1] + (list(origPrefixSet - prefixSet), )
        return count


    @staticmethod
    def afiStr(afi, safi):
        return ({
                 AFI_INET:   "inet",
                 AFI_INET6:  "inet6"
            }[afi],
            {
                 SAFI_UNICAST:   "unicast",
                 SAFI_MULTICAST: "multicast"
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
            self.value = value or (AFI_INET6, SAFI_UNICAST, IPv6IP(), [])

    def _initFromTuple(self, attrTuple):
        super(MPReachNLRIAttribute, self)._initFromTuple(attrTuple)

        self._unpackAFI(attrTuple)

        value = attrTuple[2]
        try:
            nhlen = struct.unpack('!B', value[3])[0]
            pnh = struct.unpack('!%ds' % nhlen, value[4:4+nhlen])[0]
        except struct.error:
            raise AttributeException(ERR_MSG_UPDATE_OPTIONAL_ATTR, attrTuple)

        if self.afi == AFI_INET:
            nexthop = IPv4IP(packed=pnh)
        elif self.afi == AFI_INET6:
            nexthop = IPv6IP(packed=pnh)

        nlri = self._parseNLRI(attrTuple, value[5+nhlen:])

        self.value = (self.afi, self.safi, nexthop, nlri)

    def encode(self):
        afi, safi, nexthop, nlri = self.value
        pnh = nexthop.packed()
        encodedNLRI = BGP.encodePrefixes(nlri)
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
            self.value = value or (AFI_INET6, SAFI_UNICAST, [])

    def _initFromTuple(self, attrTuple):
        super(MPUnreachNLRIAttribute, self)._initFromTuple(attrTuple)

        self._unpackAFI(attrTuple)

        nlri = self._parseNLRI(attrTuple, attrTuple[2][3:])

        self.value = (self.afi, self.safi, nlri)

    def encode(self):
        afi, safi, nlri = self.value
        encodedNLRI = BGP.encodedPrefixes(nlri)
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
                raise AttributeException(ERR_MSG_UPDATE_MALFORMED_ATTR_LIST)

        if checkMissing:
            # Check whether all mandatory well-known attributes are present
            for attr in [OriginAttribute, ASPathAttribute, NextHopAttribute]:
                if attr not in self:
                    raise AttributeException(ERR_MSG_UPDATE_MISSING_WELLKNOWN_ATTR,
                                             (0, attr.typeCode, None))


    def _add(self, attribute):
        """Adds attribute attr to the dict, raises AttributeException if already present"""

        if attribute.__class__ == Attribute:
            key = attribute.typeCode
        else:
            key = attribute.__class__

        if key in self:
            # Attribute was already present
            raise AttributeException(ERR_MSG_UPDATE_MALFORMED_ATTR_LIST)
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

class Advertisement(object):
    """
    Class that represents a single BGP advertisement, consisting of an IP network prefix,
    BGP attributes and optional extra information
    """

    def __init__(self, prefix, attributes, addressfamily=(AFI_INET, SAFI_UNICAST)):
        self.prefix = prefix
        self.attributes = attributes
        self.addressfamily = addressfamily

    def __repr__(self):
        return repr(self.__dict__)

class FSM(object):
    class BGPTimer(object):
        """
        Timer class with a slightly different Timer interface than the
        Twisted DelayedCall interface
        """

        def __init__(self, callable):
            self.delayedCall = None
            self.callable = callable

        def cancel(self):
            """Cancels the timer if it was running, does nothing otherwise"""

            try:
                self.delayedCall.cancel()
            except (AttributeError, error.AlreadyCalled, error.AlreadyCancelled):
                pass

        def reset(self, secondsFromNow):
            """Resets an already running timer, or starts it if it wasn't running."""

            try:
                self.delayedCall.reset(secondsFromNow)
            except (AttributeError, error.AlreadyCalled, error.AlreadyCancelled):
                self.delayedCall = reactor.callLater(secondsFromNow, self.callable)

        def active(self):
            """Returns True if the timer was running, False otherwise."""

            try:
                return self.delayedCall.active()
            except AttributeError:
                return False

    protocol = None

    state = ST_IDLE

    largeHoldTime = 4*60
    sendNotificationWithoutOpen = True    # No bullshit

    def __init__(self, bgpPeering=None, protocol=None):
        self.bgpPeering = bgpPeering
        self.protocol = protocol

        self.connectRetryCounter = 0
        self.connectRetryTime = 30
        self.connectRetryTimer = FSM.BGPTimer(self.connectRetryTimeEvent)
        self.holdTime = 3 * 60
        self.holdTimer = FSM.BGPTimer(self.holdTimeEvent)
        self.keepAliveTime = self.holdTime / 3
        self.keepAliveTimer = FSM.BGPTimer(self.keepAliveEvent)

        self.allowAutomaticStart = True
        self.allowAutomaticStop = False
        self.delayOpen = False
        self.delayOpenTime = 30
        self.delayOpenTimer = FSM.BGPTimer(self.delayOpenEvent)

        self.dampPeerOscillations = True
        self.idleHoldTime = 30
        self.idleHoldTimer = FSM.BGPTimer(self.idleHoldTimeEvent)

    def __setattr__(self, name, value):
        if name == 'state' and value != getattr(self, name):
            print "State is now:", stateDescr[value]
        super(FSM, self).__setattr__(name, value)

    def manualStart(self):
        """
        Should be called when a BGP ManualStart event (event 1) is requested.
        Note that a protocol instance does not yet exist at this point,
        so this method requires some support from BGPPeering.manualStart().
        """

        if self.state == ST_IDLE:
            self.connectRetryCounter = 0
            self.connectRetryTimer.reset(self.connectRetryTime)

    def manualStop(self):
        """Should be called when a BGP ManualStop event (event 2) is requested."""

        if self.state != ST_IDLE:
            self.protocol.sendNotification(ERR_CEASE, 0)
            # Stop all timers
            for timer in (self.connectRetryTimer, self.holdTimer, self.keepAliveTimer,
                          self.delayOpenTimer, self.idleHoldTimer):
                timer.cancel()
            if self.bgpPeering is not None: self.bgpPeering.releaseResources(self.protocol)
            self._closeConnection()
            self.connectRetryCounter = 0
            self.state = ST_IDLE
            raise NotificationSent(self.protocol, ERR_CEASE, 0)

    def automaticStart(self, idleHold=False):
        """
        Should be called when a BGP Automatic Start event (event 3) is requested.
        Returns True or False to indicate BGPPeering whether a connection attempt
        should be initiated.
        """

        if self.state == ST_IDLE:
            if idleHold:
                self.idleHoldTimer.reset(self.idleHoldTime)
                return False
            else:
                self.connectRetryCounter = 0
                self.connectRetryTimer.reset(self.connectRetryTime)
                return True

    def connectionMade(self):
        """Should be called when a TCP connection has successfully been
        established with the peer. (events 16, 17)
        """

        if self.state in (ST_CONNECT, ST_ACTIVE):
            # State Connect, Event 16 or 17
            if self.delayOpen:
                self.connectRetryTimer.cancel()
                self.delayOpenTimer.reset(self.delayOpenTime)
            else:
                self.connectRetryTimer.cancel()
                if self.bgpPeering: self.bgpPeering.completeInit(self.protocol)
                self.protocol.sendOpen()
                self.holdTimer.reset(self.largeHoldTime)
                self.state = ST_OPENSENT

    def connectionFailed(self):
        """Should be called when the associated TCP connection failed, or
        was lost. (event 18)"""

        if self.state == ST_CONNECT:
            # State Connect, event 18
            if self.delayOpenTimer.active():
                 self.connectRetryTimer.reset(self.connectRetryTime)
                 self.delayOpenTimer.cancel()
                 self.state = ST_ACTIVE
            else:
                self.connectRetryTimer.cancel()
                self._closeConnection()
                if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
                self.state = ST_IDLE
        elif self.state == ST_ACTIVE:
            # State Active, event 18
            self.connectRetryTimer.reset(self.connectRetryTime)
            self.delayOpenTimer.cancel()
            if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
            self.connectRetryCounter += 1
            # TODO: osc damping
            self.state = ST_IDLE
        elif self.state == ST_OPENSENT:
            # State OpenSent, event 18
            if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
            self._closeConnection()
            self.connectRetryTimer.reset(self.connectRetryTime)
            self.state = ST_ACTIVE
        elif self.state in (ST_OPENCONFIRM, ST_ESTABLISHED):
            self._errorClose()


    def openReceived(self):
        """Should be called when a BGP Open message was received from
        the peer. (events 19, 20)
        """

        if self.state in (ST_CONNECT, ST_ACTIVE):
            if self.delayOpenTimer.active():
                # State Connect, event 20
                self.connectRetryTimer.cancel()
                if self.bgpPeering: self.bgpPeering.completeInit(self.protocol)
                self.delayOpenTimer.cancel()
                self.protocol.sendOpen()
                self.protocol.sendKeepAlive()
                if self.holdTime != 0:
                    self.KeepAliveTimer.reset(self.keepAliveTime)
                    self.holdTimer.reset(self.holdTimer)
                else:    # holdTime == 0
                    self.keepAliveTimer.cancel()
                    self.holdTimer.cancel()

                self.state = ST_OPENCONFIRM
            else:
                # State Connect, event 19
                self._errorClose()

        elif self.state == ST_OPENSENT:
            # State OpenSent, events 19, 20
            self.delayOpenTimer.cancel()
            self.connectRetryTimer.cancel()
            self.protocol.sendKeepAlive()
            if self.holdTime > 0:
                self.keepAliveTimer.reset(self.keepAliveTime)
                self.holdTimer.reset(self.holdTime)
            self.state = ST_OPENCONFIRM

        elif self.state == ST_OPENCONFIRM:
            # State OpenConfirm, events 19, 20
            # DEBUG
            print "Running collision detection"

            # Perform collision detection
            self.protocol.collisionDetect()

        elif self.state == ST_ESTABLISHED:
            # State Established, event 19 or 20
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def headerError(self, suberror, data=''):
        """
        Should be called when an invalid BGP message header was received.
        (event 21)
        """

        self.protocol.sendNotification(ERR_MSG_HDR, suberror, data)
        # Note: RFC4271 states that we should send ERR_FSM in the
        # Established state, which contradicts earlier statements.
        self._errorClose()
        raise NotificationSent(self.protocol, ERR_MSG_HDR, suberror, data)

    def openMessageError(self, suberror, data=''):
        """
        Should be called when an invalid BGP Open message was received.
        (event 22)
        """

        self.protocol.sendNotification(ERR_MSG_OPEN, suberror, data)
        # Note: RFC4271 states that we should send ERR_FSM in the
        # Established state, which contradicts earlier statements.
        self._errorClose()
        raise NotificationSent(self.protocol, ERR_MSG_OPEN, suberror, data)

    def keepAliveReceived(self):
        """
        Should be called when a BGP KeepAlive packet was received
        from the peer. (event 26)
        """

        if self.state == ST_OPENCONFIRM:
            # State OpenSent, event 26
            self.holdTimer.reset(self.holdTime)
            self.state = ST_ESTABLISHED
            self.protocol.deferred.callback(self.protocol)
        elif self.state == ST_ESTABLISHED:
            # State Established, event 26
            self.holdTimer.reset(self.holdTime)
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            # States Connect, Active, event 26
            self._errorClose()

    def versionError(self):
        """
        Should be called when a BGP Notification Open Version Error
        message was received from the peer. (event 24)
        """

        if self.state in (ST_OPENSENT, ST_OPENCONFIRM):
            # State OpenSent, event 24
            self.connectRetryTimer.cancel()
            if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
            self._closeConnection()
            self.state = ST_IDLE
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            # State Connect, event 24
            self._errorClose()

    def notificationReceived(self, error, suberror):
        """
        Should be called when a BGP Notification message was
        received from the peer. (events 24, 25)
        """

        if error == ERR_MSG_OPEN and suberror == 1:
            # Event 24
            self.versionError()
        else:
            if self.state != ST_IDLE:
                # State != Idle, events 24, 25
                self._errorClose()

    def updateReceived(self, update):
        """Called when a valid BGP Update message was received. (event 27)"""

        if self.state == ST_ESTABLISHED:
            # State Established, event 27
            if self.holdTime != 0:
                self.holdTimer.reset(self.holdTime)

            self.bgpPeering.update(update)
        elif self.state in (ST_ACTIVE, ST_CONNECT):
            # States Active, Connect, event 27
            self._errorClose()
        elif self.state in (ST_OPENSENT, ST_OPENCONFIRM):
            # States OpenSent, OpenConfirm, event 27
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def updateError(self, suberror, data=''):
        """Called when an invalid BGP Update message was received. (event 28)"""

        if self.state == ST_ESTABLISHED:
            # State Established, event 28
            self.protocol.sendNotification(ERR_MSG_UPDATE, suberror, data)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_MSG_UPDATE, suberror, data)
        elif self.state in (ST_ACTIVE, ST_CONNECT):
            # States Active, Connect, event 28
            self._errorClose()
        elif self.state in (ST_OPENSENT, ST_OPENCONFIRM):
            # States OpenSent, OpenConfirm, event 28
            self.protocol.sendNotification(self.protocol, ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def openCollisionDump(self):
        """
        Called when the collision detection algorithm determined
        that the associated connection should be dumped.
        (event 23)
        """

        # DEBUG
        print "Collided, closing."

        if self.state == ST_IDLE:
            return
        elif self.state in (ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED):
            self.protocol.sendNotification(ERR_CEASE, 0)

        self._errorClose()
        raise NotificationSent(self.protocol, ERR_CEASE, 0)

    def delayOpenEvent(self):
        """Called when the DelayOpenTimer expires. (event 12)"""

        assert(self.delayOpen)

        # DEBUG
        print "Delay Open event"

        if self.state == ST_CONNECT:
            # State Connect, event 12
            self.protocol.sendOpen()
            self.holdTimer.reset(self.largeHoldTime)
            self.state = ST_OPENSENT
        elif self.state == ST_ACTIVE:
            # State Active, event 12
            self.connectRetryTimer.cancel()
            self.delayOpenTimer.cancel()
            if self.bgpPeering: self.bgpPeering.completeInit(self.protocol)
            self.sendOpen()
            self.holdTimer.reset(self.largeHoldTime)
            self.state = ST_OPENSENT
        elif self.state != ST_IDLE:
            # State OpenSent, OpenConfirm, Established, event 12
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def keepAliveEvent(self):
        """Called when the KeepAliveTimer expires. (event 11)"""

        if self.state in (ST_OPENCONFIRM, ST_ESTABLISHED):
            # State OpenConfirm, Established, event 11
            self.protocol.sendKeepAlive()
            if self.holdTime > 0:
                self.keepAliveTimer.reset(self.keepAliveTime)
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            self._errorClose()

    def holdTimeEvent(self):
        """Called when the HoldTimer expires. (event 10)"""

        if self.state in (ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED):
            # States OpenSent, OpenConfirm, Established, event 10
            self.protocol.sendNotification(ERR_HOLD_TIMER_EXPIRED, 0)
            self.connectRetryTimer.cancel()
            self._errorClose()
            self.connectRetryCounter += 1
            # TODO: peer osc damping
            self.state = ST_IDLE

            #self.protocol.deferred.errback(HoldTimerExpired(self.protocol))
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            self._errorClose()

    def connectRetryTimeEvent(self):
        """Called when the ConnectRetryTimer expires. (event 9)"""

        if self.state in (ST_CONNECT, ST_ACTIVE):
            # State Connect, event 9
            self._closeConnection()
            self.connectRetryTimer.reset(self.connectRetryTime)
            self.delayOpenTimer.cancel()
            # Initiate TCP connection
            if self.bgpPeering: self.bgpPeering.connectRetryEvent(self.protocol)
        elif self.state != ST_IDLE:
            # State OpenSent, OpenConfirm, Established, event 12
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def idleHoldTimeEvent(self):
        """Called when the IdleHoldTimer expires. (event 13)"""

        if self.state == ST_IDLE:
            if self.bgpPeering: self.bgpPeering.automaticStart(idleHold=False)

    def updateSent(self):
        """Called by the protocol instance when it just sent an Update message."""

        if self.holdTime > 0:
            self.keepAliveTimer.reset(self.keepAliveTime)

    def _errorClose(self):
        """Internal method that closes a connection and returns the state
        to IDLE.
        """

        # Stop the timers
        for timer in (self.connectRetryTimer, self.delayOpenTimer, self.holdTimer,
            self.keepAliveTimer):
            timer.cancel()

        # Release BGP resources (routes, etc)
        if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)

        self._closeConnection()

        self.connectRetryCounter += 1
        self.state = ST_IDLE

    def _closeConnection(self):
        """Internal method that close the connection if a valid BGP protocol
        instance exists.
        """

        if self.protocol is not None:
            self.protocol.closeConnection()
        # Remove from connections list
        if self.bgpPeering: self.bgpPeering.connectionClosed(self.protocol)

class BGPMessage(object):
    msgtype = None
    msgLenOffset = 16

    def __init__(self):
        self.msg = (bytearray(HDR_LEN), )
        self.constructHeader()

    def __repr__(self):
        msgType = {
            MSG_OPEN: "OPEN",
            MSG_UPDATE: "UPDATE",
            MSG_NOTIFICATION: "NOTIFICATION",
            MSG_KEEPALIVE: "KEEPALIVE",

        }.get(self.msgtype, "Invalid")
        return "<BGP %s, len %d>" % (msgType, len(self))

    def __str__(self):
        return "".join([str(part) for part in self.msg])

    def __len__(self):
        return sum([len(part) for part in self.msg])

    def __getitem__(self, i):
        return buffer(self.msg[i])

    @staticmethod
    def prependHeader(message, type):
        """Prepends the mandatory header to a constructed BGP message"""

        return struct.pack('!16sHB',
                           chr(255)*16,
                           len(message)+HDR_LEN,
                           type) + message

    def constructHeader(self, buffer=None):
        struct.pack_into('!16sHB', (buffer or self.msg[0]), 0,
            chr(255)*16,
            len(self),
            self.msgtype)

    def freeSpace(self):
        """
        Returns the available free space in the packet
        """
        return MAX_LEN - len(self)

    def _updateRecordLen(self, buf, offset=None, length=None):
        """
        Updates the length of the variable length field at the given
        offset in the provided buffer
        """

        struct.pack_into('!H', buf, offset, length)

    def _updateMsgLen(self):
        """
        Updates the length of the message in the message header
        """

        struct.pack_into('!H', self.msg[0], self.msgLenOffset, len(self))

    def _appendAll(self, buf, data, lenOffset=None):
        """
        Appends variable records (e.g. NLRI, attributes) and updates
        the variable length and total message size.
        """

        newSize = len(self) + len(data)
        if newSize <= MAX_LEN:
            buf.extend(data)
            if lenOffset is not None:
                self._updateRecordLen(buf, lenOffset, len(buf) - lenOffset - 2)
            self._updateMsgLen()
        else:
            raise ValueError("New message size %s would exceed MAX_LEN %d" %
                (newSize, MAX_LEN))

class BGPUpdateMessage(BGPMessage):
    msgtype = MSG_UPDATE

    def __init__(self):
        super(BGPUpdateMessage, self).__init__()
        self.msg = (self.msg[0], bytearray(2), bytearray(2), bytearray())
        self.withdrCount, self.attrCount, self.nlriCount = 0, 0, 0

    def __repr__(self):
        return (super(BGPUpdateMessage, self).__repr__()[:-1]
            + ", [%d:%d] withdrawals" % (self.withdrCount, len(self.msg[1]))
            + ", [%d:%d] attributes" % (self.attrCount, len(self.msg[2]))
            + ", [%d:%d] NLRI>" % (self.nlriCount, len(self.msg[3])))


    def addSomeWithdrawals(self, withdrawalSet):
        """
        Incrementally adds as many withdrawals to the UPDATE message as will
        fit in the remainder of the packet, removing added prefixes from the set
        Returns the number of withdrawals added.
        """
        added = BGP.encodeSomePrefixes(
            prefixSet=withdrawalSet,
            bArray=self.msg[1],
            offset=len(self.msg[1]),
            maxLen=self.freeSpace())
        self._updateRecordLen(self.msg[1], 0, len(self.msg[1]) - 2)
        self._updateMsgLen()
        self.withdrCount += added
        return added

    def addAttributes(self, attributes):
        """
        Incrementally adds NLRI attributes to the UPDATE message.
        """

        self._appendAll(self.msg[2], BGP.encodeAttributes(attributes), lenOffset=0)
        self.attrCount += len(attributes)

    def clearAttributes(self):
        """
        Removes all previously added attributes from the packet.
        """

        del self.msg[2][2:]
        self.msg[2][0:2] = 0, 0
        self._updateMsgLen()

    def addSomeNLRI(self, nlriSet):
        """
        Incrementally adds as many nlri to the UPDATE message as will
        fit in the remainder of the packet, removing added prefixes from the set
        Returns the number of nlri added.
        """

        added = BGP.encodeSomePrefixes(
            prefixSet=nlriSet,
            bArray=self.msg[3],
            offset=len(self.msg[3]),
            maxLen=self.freeSpace())
        self._updateMsgLen()
        self.nlriCount += added
        return added

class BGP(protocol.Protocol):
    """Protocol class for BGP 4"""

    def __init__(self):
        self.deferred = defer.Deferred()
        self.fsm = None

        self.disconnected = False
        self.receiveBuffer = ''

    def connectionMade(self):
        """
        Starts the initial negotiation of the protocol
        """

        # Set transport socket options
        self.transport.setTcpNoDelay(True)

        # DEBUG
        print "Connection established"

        # Set the local BGP id from the local IP address if it's not set
        if self.factory.bgpId is None:
            self.factory.bgpId = IPv4IP(self.transport.getHost().host).ipToInt()  # FIXME: IPv6

        try:
            self.fsm.connectionMade()
        except NotificationSent, e:
            self.deferred.errback(e)

    def connectionLost(self, reason):
        """Called when the associated connection was lost."""

        # Don't do anything if we closed the connection explicitly ourselves
        if self.disconnected:
            # Callback sessionEstablished shouldn't be called, especially not
            # with an argument protocol = True. Calling errback doesn't seem
            # appropriate either. Just do nothing?
            #self.deferred.callback(True)
            self.factory.connectionClosed(self)
            return

        # DEBUG
        print "Connection lost:", reason.getErrorMessage()

        try:
            self.fsm.connectionFailed()
        except NotificationSent, e:
            self.deferred.errback(e)

    def dataReceived(self, data):
        """
        Appends newly received data to the receive buffer, and
        then attempts to parse as many BGP messages as possible.
        """

        # Buffer possibly incomplete data first
        self.receiveBuffer += data

        # Attempt to parse as many messages as possible
        while(self.parseBuffer()): pass

    def closeConnection(self):
        """Close the connection"""

        if self.transport.connected:
            self.transport.loseConnection()
            self.disconnected = True

    def sendOpen(self):
        """Sends a BGP Open message to the peer"""

        # DEBUG
        print "Sending Open"

        self.transport.write(self.constructOpen())

    def sendUpdate(self, withdrawnPrefixes, attributes, nlri):
        """Sends a BGP Update message to the peer"""

        # DEBUG
        print "Sending Update"
        print "Withdrawing:", withdrawnPrefixes
        print "Attributes:", attributes
        print "NLRI:", nlri

        self.transport.write(self.constructUpdate(withdrawnPrefixes, attributes, nlri))
        self.fsm.updateSent()

    def sendKeepAlive(self):
        """Sends a BGP KeepAlive message to the peer"""

        self.transport.write(self.constructKeepAlive())

    def sendNotification(self, error, suberror, data=''):
        """Sends a BGP Notification message to the peer
        """

        self.transport.write(self.constructNotification(error, suberror, data))

    def sendMessage(self, bgpMessage):
        """
        Sends a bgpMessage
        """

        # DEBUG
        print "Sending BGP message:", repr(bgpMessage)

        # FIXME: Twisted on Python 2 doesn't support bytearrays
        self.transport.writeSequence(bytes(bgpMessage))

    def constructOpen(self):
        """Constructs a BGP Open message"""

        # Construct optional parameters
        capabilities = self.constructCapabilities(self._capabilities())
        optParams = self.constructOpenOptionalParameters(
                parameters=(capabilities and [capabilities] or []))

        msg = struct.pack('!BHHI',
                          VERSION,
                          self.factory.myASN,
                          self.fsm.holdTime,
                          self.factory.bgpId) + optParams

        return BGPMessage.prependHeader(msg, MSG_OPEN)

    def constructUpdate(self, withdrawnPrefixes, attributes, nlri):
        """Constructs a BGP Update message"""

        withdrawnPrefixesData = BGP.encodePrefixes(withdrawnPrefixes)
        attributesData = BGP.encodeAttributes(attributes)
        nlriData = BGP.encodePrefixes(nlri)

        msg = (struct.pack('!H', len(withdrawnPrefixesData))
               + withdrawnPrefixesData
               + struct.pack('!H', len(attributesData))
               + attributesData
               + nlriData)

        return BGPMessage.prependHeader(msg, MSG_UPDATE)

    def constructKeepAlive(self):
        """Constructs a BGP KeepAlive message"""

        return BGPMessage.prependHeader('', MSG_KEEPALIVE)

    def constructNotification(self, error, suberror=0, data=''):
        """Constructs a BGP Notification message"""

        msg = struct.pack('!BB', error, suberror) + data
        return BGPMessage.prependHeader(msg, MSG_NOTIFICATION)

    def constructOpenOptionalParameters(self, parameters):
        """Constructs the OptionalParameters fields of a BGP Open message"""

        params = "".join(parameters)
        return struct.pack('!B', len(params)) + params

    def constructCapabilities(self, capabilities):
        """Constructs a Capabilities optional parameter of a BGP Open message"""

        if len(capabilities) > 0:
            caps = "".join([struct.pack('!BB', capCode, len(capValue)) + capValue
                            for capCode, capValue
                            in capabilities])
            return struct.pack('!BB', OPEN_PARAM_CAPABILITIES, len(caps)) + caps
        else:
            return None

    def parseBuffer(self):
        """Parse received data in receiveBuffer"""

        buf = self.receiveBuffer

        if len(buf) < HDR_LEN:
            # Every BGP message is at least 19 octets. Maybe the rest
            # hasn't arrived yet.
            return False

        # Check whether the first 16 octets of the buffer consist of
        # the BGP marker (all bits one)
        if buf[:16] != chr(255)*16:
            self.fsm.headerError(ERR_MSG_HDR_CONN_NOT_SYNC)

        # Parse the header
        try:
            marker, length, type = struct.unpack('!16sHB', buf[:HDR_LEN])
        except struct.error:
            self.fsm.headerError(ERR_MSG_HDR_CONN_NOT_SYNC)

        # Check the length of the message
        if length < HDR_LEN or length > MAX_LEN:
            self.fsm.headerError(ERR_MSG_HDR_BAD_MSG_LEN, struct.pack('!H', length))

        # Check whether the entire message is already available
        if len(buf) < length: return False

        message = buf[HDR_LEN:length]
        try:
            try:
                if type == MSG_OPEN:
                    self.openReceived(*self.parseOpen(message))
                elif type == MSG_UPDATE:
                    self.updateReceived(*self.parseUpdate(message))
                elif type == MSG_KEEPALIVE:
                    self.parseKeepAlive(message)
                    self.keepAliveReceived()
                elif type == MSG_NOTIFICATION:
                    self.notificationReceived(*self.parseNotification(message))
                else:    # Unknown message type
                    self.fsm.headerError(ERR_MSG_HDR_BAD_MSG_TYPE, chr(type))
            except BadMessageLength:
                self.fsm.headerError(ERR_MSG_HDR_BAD_MSG_LEN, struct.pack('!H', length))
        except NotificationSent, e:
            self.deferred.errback(e)

        # Message successfully processed, jump to next message
        self.receiveBuffer = self.receiveBuffer[length:]
        return True

    def parseOpen(self, message):
        """Parses a BGP Open message"""

        try:
            peerVersion, peerASN, peerHoldTime, peerBgpId, paramLen = struct.unpack('!BHHIB', message[:10])
        except struct.error:
            raise BadMessageLength(self)

        # Check whether these values are acceptable

        if peerVersion != VERSION:
            self.fsm.openMessageError(ERR_MSG_OPEN_UNSUP_VERSION,
                                      struct.pack('!B', VERSION))

        if peerASN in (0, 2**16-1):
            self.fsm.openMessageError(ERR_MSG_OPEN_BAD_PEER_AS)

        # Hold Time is negotiated and/or rejected later

        if peerBgpId in (0, 2**32-1, self.bgpPeering.bgpId):
            self.fsm.openMessageError(ERR_MSG_OPEN_BAD_BGP_ID)

        # TODO: optional parameters

        return peerVersion, peerASN, peerHoldTime, peerBgpId

    def parseUpdate(self, message):
        """Parses a BGP Update message"""

        try:
            withdrawnLen = struct.unpack('!H', message[:2])[0]
            withdrawnPrefixesData = message[2:withdrawnLen+2]
            attrLen = struct.unpack('!H', message[withdrawnLen+2:withdrawnLen+4])[0]
            attributesData = message[withdrawnLen+4:withdrawnLen+4+attrLen]
            nlriData = message[withdrawnLen+4+attrLen:]

            withdrawnPrefixes = BGP.parseEncodedPrefixList(withdrawnPrefixesData)
            attributes = BGP.parseEncodedAttributes(attributesData)
            nlri = BGP.parseEncodedPrefixList(nlriData)
        except BGPException, e:
            if (e.error, e.suberror) == (ERR_MSG_UPDATE, ERR_MSG_UPDATE_INVALID_NETWORK_FIELD):
                self.fsm.updateError(e.suberror)
            else:
                raise
        except Exception:
            # RFC4271 dictates that we send ERR_MSG_UPDATE Malformed Attribute List
            # in this case
            self.fsm.updateError(ERR_MSG_UPDATE_MALFORMED_ATTR_LIST)

            # updateError may have raised an exception. If not, we'll do it here.
            raise
        else:
            return withdrawnPrefixes, attributes, nlri

    def parseKeepAlive(self, message):
        """Parses a BGP KeepAlive message"""

        # KeepAlive body must be empty
        if len(message) != 0: raise BadMessageLength(self)

    def parseNotification(self, message):
        """Parses a BGP Notification message"""

        try:
            error, suberror = struct.unpack('!BB', message[:2])
        except struct.error:
            raise BadMessageLength(self)

        return error, suberror, message[2:]

    def openReceived(self, version, ASN, holdTime, bgpId):
        """Called when a BGP Open message was received."""

        # DEBUG
        print "OPEN: version:", version, "ASN:", ASN, "hold time:", \
            holdTime, "id:", bgpId

        self.peerId = bgpId
        self.bgpPeering.setPeerId(bgpId)

        # Perform collision detection
        self.collisionDetect()

        self.negotiateHoldTime(holdTime)
        self.fsm.openReceived()

    def updateReceived(self, withdrawnPrefixes, attributes, nlri):
        """Called when a BGP Update message was received."""

        try:
            attrSet = AttributeDict(attributes, checkMissing=(len(nlri)>0))
        except AttributeException, e:
            if type(e.data) is tuple:
                self.fsm.updateError(e.suberror, (e.data[2] and self.encodeAttribute(e.data) or chr(e.data[1])))
            else:
                self.fsm.updateError(e.suberror)
        else:
            self.fsm.updateReceived((withdrawnPrefixes, attrSet, nlri))

    def keepAliveReceived(self):
        """Called when a BGP KeepAlive message was received.
        """

        assert self.fsm.holdTimer.active()
        self.fsm.keepAliveReceived()

    def notificationReceived(self, error, suberror, data=''):
        """Called when a BGP Notification message was received.
        """

        # DEBUG
        print "NOTIFICATION:", error, suberror, [ord(d) for d in data]

        self.fsm.notificationReceived(error, suberror)

    def negotiateHoldTime(self, holdTime):
        """Negotiates the hold time"""

        self.fsm.holdTime = min(self.fsm.holdTime, holdTime)
        if self.fsm.holdTime != 0 and self.fsm.holdTime < 3:
            self.fsm.openMessageError(ERR_MSG_OPEN_UNACCPT_HOLD_TIME)

        # Derived times
        self.fsm.keepAliveTime = self.fsm.holdTime / 3

        # DEBUG
        print "Hold time:", self.fsm.holdTime, "Keepalive time:", self.fsm.keepAliveTime

    def collisionDetect(self):
        """Performs collision detection. Outsources to factory class BGPPeering."""

        return self.bgpPeering.collisionDetect(self)

    def isOutgoing(self):
        """Returns True when this protocol represents an outgoing connection,
        and False otherwise."""

        return (self.transport.getPeer().port == PORT)


    def _capabilities(self):
        # Determine capabilities
        capabilities = []
        for afi, safi in list(self.factory.addressFamilies):
            capabilities.append((CAP_MP_EXT, struct.pack('!HBB', afi, 0, safi)))

        return capabilities

    @staticmethod
    def parseEncodedPrefixList(data, addressFamily=AFI_INET):
        """Parses an RFC4271 encoded blob of BGP prefixes into a list"""

        prefixes = []
        postfix = data
        while len(postfix) > 0:
            prefixLen = ord(postfix[0])
            if (addressFamily == AFI_INET and prefixLen > 32
                ) or (addressFamily == AFI_INET6 and prefixLen > 128):
                raise BGPException(ERR_MSG_UPDATE, ERR_MSG_UPDATE_INVALID_NETWORK_FIELD)

            octetLen, remainder = prefixLen / 8, prefixLen % 8
            if remainder > 0:
                # prefix length doesn't fall on octet boundary
                octetLen += 1

            prefixData = map(ord, postfix[1:octetLen+1])
            # Zero the remaining bits in the last octet if it didn't fall
            # on an octet boundary
            if remainder > 0:
                prefixData[-1] = prefixData[-1] & (255 << (8-remainder))

            prefixes.append(IPPrefix((prefixData, prefixLen), addressFamily))

            # Next prefix
            postfix = postfix[octetLen+1:]

        return prefixes

    @staticmethod
    def parseEncodedAttributes(data):
        """Parses an RFC4271 encoded blob of BGP prefixes into a list"""

        attributes = []
        postfix = data
        while len(postfix) > 0:
            flags, typeCode = struct.unpack('!BB', postfix[:2])

            if flags & ATTR_EXTENDED_LEN:
                attrLen = struct.unpack('!H', postfix[2:4])[0]
                value = postfix[4:4+attrLen]
                postfix = postfix[4+attrLen:]    # Next attribute
            else:    # standard 1-octet length
                attrLen = ord(postfix[2])
                value = postfix[3:3+attrLen]
                postfix = postfix[3+attrLen:]    # Next attribute

            attribute = (flags, typeCode, value)
            attributes.append(attribute)

        return attributes

    @staticmethod
    def encodeAttribute(attrTuple):
        """Encodes a single attribute"""

        flags, typeCode, value = attrTuple
        if flags & ATTR_EXTENDED_LEN:
            fmtString = '!BBH'
        else:
            fmtString = '!BBB'

        return struct.pack(fmtString, flags, typeCode, len(value)) + value

    @staticmethod
    def encodeAttributes(attributes):
        """Encodes a set of attributes"""

        attrData = ""
        for attr in attributes.itervalues():
            if isinstance(attr, Attribute):
                attrData += attr.encode()
            else:
                attrData += BGP.encodeAttribute(attr)

        return attrData

    @staticmethod
    def encodeSomePrefixes(prefixSet, bArray, offset, maxLen):
        """
        Encodes as many IPPrefix prefixes from set prefixSet as will fit
        within maxLen. Removes prefixes from the set as they are added,
        so leaves any remaining prefixes didn't fit.
        Returns the number of prefixes added.
        """

        if not isinstance(prefixSet, set):
            raise TypeError("prefixSet needs to be instance of set()")

        bytesWritten = 0
        prefixesAdded = 0
        while True:
            try:
                prefix = prefixSet.pop()
            except KeyError:
                # Set is empty
                break
            else:
                octetLen, remainder = len(prefix) / 8, len(prefix) % 8
                if remainder > 0:
                    # prefix length doesn't fall on octet boundary
                    octetLen += 1
                if maxLen - bytesWritten >= octetLen + 1:
                    if len(bArray) - offset - bytesWritten < octetLen + 1:
                        # Make space
                        bArray.extend(b'\0' * (octetLen + 1
                            - (len(bArray) - offset- bytesWritten)))
                    struct.pack_into(
                        ("!B%ds" % octetLen),
                        bArray, (offset + bytesWritten),
                        len(prefix), prefix.packed()[:octetLen])
                    bytesWritten += (octetLen+1)
                    prefixesAdded += 1
                else:
                    # We didn't have space, put the prefix back
                    prefixSet.add(prefix)
                    break

        return prefixesAdded

    @staticmethod
    def encodePrefixes(prefixes):
        """Encodes a list of IPPrefix"""

        prefixData = bytearray()
        for prefix in prefixes:
            octetLen, remainder = len(prefix) / 8, len(prefix) % 8
            if remainder > 0:
                # prefix length doesn't fall on octet boundary
                octetLen += 1

            prefixData.extend(struct.pack('!B', len(prefix)) + prefix.packed()[:octetLen])

        return bytes(prefixData)


class BGPFactory(protocol.Factory):
    """Base factory for creating BGP protocol instances"""

    protocol = BGP
    FSM = FSM

    myASN = None
    bgpId = None

    def buildProtocol(self, addr):
        """Builds a BGPProtocol instance"""

        assert self.myASN is not None

        return protocol.Factory.buildProtocol(self, addr)

    def startedConnecting(self, connector):
        """Called when a connection attempt has been initiated."""
        pass

    def clientConnectionLost(self, connector, reason):
        # DEBUG
        print "Client connection lost:", reason.getErrorMessage()

class BGPServerFactory(BGPFactory):
    """Class managing the server (listening) side of the BGP
    protocol. Hands over the factory work to a specific BGPPeering
    (factory) instance.
    """

    def __init__(self, peers, myASN=None):
        self.peers = peers
        self.myASN = myASN

    def buildProtocol(self, addr):
        """Builds a BGPProtocol instance by finding an appropriate
        BGPPeering factory instance to hand over to.
        """

        # DEBUG
        print "Connection received from", addr.host

        try:
            bgpPeering = self.peers[addr.host]
        except KeyError:
            # This peer is unknown. Reject the incoming connection.
            return None

        return bgpPeering.takeServerConnection(addr)


class BGPPeering(BGPFactory):
    """Class managing a BGP session with a peer"""

    implements(IBGPPeering, interfaces.IPushProducer)

    def __init__(self, myASN=None, peerAddr=None):
        self.myASN = myASN
        self.peerAddr = peerAddr
        self.peerId = None
        self.fsm = BGPFactory.FSM(self)
        self.addressFamilies = set(( AFI_INET, SAFI_UNICAST ))
        self.inConnections = []
        self.outConnections = []
        self.estabProtocol = None    # reference to the BGPProtocol instance in ESTAB state
        self.consumers = set()

    def buildProtocol(self, addr):
        """Builds a BGP protocol instance"""

        print "Building a new BGP protocol instance"

        p = BGPFactory.buildProtocol(self, addr)
        if p is not None:
            self._initProtocol(p, addr)
            self.outConnections.append(p)

        return p

    def takeServerConnection(self, addr):
        """Builds a BGP protocol instance for a server connection"""

        p = BGPFactory.buildProtocol(self, addr)
        if p is not None:
            self._initProtocol(p, addr)
            self.inConnections.append(p)

        return p

    def _initProtocol(self, protocol, addr):
        """Initializes a BGPProtocol instance"""

        protocol.bgpPeering = self

        # Hand over the FSM
        protocol.fsm = self.fsm
        protocol.fsm.protocol = protocol

        # Create a new fsm for internal use for now
        self.fsm = BGPFactory.FSM(self)
        self.fsm.state = protocol.fsm.state

        if addr.port == PORT:
            protocol.fsm.state = ST_CONNECT
        else:
            protocol.fsm.state = ST_ACTIVE

        # Set up callback and error handlers
        protocol.deferred.addCallbacks(self.sessionEstablished, self.protocolError)

    def clientConnectionFailed(self, connector, reason):
        """Called when the outgoing connection failed."""

        # DEBUG
        print "Client connection failed:", reason.getErrorMessage()

        # There is no protocol instance yet at this point.
        # Catch a possible NotificationException
        try:
            self.fsm.connectionFailed()
        except NotificationSent, e:
            # TODO: error handling
            pass

    def manualStart(self):
        """BGP ManualStart event (event 1)"""

        if self.fsm.state == ST_IDLE:
            self.fsm.manualStart()
            # Create outbound connection
            self.connect()
            self.fsm.state = ST_CONNECT

    def manualStop(self):
        """BGP ManualStop event (event 2) Returns a Deferred that will fire once the connection(s) have closed"""

        # This code is currently synchronous, so no need to actually wait

        for c in self.inConnections + self.outConnections:
            # Catch a possible NotificationSent exception
            try:
                c.fsm.manualStop()
            except NotificationSent, e:
                pass

        return defer.succeed(True)

    def automaticStart(self, idleHold=False):
        """BGP AutomaticStart event (event 3)"""

        if self.fsm.state == ST_IDLE:
            if self.fsm.automaticStart(idleHold):
                # Create outbound connection
                self.connect()
                self.fsm.state = ST_CONNECT

    def releaseResources(self, protocol):
        """
        Called by FSM when BGP resources (routes etc.) should be released
        prior to ending a session.
        """
        pass

    def connectionClosed(self, protocol, disconnect=False):
        """
        Called by FSM or Protocol when the BGP connection has been closed.
        """

        print "Connection closed"

        if protocol is not None:
            # Connection succeeded previously, protocol exists
            # Remove the protocol, if it exists
            try:
                if protocol.isOutgoing():
                    self.outConnections.remove(protocol)
                else:
                    self.inConnections.remove(protocol)
            except ValueError:
                pass

            if protocol is self.estabProtocol:
                self.estabProtocol = None
                # self.fsm should still be valid and set to ST_IDLE
                assert self.fsm.state == ST_IDLE

        if self.fsm.allowAutomaticStart: self.automaticStart(idleHold=True)

    def completeInit(self, protocol):
        """
        Called by FSM when BGP resources should be initialized.
        """

    def sessionEstablished(self, protocol):
        """Called when the BGP session was established"""

        # The One True protocol
        self.estabProtocol = protocol
        self.fsm = protocol.fsm

        # Create a new deferred for later possible errors
        protocol.deferred = defer.Deferred()
        protocol.deferred.addErrback(self.protocolError)

        # Kill off all other possibly running protocols
        for p in self.inConnections + self.outConnections:
            if p != protocol:
                try:
                    p.fsm.openCollisionDump()
                except NotificationSent, e:
                    pass

        # BGP announcements / UPDATE messages can be sent now
        self.sendAdvertisements()

    def connectRetryEvent(self, protocol):
        """Called by FSM when we should reattempt to connect."""

        self.connect()

    def protocolError(self, failure):
        failure.trap(BGPException)

        print "BGP exception", failure

        e = failure.check(NotificationSent)
        try:
            # Raise the original exception
            failure.raiseException()
        except NotificationSent, e:
            if (e.error, e.suberror) == (ERR_MSG_UPDATE, ERR_MSG_UPDATE_ATTR_FLAGS):
                print "exception on flags:", BGP.parseEncodedAttributes(e.data)
            else:
                print e.error, e.suberror, e.data

        # FIXME: error handling

    def setPeerId(self, bgpId):
        """
        Should be called when an Open message was received from a peer.
        Sets the BGP identifier of the peer if it wasn't set yet. If the
        new peer id is unequal to the existing one, CEASE all connections.
        """

        if self.peerId is None:
            self.peerId = bgpId
        elif self.peerId != bgpId:
            # Ouch, schizophrenia. The BGP id of the peer is unequal to
            # the ids of current and/or previous sessions. Close all
            # connections.
            self.peerId = None
            for c in self.inConnections + self.outConnections:
                try:
                    c.fsm.openCollisionDump()
                except NotificationSent, e:
                    c.deferred.errback(e)

    def collisionDetect(self, protocol):
        """
        Runs the collision detection algorithm as defined in the RFC.
        Returns True if the requesting protocol has to CEASE
        """

        # Construct a list of other connections to examine
        openConfirmConnections = [c
             for c
             in self.inConnections + self.outConnections
             if c != protocol and c.fsm.state in (ST_OPENCONFIRM, ST_ESTABLISHED)]

        # We need at least 1 other connections to have a collision
        if len(openConfirmConnections) < 1:
            return False

        # A collision exists at this point.

        # If one of the other connections is already in ESTABLISHED state,
        # it wins
        if ST_ESTABLISHED in [c.fsm.state for c in openConfirmConnections]:
            protocol.fsm.openCollisionDump()
            return True

        # Break the tie
        assert self.bgpId != protocol.peerId
        if self.bgpId < protocol.peerId:
            dumpList = self.outConnections
        elif self.bgpId > protocol.peerId:
            dumpList = self.inConnections

        for c in dumpList:
            try:
                c.fsm.openCollisionDump()
            except NotificationSent, e:
                c.deferred.errback(e)

        return (protocol in dumpList)

    def connect(self):
        """Initiates a TCP connection to the peer. Should only be called from
        BGPPeering or FSM, otherwise use manualStart() instead.
        """

        # DEBUG
        print "(Re)connect to", self.peerAddr

        if self.fsm.state != ST_ESTABLISHED:
            reactor.connectTCP(self.peerAddr, PORT, self)
            return True
        else:
            return False

    def pauseProducing(self):
        """IPushProducer method - noop"""
        pass

    def resumeProducing(self):
        """IPushProducer method - noop"""
        pass

    def registerConsumer(self, consumer):
        """Subscription interface to BGP update messages"""

        consumer.registerProducer(self, streaming=True)
        self.consumers.add(consumer)

    def unregisterConsumer(self, consumer):
        """Unsubscription interface to BGP update messages"""

        consumer.unregisterProducer()
        self.consumers.remove(consumer)

    def update(self, update):
        """Called by FSM when a BGP Update message is received."""

        # Write to all BGPPeering consumers
        for consumer in self.consumers:
            consumer.write(update)

    def sendAdvertisements(self):
        """Called when the BGP session is established, and announcements can be sent."""
        pass

    def setEnabledAddressFamilies(self, addressFamilies):
        """
        Expects a dict with address families to be enabled,
        containing iterables with Sub-AFIs
        """

        for afi, safi in list(addressFamilies):
            if afi not in SUPPORTED_AFI or safi not in SUPPORTED_SAFI:
                raise ValueError("Address family (%d, %d) not supported" % (afi, safi))

        self.addressFamilies = addressFamilies

class NaiveBGPPeering(BGPPeering):
    """
    "Naive" class managing a simple BGP session, not optimized for very many
    announced prefixes.
    """

    def __init__(self, myASN=None, peerAddr=None):
        BGPPeering.__init__(self, myASN, peerAddr)

        # Dicts of sets per (AFI, SAFI) combination
        self.advertised = {}
        self.toAdvertise = {}

    def completeInit(self, protocol):
        """
        Called by FSM when BGP resources should be initialized.
        """

        BGPPeering.completeInit(self, protocol)

        # (Re)init the existing set, they may get reused
        self.advertised = {}

    def sendAdvertisements(self):
        """
        Called when the BGP session has been established and is
        ready for sending announcements.
        """

        self._sendUpdates(self.advertised, self.toAdvertise)

    def setAdvertisements(self, advertisements):
        """
        Takes a set of Advertisements that will be announced.
        """

        self.toAdvertise = {}
        for af in self.addressFamilies:
            self.advertised.setdefault(af, set())
            self.toAdvertise[af] = set([ad for ad in iter(advertisements) if ad.addressfamily == af])

        # Try to send
        self._sendUpdates(*self._calculateChanges())

    def _calculateChanges(self):
        """Calculates the needed updates (for all address (sub)families)
        between previous advertisements (self.advertised) and to be
        advertised NLRI (in self.toAdvertise)
        """

        withdrawals, updates = {}, {}
        for af in set(self.advertised.keys() + self.toAdvertise.keys()):
            withdrawals[af] = self.advertised[af] - self.toAdvertise[af]
            updates[af] = self.toAdvertise[af] - self.advertised[af]

        return withdrawals, updates


    def _sendUpdates(self, withdrawals, updates):
        """
        Takes a dict of sets of withdrawals and a dict of sets of
        updates (both per (AFI, SAFI) combination), sorts them to
        equal attributes and sends the advertisements if possible.
        Assumes that self.toAdvertise reflects the advertised state
        after withdrawals and updates.
        """

        # This may have to wait for another time...
        if not self.estabProtocol or self.fsm.state != ST_ESTABLISHED:
            return

        # Process per (AFI, SAFI) pair
        for af in set(withdrawals.keys() + updates.keys()):
            withdrawals.setdefault(af, set())
            updates.setdefault(af, set())

            # Map equal attributes to advertisements
            attributeMap = {}
            for advertisement in updates[af]:
                attributeMap.setdefault(advertisement.attributes, set()).add(advertisement)

            # Send
            if af == (AFI_INET, SAFI_UNICAST):
                self._sendInetUnicastUpdates(withdrawals[af], attributeMap)
            else:
                # NLRI for address families other than inet unicast should
                # get sent in MP Reach NLRI and MP Unreach NLRI attributes
                self._sendMPUpdates(af, withdrawals[af], attributeMap)

            self.advertised[af] = self.toAdvertise[af]

    def _sendInetUnicastUpdates(self, withdrawals, attributeMap):
        """
        Sends (multiple) UPDATE messages for the inet-unicast way,
        i.e. the straightforward way.

        Arguments:
        - withdrawals: a set of advertisements to withdraw
        - attributeMap: a dict of FrozenAttributeDict to updates sets
        """

        for attributes, advertisements in attributeMap.iteritems():
            withdrawalPrefixSet = set([w.prefix for w in withdrawals])
            adPrefixSet = set([ad.prefix for ad in advertisements])

            bgpupdate = BGPUpdateMessage()
            # Start with withdrawals, if there are any
            while len(withdrawals) > 0:
                prefixesAdded = bgpupdate.addSomeWithdrawals(withdrawalPrefixSet)
                if prefixesAdded == 0:
                    raise ValueError("Could not add any withdrawals")
                if len(withdrawals) > 0:
                    # We overflowed the packet
                    self.estabProtocol.sendMessage(bgpupdate)
                    bgpupdate = BGPUpdateMessage()

            # Attempt to add all attributes and (some) NLRI to the existing
            # packet, to optimize for the common case of small updates.
            # The same prefix SHOULD NOT be sent in both withdrawals
            # and updated NLRI, but NaiveBGPPeering should have already
            # taken care of that.
            try:
                bgpupdate.addAttributes(attributes)
            except ValueError:
                # Alas, didn't fit. Just send out.
                self.estabProtocol.sendMessage(bgpupdate)
            else:
                prefixesAdded = bgpupdate.addSomeNLRI(adPrefixSet)
                if prefixesAdded == 0:
                    # Packet was full, no NLRI added. Nevermind, let's send
                    # this one without attributes & NLRI.
                    bgpupdate.clearAttributes()
                self.estabProtocol.sendMessage(bgpupdate)

            # Start with a clean slate
            while len(adPrefixSet) > 0:
                bgpupdate = BGPUpdateMessage()
                # For inet-unicast, we need to add the complete set of
                # attributes to every packet.
                try:
                    bgpupdate.addAttributes(attributes)
                except ValueError:
                    # Too many attributes to fit an empty packet. That's a
                    # problem we can't solve.
                    raise
                else:
                    prefixesAdded = bgpupdate.addSomeNLRI(adPrefixSet)
                    if prefixesAdded == 0:
                        raise ValueError("Could not add any NLRI prefixes")
                    self.estabProtocol.sendMessage(bgpupdate)

    def _sendMPUpdates(self, addressfamily, withdrawals, attributeMap):
        """
        Sends (multiple) UPDATE messages the RFC4760 way.

        Arguments:
        - addressfamily: (AFI, SAFI) tuple
        - withdrawals: a set of advertisements to withdraw
        - attributeMap: a dict of FrozenAttributeDict to updates sets
        """

        afi, safi = addressfamily

        # Construct MPUnreachNLRI for withdrawals and send them

        while len(withdrawals) > 0:
            bgpupdate = BGPUpdateMessage()
            unreachAttr = MPUnreachNLRIAttribute((afi, safi, []))
            prefixesAdded = unreachAttr.addSomePrefixes(
                prefixSet=set([w.prefix for w in withdrawals[addressfamily]]),
                maxLen=bgpupdate.freeSpace())
            if prefixesAdded == 0:
                raise ValueError("Could not add any prefixes to MPUnreachNLRI attribute")
            bgpupdate.addAttributes(FrozenAttributeDict(unreachAttr))
            self.estabProtocol.sendMessage(bgpupdate)

        # Move NLRI into MPReachNLRI attributes and send them

        for attributes, advertisements in attributeMap.iteritems():
            newAttributes = AttributeDict(attributes)   # Shallow copy
            # Filter existing MPReachNLRIAttribute from the existing map
            try:
                origReachAttr = newAttributes.pop(MPReachNLRIAttribute)
            except KeyError:
                raise ValueError("Missing MPReachNLRIAttribute")

            adPrefixSet = set([ad.prefix for ad in advertisements])
            while len(adPrefixSet) > 0:
                bgpupdate = BGPUpdateMessage()
                # We need to add the complete set of attributes besides
                # MPReachNLRI to every packet.
                try:
                    bgpupdate.addAttributes(newAttributes)
                except ValueError:
                    # Too many attributes to fit an empty packet. That's a
                    # problem we can't solve.
                    raise
                else:
                    # FIXME: MPReachNLRIAttribute.fromTuple(origReachAttr.tuple()) doesn't work
                    # as tuple() returns a decoded tuple, not an encoded tuple. Attribute classes
                    # overload self.value for both.
                    reachAttr = MPReachNLRIAttribute(value=origReachAttr.tuple()[2])
                    prefixesAdded = reachAttr.addSomePrefixes(
                        adPrefixSet, maxLen=bgpupdate.freeSpace())
                    if prefixesAdded == 0:
                        raise ValueError("Could not add any prefixes to MPReachNLRI attribute")
                    bgpupdate.addAttributes(FrozenAttributeDict([reachAttr]))
                    self.estabProtocol.sendMessage(bgpupdate)
