# ip.py
# Copyright (c) 2007 by Mark Bergsma <mark@nedworks.org>

import struct

# Constants
AFI_INET = 1
AFI_INET6 = 2

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
