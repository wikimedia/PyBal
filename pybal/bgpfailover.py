#!/usr/bin/python

"""
PyBal
Copyright (C) 2006-2017 by Mark Bergsma <mark@nedworks.org>

LVS Squid balancer/monitor for managing the Wikimedia Squid servers using LVS
"""

from twisted.internet import reactor

from pybal.util import log
try:
    from pybal.bgp import bgp
except ImportError:
    pass


class BGPFailover:
    """Class for maintaining a BGP session to a router for IP address failover"""

    prefixes = {}
    peerings = []

    def __init__(self, globalConfig):
        self.globalConfig = globalConfig

        if self.globalConfig.getboolean('bgp', False):
            self.setup()

    def setup(self):
        try:
            self.bgpPeering = bgp.NaiveBGPPeering(myASN=self.globalConfig.getint('bgp-local-asn'),
                                                  peerAddr=self.globalConfig.get('bgp-peer-address'))

            asPath = [int(asn) for asn in self.globalConfig.get('bgp-as-path', str(self.bgpPeering.myASN)).split()]
            med = self.globalConfig.getint('bgp-med', 0)
            baseAttrs = [bgp.OriginAttribute(), bgp.ASPathAttribute(asPath)]
            if med:
                baseAttrs.append(bgp.MEDAttribute(med))

            attributes = {}
            try:
                attributes[(bgp.AFI_INET, bgp.SAFI_UNICAST)] = bgp.FrozenAttributeDict(baseAttrs + [
                    bgp.NextHopAttribute(self.globalConfig['bgp-nexthop-ipv4'])])
            except KeyError:
                if (bgp.AFI_INET, bgp.SAFI_UNICAST) in BGPFailover.prefixes:
                    raise ValueError("IPv4 BGP NextHop (global configuration variable 'bgp-nexthop-ipv4') not set")

            try:
                attributes[(bgp.AFI_INET6, bgp.SAFI_UNICAST)] = bgp.FrozenAttributeDict(baseAttrs + [
                    bgp.MPReachNLRIAttribute((bgp.AFI_INET6, bgp.SAFI_UNICAST,
                                             bgp.IPv6IP(self.globalConfig['bgp-nexthop-ipv6']), []))])
            except KeyError:
                if (bgp.AFI_INET6, bgp.SAFI_UNICAST) in BGPFailover.prefixes:
                    raise ValueError("IPv6 BGP NextHop (global configuration variable 'bgp-nexthop-ipv6') not set")

            advertisements = set([bgp.Advertisement(prefix, attributes[af], af)
                                  for af in attributes.keys()
                                  for prefix in BGPFailover.prefixes.get(af, set())])

            self.bgpPeering.setEnabledAddressFamilies(set(attributes.keys()))
            self.bgpPeering.setAdvertisements(advertisements)
            self.bgpPeering.automaticStart()
        except Exception:
            log.critical("Could not set up BGP peering instance.")
            raise
        else:
            BGPFailover.peerings.append(self.bgpPeering)
            reactor.addSystemEventTrigger('before', 'shutdown', self.closeSession, self.bgpPeering)
            try:
                # Try to listen on the BGP port, not fatal if fails
                reactor.listenTCP(bgp.PORT, bgp.BGPServerFactory({self.bgpPeering.peerAddr: self.bgpPeering}))
            except Exception:
                pass

    def closeSession(self, peering):
        log.info("Clearing session to {}".format(peering.peerAddr))
        # Withdraw all announcements
        peering.setAdvertisements(set())
        return peering.manualStop()

    @classmethod
    def addPrefix(cls, prefix):
        try:
            if ':' not in prefix:
                cls.prefixes.setdefault((bgp.AFI_INET, bgp.SAFI_UNICAST), set()).add(bgp.IPv4IP(prefix))
            else:
                cls.prefixes.setdefault((bgp.AFI_INET6, bgp.SAFI_UNICAST), set()).add(bgp.IPv6IP(prefix))
        except NameError:
            # bgp not imported
            pass
