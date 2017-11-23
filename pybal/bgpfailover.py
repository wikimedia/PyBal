#!/usr/bin/python

"""
PyBal
Copyright (C) 2006-2017 by Mark Bergsma <mark@nedworks.org>

LVS Squid balancer/monitor for managing the Wikimedia Squid servers using LVS
"""

from twisted.internet import reactor
from twisted.internet.error import CannotListenError

from pybal.util import log
try:
    from pybal.bgp import bgp
except ImportError:
    pass


class BGPFailover:
    """Class for maintaining BGP sessions to routers for IP address failover"""

    prefixes = {}
    peerings = {}

    def __init__(self, globalConfig):
        if not globalConfig.getboolean('bgp', False):
            return

        self.globalConfig = globalConfig
        self.setup()

    def setup(self):
        try:
            myASN = self.globalConfig.getint('bgp-local-asn')
            asPath = self.globalConfig.get('bgp-as-path', str(myASN))
            asPath = [int(asn) for asn in asPath.split()]
            med = self.globalConfig.getint('bgp-med', 0)
            baseAttrs = [bgp.OriginAttribute(), bgp.ASPathAttribute(asPath)]
            if med: baseAttrs.append(bgp.MEDAttribute(med))

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

            bgpPeerAddress = self.globalConfig.get('bgp-peer-address', '').strip()
            if bgpPeerAddress[0] != '[': bgpPeerAddress = "[ \"{}\" ]".format(bgpPeerAddress)
            peerAddresses = eval(bgpPeerAddress)
            assert isinstance(peerAddresses, list)

            for peerAddr in peerAddresses:
                peering = bgp.NaiveBGPPeering(myASN, peerAddr)
                peering.setEnabledAddressFamilies(set(attributes.keys()))
                peering.setAdvertisements(advertisements)

                log.info("Starting BGP session with peer {}".format(peerAddr))
                peering.automaticStart()
                self.peerings[peerAddr] = peering
                reactor.addSystemEventTrigger('before', 'shutdown', self.closeSession, peering)

        except Exception:
            log.critical("Could not set up BGP peering instances.")
            raise
        else:

            # Bind on the IPs listed in 'bgp_local_ips'. Default to
            # localhost v4 and v6 if no IPs have been specified in the
            # configuration.
            bgp_local_ips = eval(self.globalConfig.get('bgp-local-ips', '[""]'))
            bgp_local_port = self.globalConfig.getint('bgp-local-port', bgp.PORT)
            # Try to listen on the BGP port, not fatal if fails
            for ip in bgp_local_ips:
                try:
                    reactor.listenTCP(
                        bgp_local_port,
                        bgp.BGPServerFactory(self.peerings),
                        interface=ip)
                except CannotListenError as e:
                    log.critical(
                        "Could not listen for BGP connections: " + str(e))
                    raise

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
