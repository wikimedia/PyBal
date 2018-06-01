#!/usr/bin/python

"""
PyBal
Copyright (C) 2006-2017 by Mark Bergsma <mark@nedworks.org>

LVS Squid balancer/monitor for managing the Wikimedia Squid servers using LVS
"""

from twisted.internet import reactor
from twisted.internet.error import CannotListenError

from pybal.util import log
from pybal.bgp import bgp, peering as bgppeering, attributes as attrs
from pybal.bgp.ip import IPv4IP, IPv6IP
from pybal.metrics import Gauge


class BGPFailover:
    """Class for maintaining BGP sessions to routers for IP address failover"""

    prefixes = {}
    peerings = {}
    ipServices = {}

    metric_keywords = {
        'namespace': 'pybal',
        'subsystem': 'bgp'
    }
    metrics = {
        'enabled': Gauge('enabled', 'BGP Enabled', **metric_keywords)
    }

    def __init__(self, globalConfig):
        # Store globalconfig so setup() can check whether BGP is enabled.
        self.globalConfig = globalConfig
        if not globalConfig.getboolean('bgp', False):
            self.metrics['enabled'].set(0)
            return
        self.metrics['enabled'].set(1)
        self._parseConfig()

    def _parseConfig(self):
        log.info("parsing BGP config", system="bgp")
        self.myASN = self.globalConfig.getint('bgp-local-asn')
        self.asPath = self.globalConfig.get('bgp-as-path', str(self.myASN))
        self.asPath = [int(asn) for asn in self.asPath.split()]

        self.defaultMED = self.globalConfig.getint('bgp-med', 0)

        try:
            self.nexthopIPv4 = self.globalConfig['bgp-nexthop-ipv4']
        except KeyError:
            if (bgp.AFI_INET, bgp.SAFI_UNICAST) in BGPFailover.prefixes:
                raise ValueError("IPv4 BGP NextHop (global configuration variable 'bgp-nexthop-ipv4') not set")

        try:
            self.nexthopIPv6 = self.globalConfig['bgp-nexthop-ipv6']
        except KeyError:
            if (bgp.AFI_INET6, bgp.SAFI_UNICAST) in BGPFailover.prefixes:
                raise ValueError("IPv6 BGP NextHop (global configuration variable 'bgp-nexthop-ipv6') not set")

        bgpPeerAddress = self.globalConfig.get('bgp-peer-address', '').strip()
        if not bgpPeerAddress.startswith('['):
            bgpPeerAddress = "[ \"{}\" ]".format(bgpPeerAddress)
        self.peerAddresses = eval(bgpPeerAddress)
        assert isinstance(self.peerAddresses, list)

    def setup(self):
        if not self.globalConfig.getboolean('bgp', False):
            return

        try:
            advertisements = self.buildAdvertisements()

            for peerAddr in self.peerAddresses:
                peering = bgppeering.NaiveBGPPeering(self.myASN, peerAddr)
                peering.setEnabledAddressFamilies(set(self.prefixes.keys()))
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
                        peering.BGPServerFactory(self.peerings),
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

    def buildAdvertisements(self):
        baseAttrs = attrs.AttributeDict([attrs.OriginAttribute(), attrs.ASPathAttribute(self.asPath)])

        advertisements = set()
        for af in self.prefixes:
            afAttrs = bgp.AttributeDict(baseAttrs)
            if af[0] == (bgp.AFI_INET):
                afAttrs[attrs.NextHopAttribute] = attrs.NextHopAttribute(self.nexthopIPv4)
            elif af[0] == (bgp.AFI_INET6):
                afAttrs[attrs.MPReachNLRIAttribute] = attrs.MPReachNLRIAttribute((af[0], af[1], IPv6IP(self.nexthopIPv6), []))
            else:
                raise ValueError("Unsupported address family {}".format(af))

            for prefix in self.prefixes[af]:
                attributes = bgp.AttributeDict(afAttrs)
                # This service IP may use a non-default MED
                med = self.ipServices[prefix][0]['med'] # Guaranteed to exist, may be None
                if med is None:
                    attributes[attrs.MEDAttribute] = attrs.MEDAttribute(self.defaultMED)
                else:
                    attributes[attrs.MEDAttribute] = attrs.MEDAttribute(med)

                attributes = attrs.FrozenAttributeDict(attributes)
                advertisements.add(bgp.Advertisement(prefix, attributes, af))

        return advertisements

    @classmethod
    def associateService(cls, ip, lvsservice, med):
        if ':' not in ip:
            af = (bgp.AFI_INET, bgp.SAFI_UNICAST)
            prefix = IPv4IP(ip)
        else:
            af = (bgp.AFI_INET6, bgp.SAFI_UNICAST)
            prefix = IPv6IP(ip)

        # All services need to agree on the same MED for this IP
        if prefix in cls.ipServices and not med == cls.ipServices[prefix][0]['med']:
            raise ValueError(
                "LVS service {} MED value {} differs from other MED values for IP {}".format(
                lvsservice.name, med, ip))

        service_state = {
            'lvsservice': lvsservice,
            'af': af,
            'med': med
        }

        cls.ipServices.setdefault(prefix, []).append(service_state)
        cls.prefixes.setdefault(af, set()).add(prefix)
