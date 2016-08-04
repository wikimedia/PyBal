"""
pybal.ipvs.exception

Copyright (c) 2006-2017 Mark Bergsma <mark@nedworks.org>

LVS service interface for PyBal - Exceptions
"""
from twisted.internet import reactor

from pybal.util import log


class IpvsError(Exception):
    pass


def abortOnIpvsError(err, *args, **kwargs):
    err.trap(IpvsError)
    log.error("Irrecoverable IPVS error: %s" % err)
    # Todo: pybal should just stop announcing the IP for this service
    # and raise an alert; for now let's just stop pybal
    reactor.stop()
