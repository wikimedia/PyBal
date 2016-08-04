# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains fixtures and helpers for PyBal's test suite.

"""
import unittest

import mock

import pybal.util
import twisted.test.proto_helpers
import twisted.trial.unittest
from twisted.internet import defer

from gnlpy import ipvs as netlink

from pybal.ipvs import service, server


class ServerStub(object):
    """Test stub for `pybal.Server`."""
    def __init__(self, host, ip=None, port=None, weight=None, lvsservice=None):
        self.host = host
        self.ip = ip
        self.weight = weight
        self.port = port
        self.lvsservice = lvsservice
        self.ip4_addresses = set()
        self.ip6_addresses = set()
        if ip is not None:
            (self.ip6_addresses if ':' in ip else self.ip4_addresses).add(ip)
        self.up = False
        self.pooled = False

    def textStatus(self):
        return '...'

    def __repr__(self):
        return "ServerStub(%s)" % self.host

    def __hash__(self):
        return hash((self.host, self.ip, self.weight, self.port))

    def dumpState(self):
        """Dump current state of the server"""
        return {'pooled': self.pooled, 'weight': self.weight,
                'up': self.up}


class StubCoordinator(object):
    """Test stub for `pybal.pybal.Coordinator`."""

    def __init__(self):
        self.up = None
        self.reason = None
        self.servers = {}

    def resultUp(self, monitor):
        self.up = True

    def resultDown(self, monitor, reason=None):
        self.up = False
        self.reason = reason

    def onConfigUpdate(self, config):
        self.config = config


class StubLVSService(object):
    """Test stub for `pybal.ipvs.LVSService`."""

    def __init__(self, name, (protocol, ip, port, scheduler), configuration):
        self.name = name

        self.servers = {}
        self.protocol = protocol
        self.ip = ip
        self.port = port
        self.scheduler = scheduler
        self.configuration = configuration


class MockClientGetPage(object):
    def __init__(self, data):
        self.return_value = data

    def getPage(self, url):
        d = defer.Deferred()
        d.callback(self.return_value)
        return d

    def addErr(self, msg):
        self.errMsg = ValueError(msg)

    def getPageError(self, url):
        d = defer.Deferred()
        d.errback(self.errMsg)
        return d


class PyBalTestCase(twisted.trial.unittest.TestCase):
    """Base class for PyBal test cases."""

    # Use the newer `TestCase.assertRaises` in Python 2.7's stdlib
    # rather than the one provided by twisted.trial.unittest.
    assertRaises = unittest.TestCase.assertRaises

    name = 'test'
    host = 'localhost'
    ip = '127.0.0.1'
    port = 80
    scheduler = 'rr'
    protocol = 'tcp'

    def setUp(self):
        self.coordinator = StubCoordinator()
        self.config = pybal.util.ConfigDict()
        service_def = (self.protocol, self.ip, self.port, self.scheduler)
        self.lvsservice = StubLVSService(self.name, service_def, self.config)
        self.server = ServerStub(self.host, self.ip, self.port,
                                 lvsservice=self.lvsservice)
        self.reactor = twisted.test.proto_helpers.MemoryReactor()


class IpvsTestCase(twisted.trial.unittest.TestCase):

    def getMockClient(self):
        c = mock.MagicMock(spec=netlink.IpvsClient)
        return c

    def getService(self):
        # currentState will be overridden by the actual state
        t = ('tcp', '192.168.1.1', 80)
        s = service.Service(self.client, t)
        s.currentState = s.states['present']
        return s

    def getServer(self, srv=None):
        if srv is None:
            srv = self.getLogicalServers()[0]
        s = self.getService()
        return server.Server(self.client, srv, s)

    def getPool(self, dest_range=range(3)):
        serv = service.Service(self.client, ('tcp', '192.168.1.1', 80))
        dests = []
        for i in dest_range:
            d = netlink.Dest({'ip': '10.0.0.%d' % (i + 1), 'port': 80, 'weight': 10})
            dests.append(d)
        return {'service': serv, 'dests': dests}

    def getLogicalServers(self):
        s = [
            ServerStub('www1.local', ip='10.0.0.1', port=80, weight=10),
            ServerStub('www2.local', ip='10.0.0.2', port=80, weight=10),
            ServerStub('www3.local', ip='10.0.0.3', port=80, weight=10)
        ]
        for srv in s:
            srv.up = True
            srv.pooled = True
        return s
