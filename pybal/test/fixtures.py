# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains fixtures and helpers for PyBal's test suite.

"""
import unittest

import pybal.util
import twisted.test.proto_helpers
import twisted.trial.unittest
from twisted.internet import defer


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
        self.pool = False

    def textStatus(self):
        return '...'

    def __hash__(self):
        return hash((self.host, self.ip, self.weight, self.port))

    def dumpState(self):
        """Dump current state of the server"""
        return {'pooled': self.pool, 'weight': self.weight,
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

        self.servers = set()
        self.protocol = protocol
        self.ip = ip
        self.port = port
        self.scheduler = scheduler
        self.configuration = configuration

    def assignServers(self, newServers):
        for server in (self.servers | newServers):
            server.is_pooled = (server in newServers)
        self.servers = newServers

    def addServer(self, server):
        server.is_pooled = True

    def removeServer(self, server):
        server.is_pooled = False


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
