# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.server.Server`.

"""

import mock

import pybal.server

from twisted.python import failure
from twisted.internet.reactor import getDelayedCalls

from .fixtures import PyBalTestCase, StubLVSService

class ServerTestCase(PyBalTestCase):
    """Test case for `pybal.server.Server`."""

    def setUp(self):
        super(ServerTestCase, self).setUp()

        self.server = pybal.server.Server(
            'example.com', self.lvsservice)

        self.mockMonitor = mock.MagicMock()
        self.mockCoordinator = mock.MagicMock()
        self.server.addMonitor(self.mockMonitor)

        self.exampleConfigDict = {
            'host': "example1.example.com",
            'weight': 66,
            'enabled': True,
            # FIXME: bug in Server.merge
            #'rogue': "this attribute should not be merged"
        }

    def tearDown(self):
        for call in getDelayedCalls():
            if call.func.func_name == 'maybeParseConfig':
                call.cancel()

    def testEq(self):
        self.assertEquals(self.server, self.server)

        # Create a Server instance with different hostname
        otherServer = pybal.server.Server('other.example.com', self.lvsservice)
        self.assertNotEqual(self.server, otherServer)

        # Create a Server instance with equal hostname but different LVSService
        otherLVSService = StubLVSService(
            'otherservice',
            (self.protocol, self.ip, self.port, self.scheduler),
            self.config)
        otherServer = pybal.server.Server('example.com', otherLVSService)
        self.assertNotEqual(self.server, otherServer)

    def testHash(self):
        # Create a Server instance with different hostname
        otherServer = pybal.server.Server('other.example.com', self.lvsservice)
        self.assertNotEqual(hash(self.server), hash(otherServer))

    def testAddMonitor(self):
        self.assertIn(self.mockMonitor, self.server.monitors)

    def testRemoveMonitors(self):
        self.server.removeMonitors()
        self.assertEqual(len(self.server.monitors), 0)
        self.mockMonitor.stop.assert_called()

    def testResolveHostname(self):
        def callback(result):
            self.assertTrue((result == True or isinstance(result, failure.Failure)))

        deferred = self.server.resolveHostname()
        deferred.addCallback(callback)
        return deferred

    def testDestroy(self):
        self.server.destroy()
        self.assertFalse(self.server.enabled)
        self.assertEqual(len(self.server.monitors), 0)

    def testInitialize(self):
        def callback(result):
            self.assertTrue(isinstance(result, bool))
            self.assertEquals(self.server.ready, result)

        self.server.createMonitoringInstances = mock.MagicMock()
        deferred = self.server.initialize(self.mockCoordinator)
        deferred.addCallback(callback)
        return deferred

    @mock.patch('pybal.server.Server.createMonitoringInstances')
    def testReady(self, mock_createMonitoringInstances):
        r = self.server._ready(True, self.mockCoordinator)
        self.assertTrue(r)
        self.assertTrue(self.server.ready)
        mock_createMonitoringInstances.assert_called()

    def testInitFailed(self):
        r = self.server._initFailed(failure.Failure(Exception("Fake failure")))
        self.assertFalse(r)
        self.assertFalse(self.server.ready)

    def testCreateMonitoringInstances(self):
        assert 'monitors' not in self.config
        self.assertRaises(KeyError,
            self.server.createMonitoringInstances, self.mockCoordinator)

        self.config['monitors'] = "[ \"NonexistentMonitor\" ]"
        self.server.createMonitoringInstances(self.mockCoordinator)

        # TODO: test creation of a (mock) monitor

    def testCalcStatus(self):
        self.mockMonitor.up = True
        self.assertTrue(self.server.calcStatus())
        self.assertTrue(self.server.calcPartialStatus())

        m = mock.MagicMock()
        m.up = True
        self.server.addMonitor(m)
        self.assertTrue(self.server.calcStatus())
        self.assertTrue(self.server.calcPartialStatus())

        m.up = False
        self.assertFalse(self.server.calcStatus())
        self.assertTrue(self.server.calcPartialStatus())

        self.mockMonitor.up = False
        self.assertFalse(self.server.calcPartialStatus())

        # Currently, no monitors implies False Status
        self.server.removeMonitors()
        self.assertFalse(self.server.calcStatus())
        self.assertTrue(self.server.calcPartialStatus())

    def testTextStatus(self):
        textStatus = self.server.textStatus()
        self.assertTrue(isinstance(textStatus, str))
        self.assertEquals(len(textStatus.split('/')), 3)

    def testMaintainState(self):
        self.server.pooled = True
        self.server.enabled = False
        self.server.maintainState()
        self.assertFalse(self.server.pooled)

        self.server.pooled = False
        self.server.enabled = True
        self.server.maintainState()
        self.assertFalse(self.server.up)

    def testMerge(self):
        self.server.merge(self.exampleConfigDict)
        self.assertEquals(self.server.host, self.exampleConfigDict['host'])
        self.assertEquals(self.server.weight, self.exampleConfigDict['weight'])
        self.assertEquals(self.server.enabled, self.exampleConfigDict['enabled'])
        self.assertDictContainsSubset(self.exampleConfigDict, self.server.__dict__)

    def testDumpState(self):
        state = self.server.dumpState()
        self.assertLessEqual(
            {'pooled', 'weight', 'up', 'enabled'},
            set(state.keys()))

    def testBuildServer(self):
        server = self.server.buildServer(
            hostName=self.exampleConfigDict['host'],
            configuration=self.exampleConfigDict,
            lvsservice=mock.MagicMock())
        self.assertTrue(isinstance(server, pybal.server.Server))
        self.assertFalse(server.modified)
