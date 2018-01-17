# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.server.Server`.

"""

import mock

import pybal.coordinator

from twisted.python import failure
from twisted.internet.reactor import getDelayedCalls

from .fixtures import PyBalTestCase

class ServerTestCase(PyBalTestCase):
    """Test case for `pybal.server.Server`."""

    def setUp(self):
        super(ServerTestCase, self).setUp()

        self.server = pybal.server.Server(
            'example.com', mock.MagicMock())

        self.mockMonitor = mock.MagicMock()
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
        deferred = self.server.initialize(coordinator=mock.MagicMock())
        deferred.addCallback(callback)
        return deferred

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
