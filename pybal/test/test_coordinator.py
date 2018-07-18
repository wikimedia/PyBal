# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.coordinator`.

"""

import mock
import unittest

import pybal.coordinator
import pybal.server
import pybal.util

from twisted.internet.reactor import getDelayedCalls

from .fixtures import PyBalTestCase


class CoordinatorTestCase(PyBalTestCase):
    """Test case for `pybal.coordinator.Coordinator`."""

    def setUp(self):
        super(CoordinatorTestCase, self).setUp()

        configUrl = "file:///dev/null"

        self.coordinator = pybal.coordinator.Coordinator(
                mock.MagicMock(), configUrl)

        self.coordinator.lvsservice.getDepoolThreshold = mock.MagicMock(
                return_value=0.5)

        self.coordinator.lvsservice.assignServers = mock.MagicMock(
            side_effect=self.lvsservice.assignServers)
        self.coordinator.lvsservice.addServer = mock.MagicMock(
            side_effect=self.lvsservice.addServer)
        self.coordinator.lvsservice.removeServer = mock.MagicMock(
            side_effect=self.lvsservice.removeServer)

    def tearDown(self):
        self.coordinator.configObserver.reloadTask.stop()

        for call in getDelayedCalls():
            if call.func.func_name == 'maybeParseConfig':
                call.cancel()

    def setServers(self, servers, **kwargs):
        """
        Takes a dictionary of server hostnames to a dict of (initial)
        configuration values, and passes this to coordinator.onConfigUpdate,
        which will construct new Server instances when necessary, and
        ensure the coordinator uses this list as the complete set
        of current servers.

        After that, all servers will have their attributes updates from kwargs
        for subsequent tests. No additional validation is done to ensure these
        attributes and their values make sense.
        """

        # Pass the server list to coordinator.onConfigUpdate to ensure it's
        # the complete new configuration/server list.
        with mock.patch.object(pybal.server.Server, 'initialize') as mock_initialize:
            self.coordinator.onConfigUpdate(config=servers)

        # Update all servers with attributes from kwargs
        for server in self.coordinator.servers.itervalues():
            server.__dict__.update(kwargs)

    def testAssignServers(self):
        # All servers enabled and up
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
            'cp1047.eqiad.wmnet': {}
        }
        self.setServers(servers, up=True, enabled=True, pool=True, is_pooled=True, ready=True)
        self.assertServerInvariants(coordinator=self.coordinator)

        # All hosts should get assigned
        self.coordinator.assignServers()
        self.assertServerInvariants(coordinator=self.coordinator)
        self.coordinator.lvsservice.assignServers.assert_called_with(
            set(self.coordinator.servers.itervalues()))
        self.coordinator.lvsservice.assignServers.reset_mock()

        # One host disabled and thus not pooled
        self.coordinator.servers['cp1045.eqiad.wmnet'].enabled = False
        self.coordinator.servers['cp1045.eqiad.wmnet'].pool = False

        # One host down and thus not pooled
        self.coordinator.servers['cp1046.eqiad.wmnet'].up = False
        self.coordinator.servers['cp1046.eqiad.wmnet'].pool = False

        # One host down but still pooled (depool threshold)
        self.coordinator.servers['cp1047.eqiad.wmnet'].up = False

        # Only 'pooled' hosts should get assigned
        self.coordinator.assignServers()
        self.assertServerInvariants(coordinator=self.coordinator)
        self.coordinator.lvsservice.assignServers.assert_called_with(
            set([self.coordinator.servers['cp1047.eqiad.wmnet']]))
        self.assertTrue(self.coordinator.servers['cp1047.eqiad.wmnet'].is_pooled)
        for server in self.coordinator.servers.itervalues():
            self.assertEquals(server.pool, server.is_pooled, server.host)

    def testRefreshPreexistingServer(self):
        servers = {
            'cp1046.eqiad.wmnet': {},
        }
        self.setServers(servers, up=True, enabled=False, ready=True)
        self.assertServerInvariants(coordinator=self.coordinator)

        for s in self.coordinator.servers.values():
            self.coordinator.refreshPreexistingServer(s)

        self.assertServerInvariants(coordinator=self.coordinator)

        cp1046 = self.coordinator.servers['cp1046.eqiad.wmnet']
        cp1046.pool = True

        self.coordinator.refreshPreexistingServer(cp1046)

        # cp1046 should no longer have 'pool' set (disabled)
        self.assertFalse(cp1046.pool)
        self.assertServerInvariants(coordinator=self.coordinator)

    def testResultDown(self):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }
        self.setServers(servers, up=True, enabled=True)
        self.assertServerInvariants(coordinator=self.coordinator)
        # All enabled and up, but not pooled
        self.assertTrue(all(
            server.enabled and server.up and not server.pool
            for server in self.coordinator.servers.itervalues()))

        mockMonitor = mock.MagicMock()
        cp1045 = self.coordinator.servers['cp1045.eqiad.wmnet']
        mockMonitor.server = cp1045

        with mock.patch.object(self.coordinator, 'depool') as mockDepool:
            self.coordinator.resultDown(mockMonitor, "fake down result")
            self.assertServerInvariants(mockMonitor.server,
                                        coordinator=self.coordinator)
            self.assertFalse(cp1045.up)
            mockDepool.assert_not_called() # wasn't pooled

            # Test whether cp1045 gets depooled
            mockDepool.reset_mock()
            cp1045.up = True
            cp1045.pool = True
            self.coordinator.resultDown(mockMonitor, None)
            self.assertFalse(cp1045.up)
            mockDepool.assert_called()
            cp1045.pool = False
            self.assertServerInvariants(cp1045, coordinator=self.coordinator)

    def testResultUp(self):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }
        self.setServers(servers, up=True, enabled=True, ready=True)

        cp1045 = self.coordinator.servers['cp1045.eqiad.wmnet']
        cp1045.up = False
        cp1045.calcStatus = mock.MagicMock(return_value=False)

        mockMonitor = mock.MagicMock()
        mockMonitor.server = cp1045

        with mock.patch.object(self.coordinator, 'repool') as mockRepool:
            # Another monitor is still down, nothing should happen
            self.coordinator.resultUp(mockMonitor)
            self.assertServerInvariants(mockMonitor.server,
                                        coordinator=self.coordinator)
            self.assertFalse(cp1045.up)
            mockRepool.assert_not_called()

            mockRepool.reset_mock()
            cp1045.calcStatus.return_value = True

            # Expect cp1045 to get repooled
            self.coordinator.resultUp(mockMonitor)
            self.assertTrue(cp1045.up)
            mockRepool.assert_called()
            cp1045.pool = True
            self.assertServerInvariants(mockMonitor.server,
                                        coordinator=self.coordinator)

            mockRepool.reset_mock()

            # Nothing should happen, already up
            self.coordinator.resultUp(mockMonitor)
            self.assertServerInvariants(mockMonitor.server,
                                        coordinator=self.coordinator)
            self.assertTrue(cp1045.up)
            mockRepool.assert_not_called()

            cp1045.enabled = False
            cp1045.up = False
            cp1045.pool = False
            mockRepool.reset_mock()

            # Disabled server, shouldn't get repooled
            self.coordinator.resultUp(mockMonitor)
            self.assertTrue(cp1045.up)
            mockRepool.assert_not_called()
            self.assertServerInvariants(mockMonitor.server,
                                        coordinator=self.coordinator)

    def testDepool(self):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }
        self.setServers(servers, up=True, enabled=True, pool=True, is_pooled=True, ready=True)
        self.assertTrue(self.coordinator.canDepool()) # threshold is mocked at .5

        # 2/2 servers up, can depool
        cp1045 = self.coordinator.servers['cp1045.eqiad.wmnet']
        cp1045.up = False
        self.coordinator.depool(cp1045)
        self.coordinator.lvsservice.removeServer.assert_called_once_with(cp1045)
        self.assertFalse(cp1045.is_pooled)
        self.assertNotIn(cp1045, self.coordinator.pooledDownServers)
        self.assertServerInvariants(coordinator=self.coordinator)

        self.coordinator.lvsservice.reset_mock()

        # 1/2 servers up, can't depool more
        cp1046 = self.coordinator.servers['cp1046.eqiad.wmnet']
        cp1046.up = False
        self.assertFalse(self.coordinator.canDepool())
        self.coordinator.depool(cp1046)
        self.coordinator.lvsservice.removeServer.assert_not_called()
        self.assertTrue(cp1046.is_pooled)
        self.assertIn(cp1046, self.coordinator.pooledDownServers)
        self.assertServerInvariants(coordinator=self.coordinator)

    def testRepool(self):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }
        self.setServers(servers, up=True, enabled=True, pool=False, is_pooled=False, ready=True)

        # The standard case
        cp1045 = self.coordinator.servers['cp1045.eqiad.wmnet']
        self.coordinator.repool(cp1045)
        self.assertTrue(cp1045.pool)
        self.coordinator.lvsservice.addServer.assert_called_with(cp1045)
        self.assertTrue(cp1045.is_pooled)
        self.assertServerInvariants(cp1045, coordinator=self.coordinator)

        # The previously-pooled-but-down case
        self.setServers(servers, enabled=True, pool=True, is_pooled=True, up=False, ready=True)
        # All known servers are pooled-but-down
        self.coordinator.pooledDownServers = set(self.coordinator.servers.itervalues())
        cp1045.up = True
        self.coordinator.repool(cp1045)
        self.assertTrue(cp1045.pool)
        self.assertTrue(cp1045.is_pooled)
        self.assertNotIn(cp1045, self.coordinator.pooledDownServers)

        # With depool threshold at 0.5, cp1046 should have been depooled
        cp1046 = self.coordinator.servers['cp1046.eqiad.wmnet']
        self.assertEqual(self.coordinator.lvsservice.getDepoolThreshold(), 0.5)
        self.coordinator.lvsservice.removeServer.assert_called_with(cp1046)
        self.assertFalse(cp1046.pool)
        self.assertFalse(cp1046.is_pooled)
        self.assertFalse(self.coordinator.pooledDownServers)
        self.assertServerInvariants(coordinator=self.coordinator)

    def test2serversCanDepool(self):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }
        self.setServers(servers, up=True, enabled=True)

        # 2/2 hosts serving traffic. We can depool.
        self.assertTrue(self.coordinator.canDepool())

        # 1 host goes down
        self.coordinator.servers['cp1045.eqiad.wmnet'].up = False

        # By depooling, we would end up with 1/2 hosts serving traffic. We can
        # depool.
        self.assertTrue(self.coordinator.canDepool())

        # The other host goes down too
        self.coordinator.servers['cp1046.eqiad.wmnet'].up = False

        # By depooling, we would end up with 0/2 hosts serving traffic. We
        # cannot depool.
        self.assertFalse(self.coordinator.canDepool())

    def test4serversCanDepool(self):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
            'cp1047.eqiad.wmnet': {},
            'cp1048.eqiad.wmnet': {},
        }
        self.setServers(servers, up=True, enabled=True)

        self.coordinator.servers['cp1045.eqiad.wmnet'].enabled = False

        # 3/4 hosts serving traffic. We can depool.
        self.assertTrue(self.coordinator.canDepool())

        # 1 host goes down
        self.coordinator.servers['cp1046.eqiad.wmnet'].up = False

        # By depooling, we would end up with 2/4 hosts serving traffic. We can
        # depool.
        self.assertTrue(self.coordinator.canDepool())

        # Another host goes down
        self.coordinator.servers['cp1047.eqiad.wmnet'].up = False

        # By depooling, we would end up with 1/4 hosts serving traffic. We
        # cannot depool.
        self.assertFalse(self.coordinator.canDepool())

    def testConfigServerRemoval(self):
        """
        Test whether servers that get deleted in configuration updates gets
        removed by Pybal as well
        """

        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
            'cp1047.eqiad.wmnet': {},
            'cp1048.eqiad.wmnet': {},
        }
        self.setServers(servers, up=True, enabled=True) # calls onConfigUpdate

        # Remove an arbitrary server from the configuration
        removedHostname = servers.popitem()[0]
        removedServer = self.coordinator.servers[removedHostname]
        removedServer.destroy = mock.Mock()
        self.setServers(servers, up=True, enabled=True) # calls onConfigUpdate
        removedServer.destroy.assert_called()
        self.assertNotIn(removedServer, self.coordinator.servers)
