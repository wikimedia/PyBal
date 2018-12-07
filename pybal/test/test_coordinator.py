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
from twisted.internet import defer

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

    @defer.inlineCallbacks
    def setServers(self, servers, **kwargs):
        """
        Takes a dictionary of server hostnames to a dict of (initial)
        configuration values, and passes this to coordinator.onConfigUpdate,
        which will construct new Server instances when necessary, and
        ensure the coordinator uses this list as the complete set
        of current servers.

        AFTER that, all servers will have their attributes updates from kwargs
        for subsequent tests. No additional validation is done to ensure these
        attributes and their values make sense, and onConfigUpdate is NOT called
        called with the new values.
        """

        # Pass the server list to coordinator.onConfigUpdate to ensure it's
        # the complete new configuration/server list.
        with mock.patch.object(pybal.server.Server,
                               'initialize',
                               return_value=defer.succeed(True)) as mock_initialize:
            yield self.coordinator.onConfigUpdate(config=servers)

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
            'cp1047.eqiad.wmnet': {},
        }
        self.setServers(servers,
            up=True,
            enabled=False,
            ready=True,
            calcStatus=mock.MagicMock(return_value=True))
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

    def testRefreshPreexistingServerDownButPooled(self):
        servers = {
            'cp1046.eqiad.wmnet': {},
            'cp1047.eqiad.wmnet': {},
        }
        self.setServers(servers,
            up=True,
            enabled=False,
            ready=True,
            calcStatus=mock.MagicMock(return_value=True))
        self.assertServerInvariants(coordinator=self.coordinator)

        # Test down-but-pooled case
        cp1047 = self.coordinator.servers['cp1047.eqiad.wmnet']
        cp1047.enabled = True
        cp1047.pool = True
        cp1047.up = False
        cp1047.calcStatus=mock.MagicMock(return_value=False)
        self.coordinator.pooledDownServers.add(cp1047)

        self.assertServerInvariants(coordinator=self.coordinator)

        self.coordinator.refreshPreexistingServer(cp1047)

        # cp1047 should still be pooled
        self.assertTrue(cp1047.pool)
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

        mockMonitor = mock.Mock(spec=pybal.monitor.MonitoringProtocol)
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

        mockMonitor = mock.Mock(spec=pybal.monitor.MonitoringProtocol, server=cp1045, firstCheck=False)

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

    def testResultUpFirstCheck(self):
        """
        Tests whether a Coordinator.resultUp depools any previously down-but-pooled
        servers if possible, on the first check result.
        """

        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }

        self.setServers(servers, enabled=True, pool=True, is_pooled=True, ready=True)
        self.assertServerInvariants(coordinator=self.coordinator)

        cp1045 = self.coordinator.servers['cp1045.eqiad.wmnet']
        cp1046 = self.coordinator.servers['cp1046.eqiad.wmnet']

        # cp1045 was up and pooled from initial initialization
        cp1045.up = True
        # cp1046 was down-but-pooled
        cp1046.up = False
        self.coordinator.pooledDownServers = {cp1046}

        # All of cp1045's monitors are now Up
        for i in range(2):
            cp1045.addMonitor(mock.Mock(spec=pybal.monitor.MonitoringProtocol,
                                        name='monitor{}'.format(i),
                                        server=cp1045,
                                        up=True,
                                        firstCheck=True))


        aMonitor = next(iter(cp1045.monitors))
        with mock.patch.object(self.coordinator, 'repool') as mockRepool:
            self.coordinator.resultUp(aMonitor)
        self.assertTrue(cp1045.up)
        self.assertTrue(cp1045.pool)
        self.assertTrue(cp1045.is_pooled)
        # repool should not have been called, because first checks had not completed.
        mockRepool.assert_not_called()

        # Test the case where the last cp1045 monitor (aMonitor) reports a result
        for monitor in cp1045.monitors:
            monitor.firstCheck = False
        aMonitor.firstCheck = True
        self.coordinator.resultUp(aMonitor)
        self.assertTrue(cp1045.up)
        self.assertTrue(cp1045.pool)
        self.assertTrue(cp1045.is_pooled)

        # With depool threshold at 0.5, cp1046 should have been depooled by repool()
        self.assertEqual(self.coordinator.lvsservice.getDepoolThreshold(), 0.5)
        self.coordinator.lvsservice.removeServer.assert_called_once_with(cp1046)
        self.assertFalse(cp1046.pool)
        self.assertFalse(cp1046.is_pooled)
        self.assertFalse(self.coordinator.pooledDownServers)
        self.assertServerInvariants(coordinator=self.coordinator)

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

    def testRepoolStandard(self):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }
        self.setServers(servers,
            up=True,
            enabled=True,
            pool=False,
            is_pooled=False,
            ready=True,
            calcStatus=mock.MagicMock(return_value=True))

        # The standard case
        cp1045 = self.coordinator.servers['cp1045.eqiad.wmnet']
        self.coordinator.repool(cp1045)
        self.assertTrue(cp1045.pool)
        self.coordinator.lvsservice.addServer.assert_called_with(cp1045)
        self.assertTrue(cp1045.is_pooled)
        self.assertServerInvariants(cp1045, coordinator=self.coordinator)

    def testRepoolPreviouslyPooled(self):
        """
        Tests Coordinator.repool behavior when a server is already pooled but up
        (like on the first check result).
        """

        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }
        self.setServers(servers,
            up=True,
            enabled=True,
            pool=True,
            is_pooled=True,
            ready=True,
            calcStatus=mock.MagicMock(return_value=True))

        # One server up and already pooled (like on first check)
        cp1045 = self.coordinator.servers['cp1045.eqiad.wmnet']
        self.coordinator.repool(cp1045)
        self.assertTrue(cp1045.pool)
        self.coordinator.lvsservice.addServer.assert_not_called()
        self.assertTrue(cp1045.is_pooled)
        self.assertServerInvariants(cp1045, coordinator=self.coordinator)

    def testRepoolPreviouslyPooledButDown(self):
        """
        Tests Coordinator.repool behavior when a server is already pooled and down
        (because of depool threshold)
        """

        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }

        # The previously-pooled-but-down case
        self.setServers(servers,
            enabled=True,
            pool=True,
            is_pooled=True,
            up=False,
            ready=True,
            calcStatus=mock.MagicMock(return_value=False)
        )

        # All known servers are pooled-but-down
        cp1045 = self.coordinator.servers['cp1045.eqiad.wmnet']
        self.coordinator.pooledDownServers = set(self.coordinator.servers.itervalues())
        cp1045.up = True
        self.coordinator.repool(cp1045)
        self.assertTrue(cp1045.pool)
        self.coordinator.lvsservice.addServer.assert_not_called()
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

    def testConfigServerRemovalUpdate(self):
        """
        Test whether servers that get added, deleted or updated in configuration
        updates get added, removed or updated by Pybal as well.
        """

        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
            'cp1047.eqiad.wmnet': {},
            'cp1048.eqiad.wmnet': {},
        }
        with mock.patch.object(self.coordinator,
                               'refreshPreexistingServer') as mock_rPS:
            self.setServers(servers, up=True, enabled=True) # calls onConfigUpdate
        mock_rPS.assert_not_called()

        # Remove an arbitrary server from the configuration
        removedHostname = servers.popitem()[0]
        removedServer = self.coordinator.servers[removedHostname]
        removedServer.destroy = mock.Mock()

        # Update an arbitrary remaining server in the configuration
        updatedHostname = next(iter(servers))
        updatedServer = self.coordinator.servers[updatedHostname]
        servers[updatedHostname]['enabled'] = 'False'
        updatedServer.merge = mock.Mock()

        preexistingServers = set(self.coordinator.servers.values()) - {removedServer}

        # Add a new server
        servers['shiny-new-server.eqiad.wmnet'] = {}
        with mock.patch.object(self.coordinator,
                               'refreshPreexistingServer') as mock_rPS:
            self.setServers(servers) # calls onConfigUpdate

        # Test removed server
        removedServer.destroy.assert_called()
        self.assertNotIn(removedServer, self.coordinator.servers)

        # Test preexisting and updated servers
        updatedServer.merge.assert_called_once_with(servers[updatedHostname])
        # Was refreshPreexistingServer called for all preexisting servers?
        self.assertEqual(len(mock_rPS.call_args_list), len(preexistingServers))
        self.assertEqual({posargs[0] for posargs, kwargs in mock_rPS.call_args_list},
                         preexistingServers)

        # The new server should have been added now.
        self.assertIn('shiny-new-server.eqiad.wmnet', self.coordinator.servers)

    def testEnsureDepoolThreshold(self):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
            'cp1047.eqiad.wmnet': {},
            'cp1048.eqiad.wmnet': {},
        }

        def isDepoolThresholdEnsured():
            threshold = len(self.coordinator.servers) * self.coordinator.lvsservice.getDepoolThreshold()
            pooledServerCount = sum(1 for server in self.coordinator.servers.itervalues() if server.pool)
            return pooledServerCount >= threshold

        self.setServers(servers, up=False, enabled=False, ready=True)   # calls onConfigUpdate
        self.assertFalse(self.coordinator._ensureDepoolThreshold())
        self.assertFalse(isDepoolThresholdEnsured())
        self.setServers(servers, up=False, enabled=True, ready=True, pool=False)  # calls onConfigUpdate
        self.assertTrue(self.coordinator._ensureDepoolThreshold())
        self.assertTrue(isDepoolThresholdEnsured())
