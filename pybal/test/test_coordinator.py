# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.coordinator`.

"""
import mock

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

    def tearDown(self):
        self.coordinator.configObserver.reloadTask.stop()

        for call in getDelayedCalls():
            if call.func.func_name == 'maybeParseConfig':
                call.cancel()

    def setServers(self, servers):
        self.coordinator.onConfigUpdate(config=servers)

        for server in self.coordinator.servers.itervalues():
            server.up = True
            server.enabled = True

    @mock.patch('pybal.server.Server.initialize')
    def test2serversCanDepool(self, mock_initialize):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
        }
        self.setServers(servers)

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

    @mock.patch('pybal.server.Server.initialize')
    def test4serversCanDepool(self, mock_initialize):
        servers = {
            'cp1045.eqiad.wmnet': {},
            'cp1046.eqiad.wmnet': {},
            'cp1047.eqiad.wmnet': {},
            'cp1048.eqiad.wmnet': {},
        }
        self.setServers(servers)

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
