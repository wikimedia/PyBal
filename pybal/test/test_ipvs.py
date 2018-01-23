# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.ipvs`.

"""
import copy
import pybal.ipvs
import pybal.util
import pybal.bgpfailover

from .fixtures import PyBalTestCase, ServerStub


class IPVSManagerTestCase(PyBalTestCase):
    """Test case for `pybal.ipvs.IPVSManager`."""

    def testSubCommandService(self):
        """Test `IPVSManager.subCommandService`."""
        # Maps tuples of (protocol, address, port) to string of ipvsadm
        # args declaring an equivalent virtual network service.
        services = {
            ('tcp', '2620::123', 443): '-t [2620::123]:443',
            ('udp', '208.0.0.1', 123): '-u 208.0.0.1:123',
        }
        for service, expected_subcommand in services.items():
            subcommand = pybal.ipvs.IPVSManager.subCommandService(service)
            self.assertEquals(subcommand, expected_subcommand)

    def testSubCommandServer(self):
        """Test `IPVSManager.subCommandServer`."""
        servers = {
            ServerStub('localhost', None): '-r localhost',
            ServerStub('localhost', '127.0.0.1'): '-r 127.0.0.1',
        }
        for server, expected_subcommand in servers.items():
            subcommand = pybal.ipvs.IPVSManager.subCommandServer(server)
            self.assertEquals(subcommand, expected_subcommand)

    def testCommandClearServiceTable(self):
        """Test `IPVSManager.commandClearServiceTable`."""
        subcommand = pybal.ipvs.IPVSManager.commandClearServiceTable()
        self.assertEquals(subcommand, '-C')

    def testCommandRemoveService(self):
        """Test `IPVSManager.commandRemoveService`."""
        services = {
            ('tcp', '2620::123', 443): '-D -t [2620::123]:443',
            ('udp', '208.0.0.1', 123): '-D -u 208.0.0.1:123',
        }
        for service, expected_subcommand in services.items():
            subcommand = pybal.ipvs.IPVSManager.commandRemoveService(service)
            self.assertEquals(subcommand, expected_subcommand)

    def testCommandAddService(self):
        """Test `IPVSManager.commandAddService`."""
        services = {
            ('tcp', '2620::123', 443): '-A -t [2620::123]:443',
            ('udp', '208.0.0.1', 123, 'rr'): '-A -u 208.0.0.1:123 -s rr',
        }
        for service, expected_subcommand in services.items():
            subcommand = pybal.ipvs.IPVSManager.commandAddService(service)
            self.assertEquals(subcommand, expected_subcommand)

    def testCommandRemoveServer(self):
        """Test `IPVSManager.commandRemoveServer`."""
        service = ('tcp', '2620::123', 443)
        server = ServerStub('localhost', None)
        subcommand = pybal.ipvs.IPVSManager.commandRemoveServer(
            service, server)
        self.assertEquals(subcommand, '-d -t [2620::123]:443 -r localhost')

    def testCommandAddServer(self):
        """Test `IPVSManager.commandAddServer`."""
        service = ('tcp', '2620::123', 443)

        server = ServerStub('localhost', None)
        subcommand = pybal.ipvs.IPVSManager.commandAddServer(service, server)
        self.assertEquals(subcommand, '-a -t [2620::123]:443 -r localhost')

        server.weight = 25
        subcommand = pybal.ipvs.IPVSManager.commandAddServer(service, server)
        self.assertEquals(
            subcommand, '-a -t [2620::123]:443 -r localhost -w 25')

    def testCommandEditServer(self):
        """Test `IPVSManager.commandEditServer`."""
        service = ('tcp', '2620::123', 443)

        server = ServerStub('localhost', None)
        subcommand = pybal.ipvs.IPVSManager.commandEditServer(service, server)
        self.assertEquals(subcommand, '-e -t [2620::123]:443 -r localhost')

        server.weight = 25
        subcommand = pybal.ipvs.IPVSManager.commandEditServer(service, server)
        self.assertEquals(
            subcommand, '-e -t [2620::123]:443 -r localhost -w 25')


class LVSServiceTestCase(PyBalTestCase):
    """Test case for `pybal.ipvs.LVSService`."""

    def setUp(self):
        super(LVSServiceTestCase, self).setUp()
        self.config['dryrun'] = 'true'
        self.service = ('tcp', '127.0.0.1', 80, 'rr', False)
        pybal.bgpfailover.BGPFailover.prefixes.clear()
        pybal.bgpfailover.BGPFailover.ipServices.clear()

        def stubbedModifyState(cls, cmdList):
            cls.cmdList = cmdList

        self.origModifyState = pybal.ipvs.IPVSManager.modifyState
        setattr(pybal.ipvs.IPVSManager, 'modifyState',
                classmethod(stubbedModifyState))

    def tearDown(self):
        pybal.ipvs.IPVSManager.modifyState = self.origModifyState
        pybal.bgpfailover.BGPFailover.prefixes.clear()
        pybal.bgpfailover.BGPFailover.ipServices.clear()

    def testConstructor(self):
        """Test `LVSService.__init__`."""
        with self.assertRaises(ValueError):
            service = ('invalid-protocol', '127.0.0.1', 80, 'rr', False)
            pybal.ipvs.LVSService('invalid-protocol', service, self.config)

        with self.assertRaises(ValueError):
            service = ('tcp', '127.0.0.1', 80, 'invalid-scheduler', False)
            pybal.ipvs.LVSService('invalid-scheduler', service, self.config)

        with self.assertRaises(ValueError):
            service = ('tcp', '127.0.0.1', 80, 'rr', True)
            pybal.ipvs.LVSService('ops-with-tcp', service, self.config)

        self.config['bgp'] = 'true'
        pybal.ipvs.LVSService('http', self.service, self.config)
        self.assertItemsEqual(pybal.bgpfailover.BGPFailover.prefixes, {(1, 1)})

        service = ('tcp', '::1', 443, 'rr', False)
        config = copy.deepcopy(self.config)
        config['bgp-med'] = '50'
        pybal.ipvs.LVSService('per-service-MED', service, config)

        for services in pybal.bgpfailover.BGPFailover.ipServices.itervalues():
            for service in services:
                self.assertIsInstance(service['med'], (type(None), int))

    def testService(self):
        """Test `LVSService.service`."""
        lvs_service = pybal.ipvs.LVSService('http', self.service, self.config)
        self.assertEquals(lvs_service.service(), self.service)

    def testCreateService(self):
        """Test `LVSService.createService`."""
        lvs_service = pybal.ipvs.LVSService('http', self.service, self.config)
        self.assertEquals(lvs_service.ipvsManager.cmdList,
                          ['-D -t 127.0.0.1:80', '-A -t 127.0.0.1:80 -s rr'])

    def testCreateServiceOps(self):
        """Test `LVSService.createService`."""
        service = ('udp', '127.0.0.1', 53, 'rr', True)
        lvs_service = pybal.ipvs.LVSService('dns', service, self.config)
        self.assertEquals(lvs_service.ipvsManager.cmdList,
            ['-D -u 127.0.0.1:53', '-A -u 127.0.0.1:53 -s rr -o'])

    def testAssignServers(self):
        """Test `LVSService.assignServers`."""
        lvs_service = pybal.ipvs.LVSService('http', self.service, self.config)
        old_servers = {ServerStub('a'), ServerStub('b'), ServerStub('c')}
        new_servers = {ServerStub('c'), ServerStub('d'), ServerStub('e')}
        for server in old_servers:
            server.pooled = True
            lvs_service.addServer(server)
        lvs_service.ipvsManager.cmdList = []
        for server in (old_servers | new_servers):
            server.pooled = (server in new_servers)
        lvs_service.assignServers(new_servers)
        self.assertEquals(
            sorted(lvs_service.ipvsManager.cmdList),
            ['-a -t 127.0.0.1:80 -r %s' % s for s in 'cde'] +
            ['-d -t 127.0.0.1:80 -r %s' % s for s in 'abc']
        )
        for server in (old_servers | new_servers):
            self.assertEquals(server.is_pooled, server in new_servers)
            self.assertEquals(server.is_pooled, server.pooled)

    def testAddServer(self):
        """Test `LVSService.addServer`."""
        lvs_service = pybal.ipvs.LVSService('http', self.service, self.config)
        self.server.pooled = True
        lvs_service.addServer(self.server)
        self.assertTrue(self.server.is_pooled)
        self.assertEquals(lvs_service.ipvsManager.cmdList,
                          ['-a -t 127.0.0.1:80 -r 127.0.0.1'])
        lvs_service.addServer(self.server)
        self.assertEquals(lvs_service.ipvsManager.cmdList,
                          ['-e -t 127.0.0.1:80 -r 127.0.0.1'])

    def testRemoveServer(self):
        """Test `LVSService.removeServer`."""
        lvs_service = pybal.ipvs.LVSService('http', self.service, self.config)
        self.server.pooled = True
        lvs_service.addServer(self.server)
        self.server.pooled = False
        lvs_service.removeServer(self.server)
        self.assertFalse(self.server.is_pooled)
        self.assertEquals(lvs_service.ipvsManager.cmdList,
                          ['-d -t 127.0.0.1:80 -r 127.0.0.1'])

    def testInitServer(self):
        """Test `LVSService.initServer`."""
        lvs_service = pybal.ipvs.LVSService('http', self.service, self.config)
        lvs_service.initServer(self.server)
        self.assertEquals(self.server.port, 80)

    def testGetDepoolThreshold(self):
        """Test `LVSService.getDepoolThreshold`."""
        lvs = pybal.ipvs.LVSService('test', self.service, self.config)
        self.assertEquals(lvs.getDepoolThreshold(), 0.5)
        self.config['depool-threshold'] = 0.25
        lvs = pybal.ipvs.LVSService('test', self.service, self.config)
        self.assertEquals(lvs.getDepoolThreshold(), 0.25)
