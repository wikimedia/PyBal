import mock

from twisted.internet import defer, reactor
from twisted.trial import unittest

from pybal.ipvs import manager
from pybal.test.fixtures import ServerStub


class TestNetlinkServiceManager(unittest.TestCase):

    def setUp(self):
        self.service = ('tcp', '192.168.1.1', 6379, 'wrr')
        self.nl_patcher = mock.patch('pybal.ipvs.manager.IpvsClient')
        self.service_patcher = mock.patch('pybal.ipvs.service.Service')
        self.server_patcher = mock.patch('pybal.ipvs.server.Server')
        self.conf = mock.MagicMock()
        self.nl_mock = self.nl_patcher.start()
        self.service_mock = self.service_patcher.start()
        self.server_mock = self.server_patcher.start()
        server_instance = self.server_mock.return_value
        server_instance.toState.return_value = defer.Deferred()
        server_instance.currentState = mock.PropertyMock()
        self.server_mock.toState = mock.MagicMock(return_value=defer.Deferred())
        self.server = ServerStub('a')

    def tearDown(self):
        self.nl_patcher.stop()
        self.service_patcher.stop()
        self.server_patcher.stop()

    def testInit(self):
        self.conf.getboolean.return_value = False
        mgr = manager.NetlinkServiceManager('foo', self.service, self.conf)
        self.assertEqual(mgr.name, 'foo')
        self.assertEqual(mgr.servers, set())
        self.assertEqual(mgr.destinations, {})
        self.assertEqual(mgr.protocol, 'tcp')
        self.assertEqual(mgr.ip, '192.168.1.1')
        self.assertEqual(mgr.port, 6379)
        self.assertEqual(mgr.scheduler, 'wrr')
        self.assertEqual(mgr.configuration, self.conf)
        self.assertFalse(mgr.Debug)
        self.assertFalse(mgr.DryRun)
        self.nl_mock.assert_called_with(verbose=False)
        self.service_mock.assert_called_with(mgr.nlClient, self.service)
        # Unknown protocol pony raises an exception
        with self.assertRaises(ValueError):
            mgr = manager.NetlinkServiceManager('foo', ('pony', '192.168.1.1', 6379, 'wrr'), self.conf)
        # Unknown scheduler rainbows raises an exception
        with self.assertRaises(ValueError):
            mgr = manager.NetlinkServiceManager('foo', ('udp', '192.168.1.1', 6379, 'rainbows'), self.conf)

    def testService(self):
        """Test `LVSService.service`."""
        lvs_service = manager.NetlinkServiceManager('http', self.service, self.conf)
        self.assertEquals(lvs_service.service(), self.service)

    def testCreateService(self):
        """Test `LVSService.createService`."""
        lvs_service = manager.NetlinkServiceManager('http', self.service, self.conf)
        lvs_service.fsm.toState.assert_called_with('present')

    def testAddServer(self):
        """Test `LVSService.addServer`."""
        lvs_service = manager.NetlinkServiceManager('http', self.service, self.conf)
        d = lvs_service.addServer(self.server)
        self.assertIsInstance(d, defer.Deferred)

        def _test(_):
            self.assertTrue(self.server.pooled)
            self.assertEqual(lvs_service.servers, set([self.server]))
            instance = lvs_service.destinations[self.server.host]
            instance.toState.assert_called_with('up')
            instance.currentState.assert_not_called()

        d.addCallback(_test)
        # Test we go through refresh
        self.server.weight = 3
        d1 = lvs_service.addServer(self.server)

        def _test_b(_):
            instance = lvs_service.destinations[self.server.host]
            self.assertEqual(instance.currentState, instance.states['refresh'])

        d1.addCallback(_test_b)
        reactor.callLater(0, d.callback, None)
        return d

    def testRemoveServer(self):
        lvs_service = manager.NetlinkServiceManager('http', self.service, self.conf)
        lvs_service.servers = set([self.server])

        ipvsserver = lvs_service._to_ipvs(self.server)
        d = lvs_service.removeServer(self.server)
        d.addCallback(lambda _: self.assertEqual(lvs_service.servers, set()))
        d.addCallback(
            lambda _:
            ipvsserver.toState.assert_called_with('unknown')
        )
        reactor.callLater(0, d.callback, None)
        return d

    def testAssignServers(self):
        """Test `LVSService.assignServers`."""
        lvs_service = manager.NetlinkServiceManager('http', self.service, self.conf)
        old_servers = [ServerStub('a'), ServerStub('b'), ServerStub('c'), ServerStub('d')]
        new_servers = set(old_servers)
        new_servers.remove(old_servers[0])
        new_servers.remove(old_servers[1])
        new_servers.add(ServerStub('e'))
        # Initialize values
        lvs_service.servers = set(old_servers)
        lvs_service.addServer = mock.MagicMock(return_value=defer.Deferred())
        lvs_service.removeServer = mock.MagicMock(return_value=defer.Deferred())
        d = lvs_service.assignServers(new_servers)
        self.assertIsInstance(d, defer.DeferredList)
        old_calls = [
            mock.call(old_servers[0]),
            mock.call(old_servers[1])
        ]
        d.addCallback(
            lambda _: lvs_service.removeServer.assert_has_calls(old_calls, any_order=True)
        )
        new_calls = [mock.call(s) for s in new_servers]
        d.addCallback(lambda _: lvs_service.addServer.assert_has_calls(new_calls, any_order=True))
        reactor.callLater(0, d.callback, None)
        return d
