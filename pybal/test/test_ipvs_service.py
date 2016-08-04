import mock
import socket

from gnlpy import ipvs as netlink

from pybal.ipvs import service
from pybal.test import fixtures
from pybal.ipvs.exception import IpvsError

class IpvsServiceTestCase(fixtures.IpvsTestCase):

    def getPool(self):
        serv = service.Service.from_tuple(('tcp', '192.168.1.1', 6379))
        return netlink.Pool({'service': serv, 'dests': []})

    def testFromTuple(self):
        tup = ('proto', 'vip', 'port', 'sched')
        s = service.Service.from_tuple(tup)
        for k, v in s.items():
            self.assertEquals(k, v)
        # Default to round-robin scheduling
        tup = ('proto', 'vip', 'port')
        s = service.Service.from_tuple(tup)
        self.assertEquals(s['sched'], 'rr')

    def testInit(self):
        c = self.getMockClient()
        # An invalid tuple raises an exception
        t = ('tcp', '192.168,0,0', 6379)
        self.assertRaises(AssertionError, service.Service, c, t)
        # A correct initialization will set up all the service variables
        t = ('tcp', '192.168.1.1', 6379)
        s = service.Service(c, t)
        self.assertEquals(s.proto_, 'tcp')
        self.assertEquals(s.vip_, '192.168.1.1')
        self.assertEquals(s.port_, 6379)
        self.assertEquals(s.sched_, 'rr')
        # The FSM has been set up
        self.assertIn('unknown', s.states)
        self.assertIn('present', s.states)
        self.assertIn('present', s.states['unknown'].transitions)
        self.assertIn('unknown', s.states['present'].transitions)
        # State should be 'unknown' given we gave no answer
        self.assertEquals(s.currentState, s.states['unknown'])

    def testCheckActualState(self):
        c = self.getMockClient()
        # If the fsm state is incorrect, an exception is raised.
        t = ('tcp', '192.168.1.1', 6379)
        s = service.Service(c, t)
        s.currentState = s.states['present']
        self.assertRaises(IpvsError, s.assertState)
        # the fsm still thinks it's in state present
        self.assertEquals(s.currentState.name, 'present')
        # if the pool is present, the actual state will become present
        c.get_service.return_value = s
        s.assertState()
        # If not required, assertState will do nothing
        s.currentState = s.states['unknown']
        s.check_state = False
        s.assertState()
        # If the request for pools raises an exception,
        # do not try to catch it.
        s.check_state = True
        with self.assertRaises(Exception):
            c.get_service.side_effect = Exception('something!')
            s.assertState()

    def testTransitionToPresent(self):
        # First situation: service is not present, we transition to s1 (present)
        c = self.getMockClient()
        t = ('tcp', '192.168.1.1', 6379)
        s = service.Service(c, t)
        c.get_service.return_value = None
        d = s.toState('present')
        d.addCallback(self.assertEqual, s.states['present'])
        d.addCallback(lambda _: s.client.add_service.assert_called_with(
            '192.168.1.1', 6379, protocol=socket.IPPROTO_TCP,
            sched_name='rr'))
        # Check the current state has been set
        assert s.currentState == s.states['present']

    def testTransitionToUnknown(self):
        c = self.getMockClient()
        t = ('tcp', '192.168.1.1', 6379)
        c.get_service.return_value = service.Service(c, t)
        s = service.Service(c, t)
        assert s.currentState == s.states['present']
        d = s.toState('unknown')
        d.addCallback(self.assertEqual, s.states['unknown'])
        d.addCallback(lambda _: c.del_service.assert_called_with(
            '192.168.1.1', 6379, protocol=socket.IPPROTO_TCP))
        # Now let's try to move to "unknown" again, nothing will happen
        c.get_service.return_value = None
        c.del_service.reset_mock()
        d1 = s.toState('unknown')
        d1.addCallback(lambda _: c.del_service.assert_not_called())

    def testFaultyTransaction(self):
        c = self.getMockClient()
        t = ('tcp', '192.168.1.1', 6379)
        s = service.Service(c, t)
        c.get_service.return_value = s
        s.currentState = s.states['present']
        # Simulate the netlink layer failing
        c.del_service.side_effect = IpvsError('welcome to the terrordome!')
        # Failure doesn't propagate outside of the fsm
        try:
            d = s.toState('unknown')
        except Exception as e:
            self.fail("Unhandled failure in state transition, %s" % e)

        # Verify that the deferred returns None in this case
        d.addCallback(self.assertEquals, None)
        # State is still present
        d.addCallback(lambda _: self.assertEquals(s.currentState.name,
                                                  'present'))
