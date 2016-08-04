from pybal.ipvs import server
from pybal.ipvs.exception import IpvsError
from pybal.test.fixtures import ServerStub, IpvsTestCase


def trapValueError(f):
    f.trap(ValueError)
    return None


def callbackFailure(_):
    raise Exception("Not raised the exceptio")


class IpvsServerTestCase(IpvsTestCase):

    def setUp(self):
        self.client = self.getMockClient()
        p = self.getPool()
        # by default, report the service is present
        self.client.get_service.return_value = p['service']
        self.server = self.getServer()

    def testInit(self):
        # An invalid IP address causes an exception
        s = ServerStub('www1.local', '10.0.0,1', 80, 10)
        self.assertRaises(AssertionError, server.Server, self.client, s,
                          self.getService())
        # A non-numeric port causes an exception
        s = ServerStub('www1.local', '10.0.0.1', '80', 10)
        self.assertRaises(AssertionError, server.Server, self.client, s,
                          self.getService())

        # A non-present weight defaults to 1
        s = ServerStub('www1.local', '10.0.0.1', 80)
        srv = server.Server(self.client, s, self.getService())
        self.assertEquals(srv.weight_, 1)

        # The FSM has been set up
        states = ['unknown', 'drained', 'up', 'refresh']
        for state in states:
            self.assertIn(state, srv.states)

        # Status should be 'unkown' since we have no service defined
        srv.assertState()
        self.assertEquals(srv.currentState.name, 'unknown')

    def testCheckActualState(self):
        # All states behave like expected
        # S0
        self.client.get_service.return_value = None
        self.server.assertState()
        self.assertEquals(self.server.currentState.name, 'unknown')
        self.client.get_dests.return_value = []
        self.server.assertState()
        self.assertEquals(self.server.currentState.name, 'unknown')
        # S1
        p = self.getPool()
        dests = p['dests']
        dests[0].weight_ = 0
        self.client.get_dests.return_value = dests
        # if we set check_service to false, assertState() won't do anything.
        self.server.check_state = False
        self.server.assertState()
        self.assertEqual(self.server.currentState.name, 'unknown')
        self.server.check_state = True
        self.assertRaises(IpvsError, self.server.assertState)
        self.assertEquals(self.server._getActualState().name, 'drained')
        # S2
        dests[0].weight_ = self.server.weight()
        self.assertRaises(IpvsError, self.server.assertState)
        self.assertEquals(self.server._getActualState().name, 'up')
        # S3
        dests[0].weight_ = 54
        self.assertEquals(self.server._getActualState().name, 'refresh')
        # If the dests request raises  an exception, it doesn't get caught
        self.client.get_dests.side_effect = Exception('Boom!')
        with self.assertRaises(Exception):
            self.server.assertState()

    def testTransitionFromUnknown(self):
        # Initial state: unknown
        p = self.getPool()
        dests = p['dests']
        myDest = dests[0]
        self.client.get_service.return_value = p['service']
        self.client.get_dests.return_value = []
        # To "up"
        d = self.server.toState('up')
        d.addCallback(
            lambda _: self.client.add_dest.assert_called_with(
                self.server.service.vip(),
                self.server.service.port(),
                self.server.ip(),
                weight=self.server.weight(),
                method=self.server.fwd_method(),
                protocol=6,
            )
        )
        d.addCallback(
            lambda _:
            self.assertEquals(self.server.currentState.name, 'up')
        )
        # To "drained"
        self.server.currentState = self.server.states['unknown']
        d = self.server.toState('drained')
        d.addCallback(
            lambda _: self.client.add_dest.assert_called_with(
                self.server.service.vip(),
                self.server.service.port(),
                self.server.ip(),
                weight=0,
                method=self.server.fwd_method(),
                protocol=6,
            )
        )
        d.addCallback(
            lambda _:
            self.assertEquals(self.server.currentState.name, 'drained')
        )
        # To "referesh" doesn't exist
        self.server.currentState = self.server.states['unknown']
        r = self.server.toState('refresh')
        r.addCallbacks(callbackFailure, trapValueError)

    def testTransitionFromDrained(self):
        p = self.getPool()
        dests = p['dests']
        myDest = dests[0]
        myDest.weight_ = 0
        self.client.get_service.return_value = p['service']
        self.client.get_dests.return_value = dests
        # To unknown
        self.server.currentState = self.server.states['drained']
        d = self.server.toState('unknown')
        d.addCallback(self.assertEquals, self.server.states['unknown'])
        d.addCallback(
            lambda _: self.client.del_dest.assert_called_with(
                self.server.service.vip(),
                self.server.service.port(),
                self.server.ip(),
                protocol=6
            )
        )
        # To up
        self.server.currentState = self.server.states['drained']
        d = self.server.toState('up')
        d.addCallback(self.assertEquals, self.server.states['up'])
        d.addCallback(
            lambda _: self.client.update_dest.assert_called_with(
                self.server.service.vip(),
                self.server.service.port(),
                self.server.ip(),
                protocol=6,
                weight=self.server.weight(),
                method=self.server.fwd_method(),
            )
        )
        # To "referesh" doesn't exist
        self.server.currentState = self.server.states['drained']
        r = self.server.toState('refresh')
        r.addCallbacks(callbackFailure, trapValueError)

    def testTransitionFromUp(self):
        p = self.getPool()
        dests = p['dests']
        self.client.get_dests.return_value = dests
        # To unknown
        self.server.currentState = self.server.states['up']
        d = self.server.toState('unknown')
        d.addCallback(self.assertEquals, self.server.states['unknown'])
        d.addCallback(
            lambda _: self.client.del_dest.assert_called_with(
                self.server.service.vip(),
                self.server.service.port(),
                self.server.ip(),
                protocol=6
            )
        )
        # To drained
        self.server.currentState = self.server.states['up']
        d = self.server.toState('drained')
        d.addCallback(self.assertEquals, self.server.states['drained'])
        d.addCallback(
            lambda _: self.client.update_dest.assert_called_with(
                self.server.service.vip(),
                self.server.service.port(),
                self.server.ip(),
                protocol=6,
                weight=0,
                method=self.server.fwd_method(),
            )
        )
        # To "referesh" doesn't exist
        self.server.currentState = self.server.states['up']
        r = self.server.toState('refresh')
        r.addCallbacks(callbackFailure, trapValueError)

    def testTransitionFromRefresh(self):
        p = self.getPool()
        dests = p['dests']
        myDest = dests[0]
        myDest.weight_ = 147
        self.client.get_service.return_value = p['service']
        self.client.get_dests.return_value = dests
        # to unknown
        self.server.currentState = self.server.states['refresh']
        d = self.server.toState('unknown')
        d.addCallback(self.assertEquals, self.server.states['unknown'])
        d.addCallback(
            lambda _: self.client.del_dest.assert_called_with(
                self.server.service.vip(),
                self.server.service.port(),
                self.server.ip(),
                protocol=6
            )
        )
        # to up
        self.server.currentState = self.server.states['refresh']
        d = self.server.toState('up')
        d.addCallback(self.assertEquals, self.server.states['up'])
        d.addCallback(
            lambda _: self.client.update_dest.assert_called_with(
                self.server.service.vip(),
                self.server.service.port(),
                self.server.ip(),
                protocol=6,
                weight=self.server.weight(),
                method=self.server.fwd_method(),
            )
        )
        # to drained
        self.server.currentState = self.server.states['refresh']
        d = self.server.toState('drained')
        d.addCallback(self.assertEquals, self.server.states['drained'])
        d.addCallback(
            lambda _: self.client.update_dest.assert_called_with(
                self.server.service.vip(),
                self.server.service.port(),
                self.server.ip(),
                protocol=6,
                weight=0,
                method=self.server.fwd_method(),
            )
        )

    def testTransitionCornerCases(self):
        ## If the service is absent, the transaction fails
        self.server.service.currentState = self.server.service.states['unknown']
        p = self.getPool()
        dests = p['dests']
        self.client.get_dests.return_value = []
        d = self.server.toState('up')
        d.addCallback(self.assertEquals, None)
        self.server.service.currentState = self.server.service.states['present']
        # If the add_dest method returns an exception, the transaction fails
        self.client.add_dest.side_effect = Exception('Poww!')
        d = self.server.toState('up')
        d.addCallback(self.assertEquals, None)
        d.addCallback(lambda _: self.assertEquals(
            self.server.currentState.name, 'unknown')
        )
        # Call from the already 'present' state should not be doing anything.
        self.server.currentState = self.server.states['up']
        self.client.get_dests.return_value = dests
        self.client.reset_mock()
        d = self.server.toState('up')
        d.addCallback(
            lambda _: self.client.update_dest.assert_not_called())
