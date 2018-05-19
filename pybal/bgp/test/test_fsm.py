"""
  bgp.fsm unit tests
  ~~~~~~~~~~~~~~~~~~

  This module contains tests for `bgp.fsm`.

"""

# Twisted imports
from twisted.internet import task

# BGP imports
from .. import bgp, fsm
from ..exceptions import NotificationSent
from ..constants import ST_IDLE, ST_CONNECT, ST_ACTIVE, ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED

import unittest, mock
from contextlib import contextmanager

eventMethods = fsm.FSM.eventMethods


def edge(state, *events):
    """
    Function decorator to indicate and track the "edge" of the (FSM) graph
    a test function covers.
    Stores the list of events the function covers as a function attribute.
    """

    def decorator(func):
        # Map function to a list of events
        func.events = events
        # Map (state, event) to a list of functions
        for event in events:
            edge.edges.setdefault((state, event), []).append(func)

        return func
    return decorator
edge.edges = {}

def replicate_tests(aClass):
    """
    Class decorator to replicate test functions which cover multiple events
    """

    def make_wrapper(func, event):
        """
        Factory for wrapper function to avoid late binding of func and event
        """

        def wrapper(instance):
            # Pass in event for the replicated method
            return func(instance, event=event)
        return wrapper

    methods_to_replicate = {func
        for func
        in aClass.__dict__.values()
        if callable(func) and hasattr(func, 'events') and len(func.events) > 1}
    for func in methods_to_replicate:
        for event in func.events:
            # Replicate!
            new_func_name = func.__name__ + "_evt_{}".format(event)
            setattr(aClass, new_func_name, make_wrapper(func, event))
        # Remove original template method which covered multiple events
        delattr(aClass, func.__name__)

    return aClass


class FSMDefinitionTestCase(unittest.TestCase):
    """
    Tests fsm.FSM according to the FSM definition in RFC 4271

    This code explicitly does not try to avoid duplication by refactoring much,
    but instead tries to follow the RFC as closely as possible - as factoring
    out common code (like the fsm.FSM code does) can introduce bugs.
    """

    def setUp(self):
        self.fsm = fsm.FSM(
            bgpPeering=mock.Mock(spec=bgp.BGPPeering),
            protocol=mock.Mock(spec=bgp.BGP)
        )
        # Mock self.fsm.log for less noisy output
        self.fsm.log = mock.MagicMock()
        # Mock all BGP BGPTimers
        for timer in self.fsm.bgpTimers:
            self._mockTimer(timer)
        # Store the original connectRetryCounter
        self.origConnectRetryCounter = self.fsm.connectRetryCounter

    def _mockTimer(self, timername):
        mockedTimer = mock.Mock(
            spec=fsm.FSM.BGPTimer,
            name=timername,
            timertime=None)

        def reset(time):
            mockedTimer.timertime = time

        def cancel():
            mockedTimer.timertime = None

        def active():
            return mockedTimer.timertime is not None

        mockedTimer.reset.side_effect = reset
        mockedTimer.cancel.side_effect = cancel
        mockedTimer.active.side_effect = active

        setattr(self.fsm, timername, mockedTimer)

    def _setState(self, state):
        """Sets up the FSM under test with a given state"""
        self.fsm.state = state

    def assertState(self, state):
        """Asserts that the FSM is in the desired state"""
        self.assertEqual(self.fsm.state, state,
            "State is {} instead of expected {}".format(
                bgp.stateDescr[self.fsm.state], bgp.stateDescr[state]))

    def assertTimerInactive(self, timer):
        """Asserts that the passed (mocked) timer is set to 0."""
        self.assertFalse(timer.active())

    def assertTimerReset(self, timer, new_time):
        """
        Asserts that the passed (mocked) timer has been reset to the
        specified time.
        """
        timer.reset.assert_called_with(new_time)
        self.assertEqual(timer.timertime, new_time)

    def assertReleasedAndDropped(self):
        """
        Asserts that a connection has been dropped and all associated
        BGP resources have been released.
        """
        self.assertConnectionDropped()
        self.fsm.bgpPeering.releaseResources.assert_called()

    def _testIgnoreEvent(self, eventMethod, *args, **kwargs):
        with mock.patch.object(self.fsm, '__setattr__') as mock_setattr:
            with self.eventUnderTest():
                getattr(self.fsm, eventMethod)(*args, **kwargs)
        # Ensure no attributes on self.fsm have been set
        mock_setattr.assert_not_called()
        # Make sure no methods on the timers have been called
        for timer in self.fsm.bgpTimers:
            getattr(self.fsm, timer).assert_not_called()

    def assertConnectionDropped(self):
        """Tests whether the BGP TCP connection has been dropped"""
        self.fsm.protocol.closeConnection.assert_called()
        self.fsm.bgpPeering.connectionClosed.assert_called()

    def assertCRCIncremented(self):
        self.assertEqual(
            self.fsm.connectRetryCounter,
            self.origConnectRetryCounter + 1,
            "connectRetryCounter was not incremented by 1")

    @contextmanager
    def allowNSException(self):
        """
        A context manager that catches, but doesn't require, a notificationSent
        exception in the context (with block).
        """

        try:
            yield   # Execute with block
        except NotificationSent:
            pass

    @contextmanager
    def eventUnderTest(self, NS=None, *args, **kwargs):
        """
        A context manager for unit testing fsm.FSM event methods

        Params:
        - NS:   'assert' asserts that NotificationSent is raised.
                'allow' allows NotificationSent to be raised and catches it.
        """

        @contextmanager
        def noop(*args, **kwargs):
            yield

        if NS is None:
            # Don't treat NotificationSent specially
            assertNotificationSent = noop()
        elif NS == 'assert':
            # Ensure NotificationSent is raised
            assertNotificationSent = self.assertRaises(NotificationSent)
        elif NS == 'allow':
            # Allow (and catch), but don't require NotificationSent to be raised
            assertNotificationSent = self.allowNSException()

        # Execute the test
        with assertNotificationSent:
            yield

    def _testFSM_error(self, eventMethod):
        with self.eventUnderTest(NS='allow'):
            getattr(self.fsm, eventMethod)()
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_FSM, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

@replicate_tests
class FSMDefinitionStateIdleTestCase(FSMDefinitionTestCase):
    # State IDLE

    def setUp(self):
        super(FSMDefinitionStateIdleTestCase, self).setUp()
        self._setState(ST_IDLE)

    @edge(ST_IDLE, 1)
    def test_Idle_event_1(self, event=1):
        with self.eventUnderTest():
            self.fsm.manualStart()
        self.assertEqual(self.fsm.connectRetryCounter, 0)
        self.assertTimerReset(self.fsm.connectRetryTimer, self.fsm.connectRetryTime)
        self.fsm.bgpPeering.connect.assert_called()
        self.assertState(ST_CONNECT)

    @edge(ST_IDLE, 3)
    def test_Idle_event_3(self, event=3):
        with self.eventUnderTest():
            connect = self.fsm.automaticStart()
        self.assertEqual(self.fsm.connectRetryCounter, 0)
        self.assertTimerReset(self.fsm.connectRetryTimer, self.fsm.connectRetryTime)
        self.fsm.bgpPeering.connect.assert_called()
        self.assertState(ST_CONNECT)
        self.assertTrue(connect)

    @edge(ST_IDLE, 2, 9, 10, 11, 17, 18, 19, 20, 23, 24, 26)
    def test_Idle_Noops_event_2_9_10_11_17_18_19_20_23_24_26(self, event):
        self._testIgnoreEvent(eventMethods[event])

    @edge(ST_IDLE, 12)
    def test_Idle_event_12(self, event=12):
        self.fsm.delayOpen = True
        self._testIgnoreEvent(eventMethods[event])

    @edge(ST_IDLE, 13)
    def test_Idle_event_13(self, event=13):
        self.assertTrue(self.fsm.dampPeerOscillations)
        with self.eventUnderTest():
            self.fsm.idleHoldTimeEvent()
        self.fsm.bgpPeering.automaticStart.assert_called_with(idleHold=False)

    @edge(ST_IDLE, 21, 22, 27, 28)
    def test_Idle_event_21_22_27_28(self, event):
        self._testIgnoreEvent(eventMethods[event], '')

    @edge(ST_IDLE, 25)
    def test_Idle_event_25(self, event=25):
        self._testIgnoreEvent(eventMethods[event], bgp.ERR_CEASE, 0)


@replicate_tests
class FSMDefinitionStateConnectTestCase(FSMDefinitionTestCase):
    # State CONNECT

    def setUp(self):
        super(FSMDefinitionStateConnectTestCase, self).setUp()
        self._setState(ST_CONNECT)

    def _subtest_Connect_to_Idle(self, eventMethod):
        with self.eventUnderTest(NS='allow'):
            getattr(self.fsm, eventMethod)()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_CONNECT, 1, 3)
    def test_Connect_Noops_event_1_3(self, event):
        self._testIgnoreEvent(eventMethods[event])

    @edge(ST_CONNECT, 2)
    def test_Connect_event_2(self, event=2):
        with self.eventUnderTest(NS='assert'):
            self.fsm.manualStop()
        self.assertReleasedAndDropped()
        self.assertEqual(self.fsm.connectRetryCounter, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertState(ST_IDLE)

    @edge(ST_CONNECT, 9)
    def test_Connect_event_9(self, event=9):
        with self.eventUnderTest():
            self.fsm.connectRetryTimeEvent()
        self.assertConnectionDropped()
        self.assertTimerReset(self.fsm.connectRetryTimer, self.fsm.connectRetryTime)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        # TODO: check BGPPeering.connectRetryEvent
        self.fsm.bgpPeering.connectRetryEvent.assert_called()
        self.assertState(ST_CONNECT)

    @edge(ST_CONNECT, 10, 11, 13, 23, 26)
    def test_Connect_event_10_11_13_23_26(self, event):
        self._subtest_Connect_to_Idle(eventMethods[event])

    @edge(ST_CONNECT, 12)
    def test_Connect_event_12(self, event=12):
        self.fsm.delayOpen = True
        with self.eventUnderTest():
            self.fsm.delayOpenEvent()
        self.fsm.protocol.sendOpen.assert_called()
        self.assertTimerReset(self.fsm.holdTimer, self.fsm.largeHoldTime)
        self.assertState(ST_OPENSENT)

    @edge(ST_CONNECT, 16, 17)
    def test_Connect_event_16_17_delayOpen_True(self, event):
        self.fsm.delayOpen = True
        with self.eventUnderTest():
            self.fsm.connectionMade()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerReset(self.fsm.delayOpenTimer, self.fsm.delayOpenTime)
        self.assertState(ST_CONNECT)

    @edge(ST_CONNECT, 16, 17)
    def test_Connect_event_16_17_delayOpen_False(self, event):
        self.fsm.delayOpen = False
        with self.eventUnderTest():
            self.fsm.connectionMade()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.fsm.bgpPeering.completeInit.assert_called()
        self.fsm.protocol.sendOpen.assert_called()
        self.assertTimerReset(self.fsm.holdTimer, self.fsm.largeHoldTime)
        self.assertState(ST_OPENSENT)

    @edge(ST_CONNECT, 18)
    def test_Connect_event_18_DelayOpenTimer_running(self, event=18):
        self.fsm.delayOpenTimer.reset(self.fsm.delayOpenTime)
        self.assertTrue(self.fsm.delayOpenTimer.active())
        with self.eventUnderTest():
            self.fsm.connectionFailed()
        self.assertTimerReset(self.fsm.connectRetryTimer, self.fsm.connectRetryTime)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertState(ST_ACTIVE)

    @edge(ST_CONNECT, 18)
    def test_Connect_event_18_DelayOpenTimer_not_running(self, event=18):
        self.fsm.delayOpenTimer.cancel()
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        with self.eventUnderTest():
            self.fsm.connectionFailed()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertConnectionDropped()
        self.assertState(ST_IDLE)

    @edge(ST_CONNECT, 19)
    def test_Connect_event_19(self, event=19):
        self.assertFalse(self.fsm.delayOpen)
        self._subtest_Connect_to_Idle(eventMethods[event])

    def _subtest_Connect_event_20(self):
        self.fsm.delayOpen = True
        # DelayOpenTimer needs to be running
        self.fsm.delayOpenTimer.reset(1)
        with self.eventUnderTest():
            self.fsm.openReceived()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.fsm.bgpPeering.completeInit.assert_called()
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.fsm.protocol.sendOpen.assert_called()
        self.fsm.protocol.sendKeepAlive.assert_called()
        if self.fsm.holdTime > 0:
            self.assertTimerReset(self.fsm.keepAliveTimer, self.fsm.keepAliveTime)
            self.assertTimerReset(self.fsm.holdTimer, self.fsm.holdTime)
        else:
            self.assertTimerInactive(self.fsm.keepAliveTimer)
            self.assertTimerInactive(self.fsm.holdTimer)
        self.assertState(ST_OPENCONFIRM)

    @edge(ST_CONNECT, 20)
    def test_Connect_event_20_HoldTime_nonzero(self, event=20):
        self.assertGreater(self.fsm.holdTime, 0)
        self._subtest_Connect_event_20()

    @edge(ST_CONNECT, 20)
    def test_Connect_event_20_HoldTime_zero(self, event=20):
        self.fsm.holdTime = 0
        self._subtest_Connect_event_20()

    @edge(ST_CONNECT, 21)
    def test_Connect_event_21(self, event=21):
        with self.eventUnderTest(NS='assert'):
            self.fsm.headerError(bgp.ERR_MSG_HDR_CONN_NOT_SYNC)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_CONNECT, 22)
    def test_Connect_event_22(self, event=22):
        with self.eventUnderTest(NS='assert'):
            self.fsm.openMessageError(bgp.ERR_MSG_OPEN_UNSUP_VERSION)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_CONNECT, 24)
    def test_Connect_event_24_DelayOpenTimer_running(self, event=24):
        self.fsm.delayOpenTimer.reset(self.fsm.delayOpenTime)
        with self.eventUnderTest():
            self.fsm.versionError()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertReleasedAndDropped()
        self.assertState(ST_IDLE)

    @edge(ST_CONNECT, 24)
    def test_Connect_event_24_DelayOpenTimer_notrunning(self, event=24):
        self.fsm.delayOpenTimer.cancel()
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        with self.eventUnderTest():
            self.fsm.versionError()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_CONNECT, 25)
    def test_Connect_event_25(self, event=25):
        with self.eventUnderTest():
            self.fsm.notificationReceived(bgp.ERR_CEASE, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_CONNECT, 27)
    def test_Connect_event_27(self, event=27):
        with self.eventUnderTest():
            self.fsm.updateReceived('')
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_CONNECT, 28)
    def test_Connect_event_28(self, event=28):
        with self.eventUnderTest(NS='allow'):
            self.fsm.updateError(bgp.ERR_MSG_UPDATE_ATTR_LEN)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

@replicate_tests
class FSMDefinitionStateActiveTestCase(FSMDefinitionTestCase):
    # State ACTIVE

    def setUp(self):
        super(FSMDefinitionStateActiveTestCase, self).setUp()
        self._setState(ST_ACTIVE)

    def _subtest_Active_to_Idle(self, eventMethod):
        with self.eventUnderTest(NS='allow'):
            getattr(self.fsm, eventMethod)()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.fsm.delayOpenTimer.assert_not_called()
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_ACTIVE, 1, 3)
    def test_Active_Noops_event_1_3(self, event):
        self._testIgnoreEvent(eventMethods[event])

    @edge(ST_ACTIVE, 2)
    def test_Active_event_2(self, event=2):
        with self.eventUnderTest(NS='assert'):
            self.fsm.manualStop()
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertReleasedAndDropped()
        self.assertEqual(self.fsm.connectRetryCounter, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertState(ST_IDLE)

    @edge(ST_ACTIVE, 9)
    def test_Active_event_9(self, event=9):
        with self.eventUnderTest():
            self.fsm.connectRetryTimeEvent()
        self.assertTimerReset(self.fsm.connectRetryTimer, self.fsm.connectRetryTime)
        # TODO: check BGPPeering.connectRetryEvent
        self.fsm.bgpPeering.connectRetryEvent.assert_called()
        self.assertState(ST_CONNECT)

    @edge(ST_ACTIVE, 10, 11, 13, 23, 26)
    def test_Active_event_10_11_13_23_26(self, event):
        self._subtest_Active_to_Idle(eventMethods[event])

    @edge(ST_ACTIVE, 12)
    def test_Active_event_12(self, event=12):
        self.fsm.delayOpen = True
        with self.eventUnderTest():
            self.fsm.delayOpenEvent()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.fsm.bgpPeering.completeInit.assert_called()
        self.fsm.protocol.sendOpen.assert_called() # Bug
        self.assertTimerReset(self.fsm.holdTimer, self.fsm.largeHoldTime)
        self.assertState(ST_OPENSENT)

    @edge(ST_ACTIVE, 17)
    def test_Active_event_17_delayOpen_true(self, event=17):
        self.fsm.delayOpen = True
        with self.eventUnderTest():
            self.fsm.connectionMade()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerReset(self.fsm.delayOpenTimer, self.fsm.delayOpenTime)
        self.assertState(ST_ACTIVE)

    @edge(ST_ACTIVE, 17)
    def test_Active_event_17_delayOpen_false(self, event=17):
        self.fsm.delayOpen = False
        with self.eventUnderTest():
            self.fsm.connectionMade()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.fsm.bgpPeering.completeInit.assert_called()
        self.fsm.protocol.sendOpen.assert_called()
        self.assertTimerReset(self.fsm.holdTimer, self.fsm.largeHoldTime)
        self.assertState(ST_OPENSENT)

    @edge(ST_ACTIVE, 18)
    def test_Active_event_18(self, event=18):
        with self.eventUnderTest():
            self.fsm.connectionFailed()
        self.assertTimerReset(self.fsm.connectRetryTimer, self.fsm.connectRetryTime)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.fsm.bgpPeering.releaseResources.assert_called()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_ACTIVE, 19)
    def test_Active_event_19(self, event=19):
        self.assertFalse(self.fsm.delayOpen)
        self._subtest_Active_to_Idle(eventMethods[event])

    def _subtest_Active_event_20(self):
        self.fsm.delayOpen = True
        # DelayOpenTimer needs to be running
        self.fsm.delayOpenTimer.reset(1)
        with self.eventUnderTest():
            self.fsm.openReceived()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.fsm.bgpPeering.completeInit.assert_called()
        self.fsm.protocol.sendOpen.assert_called()
        self.fsm.protocol.sendKeepAlive.assert_called()
        if self.fsm.holdTime > 0:
            self.assertTimerReset(self.fsm.keepAliveTimer, self.fsm.keepAliveTime)
            self.fsm.holdTimer.reset.assert_called()
        else:
            self.assertTimerInactive(self.fsm.keepAliveTimer)
            self.assertTimerInactive(self.fsm.holdTimer)
        self.assertState(ST_OPENCONFIRM)

    @edge(ST_ACTIVE, 20)
    def test_Active_event_20_HoldTime_nonzero(self, event=20):
        self.assertGreater(self.fsm.holdTime, 0)
        self._subtest_Active_event_20()

    @edge(ST_ACTIVE, 20)
    def test_Active_event_20_HoldTime_zero(self, event=20):
        self.fsm.holdTime = 0
        self._subtest_Active_event_20()

    @edge(ST_ACTIVE, 21)
    def test_Active_event_21(self, event=21):
        with self.eventUnderTest(NS='assert'):
            self.fsm.headerError(bgp.ERR_MSG_HDR_CONN_NOT_SYNC)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_ACTIVE, 22)
    def test_Active_event_22(self, event=22):
        with self.eventUnderTest(NS='assert'):
            self.fsm.openMessageError(bgp.ERR_MSG_OPEN_UNSUP_VERSION)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_ACTIVE, 24)
    def test_Active_event_24_DelayOpenTimer_running(self, event=24):
        self.fsm.delayOpenTimer.reset(self.fsm.delayOpenTime)
        with self.eventUnderTest():
            self.fsm.versionError()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertReleasedAndDropped()
        self.assertState(ST_IDLE)

    @edge(ST_ACTIVE, 24)
    def test_Active_event_24_DelayOpenTimer_notrunning(self, event=24):
        self.fsm.delayOpenTimer.cancel()
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        with self.eventUnderTest():
            self.fsm.versionError()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_ACTIVE, 25)
    def test_Active_event_25(self, event=25):
        with self.eventUnderTest():
            self.fsm.notificationReceived(bgp.ERR_CEASE, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.fsm.delayOpenTimer.assert_not_called()
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_ACTIVE, 27)
    def test_Active_event_27(self, event=27):
        with self.eventUnderTest():
            self.fsm.updateReceived('')
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.fsm.delayOpenTimer.assert_not_called()
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_ACTIVE, 28)
    def test_Active_event_28(self, event=28):
        with self.eventUnderTest(NS='allow'):
            self.fsm.updateError(bgp.ERR_MSG_UPDATE_ATTR_LEN)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

@replicate_tests
class FSMDefinitionStateOpenSentTestCase(FSMDefinitionTestCase):
    # State OPENSENT

    def setUp(self):
        super(FSMDefinitionStateOpenSentTestCase, self).setUp()
        self._setState(ST_OPENSENT)

    @edge(ST_OPENSENT, 1, 3)
    def test_OpenSent_Noops_event_1_3(self, event):
        self._testIgnoreEvent(eventMethods[event])

    @edge(ST_OPENSENT, 2)
    def test_OpenSent_event_2(self, event=2):
        with self.eventUnderTest():
            with self.assertRaises(NotificationSent) as ar_ns:
                self.fsm.manualStop()
        self.assertEqual(ar_ns.exception.error, bgp.ERR_CEASE)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertEqual(self.fsm.connectRetryCounter, 0)
        self.assertState(ST_IDLE)

    @edge(ST_OPENSENT, 9, 11, 13, 26)
    def test_OpenSent_event_9_11_13_26(self, event):
        self._testFSM_error(eventMethods[event])

    @edge(ST_OPENSENT, 10)
    def test_OpenSent_event_10(self, event=10):
        with self.eventUnderTest():
            self.fsm.holdTimeEvent()
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_HOLD_TIMER_EXPIRED, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENSENT, 12)
    def test_OpenSent_event_12(self, event=12):
        self.fsm.delayOpen = True
        self._testFSM_error(eventMethods[event])

    @edge(ST_OPENSENT, 17)
    def test_OpenSent_event_17(self, event=17):
        self.fsm.connectionMade()

    @edge(ST_OPENSENT, 18)
    def test_OpenSent_event_18(self, event=18):
        with self.eventUnderTest():
            self.fsm.connectionFailed()
        self.assertConnectionDropped()
        self.assertTimerReset(self.fsm.connectRetryTimer, self.fsm.connectRetryTime)
        self.assertState(ST_ACTIVE)

    @edge(ST_OPENSENT, 19)
    def test_OpenSent_event_19_HoldTime_zero(self, event=19):
        self.fsm.holdTime = 0   # Set negotiated holdTime to 0
        self.assertFalse(self.fsm.delayOpen)
        with self.eventUnderTest():
            self.fsm.openReceived()
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.fsm.protocol.sendKeepAlive.assert_called()
        self.fsm.holdTimer.reset.assert_not_called()
        self.fsm.keepAliveTimer.reset.assert_not_called()
        self.assertState(ST_OPENCONFIRM)

    @edge(ST_OPENSENT, 19)
    def test_OpenSent_event_19_HoldTime_nonzero(self, event=19):
        self.fsm.holdTime = self.fsm.largeHoldTime   # Set negotiated holdTime > 0
        self.assertFalse(self.fsm.delayOpen)
        with self.eventUnderTest():
            self.fsm.openReceived()
        self.assertTimerInactive(self.fsm.delayOpenTimer)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.fsm.protocol.sendKeepAlive.assert_called()
        self.assertTimerReset(self.fsm.holdTimer, self.fsm.holdTime)
        self.assertTimerReset(self.fsm.keepAliveTimer, self.fsm.keepAliveTime)
        self.assertState(ST_OPENCONFIRM)

    @edge(ST_OPENSENT, 20)
    def test_OpenSent_event_20(self, event=20):
        self.fsm.delayOpen = True
        self._testFSM_error(eventMethods[event])

    @edge(ST_OPENSENT, 21)
    def test_OpenSent_event_21(self, event=21):
        with self.eventUnderTest(NS='assert'):
            self.fsm.headerError(bgp.ERR_MSG_HDR_CONN_NOT_SYNC)
        self.fsm.protocol.sendNotification.assert_called()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENSENT, 22)
    def test_OpenSent_event_22(self, event=22):
        with self.eventUnderTest(NS='assert'):
            self.fsm.openMessageError(bgp.ERR_MSG_OPEN_UNSUP_VERSION)
        self.fsm.protocol.sendNotification.assert_called()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENSENT, 23)
    def test_OpenSent_event_23(self, event=23):
        with self.eventUnderTest(NS='assert'):
            self.fsm.openCollisionDump()
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_CEASE, 0)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENSENT, 24)
    def test_OpenSent_event_24(self, event=24):
        with self.eventUnderTest():
            self.fsm.versionError()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertState(ST_IDLE)

    @edge(ST_OPENSENT, 25)
    def test_OpenSent_event_25(self, event=25):
        with self.eventUnderTest(NS='allow'):
            self.fsm.notificationReceived(bgp.ERR_CEASE, 0)
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_FSM, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENSENT, 27)
    def test_OpenSent_event_27(self, event=27):
        with self.eventUnderTest(NS='allow'):
            self.fsm.updateReceived('')
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_FSM, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENSENT, 28)
    def test_OpenSent_event_28(self, event=28):
        with self.eventUnderTest(NS='allow'):
            self.fsm.updateError(bgp.ERR_MSG_UPDATE_ATTR_LEN)
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_FSM, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

@replicate_tests
class FSMDefinitionStateOpenConfirmTestCase(FSMDefinitionTestCase):
    # State OPENCONFIRM

    def setUp(self):
        super(FSMDefinitionStateOpenConfirmTestCase, self).setUp()
        self._setState(ST_OPENCONFIRM)

    @edge(ST_OPENCONFIRM, 1, 3)
    def test_OpenConfirm_Noops_event_1_3(self, event):
        self._testIgnoreEvent(eventMethods[event])

    @edge(ST_OPENCONFIRM, 2)
    def test_OpenConfirm_event_2(self, event=2):
        with self.eventUnderTest():
            with self.assertRaises(NotificationSent) as ar_ns:
                self.fsm.manualStop()
        self.assertEqual(ar_ns.exception.error, bgp.ERR_CEASE)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertEqual(self.fsm.connectRetryCounter, 0)
        self.assertState(ST_IDLE)

    @edge(ST_OPENCONFIRM, 9, 13)
    def test_OpenConfirm_event_9_13(self, event):
        self._testFSM_error(eventMethods[event])

    @edge(ST_OPENCONFIRM, 10)
    def test_OpenConfirm_event_10(self, event=10):
        with self.eventUnderTest():
            self.fsm.holdTimeEvent()
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_HOLD_TIMER_EXPIRED, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENCONFIRM, 11)
    def test_OpenConfirm_event_11(self, event=11):
        with self.eventUnderTest():
            self.fsm.keepAliveEvent()
        self.fsm.protocol.sendKeepAlive.assert_called()
        self.assertTimerReset(self.fsm.keepAliveTimer, self.fsm.keepAliveTime)
        self.assertState(ST_OPENCONFIRM)

    @edge(ST_OPENCONFIRM, 12)
    def test_OpenConfirm_event_12(self, event=12):
        self.fsm.delayOpen = True
        self._testFSM_error(eventMethods[event])

    @edge(ST_OPENCONFIRM, 17)
    def test_OpenConfirm_event_17(self, event=17):
        with self.eventUnderTest():
            self.fsm.connectionMade()

    @edge(ST_OPENCONFIRM, 18)
    def test_OpenConfirm_event_18(self, event=18):
        with self.eventUnderTest():
            self.fsm.connectionFailed()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENCONFIRM, 19)
    def test_OpenConfirm_event_19(self, event=19):
        self.assertFalse(self.fsm.delayOpen)
        with self.eventUnderTest():
            self.fsm.openReceived()
        self.fsm.protocol.collisionDetect.assert_called()

    @edge(ST_OPENCONFIRM, 20)
    def test_OpenConfirm_event_20(self, event=20):
        self.fsm.delayOpen = True
        self._testFSM_error(eventMethods[event])

    @edge(ST_OPENCONFIRM, 21)
    def test_OpenConfirm_event_21(self, event=21):
        with self.eventUnderTest(NS='assert'):
            self.fsm.headerError(bgp.ERR_MSG_HDR_CONN_NOT_SYNC)
        self.fsm.protocol.sendNotification.assert_called()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENCONFIRM, 22)
    def test_OpenConfirm_event_22(self, event=22):
        with self.eventUnderTest(NS='assert'):
            self.fsm.openMessageError(bgp.ERR_MSG_OPEN_UNSUP_VERSION)
        self.fsm.protocol.sendNotification.assert_called()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENCONFIRM, 23)
    def test_OpenConfirm_event_23(self, event=23):
        with self.eventUnderTest(NS='assert'):
            self.fsm.openCollisionDump()
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_CEASE, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENCONFIRM, 24)
    def test_OpenConfirm_event_24(self, event=24):
        with self.eventUnderTest():
            self.fsm.versionError()
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertState(ST_IDLE)

    @edge(ST_OPENCONFIRM, 25)
    def test_OpenConfirm_event_25(self, event=25):
        with self.eventUnderTest():
            self.fsm.notificationReceived(bgp.ERR_CEASE, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENCONFIRM, 26)
    def test_OpenConfirm_event_26(self, event=26):
        self.fsm.protocol.deferred = mock.MagicMock()
        with self.eventUnderTest():
            self.fsm.keepAliveReceived()
        self.assertTimerReset(self.fsm.holdTimer, self.fsm.holdTime)
        self.assertState(ST_ESTABLISHED)

    @edge(ST_OPENCONFIRM, 27)
    def test_OpenConfirm_event_27(self, event=27):
        with self.eventUnderTest(NS='allow'):
            self.fsm.updateReceived('')
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_FSM, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_OPENCONFIRM, 28)
    def test_OpenConfirm_event_28(self, event=28):
        with self.eventUnderTest(NS='allow'):
            self.fsm.updateError(bgp.ERR_MSG_UPDATE_ATTR_LEN)
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_FSM, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

@replicate_tests
class FSMDefinitionStateEstablishedTestCase(FSMDefinitionTestCase):
    # State ESTABLISHED

    def setUp(self):
        super(FSMDefinitionStateEstablishedTestCase, self).setUp()
        self._setState(ST_ESTABLISHED)
        self.sampleUpdate = 'test'

    def _subtest_Established_to_Idle(self):
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_ESTABLISHED, 1, 3)
    def test_Established_Noops_event_1_3(self, event):
        self._testIgnoreEvent(eventMethods[event])

    @edge(ST_ESTABLISHED, 2)
    def test_Established_event_2(self, event=2):
        with self.eventUnderTest(NS='assert'):
            self.fsm.manualStop()
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_CEASE, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertEqual(self.fsm.connectRetryCounter, 0)
        self.assertState(ST_IDLE)

    @edge(ST_ESTABLISHED, 9, 13)
    def test_Established_event_9_13(self, event):
        self._testFSM_error(eventMethods[event])

    @edge(ST_ESTABLISHED, 10)
    def test_Established_event_10(self, event=10):
        with self.eventUnderTest():
            self.fsm.holdTimeEvent()
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_HOLD_TIMER_EXPIRED, 0)
        self.assertTimerInactive(self.fsm.connectRetryTimer)
        self.assertReleasedAndDropped()
        self.assertCRCIncremented()
        self.assertState(ST_IDLE)

    @edge(ST_ESTABLISHED, 11)
    def test_Established_event_11_HoldTime_zero(self, event=11):
        self.fsm.holdTime = 0
        with self.eventUnderTest():
            self.fsm.keepAliveEvent()
        self.fsm.protocol.sendKeepAlive.assert_called()
        self.fsm.keepAliveTimer.assert_not_called()
        self.assertState(ST_ESTABLISHED)

    @edge(ST_ESTABLISHED, 11)
    def test_Established_event_11_HoldTime_nonzero(self, event=11):
        self.fsm.holdTime = self.fsm.largeHoldTime
        with self.eventUnderTest():
            self.fsm.keepAliveEvent()
        self.fsm.protocol.sendKeepAlive.assert_called()
        self.assertTimerReset(self.fsm.keepAliveTimer, self.fsm.keepAliveTime)
        self.assertState(ST_ESTABLISHED)

    @edge(ST_ESTABLISHED, 12)
    def test_Established_event_12(self, event=12):
        self.fsm.delayOpen = True
        self._testFSM_error(eventMethods[event])

    @edge(ST_ESTABLISHED, 17)
    def test_Established_event_17(self, event=17):
        with self.eventUnderTest():
            self.fsm.connectionMade()

    @edge(ST_ESTABLISHED, 18)
    def test_Established_event_18(self, event=18):
        with self.eventUnderTest():
            self.fsm.connectionFailed()
        self._subtest_Established_to_Idle()

    # RFC 4271 is unclear about the exact procedure when the optional
    # CollisionDetectEstablishedState is not implemented.
    # Just test whether the connection gets closed.
    @edge(ST_ESTABLISHED, 19)
    def test_OpenConfirm_event_19(self, event=19):
        self.assertFalse(self.fsm.delayOpen)
        with self.eventUnderTest(NS='allow'):
            self.fsm.openReceived()
        self.assertReleasedAndDropped()

    @edge(ST_ESTABLISHED, 20)
    def test_Established_event_20(self, event=20):
        self.fsm.delayOpen = True
        self._testFSM_error(eventMethods[event])

    @edge(ST_ESTABLISHED, 21)
    def test_Established_event_21(self, event=21):
        with self.eventUnderTest(NS='assert'):
            self.fsm.headerError(bgp.ERR_MSG_HDR_CONN_NOT_SYNC)
        self.fsm.protocol.sendNotification.assert_called()
        self._subtest_Established_to_Idle()

    @edge(ST_ESTABLISHED, 22)
    def test_Established_event_22(self, event=22):
        with self.eventUnderTest(NS='assert'):
            self.fsm.openMessageError(bgp.ERR_MSG_OPEN_UNSUP_VERSION)
        self.fsm.protocol.sendNotification.assert_called()
        self._subtest_Established_to_Idle()

    @edge(ST_ESTABLISHED, 23)
    def test_Established_event_23(self, event=23):
        with self.eventUnderTest(NS='assert'):
            self.fsm.openCollisionDump()
        self.fsm.protocol.sendNotification.assert_called_with(bgp.ERR_CEASE, 0)
        self._subtest_Established_to_Idle()

    @edge(ST_ESTABLISHED, 24)
    def test_Established_event_24(self, event=24):
        with self.eventUnderTest():
            self.fsm.versionError()
        self._subtest_Established_to_Idle()

    @edge(ST_ESTABLISHED, 25)
    def test_Established_event_25(self, event=25):
        with self.eventUnderTest():
            self.fsm.notificationReceived(bgp.ERR_CEASE, 0)
        self._subtest_Established_to_Idle()

    @edge(ST_ESTABLISHED, 26)
    def test_Established_event_26_HoldTime_zero(self, event=26):
        self.fsm.holdTime = 0
        with self.eventUnderTest():
            self.fsm.keepAliveReceived()
        self.fsm.holdTimer.assert_not_called()
        self.assertState(ST_ESTABLISHED)

    @edge(ST_ESTABLISHED, 26)
    def test_Established_event_26_HoldTime_nonzero(self, event=26):
        self.fsm.holdTime = self.fsm.largeHoldTime
        with self.eventUnderTest():
            self.fsm.keepAliveReceived()
        self.assertTimerReset(self.fsm.holdTimer, self.fsm.holdTime)
        self.assertState(ST_ESTABLISHED)

    @edge(ST_ESTABLISHED, 27)
    def test_Established_event_27_HoldTime_zero(self, event=27):
        self.fsm.holdTime = 0
        with self.eventUnderTest():
            self.fsm.updateReceived(self.sampleUpdate)
        self.fsm.bgpPeering.update.assert_called_with(self.sampleUpdate)
        self.fsm.holdTimer.assert_not_called()
        self.assertState(ST_ESTABLISHED)

    @edge(ST_ESTABLISHED, 27)
    def test_Established_event_27_HoldTime_nonzero(self, event=27):
        self.fsm.holdTime = self.fsm.largeHoldTime
        with self.eventUnderTest():
            self.fsm.updateReceived(self.sampleUpdate)
        self.fsm.bgpPeering.update.assert_called_with(self.sampleUpdate)
        self.assertTimerReset(self.fsm.holdTimer, self.fsm.holdTime)
        self.assertState(ST_ESTABLISHED)

    @edge(ST_ESTABLISHED, 28)
    def test_Established_event_28(self, event=28):
        suberror = bgp.ERR_MSG_UPDATE_ATTR_FLAGS
        with self.eventUnderTest():
            with self.assertRaises(NotificationSent) as ar_ns:
                self.fsm.updateError(suberror, data=self.sampleUpdate)
        self.assertEqual(ar_ns.exception.error, bgp.ERR_MSG_UPDATE)
        self.assertEqual(ar_ns.exception.suberror, suberror)
        self._subtest_Established_to_Idle


class FSMTestCompletenessTestCase(unittest.TestCase):
    def testCompleteness(self):
        missingTests = []
        for state in bgp.stateDescr.iterkeys():
            for event in fsm.FSM.eventMethods.iterkeys():
                if not (state, event) in edge.edges:
                    missingTests.append("State {} event {} is not tested!".format(
                        bgp.stateDescr[state], event))
        self.assertFalse(missingTests, msg="\n".join(missingTests))


class BGPTimerTestCase(unittest.TestCase):
    def setUp(self):
        self.reactor_patcher = mock.patch('pybal.bgp.fsm.reactor', new_callable=task.Clock)
        self.reactor = self.reactor_patcher.start()

    def tearDown(self):
        self.reactor_patcher.stop()

    def testTriggeredTimer(self):
        called_function = mock.MagicMock()
        timer = fsm.FSM.BGPTimer(called_function)
        self.assertFalse(timer.active())
        timer.reset(fsm.FSM.largeHoldTime)
        self.assertTrue(timer.active())
        self.reactor.advance(fsm.FSM.largeHoldTime)
        called_function.assert_called_once()

    def testCancelledTimer(self):
        called_function = mock.MagicMock()
        timer = fsm.FSM.BGPTimer(called_function)
        timer.reset(fsm.FSM.largeHoldTime)
        self.reactor.advance(fsm.FSM.largeHoldTime-1)
        self.assertTrue(timer.active())
        timer.cancel()
        self.assertFalse(timer.active())
        self.reactor.advance(2)
        called_function.assert_not_called()
