# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.fsm`.

"""
from time import sleep

from twisted.internet import defer, reactor, base
from twisted.trial import unittest
import pybal.fsm
base.DelayedCall.debug = True

class FiniteStateMachineTestCase(unittest.TestCase):

    def _dumbDeferred(self, *args, **kwargs):
        return defer.succeed("")

    def _sleepyDumbDeferred(self, seconds=3, *args, **kwargs):
        d = defer.Deferred()
        reactor.callLater(seconds, d.callback, None)
        return d

    def _blockingCall(self, seconds=3, *args, **kwargs):
        sleep(seconds)
        return 1

    def _raiser(self, *args, **kwdargs):
        raise ValueError("this transition is faulty")

    def setUp(self):
        s0 = pybal.fsm.State('s0')
        s1 = pybal.fsm.State('s1')
        s2 = pybal.fsm.State('s2')
        self.fsm = pybal.fsm.FiniteStateMachine()
        self.fsm.addState(s0)
        self.fsm.addState(s1)
        self.fsm.addState(s2)
        self.fsm.addTransition(s0, s1,
                               self._sleepyDumbDeferred,
                               self.fsm.logError)
        self.fsm.addTransition(s1, s2,
                               self._dumbDeferred,
                               self.fsm.logError)
        self.fsm.addTransition(s2, s0,
                               self._blockingCall,
                               self.fsm.logError)
        # Add a transition that will fail
        self.fsm.addTransition(s0, s2,
                               self._raiser,
                               self.fsm.logError)
        self.fsm.currentState = s0

    def testState(self):
        """
        Test case for `fsm.State`
        """
        s = pybal.fsm.State('meh')
        self.assertEquals(s.name, 'meh')
        self.assertEquals(s.transitions, {})
        s.addNeighbour(self.fsm.states['s0'], self._blockingCall,
                        self.fsm.logError)
        assert 's0' in s.transitions
        self.assertRaises(ValueError, s.getTransition, self.fsm.states['s1'])
        # Check a transition that is present is returned without an error
        self.assertIs(type(s.getTransition(self.fsm.states['s0'])), tuple)

    def testInit(self):
        """
        Test case for `fsm.FiniteStateMachine.__init__`
        """
        f = pybal.fsm.FiniteStateMachine()
        self.assertIs(type(f.lock), defer.DeferredLock)
        self.assertEquals(f.currentState, None)
        self.assertEquals(f.states, {})

    def testAddState(self):
        """
        Test case for `fsm.FiniteStateMachine.addState`
        """
        self.assertRaises(ValueError, self.fsm.addState, self.fsm.currentState)

    def testAddTransition(self):
        """
        Test case for `fsm.FiniteStateMachine.addTransition`
        """
        # Adding a transition to or from an inexistent state raises
        # a ValueError
        s = pybal.fsm.State('invalid')
        self.assertRaises(ValueError, self.fsm.addTransition,
                          self.fsm.currentState, s, lambda x: x, lambda x: 2*x)
        self.assertRaises(ValueError, self.fsm.addTransition,
                          s, self.fsm.currentState, lambda x: x, lambda x: 2*x)

        # Adding a transition from a state to itself raises an exception
        self.assertRaises(ValueError, self.fsm.addTransition,
                          self.fsm.currentState, self.fsm.currentState,
                          lambda x: x, lambda x: 2*x)

        # Adding a currently defined transition will reassign the current
        # transition
        def newErr(self, error):
            print error
        s0 = self.fsm.states['s0']
        s1 = self.fsm.states['s1']
        self.fsm.addTransition(s0, s1, self._blockingCall, newErr)
        _, err = s0.getTransition(s1)
        self.assertEquals(err, newErr)

        # A correctly added transition will return None
        self.fsm.addState(s)
        self.assertEquals(
            self.fsm.addTransition(s0, s, self._blockingCall, newErr),
            None)

    def testToState(self):
        """
        Test case for `fsm.FiniteStateMachine.toState`
        """
        # Check that a transition to itself returns
        # a defer.succeed
        null = self.fsm.toState('s0')
        null.addCallback(self.assertEqual, None)
        # Check that a transition returns a deferred
        d = self.fsm.toState('s1')
        self.assertIsInstance(d, defer.Deferred)
        d.addCallback(self.assertEqual,
                      self.fsm.states['s1'])
        # Now launch another transition that would fail
        # if locking was not in place, as the preceding
        # callback sleeps for three seconds
        d1 = self.fsm.toState('s2')
        # If locking didn't work, we should get an exception
        # as s0 => s2 would fail
        self.assertEqual(self.fsm.currentState.name, 's0')
        d1.addCallback(self.assertEqual, self.fsm.states['s2'])
        # Check that transitioning to an undefined state fails
        d = self.fsm.toState('undefined')
        # _getState raises ValueError if the state is undefined. Trap the
        # failure in a error callback
        def trapValueError(f):
            f.trap(ValueError)
        d.addErrback(trapValueError)
        return d

    def testToStateBlocking(self):
        """
        Test a mix of non-blocking and blocking tasks
        """
        self.semaphore = False

        def test(*args):
            self.assertEqual(self.semaphore, True)
        self.fsm.currentState = self.fsm.states['s2']
        # This is a blocking call
        d = self.fsm.toState('s0')
        # check the exposed interface didn't change
        self.assertIsInstance(d, defer.Deferred)
        d.addCallback(self.assertEqual,
                      self.fsm.states['s0'])
        # now check the other way around...
        self.fsm.currentState = self.fsm.states['s0']
        # This is non-blocking (and returns after sleeping 3 s)
        d1 = self.fsm.toState('s1')
        self.fsm.toState('s2')
        # Blocking, will not get fired until the other two have completed
        # So setting the semaphore to true after firing the transition
        # _will_ succeed
        d3 = self.fsm.toState('s0')
        d3.addCallback(test)
        self.semaphore = True
        # We need to return a deferred or the event loop will
        # be unclean and make the test fail
        return d1
