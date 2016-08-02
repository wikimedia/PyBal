# Copyright (C) 2016 Giuseppe Lavagetto (glavagetto@wikimedia.org)
#
# General Twisted Deterministic Finite State Machine module
#
# We define a set of states S, and for every possible transition
# S1 => S2 we do define a transition function which should return
# a deferred callback (which progresses the current state of the machine to S2)
# or an errback (which does not progress the current states and gets us a Failure)
#
from twisted.internet import defer
from twisted.python import failure

from pybal import util

log = util.log


class State(object):
    """
    Generic state holding object, holding a state and its transitions to the other states
    """
    def __init__(self, name):
        self.name = name
        self.transitions = {}

    def addNeighbour(self, finalState, transition, errback):
        self.transitions[finalState.name] = (transition, errback)

    def getTransition(self, state):
        try:
            return self.transitions[state.name]
        except KeyError:
            raise ValueError("No transition defined between %s and %s" %
                             (self.name, state.name))


class FiniteStateMachine(object):
    """
    Generic Twisted Finite State Machine.

    Allows to define a set of states, and all allowed transitions between them.
    """
    def __init__(self):
        self.lock = defer.DeferredLock()
        self.states = {}
        self.currentState = None
        self.isInTransition = False

    def checkActualState(self):
        """
        This method is dumb in the base class, but could be overridden
        by state machines with side-effects to actually check the
        logical state the FSM assumes to be in and the actual state
        (which might have been changed by external factors)

        So e.g. say we set an IPVS server to be pooled, but some admin
        has manually removed it from the pool: its currentState according to
        our FSM will be 'pooled', while the actual state of the system will be
        'depooled'
        """
        pass

    def addState(self, state):
        """
        Adds a state to the FSM
        """
        if state.name in self.states:
            raise ValueError("State already defined")
        self.states[state.name] = state

    def addTransition(self, state, desiredState, func, err):
        """
        Adds a transition between two states
        """
        if state.name == desiredState.name:
            raise ValueError(
                "Can't define a transition between state %s and itself.",
                state.name)
        # Check both states exist
        if state.name not in self.states or desiredState.name not in self.states:
            raise ValueError("Could not define transition %s => %s: %s",
                             state.name,
                             desiredState.name)
        f = self._transitionWrapper(func, desiredState)
        self.states[state.name].addNeighbour(desiredState, f, err)

    def toState(self, state_name):
        """
        Transition the state machine to the new state.
        """
        # TODO: do we want just our transitions to run in order,
        # or do we want to fail any transition that is required while another
        # one is running?
        return self.lock.run(self._toState, state_name)

    def _toState(self, state_name):
        # Check the FSM is in a consistent state
        self.checkActualState()
        self.isInTransition = True
        state = self._getState(state_name)
        if state == self.currentState:
            log.debug("Transition between state %s and itself requested" %
                      state.name)
            return defer.succeed(None)
        func, err = self.currentState.getTransition(state)
        return func().addErrback(err)

    def _transitionWrapper(self, f, desiredState):
        """
        Wraps the transition function in a deferred and sets the transition
        callback
        """
        def _wrap():
            # Warning: if f is blocking, this will effectively block execution.
            # If it's an asyncronous function returning a deferred, it will not
            retval = defer.maybeDeferred(f)
            retval.addCallback(self._setState, desiredState)
            return retval
        return _wrap

    def _setState(self, result, state):
        """
        Sets the current state - used in the callback
        """
        log.debug(
            "Transition to state %s completed with return value %s" %
            (state.name, result))
        self.currentState = state
        self.isInTransition = False
        return self.currentState

    def _getState(self, name):
        try:
            return self.states[name]
        except KeyError:
            raise ValueError("No state '%s' defined" % name)

    def logError(self, err, *args, **kwdargs):
        log.error("Action failed: %s" % failure.Failure(err))
