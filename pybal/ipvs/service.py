from __future__ import absolute_import

import socket

from gnlpy import ipvs as netlink

from pybal import fsm
from pybal.util import log
from pybal.ipvs.exception import IpvsError, abortOnIpvsError


class Service(netlink.Service, fsm.FiniteStateMachine):
    """
    Handler for ipvs service using netlink
    """
    _protocols = {
        'tcp': socket.IPPROTO_TCP,
        'udp': socket.IPPROTO_UDP
    }

    check_state = True

    @staticmethod
    def from_tuple(service):
        return {
            'proto': service[0],
            'vip': service[1],
            'port': service[2],
            'sched': service[3] if len(service) > 3 else 'rr'
        }

    def __init__(self, client, service):
        s = Service.from_tuple(service)
        self.client = client
        netlink.Service.__init__(self, s, validate=True)
        fsm.FiniteStateMachine.__init__(self)
        self.setUpFSM()
        # Read the state of this state machine
        self.currentState = self._getActualState()

    def logError(self, err, *args, **kwargs):
        super(Service, self).logError(err, *args, **kwargs)
        abortOnIpvsError(err, *args, **kwargs)

    def setUpFSM(self):
        # S0: the service is unknown/deleted
        self.addState(fsm.State('unknown'))
        # S1: the service is present
        self.addState(fsm.State('present'))
        # S0 => S1
        self.addTransition(self.states['unknown'],
                           self.states['present'],
                           self._add,
                           self.logError)
        self.addTransition(self.states['present'],
                           self.states['unknown'],
                           self._del,
                           self.logError)
        self.currentState = self.states['unknown']

    def assertState(self):
        """
        Check the actual state of the fsm, and raise an exception if the two don't
        coincide.

        This is needed if we want to make sure what pybal knows about the IPVS
        state still corresponds to what is actually registered in the kernel.

        Multiple things can change the state, most notably someone using "ipvsadm"
        by hand.

        """
        if not self.check_state:
            return
        actualState = self._getActualState()
        if self.currentState != actualState:
            raise IpvsError(
                "The state of service %s is %s, expecting %s" %
                (self, actualState.name, self.currentState.name)
            )

    def _getActualState(self):
        """
        Check the actual state of the fsm

        This is used during initialization to fetch the initial state,
        and for consistency checks before performing a transition if
        check_state is set to True
        """
        # Blocking call
        s = self.client.get_service(self.to_attr_list())
        if s is not None and self.equals(s):
            actualState = self.states['present']
        else:
            actualState = self.states['unknown']
        return actualState

    def _add(self):
        log.debug("Adding service %s" % self)
        self.client.add_service(self.vip_, self.port_,
                                protocol=self.proto_num(),
                                sched_name=self.sched_)

    def _del(self):
        if self.currentState == self.states['unknown']:
            log.info("Not removing already absent service %s" % self)
            return

        log.debug("Removing service %s" % self)
        self.client.del_service(self.vip_, self.port_,
                                protocol=self.proto_num())

    def equals(self, srv):
        return (self.proto_ == srv.proto_ and self.vip() == srv.vip() and
                self.port() == srv.port() and self.sched() == srv.sched())

    def __eq__(self, srv):
        return (self.equals(srv) and self.currentState == srv.currentState)

    def __str__(self):
        return "'%s://%s:%d' with scheduler %s" % (self.proto_,
                                                   self.vip_, self.port_,
                                                   self.sched_)
