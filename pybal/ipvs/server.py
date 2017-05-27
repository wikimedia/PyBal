from __future__ import absolute_import

import socket

from gnlpy import ipvs as netlink
from pybal import fsm
from pybal.ipvs.exception import IpvsError


class Server(netlink.Dest, fsm.FiniteStateMachine):
    """
    Handler for ipvs destinations using netlink
    """

    check_state = True

    def __init__(self, client, server, service):
        self.client = client
        # This _will_ block, which is acceptable since we're
        # in a blocking part of the code
        self.ip_ = server.ip or socket.gethostbyname(server.host)
        # Server desired weight
        self.weight_ = server.weight or 1
        self.port_ = server.port
        self.fwd_method_ = netlink.IPVS_ROUTING
        self.validate()
        self.service = service
        self.protocol = netlink._to_proto_num(self.service.proto())
        fsm.FiniteStateMachine.__init__(self)
        self.setupFSM()
        self.currentState = self._getActualState()

    def validate(self):
        # Fix incomplete validation in gnlpy
        super(Server, self).validate()
        assert isinstance(self.port_, int)

    def setupFSM(self):
        # S0: The IPVS state is unknown / has been removed
        self.addState(fsm.State('unknown'))
        # S1: The server is registered, but with weight 0
        self.addState(fsm.State('drained'))
        # S2: The server is registered with its desired weight
        self.addState(fsm.State('up'))
        # S3: The server is registered with a wrong weight
        self.addState(fsm.State('refresh'))
        # S0 => S2
        # Add a server with its desired final weight
        self.addTransition(self.states['unknown'],
                           self.states['up'],
                           self._add,
                           self.logError)
        # S0 => S1
        # Add a server, but with weight zero
        self.addTransition(self.states['unknown'],
                           self.states['drained'],
                           self._add_weight_zero,
                           self.logError)
        # S1 => S0
        # Remove a previously drained server
        self.addTransition(self.states['drained'],
                           self.states['unknown'],
                           self._del,
                           self.logError)

        # S1 => S2
        # Modify the weight of a server from zero to the current
        # value
        self.addTransition(self.states['drained'],
                           self.states['up'],
                           self._set,
                           self.logError)
        # S2 => S1
        # Set the weight of a pooled server to zero
        self.addTransition(self.states['up'],
                           self.states['drained'],
                           self._drain,
                           self.logError)
        # S2 => S0
        # Remove a server from the pool
        self.addTransition(self.states['up'],
                           self.states['unknown'],
                           self._del,
                           self.logError)
        # S3 => S2
        # Refresh a server to its desired state
        self.addTransition(self.states['refresh'],
                           self.states['up'],
                           self._set,
                           self.logError)
        # S3 => S0
        # Remove a server that needed refreshing.
        self.addTransition(self.states['refresh'],
                           self.states['unknown'],
                           self._del,
                           self.logError)

        # S3 => S1
        # Drain a server that needed refreshing
        self.addTransition(self.states['refresh'],
                           self.states['drained'],
                           self._drain,
                           self.logError)

    def assertState(self):
        """
        Check the actual state of the fsm, and raise an exception if
        it's not equal to the registered current state.

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
                "The state of server %s is %s, expecting %s" %
                (self, actualState.name, self.currentState.name)
            )

    def _getActualState(self):
        """
        Returns the actual state of the fsm
        """
        # These are all blocking calls
        if not self.service_ready():
            # TODO: add a "waiting" state?
            return self.states['unknown']

        dests = self.client.get_dests(self.service.to_attr_list())
        curState = self.states['unknown']
        for dest in dests:
            dest.service = self.service
            if not self.equals(dest):
                continue
            w = dest.weight()
            if w == self.weight():
                # Server is present with its predefined weight
                curState = self.states['up']
            elif w == 0:
                # Server is present but drained
                curState = self.states['drained']
            else:
                # Server is present but needs a change in weight
                curState = self.states['refresh']
        return curState

    def service_ready(self):
        return (self.service.currentState.name == 'present')

    def assertServiceReady(self):
        if not self.service_ready():
            raise IpvsError("Tried to delete a server from service %s but "
                            "the service is not present",
                            self.service)

    def _del(self):
        self.assertServiceReady()
        self.client.del_dest(self.service.vip(), self.port_, self.ip_,
                             protocol=self.protocol)

    def _add(self, weight=None):
        self.assertServiceReady()
        if weight is None:
            weight = self.weight_
        self.client.add_dest(self.service.vip(), self.port_, self.ip_,
                             protocol=self.protocol,
                             weight=weight, method=self.fwd_method_)

    def _add_weight_zero(self):
        return self._add(weight=0)

    def _drain(self):
        self._set(weight=0)

    def _set(self, weight=None):
        self.assertServiceReady()
        if weight is None:
            weight = self.weight_
        if self.currentState.name == 'unknown':
            return self._add(weight=weight)
        self.client.update_dest(self.service.vip(), self.port_, self.ip_,
                                protocol=self.protocol,
                                weight=weight, method=self.fwd_method_)

    def equals(self, server):
        return (self.service.equals(server.service) and
                self.ip() == server.ip() and self.port() == server.port())

    def __eq__(self, server):
        return (self.equals(server) and
                self.currentState == server.currentState and
                self.weight() == server.weight())

    def __str__(self):
        return "%s:%d with weight %d" % (self.ip_, self.port_, self.weight_)
