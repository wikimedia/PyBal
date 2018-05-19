# bgp.fsm.py
# Copyright (c) 2007-2018 by Mark Bergsma <mark@nedworks.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
An implementation of the BGP FSM as defined by RFC 4271
"""

# System imports
import logging

# Twisted imports
from twisted.internet import reactor, error

# BGP imports
from constants import *
from exceptions import NotificationSent

# Pybal imports :-(
from pybal.metrics import Gauge
from pybal.util import _log


class FSM(object):
    class BGPTimer(object):
        """
        Timer class with a slightly different Timer interface than the
        Twisted DelayedCall interface
        """

        def __init__(self, callable):
            self.delayedCall = None
            self.callable = callable

        def cancel(self):
            """Cancels the timer if it was running, does nothing otherwise"""

            try:
                self.delayedCall.cancel()
            except (AttributeError, error.AlreadyCalled, error.AlreadyCancelled):
                pass

        def reset(self, secondsFromNow):
            """Resets an already running timer, or starts it if it wasn't running."""

            try:
                self.delayedCall.reset(secondsFromNow)
            except (AttributeError, error.AlreadyCalled, error.AlreadyCancelled):
                self.delayedCall = reactor.callLater(secondsFromNow, self.callable)

        def active(self):
            """Returns True if the timer was running, False otherwise."""

            try:
                return self.delayedCall.active()
            except AttributeError:
                return False

    protocol = None

    state = ST_IDLE

    largeHoldTime = 4*60
    sendNotificationWithoutOpen = True    # No bullshit

    eventMethods = {
        1:  'manualStart',
        2:  'manualStop',
        3:  'automaticStart',

        9:  'connectRetryTimeEvent',
        10: 'holdTimeEvent',
        11: 'keepAliveEvent',
        12: 'delayOpenEvent',
        13: 'idleHoldTimeEvent',

        17: 'connectionMade',
        18: 'connectionFailed',
        19: 'openReceived',
        20: 'openReceived',
        21: 'headerError',
        22: 'openMessageError',
        23: 'openCollisionDump',
        24: 'versionError',
        25: 'notificationReceived',
        26: 'keepAliveReceived',
        27: 'updateReceived',
        28: 'updateError'
    }

    bgpTimers = { 'connectRetryTimer', 'holdTimer', 'keepAliveTimer',
        'delayOpenTimer', 'idleHoldTimer' }

    metric_labelnames = {'local_asn', 'state', 'local_ip', 'remote_ip', 'side'}
    metric_keywords = {
        'labelnames': metric_labelnames,
        'namespace': 'pybal',
        'subsystem': 'bgp'
    }

    metrics = {
        'bgp_session_state_count': Gauge('session_state_count',
                                   'Number of sessions in the specified state',
                                   **metric_keywords)
    }

    def __init__(self, bgpPeering=None, protocol=None):
        self.bgpPeering = bgpPeering
        self.protocol = protocol

        self.connectRetryCounter = 0
        self.connectRetryTime = 30
        self.connectRetryTimer = FSM.BGPTimer(self.connectRetryTimeEvent)
        self.holdTime = 3 * 60
        self.holdTimer = FSM.BGPTimer(self.holdTimeEvent)
        self.keepAliveTime = self.holdTime / 3
        self.keepAliveTimer = FSM.BGPTimer(self.keepAliveEvent)

        self.allowAutomaticStart = True
        self.allowAutomaticStop = False
        self.delayOpen = False
        self.delayOpenTime = 30
        self.delayOpenTimer = FSM.BGPTimer(self.delayOpenEvent)

        self.dampPeerOscillations = True
        self.idleHoldTime = 30
        self.idleHoldTimer = FSM.BGPTimer(self.idleHoldTimeEvent)

        self.metric_labels = {
            'state': stateDescr[self.state],
            'local_asn': None,
            'local_ip': None,
            'remote_ip': None,
            'side': None
        }
        if self.bgpPeering:
            self.metric_labels['local_asn'] = self.bgpPeering.myASN

        self.initial_idle_state = True

    def log(self, msg, lvl=logging.DEBUG):
        s = "bgp.FSM@{}".format(hex(id(self)))
        if self.protocol is not None:
            s += " peer {}".format(self.protocol.peerAddrStr())
        elif self.bgpPeering is not None:
            s += " peer {}".format(self.bgpPeering.peerAddr)
        _log(msg, lvl, s)

    def __setattr__(self, name, value):
        if name == 'state' and value != getattr(self, name):
            self.log("State is now: %s" % stateDescr[value], logging.INFO)
            self.__update_metrics(value)
        super(FSM, self).__setattr__(name, value)

    def __update_metrics(self, new_state):
        if self.metric_labels['local_ip'] and self.metric_labels['remote_ip']:
                if not self.initial_idle_state:
                    self.metrics['bgp_session_state_count'].labels(**self.metric_labels).dec()
                else:
                    self.initial_idle_state = False
                self.metric_labels['state'] = stateDescr[new_state]
                self.metrics['bgp_session_state_count'].labels(**self.metric_labels).inc()

    def manualStart(self):
        """
        Should be called when a BGP ManualStart event (event 1) is requested.
        Note that a protocol instance does not yet exist at this point.
        """

        if self.state == ST_IDLE:
            self.connectRetryCounter = 0
            self.connectRetryTimer.reset(self.connectRetryTime)
            if self.bgpPeering is not None:
                # Create outbound connection
                if self.bgpPeering.connect():
                    self.state = ST_CONNECT

    def manualStop(self):
        """Should be called when a BGP ManualStop event (event 2) is requested."""

        if self.state != ST_IDLE:
            self.protocol.sendNotification(ERR_CEASE, 0)
            # Stop all timers
            for timer in (self.connectRetryTimer, self.holdTimer, self.keepAliveTimer,
                          self.delayOpenTimer, self.idleHoldTimer):
                timer.cancel()
            if self.bgpPeering is not None: self.bgpPeering.releaseResources(self.protocol)
            self._closeConnection()
            self.connectRetryCounter = 0
            self.state = ST_IDLE
            raise NotificationSent(self.protocol, ERR_CEASE, 0)

    def automaticStart(self, idleHold=False):
        """
        Should be called when a BGP Automatic Start event (event 3) is requested.
        Returns True or False to indicate BGPPeering whether a connection attempt
        has been initiated.
        """

        if self.state == ST_IDLE:
            if idleHold:
                self.idleHoldTimer.reset(self.idleHoldTime)
                return False
            else:
                self.connectRetryCounter = 0
                self.connectRetryTimer.reset(self.connectRetryTime)
                # Create outbound connection if possible
                if self.bgpPeering is not None and self.bgpPeering.connect():
                    self.state = ST_CONNECT
                    return True
                else:
                    return False

    def connectionMade(self):
        """Should be called when a TCP connection has successfully been
        established with the peer. (events 16, 17)
        """

        if self.state in (ST_CONNECT, ST_ACTIVE):
            # State Connect, Event 16 or 17
            if self.delayOpen:
                self.connectRetryTimer.cancel()
                self.delayOpenTimer.reset(self.delayOpenTime)
            else:
                self.connectRetryTimer.cancel()
                if self.bgpPeering: self.bgpPeering.completeInit(self.protocol)
                self.protocol.sendOpen()
                self.holdTimer.reset(self.largeHoldTime)
                self.state = ST_OPENSENT

    def connectionFailed(self):
        """Should be called when the associated TCP connection failed, or
        was lost. (event 18)"""

        if self.state == ST_CONNECT:
            # State Connect, event 18
            if self.delayOpenTimer.active():
                 self.connectRetryTimer.reset(self.connectRetryTime)
                 self.delayOpenTimer.cancel()
                 self.state = ST_ACTIVE
            else:
                self.connectRetryTimer.cancel()
                self._closeConnection()
                if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
                self.state = ST_IDLE
        elif self.state == ST_ACTIVE:
            # State Active, event 18
            self.connectRetryTimer.reset(self.connectRetryTime)
            self.delayOpenTimer.cancel()
            if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
            self.connectRetryCounter += 1
            # TODO: osc damping
            self.state = ST_IDLE
        elif self.state == ST_OPENSENT:
            # State OpenSent, event 18
            if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
            self._closeConnection()
            self.connectRetryTimer.reset(self.connectRetryTime)
            self.state = ST_ACTIVE
        elif self.state in (ST_OPENCONFIRM, ST_ESTABLISHED):
            self._errorClose()


    def openReceived(self):
        """Should be called when a BGP Open message was received from
        the peer. (events 19, 20)
        """

        if self.state in (ST_CONNECT, ST_ACTIVE):
            if self.delayOpenTimer.active():
                # State Connect, event 20
                self.connectRetryTimer.cancel()
                if self.bgpPeering: self.bgpPeering.completeInit(self.protocol)
                self.delayOpenTimer.cancel()
                self.protocol.sendOpen()
                self.protocol.sendKeepAlive()
                if self.holdTime != 0:
                    self.keepAliveTimer.reset(self.keepAliveTime)
                    self.holdTimer.reset(self.holdTime)
                else:    # holdTime == 0
                    self.keepAliveTimer.cancel()
                    self.holdTimer.cancel()

                self.state = ST_OPENCONFIRM
            else:
                # State Connect, event 19
                self._errorClose()

        elif self.state == ST_OPENSENT:
            if not self.delayOpen:
                # State OpenSent, event 19
                self.delayOpenTimer.cancel()
                self.connectRetryTimer.cancel()
                self.protocol.sendKeepAlive()
                if self.holdTime > 0:
                    self.keepAliveTimer.reset(self.keepAliveTime)
                    self.holdTimer.reset(self.holdTime)
                self.state = ST_OPENCONFIRM
            else:
                # State OpenSent, event 20
                self.protocol.sendNotification(ERR_FSM, 0)
                self._errorClose()
                raise NotificationSent(self.protocol, ERR_FSM, 0)

        elif self.state == ST_OPENCONFIRM:
            if not self.delayOpen:
                # State OpenConfirm, events 19
                self.log("Running collision detection")

                # Perform collision detection
                self.protocol.collisionDetect()
            else:
                # State OpenConfirm, event 20
                self.protocol.sendNotification(ERR_FSM, 0)
                self._errorClose()
                raise NotificationSent(self.protocol, ERR_FSM, 0)

        elif self.state == ST_ESTABLISHED:
            # State Established, event 19 or 20
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def headerError(self, suberror, data=''):
        """
        Should be called when an invalid BGP message header was received.
        (event 21)
        """

        if self.state != ST_IDLE:
            self.protocol.sendNotification(ERR_MSG_HDR, suberror, data)
            # Note: RFC4271 states that we should send ERR_FSM in the
            # Established state, which contradicts earlier statements.
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_MSG_HDR, suberror, data)

    def openMessageError(self, suberror, data=''):
        """
        Should be called when an invalid BGP Open message was received.
        (event 22)
        """

        if self.state != ST_IDLE:
            self.protocol.sendNotification(ERR_MSG_OPEN, suberror, data)
            # Note: RFC4271 states that we should send ERR_FSM in the
            # Established state, which contradicts earlier statements.
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_MSG_OPEN, suberror, data)

    def keepAliveReceived(self):
        """
        Should be called when a BGP KeepAlive packet was received
        from the peer. (event 26)
        """

        if self.state == ST_OPENCONFIRM:
            # State OpenSent, event 26
            self.holdTimer.reset(self.holdTime)
            self.state = ST_ESTABLISHED
            self.protocol.deferred.callback(self.protocol)
        elif self.state == ST_ESTABLISHED:
            # State Established, event 26
            self.holdTimer.reset(self.holdTime)
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            # States Connect, Active, event 26
            self._errorClose()
        elif self.state == ST_OPENSENT:
            # State OpenSent, event 26
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def versionError(self):
        """
        Should be called when a BGP Notification Open Version Error
        message was received from the peer. (event 24)
        """

        if self.state in (ST_OPENSENT, ST_OPENCONFIRM):
            # State OpenSent/OpenConfirm, event 24
            self.connectRetryTimer.cancel()
            if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)
            self._closeConnection()
            self.state = ST_IDLE
        elif self.state in (ST_CONNECT, ST_ACTIVE, ST_ESTABLISHED):
            # State Connect/Active/Established, event 24
            self._errorClose()

    def notificationReceived(self, error, suberror):
        """
        Should be called when a BGP Notification message was
        received from the peer. (events 24, 25)
        """

        if error == ERR_MSG_OPEN and suberror == 1:
            # Event 24
            self.versionError()
        else:
            if self.state != ST_IDLE:
                # State != Idle, events 24, 25
                if self.state == ST_OPENSENT:
                    self.protocol.sendNotification(ERR_FSM, 0)
                self._errorClose()

    def updateReceived(self, update):
        """Called when a valid BGP Update message was received. (event 27)"""

        if self.state == ST_ESTABLISHED:
            # State Established, event 27
            if self.holdTime != 0:
                self.holdTimer.reset(self.holdTime)

            self.bgpPeering.update(update)
        elif self.state in (ST_ACTIVE, ST_CONNECT):
            # States Active, Connect, event 27
            self._errorClose()
        elif self.state in (ST_OPENSENT, ST_OPENCONFIRM):
            # States OpenSent, OpenConfirm, event 27
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def updateError(self, suberror, data=''):
        """Called when an invalid BGP Update message was received. (event 28)"""

        if self.state == ST_ESTABLISHED:
            # State Established, event 28
            self.protocol.sendNotification(ERR_MSG_UPDATE, suberror, data)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_MSG_UPDATE, suberror, data)
        elif self.state in (ST_ACTIVE, ST_CONNECT):
            # States Active, Connect, event 28
            self._errorClose()
        elif self.state in (ST_OPENSENT, ST_OPENCONFIRM):
            # States OpenSent, OpenConfirm, event 28
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def openCollisionDump(self):
        """
        Called when the collision detection algorithm determined
        that the associated connection should be dumped.
        (event 23)
        """

        self.log("Collided, closing")

        if self.state == ST_IDLE:
            return
        elif self.state in (ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED):
            self.protocol.sendNotification(ERR_CEASE, 0)

        self._errorClose()
        raise NotificationSent(self.protocol, ERR_CEASE, 0)

    def delayOpenEvent(self):
        """Called when the DelayOpenTimer expires. (event 12)"""

        assert(self.delayOpen)

        self.log("Delay Open event")

        if self.state == ST_CONNECT:
            # State Connect, event 12
            self.protocol.sendOpen()
            self.holdTimer.reset(self.largeHoldTime)
            self.state = ST_OPENSENT
        elif self.state == ST_ACTIVE:
            # State Active, event 12
            self.connectRetryTimer.cancel()
            self.delayOpenTimer.cancel()
            if self.bgpPeering: self.bgpPeering.completeInit(self.protocol)
            self.protocol.sendOpen()
            self.holdTimer.reset(self.largeHoldTime)
            self.state = ST_OPENSENT
        elif self.state != ST_IDLE:
            # State OpenSent, OpenConfirm, Established, event 12
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def keepAliveEvent(self):
        """Called when the KeepAliveTimer expires. (event 11)"""

        if self.state in (ST_OPENCONFIRM, ST_ESTABLISHED):
            # State OpenConfirm, Established, event 11
            self.protocol.sendKeepAlive()
            if self.holdTime > 0:
                self.keepAliveTimer.reset(self.keepAliveTime)
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            self._errorClose()
        elif self.state == ST_OPENSENT:
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def holdTimeEvent(self):
        """Called when the HoldTimer expires. (event 10)"""

        if self.state in (ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED):
            # States OpenSent, OpenConfirm, Established, event 10
            self.protocol.sendNotification(ERR_HOLD_TIMER_EXPIRED, 0)
            self._errorClose()
            # TODO: peer osc damping
        elif self.state in (ST_CONNECT, ST_ACTIVE):
            self._errorClose()

    def connectRetryTimeEvent(self):
        """Called when the ConnectRetryTimer expires. (event 9)"""

        if self.state == ST_CONNECT:
            # State Connect, event 9
            self._closeConnection()
            self.connectRetryTimer.reset(self.connectRetryTime)
            self.delayOpenTimer.cancel()
            # Initiate TCP connection
            if self.bgpPeering: self.bgpPeering.connectRetryEvent(self.protocol)
        elif self.state == ST_ACTIVE:
            # State Active, event 9
            self.connectRetryTimer.reset(self.connectRetryTime)
            # Initiate TCP connection
            if self.bgpPeering: self.bgpPeering.connectRetryEvent(self.protocol)
            self.state = ST_CONNECT
        elif self.state != ST_IDLE:
            # State OpenSent, OpenConfirm, Established, event 12
            self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            raise NotificationSent(self.protocol, ERR_FSM, 0)

    def idleHoldTimeEvent(self):
        """Called when the IdleHoldTimer expires. (event 13)"""

        if self.state == ST_IDLE:
            if self.bgpPeering: self.bgpPeering.automaticStart(idleHold=False)
        else:
            fsmError = False
            if self.state in (ST_OPENSENT, ST_OPENCONFIRM, ST_ESTABLISHED):
                fsmError = True
                self.protocol.sendNotification(ERR_FSM, 0)
            self._errorClose()
            if fsmError:
                raise NotificationSent(self.protocol, ERR_FSM, 0)

    def updateSent(self):
        """Called by the protocol instance when it just sent an Update message."""

        if self.holdTime > 0:
            self.keepAliveTimer.reset(self.keepAliveTime)

    def _errorClose(self):
        """Internal method that closes a connection and returns the state
        to IDLE.
        """

        # Stop the timers
        for timer in (self.connectRetryTimer, self.delayOpenTimer, self.holdTimer,
            self.keepAliveTimer):
            timer.cancel()

        # Release BGP resources (routes, etc)
        if self.bgpPeering: self.bgpPeering.releaseResources(self.protocol)

        self._closeConnection()

        self.connectRetryCounter += 1
        self.state = ST_IDLE

    def _closeConnection(self):
        """Internal method that close the connection if a valid BGP protocol
        instance exists.
        """

        if self.protocol is not None:
            self.protocol.closeConnection()
        # Remove from connections list
        if self.bgpPeering: self.bgpPeering.connectionClosed(self.protocol)
