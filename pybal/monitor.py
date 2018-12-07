"""
monitor.py
Copyright (C) 2006-2014 by Mark Bergsma <mark@nedworks.org>

Monitor class implementations for PyBal
"""

# Python imports
import logging

# Twisted imports
import twisted.internet.reactor
from twisted.internet import task

# Pybal imports
from . import util
from pybal.metrics import Counter, Gauge


_log = util._log


class MonitoringProtocol(object):
    """
    Base class for all monitoring protocols. Declares a few obligatory
    abstract methods, and some commonly useful functions.
    """

    __name__ = ''

    metric_labelnames = ('service', 'host', 'monitor')
    metric_keywords = {
        'labelnames': metric_labelnames,
        'namespace': 'pybal',
        'subsystem': 'monitor'
    }

    metrics = {
        'up_transitions_total': Counter('up_transitions_total', 'Monitor up transition count', **metric_keywords),
        'down_transitions_total': Counter('down_transitions_total', 'Monitor down transition count', **metric_keywords),
        'up_results_total': Counter('up_results_total', 'Monitor up result count', **metric_keywords),
        'down_results_total': Counter('down_results_total', 'Monitor down result count', **metric_keywords),
        'status': Gauge('status', 'Monitor up status', **metric_keywords)
    }

    def __init__(self, coordinator, server, configuration={}, reactor=None):
        """Constructor"""

        self.coordinator = coordinator
        self.server = server
        self.configuration = configuration
        self.up = None    # None, False (Down) or True (Up)
        self.reactor = reactor or twisted.internet.reactor

        self.active = False
        self.firstCheck = True
        self._shutdownTriggerID = None

        self.metric_labels = {
            'service': self.server.lvsservice.name,
            'host': self.server.host,
            'monitor': self.name()
        }

    def run(self):
        """Start the monitoring"""
        assert self.active is False
        self.active = True

        # Install cleanup handler
        self._shutdownTriggerID = self.reactor.addSystemEventTrigger(
            'before', 'shutdown', self.stop)

    def stop(self):
        """Stop the monitoring; cancel any running or upcoming checks"""
        self.active = False
        if self._shutdownTriggerID is not None:
            # Remove cleanup handler
            self.reactor.removeSystemEventTrigger(self._shutdownTriggerID)
            self._shutdownTriggerID = None

    def name(self):
        """Returns a printable name for this monitor"""
        return self.__name__

    def _resultUp(self):
        """Sets own monitoring state to Up and notifies the coordinator
        if this implies a state change.
        """
        self.metrics['up_results_total'].labels(**self.metric_labels).inc()
        if self.active and self.up is False or self.firstCheck:
            self.up = True
            if self.coordinator:
                self.coordinator.resultUp(self)
            self.firstCheck = False

            self.metrics['up_transitions_total'].labels(**self.metric_labels).inc()
            self.metrics['status'].labels(**self.metric_labels).set(1)

    def _resultDown(self, reason=None):
        """Sets own monitoring state to Down and notifies the
        coordinator if this implies a state change."""
        self.metrics['down_results_total'].labels(**self.metric_labels).inc()
        if self.active and self.up is True or self.firstCheck:
            self.up = False
            if self.coordinator:
                self.coordinator.resultDown(self, reason)
            self.firstCheck = False

            self.metrics['down_transitions_total'].labels(**self.metric_labels).inc()
            self.metrics['status'].labels(**self.metric_labels).set(0)

    def report(self, text, level=logging.DEBUG):
        """Common method for reporting/logging check results."""
        msg = "%s (%s): %s" % (
            self.server.host,
            self.server.textStatus(),
            text
        )
        s = "%s %s" % (self.server.lvsservice.name, self.__name__)
        _log(msg, level, s)

    def _getConfigBool(self, optionname, default=None):
        return self.configuration.getboolean(
            '%s.%s' % (self.__name__.lower(), optionname), default)

    def _getConfigInt(self, optionname, default=None):
        return self.configuration.getint(
            '%s.%s' % (self.__name__.lower(), optionname), default)

    def _getConfigString(self, optionname):
        val = self.configuration[self.__name__.lower() + '.' + optionname]
        if type(val) == str:
            return val
        else:
            raise ValueError("Value of %s is not a string" % optionname)

    def _getConfigStringList(self, optionname, locals=None, globals=None):
        """Takes a (string) value, eval()s it and checks whether it
        consists of either a single string, or a single list of
        strings."""
        key = self.__name__.lower() + '.' + optionname
        val = eval(self.configuration[key], locals, globals)
        if type(val) == str:
            return val
        elif (isinstance(val, list) and
              all(isinstance(x, basestring) for x in val) and val):
            # Checked that each list member is a string and that list is not
            # empty.
            return val
        else:
            raise ValueError("Value of %s is not a string or stringlist" %
                             optionname)


class LoopingCheckMonitoringProtocol(MonitoringProtocol):
    """
    Class that sets up a looping call (self.check) to do a monitoring check with
    a semi-fixed interval.
    """

    INTV_CHECK = 10

    def __init__(self, coordinator, server, configuration={}, reactor=None):

        assert hasattr(self, 'check'), "Method 'check' is not implemented."

        super(LoopingCheckMonitoringProtocol, self).__init__(
            coordinator,
            server,
            configuration,
            reactor)

        self.intvCheck = self._getConfigInt('interval', self.INTV_CHECK)

        self.checkCall = None

    def run(self):
        """
        Start the monitoring. Sets up the looping call.
        """

        super(LoopingCheckMonitoringProtocol, self).run()

        self.checkCall = task.LoopingCall(self.check)
        self.checkCall.clock = self.reactor
        self.checkCall.start(self.intvCheck, now=False).addErrback(self.onCheckFailure)

    def stop(self):
        """
        Stop the monitoring. Stops the looping call.
        """

        if self.checkCall is not None and self.checkCall.running:
            self.checkCall.stop()

        super(LoopingCheckMonitoringProtocol, self).stop()

    def check(self):
        raise NotImplementedError()

    def onCheckFailure(self, failure):
        """
        Called when the looping call (check) throws an error/Failure
        As we generally want the monitor to keep running no matter what,
        restart the loop.
        """

        self.report("Check loop aborted due to failure: {}. "
            "Restarting.".format(failure.getErrorMessage()),
            level=logging.WARN)

        if not self.checkCall.running:
            self.checkCall.start(self.intvCheck, now=False)
