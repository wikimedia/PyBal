"""
monitor.py
Copyright (C) 2006-2014 by Mark Bergsma <mark@nedworks.org>

Monitor class implementations for PyBal
"""
from twisted.internet import reactor
from . import util
import logging
from pybal.metrics import Counter

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
    }

    def __init__(self, coordinator, server, configuration={}, reactor=reactor):
        """Constructor"""

        self.coordinator = coordinator
        self.server = server
        self.configuration = configuration
        self.up = None    # None, False (Down) or True (Up)
        self.reactor = reactor

        self.active = False
        self.firstCheck = True

        # Install cleanup handler
        self.reactor.addSystemEventTrigger('before', 'shutdown', self.stop)

        self.metric_labels = {
            'service': self.server.lvsservice.name,
            'host': self.server.host,
            'monitor': self.name()
        }

    def run(self):
        """Start the monitoring"""
        assert self.active is False
        self.active = True

    def stop(self):
        """Stop the monitoring; cancel any running or upcoming checks"""
        self.active = False

    def name(self):
        """Returns a printable name for this monitor"""
        return self.__name__

    def _resultUp(self):
        """Sets own monitoring state to Up and notifies the coordinator
        if this implies a state change.
        """
        if self.active and self.up is False or self.firstCheck:
            self.up = True
            self.firstCheck = False
            if self.coordinator:
                self.coordinator.resultUp(self)

            self.metrics['up_transitions_total'].labels(**self.metric_labels).inc()


    def _resultDown(self, reason=None):
        """Sets own monitoring state to Down and notifies the
        coordinator if this implies a state change."""
        if self.active and self.up is True or self.firstCheck:
            self.up = False
            self.firstCheck = False
            if self.coordinator:
                self.coordinator.resultDown(self, reason)

            self.metrics['down_transitions_total'].labels(**self.metric_labels).inc()

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
