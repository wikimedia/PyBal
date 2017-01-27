"""
util.py - PyBal utility classes
Copyright (C) 2006-2008 by Mark Bergsma <mark@nedworks.org>

LVS Squid balancer/monitor for managing the Wikimedia Squid servers using LVS
"""
import os
import sys
from twisted.python import log as tw_log
from twisted.python import util
import inspect
import logging


def get_subclasses(cls):
    """Return a list of all direct and indirect subclasses of a given class."""
    subclasses = []
    for subclass in cls.__subclasses__():
        subclasses.append(subclass)
        subclasses.extend(get_subclasses(subclass))
    return subclasses


class ConfigDict(dict):

    def getint(self, key, default=None):
        try:
            return int(self[key])
        except KeyError:
            if default is not None:
                return default
            else:
                raise
        # do not intercept ValueError

    def getboolean(self, key, default=None):
        try:
            value = self[key]
        except KeyError:
            if default is not None:
                return default
            else:
                raise
        else:
            if value in (True, False):
                return value
            value = value.strip().lower()
            if value in ('t', 'true', 'y', 'yes', 'on', '1'):
                return True
            elif value in ('f', 'false', 'n', 'no', 'off', '0'):
                return False
            else:
                raise ValueError

    def getfloat(self, key, default=None):
        try:
            return float(self[key])
        except KeyError:
            if default is not None:
                return default
            else:
                raise
        # do not intercept ValueError


class PyBalLogObserver(tw_log.FileLogObserver):
    """Simple log observer derived from FileLogObserver"""
    level = logging.INFO

    def __init__(self, f):
        tw_log.FileLogObserver.__init__(self, f)

    def __call__(self, eventDict):
        if eventDict.get('logLevel', logging.DEBUG) >= self.level:
            return self.emit(eventDict)

    def emit(self, eventDict):
        text = tw_log.textFromEventDict(eventDict)
        if text is None:
            return

        fmtDict = {'system': eventDict['system'],
                   'text': text.replace("\n", "\n\t")}
        msgStr = tw_log._safeFormat("[%(system)s] %(text)s\n", fmtDict)
        util.untilConcludes(self.write, msgStr)
        util.untilConcludes(self.flush)


class Logger(object):
    """Simple logger class that mimics the syntax of normal python logging"""
    levels = {
        logging.DEBUG: 'DEBUG',
        logging.INFO: 'INFO',
        logging.WARN: 'WARN',
        logging.ERROR: 'ERROR',
        logging.CRITICAL: 'CRITICAL'
    }

    def __init__(self, observer):
        tw_log.addObserver(observer)
        for k, v in self.levels.items():
            method_name = v.lower()
            setattr(self,
                    method_name,
                    self._genLogger(k))

    @staticmethod
    def _to_str( level):
        return Logger.levels.get(level, 'DEBUG')

    def _genLogger(self, lvl):
        def _log(msg, **kwargs):
            level = Logger._to_str(lvl)
            # If system has not been specified, default to caller function
            # module name (eg: pybal, etcd) for logs with severity WARN or
            # higher
            if 'system' not in kwargs and lvl >= logging.WARN:
                sys = os.path.basename(inspect.stack(0)[1][1]).replace('.py', '')
            else:
                sys = kwargs.get('system', 'pybal')

            message = "%s: %s" % (level, msg)
            tw_log.msg(message, logLevel=lvl, system=sys)
        return _log

    @staticmethod
    def err(*args, **kw):
        return tw_log.err(*args, **kw)


stderr = PyBalLogObserver(sys.stderr)
log = Logger(observer=stderr)


def _log(msg, lvl=logging.DEBUG, system='pybal'):
    logf = log._genLogger(lvl)
    return logf(msg, system=system)
