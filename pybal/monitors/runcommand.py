"""
runcommand.py
Copyright (C) 2008 by Mark Bergsma <mark@nedworks.org>

Monitor class implementations for PyBal
"""
import errno
import logging
import os
import signal

from twisted.internet import reactor, process, error

from pybal import monitor
from pybal.util import log


class ProcessGroupProcess(process.Process, object):
    """
    Derivative of twisted.internet.process that supports Unix
    process groups, sessions and timeouts
    """
    def __init__(self,
                 reactor, command, args, environment, path, proto,
                 uid=None, gid=None, childFDs=None,
                 sessionLeader=False, timeout=None):

        self.sessionLeader = sessionLeader
        self.timeout = timeout
        self.timeoutCall = None
        super(ProcessGroupProcess, self).__init__(
            reactor, command, args, environment, path, proto,
            uid=uid, gid=gid, childFDs=childFDs
        )

    def _execChild(self, path, uid, gid, executable, args, environment):
        if self.sessionLeader:
            self._setupSession()
        super(ProcessGroupProcess, self)._execChild(path, uid, gid, executable, args, environment)

    def _fork(self, path, uid, gid, executable, args, environment, **kwargs):
        super(ProcessGroupProcess, self)._fork(path, uid, gid, executable, args, environment, **kwargs)
        # In case we set timeouts, just respect them.
        if self.timeout:
            self.timeoutCall = reactor.callLater(self.timeout, self._processTimeout)

    def processEnded(self, status):
        if self.timeoutCall:
            try:
                self.timeoutCall.cancel()
            except Exception:
                pass

        pgid = -self.pid
        try:
            process.Process.processEnded(self, status)
        finally:
            # The process group leader may have terminated, but child process in
            # the group may still be alive. Mass slaughter.
            try:
                self.signalProcessGroup(signal.SIGKILL, pgid)
            except OSError, e:
                if e.errno == errno.EPERM:
                    self.proto.leftoverProcesses(False)
                elif e.errno != errno.ESRCH:
                    log.error("pgid: {} e:{}".format(pgid, e))
                    raise
            else:
                self.proto.leftoverProcesses(True)

    def _setupSession(self):
        os.setsid()

    def _processTimeout(self):
        """
        Called when the timeout expires.
        """
        # Kill the process group
        if not self.lostProcess:
            self.signalProcessGroup(signal.SIGKILL)

    def signalProcessGroup(self, signal, pgid=None):
        os.kill(pgid or -self.pid, signal)


class RunCommandMonitoringProtocol(monitor.MonitoringProtocol):
    """
    Monitor that checks server uptime by repeatedly fetching a certain URL
    """

    __name__ = 'RunCommand'

    INTV_CHECK = 60

    TIMEOUT_RUN = 20

    def __init__(self, coordinator, server, configuration={}):
        """Constructor"""

        # Call ancestor constructor
        super(RunCommandMonitoringProtocol, self).__init__(coordinator, server, configuration)

        locals = { 'server': server }

        self.intvCheck = self._getConfigInt('interval', self.INTV_CHECK)
        self.timeout = self._getConfigInt('timeout', self.TIMEOUT_RUN)
        self.command = self._getConfigString('command')
        self.arguments = self._getConfigStringList('arguments', locals=locals)
        self.logOutput = self._getConfigBool('log-output', True)

        self.checkCall = None
        self.runningProcess = None

    def run(self):
        """Start the monitoring"""

        super(RunCommandMonitoringProtocol, self).run()

        if not self.checkCall or not self.checkCall.active():
            self.checkCall = reactor.callLater(self.intvCheck, self.runCommand)

    def stop(self):
        """Stop all running and/or upcoming checks"""

        super(RunCommandMonitoringProtocol, self).stop()

        if self.checkCall and self.checkCall.active():
            self.checkCall.cancel()

        # Try to kill any running check
        if self.runningProcess is not None:
            try:
                self.runningProcess.signalProcess(signal.SIGKILL)
            except error.ProcessExitedAlready:
                pass

    def runCommand(self):
        """Periodically called method that does a single uptime check."""

        self.runningProcess = self._spawnProcess(self, self.command, [self.command] + self.arguments,
                                                 sessionLeader=True, timeout=(self.timeout or None))

    def makeConnection(self, process):
        pass

    def childDataReceived(self, childFD, data):
        if not self.logOutput:
            return

        # Escape control chars
        map = {'\n': r'\n',
               '\r': r'\r',
               '\t': r'\t'}
        for char, subst in map.iteritems():
            data = data.replace(char, subst)

        self.report("Cmd stdout: " + data)

    def childConnectionLost(self, childFD):
        pass

    def processEnded(self, reason):
        """
        Called when the process has ended
        """

        if reason.check(error.ProcessDone):
            self._resultUp()
        elif reason.check(error.ProcessTerminated):
            self._resultDown(reason.getErrorMessage())

        # Schedule the next check
        if self.active:
            self.checkCall = reactor.callLater(self.intvCheck, self.runCommand)

        reason.trap(error.ProcessDone, error.ProcessTerminated)

    def leftoverProcesses(self, allKilled):
        """
        Called when the child terminated cleanly, but left some of
        its child processes behind
        """

        if allKilled:
            msg = "Command %s %s left child processes behind, which have been killed!"
        else:
            msg = "Command %s %s left child processes behind, and not all could be killed!"
        self.report(msg % (self.command, str(self.arguments)),
                    level=logging.WARN)

    def _spawnProcess(self, processProtocol, executable, args=(),
                      env={}, path=None,
                      uid=None, gid=None, childFDs=None,
                      sessionLeader=False, timeout=None):
        """
        Replacement for posixbase.PosixReactorBase.spawnProcess with added
        process group / session and timeout support, and support for
        non-POSIX platforms and PTYs removed.
        """

        args, env = reactor._checkProcessArgs(args, env)
        return ProcessGroupProcess(reactor, executable, args, env, path,
                                   processProtocol, uid, gid, childFDs,
                                   sessionLeader, timeout)
