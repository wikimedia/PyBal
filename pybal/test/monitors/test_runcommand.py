# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.monitors.runcommand`.
"""

# Testing imports
from .. import test_monitor

# Pybal imports
import pybal.monitor
from pybal.monitors.runcommand import RunCommandMonitoringProtocol, ProcessGroupProcess

# Twisted imports
import twisted.internet.process
import twisted.internet.base
import twisted.internet.task
import twisted.internet.error
from twisted.python import runtime, failure

# Python imports
import unittest, mock
import signal, errno


class RunCommandMonitoringProtocolTestCase(test_monitor.BaseMonitoringProtocolTestCase):
    """Test case for `pybal.monitors.RunCommandMonitoringProtocol`."""

    monitorClass = RunCommandMonitoringProtocol

    def setUp(self):
        self.config['runcommand.command'] = '/bin/true'
        super(RunCommandMonitoringProtocolTestCase, self).setUp()

    def testInit(self):
        self.config['runcommand.arguments'] = '[ "--help" ]'
        monitor = RunCommandMonitoringProtocol(
            self.coordinator, self.server, self.config)

        self.assertEqual(monitor.intvCheck,
                          RunCommandMonitoringProtocol.INTV_CHECK)
        self.assertEqual(monitor.timeout,
                          RunCommandMonitoringProtocol.TIMEOUT_RUN)
        self.assertEqual(monitor.command, self.config['runcommand.command'])
        self.assertEqual(monitor.arguments, ["--help",])

        self.assertTrue(monitor.logOutput)

        self.assertIsNone(monitor.checkCall)
        self.assertIsNone(monitor.runningProcess)

    def testInitNoArguments(self):
        monitor = RunCommandMonitoringProtocol(
            self.coordinator, self.server, self.config)
        self.assertEquals(monitor.arguments, [""])

    def testInitArgumentsNotStringList(self):
        self.config['runcommand.arguments'] = "[]"
        monitor = RunCommandMonitoringProtocol(
            self.coordinator, self.server, self.config)
        self.assertEquals(monitor.arguments, [""])

    def testRun(self):
        with mock.patch.object(self.monitor, 'runCommand') as mock_runCommand:
            super(RunCommandMonitoringProtocolTestCase, self).testRun()
        self.assertDelayedCallInvoked(self.monitor.checkCall, mock_runCommand)

    def testStop(self):
        self.monitor.runningProcess = mock.Mock(spec=ProcessGroupProcess)
        super(RunCommandMonitoringProtocolTestCase, self).testStop()
        self.monitor.runningProcess.signalProcess.assert_called_with(signal.SIGKILL)

    def testStopExitedAlready(self):
        self.monitor.runningProcess = mock.Mock(
            spec=ProcessGroupProcess,
            side_effect=twisted.internet.error.ProcessExitedAlready("Testing"))
        super(RunCommandMonitoringProtocolTestCase, self).testStop()
        self.monitor.runningProcess.signalProcess.assert_called_with(signal.SIGKILL)

    @mock.patch('twisted.internet.process.Process.__init__')
    def testRunCommand(self, mock_processInit):
        startSeconds = runtime.seconds()
        self.monitor.runCommand()
        self.assertGreaterEqual(self.monitor.checkStartTime, startSeconds)

        # Test whether a ProcessGroupProcess has been instantiated
        # with the right arguments
        runningProcess = self.monitor.runningProcess
        self.assertIsInstance(runningProcess, ProcessGroupProcess)
        self.assertTrue(runningProcess.sessionLeader)
        self.assertEqual(runningProcess.timeout, self.monitor.timeout)
        mock_processInit.assert_called_once()
        self.assertSequenceEqual(mock_processInit.call_args[0][:3],
            (self.monitor.reactor,
            self.monitor.command,
            [self.monitor.command] + self.monitor.arguments)
        )

    def testMakeConnection(self):
        self.monitor.makeConnection(mock.sentinel.process)

    def testChildDataReceived(self):
        with mock.patch.object(self.monitor, 'report') as mock_report:
            self.monitor.childDataReceived(1, "Testing\ttab")
        mock_report.assert_called_with(r"Cmd stdout: Testing\ttab")

    def testChildDataReceivedNoLogging(self):
        self.monitor.logOutput = False
        with mock.patch.object(self.monitor, 'report') as mock_report:
            self.monitor.childDataReceived(1, "Testing no logging")
        mock_report.assert_not_called()

    def testChildConnectionLost(self):
        self.monitor.childConnectionLost(6)

    def testProcessEndedProcessDone(self):
        """Assert that a clean process exit reports the monitor as up"""

        self.monitor.active = True
        self.monitor.checkStartTime = runtime.seconds()
        reason = failure.Failure(twisted.internet.error.ProcessDone("Process ended cleanly"))
        with mock.patch.multiple(self.monitor,
                                 _resultUp=mock.DEFAULT,
                                 _resultDown=mock.DEFAULT,
                                 runCommand=mock.DEFAULT) as mocks:
            self.monitor.processEnded(reason)
        mocks['_resultUp'].assert_called()
        mocks['_resultDown'].assert_not_called()
        self.assertDelayedCallInvoked(self.monitor.checkCall, mocks['runCommand'])

    def testProcessEndedProcessTerminated(self):
        """Assert that an unclean (non-zero) exit reports the monitor as down"""

        self.monitor.active = True
        self.monitor.checkStartTime = runtime.seconds()
        reason = failure.Failure(twisted.internet.error.ProcessTerminated("Process returned error"))
        with mock.patch.multiple(self.monitor,
                                 _resultUp=mock.DEFAULT,
                                 _resultDown=mock.DEFAULT,
                                 runCommand=mock.DEFAULT) as mocks:
            self.monitor.processEnded(reason)
        mocks['_resultDown'].assert_called()
        mocks['_resultUp'].assert_not_called()
        self.assertDelayedCallInvoked(self.monitor.checkCall, mocks['runCommand'])

    def testProcessEndedProcessUnknownError(self):
        """Assert that any other (unknown) error also reports the monitor as down"""

        self.monitor.active = False
        self.monitor.checkStartTime = runtime.seconds()
        reason = failure.Failure(twisted.internet.error.ProcessExitedAlready("Other error"))
        with mock.patch.multiple(self.monitor,
                                 _resultUp=mock.DEFAULT,
                                 _resultDown=mock.DEFAULT,
                                 runCommand=mock.DEFAULT) as mocks:
            with self.assertRaises((failure.Failure, reason.type)):
                self.monitor.processEnded(reason)
        mocks['_resultDown'].assert_not_called()
        mocks['_resultUp'].assert_not_called()
        self.assertIsNone(self.monitor.checkCall)
        self.reactor.advance(self.monitor.intvCheck)
        mocks['runCommand'].assert_not_called()

    def testLeftoverProcesses(self):
        """Assert that leftoverProcesses has different output for the two cases"""

        with mock.patch.object(self.monitor, 'report') as mock_report:
            self.monitor.leftoverProcesses(True)
            self.monitor.leftoverProcesses(False)
        self.assertNotEqual(mock_report.call_args[0], mock_report.call_args[1])


class ProcessGroupProcessTestCase(unittest.TestCase):
    @mock.patch('twisted.internet.process.Process.__init__')
    def setUp(self, mock_init):
        self.testReactor = twisted.internet.task.Clock()
        self.testCommand = '/bin/true'
        self.testArgs = ["--help"]
        self.testEnvironment = mock.sentinel.testEnvironment
        self.testPath = mock.sentinel.testPath
        self.testProto = mock.Mock(spec=RunCommandMonitoringProtocol)
        self.testTimeout = 3
        self.testUID = None
        self.testGID = None

        self.pgp = ProcessGroupProcess(
            self.testReactor,
            self.testCommand,
            self.testArgs,
            self.testEnvironment,
            self.testPath,
            self.testProto,
            sessionLeader=True,
            timeout=self.testTimeout)

        self.pgp.proto = self.testProto
        self.pgp.pid = 66

    @mock.patch('twisted.internet.process.Process.__init__')
    def testInit(self, mock_init):
        args = (
            self.testReactor,
            self.testCommand,
            self.testArgs,
            self.testEnvironment,
            self.testPath,
            self.testProto
        )
        kwargs = {
            'sessionLeader': True,
            'timeout': self.testTimeout
        }
        pgp = ProcessGroupProcess(*args, **kwargs)
        mock_init.assert_called_once()
        self.assertTrue(pgp.sessionLeader)
        self.assertEqual(pgp.timeout, self.testTimeout)
        self.assertIsNone(pgp.timeoutCall)
        self.assertIs(pgp.reactor, self.testReactor)

    @mock.patch('twisted.internet.process.Process._execChild')
    def testExecChild(self, mock_execChild):
        with mock.patch.object(self.pgp, '_setupSession') as mock_setupSession:
            self.pgp._execChild(
                self.testPath,
                self.testUID,
                self.testGID,
                self.testCommand,
                self.testArgs,
                self.testEnvironment)
        mock_execChild.assert_called_once()
        mock_setupSession.assert_called_once()

    @mock.patch('twisted.internet.process.Process._fork')
    def testFork(self, mock_fork):
        with mock.patch.object(self.pgp, '_processTimeout') as mock_pTimeout:
            self.pgp._fork(
                self.testPath,
                self.testUID,
                self.testGID,
                self.testCommand,
                self.testArgs,
                self.testEnvironment)
            mock_fork.assert_called_once()
            self.assertIsInstance(self.pgp.timeoutCall, twisted.internet.base.DelayedCall)
            self.assertTrue(self.pgp.timeoutCall.active())
            mock_pTimeout.assert_not_called()
            self.testReactor.advance(self.testTimeout)
            mock_pTimeout.assert_called_once()

    @mock.patch('twisted.internet.process.Process.processEnded')
    def testProcessEnded(self, mock_pEnded):
        self.pgp.timeoutCall = self.testReactor.callLater(
            self.testTimeout, self.pgp._processTimeout)

        with mock.patch.object(self.pgp, 'signalProcessGroup') as mock_sPG:
            self.pgp.processEnded(mock.sentinel.status)

        self.assertFalse(self.pgp.timeoutCall.active())
        mock_pEnded.assert_called_once()

        # Check whether the process group has been terminated
        mock_sPG.assert_called_once_with(signal.SIGKILL, -self.pgp.pid)
        self.testProto.leftoverProcesses.assert_called_once_with(True)

    @mock.patch('twisted.internet.process.Process.processEnded')
    def testProcessEndedEPERM(self, mock_pEnded):
        self.pgp.timeoutCall = self.testReactor.callLater(
            self.testTimeout, self.pgp._processTimeout)

        with mock.patch.object(self.pgp, 'signalProcessGroup', ) as mock_sPG:
            mock_sPG.side_effect=OSError(errno.EPERM, "Testing missing permissions")
            self.pgp.processEnded(mock.sentinel.status)

        self.assertFalse(self.pgp.timeoutCall.active())
        mock_pEnded.assert_called_once()

        # Check whether the process group has been terminated
        mock_sPG.assert_called_once_with(signal.SIGKILL, -self.pgp.pid)
        self.testProto.leftoverProcesses.assert_called_once_with(False)

    @mock.patch('twisted.internet.process.Process.processEnded')
    def testProcessEndedUnknownError(self, mock_pEnded):
        with mock.patch.object(self.pgp, 'signalProcessGroup', ) as mock_sPG:
            mock_sPG.side_effect=OSError(errno.EAGAIN, "Testing unknown error")
            with self.assertRaises(OSError):
                self.pgp.processEnded(mock.sentinel.status)

        mock_pEnded.assert_called_once()

        # Check whether the process group has been terminated
        mock_sPG.assert_called_once_with(signal.SIGKILL, -self.pgp.pid)
        self.testProto.leftoverProcesses.assert_not_called()

    @mock.patch('os.setsid')
    def testSetupSession(self, mock_setsid):
        self.pgp._setupSession()
        mock_setsid.assert_called()

    def testProcessTimeout(self):
        self.pgp.lostProcess = False
        with mock.patch.object(self.pgp, 'signalProcessGroup') as mock_sPG:
            self.pgp._processTimeout()
        mock_sPG.assert_called_once_with(signal.SIGKILL)

    @mock.patch('os.kill')
    def testSignalProcessGroup(self, mock_kill):
        self.pgp.signalProcessGroup(signal.SIGKILL)
        mock_kill.assert_called_with(-self.pgp.pid, signal.SIGKILL)

        mock_kill.rest_mock()
        self.pgp.signalProcessGroup(signal.SIGTERM, pgid=99)
        mock_kill.assert_called_with(99, signal.SIGTERM)
