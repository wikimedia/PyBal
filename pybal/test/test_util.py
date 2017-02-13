# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.util`.

"""
import unittest
import tempfile
import os
import logging

import pybal
import pybal.util

from .fixtures import PyBalTestCase
import mock
import cStringIO

class MiscUtilTestCase(PyBalTestCase):
    """Test case for misc. methods in `pybal.util`."""

    def testGetSubclasses(self):
        """Test case for `pybal.util.get_subclasses`."""

        class DummyParent(object):
            pass

        class DummyChild(DummyParent):
            pass

        class DummyGrandChild(DummyChild):
            pass

        subclasses = pybal.util.get_subclasses(DummyParent)
        subclasses.sort(key=lambda cls: cls.__name__)
        self.assertEqual(subclasses, [DummyChild, DummyGrandChild])


class ConfigDictTestCase(PyBalTestCase):
    """Test case for `pybal.util.ConfigDict`."""

    def setUp(self):
        super(ConfigDictTestCase, self).setUp()
        self.config.update({
            'int': '3',
            'truthy': 'true',
            'falsy': 'false',
            'float': '3.14',
        })

    def testGetInt(self):
        """Test `ConfigDict.getint()`."""
        self.assertEqual(self.config.getint('int'), 3)
        self.assertEqual(self.config.getint('missing', 4), 4)
        with self.assertRaises(KeyError):
            self.config.getint('missing')
        with self.assertRaises(ValueError):
            self.config.getint('truthy')

    def testGetFloat(self):
        """Test `ConfigDict.getfloat()`."""
        self.assertEqual(self.config.getfloat('float'), 3.14)
        self.assertEqual(self.config.getfloat('missing', True), True)
        with self.assertRaises(KeyError):
            self.config.getfloat('missing')
        with self.assertRaises(ValueError):
            self.config.getfloat('falsy')

    def testGetBoolean(self):
        """Test `ConfigDict.getboolean()`."""
        self.assertEqual(self.config.getboolean('truthy'), True)
        self.assertEqual(self.config.getboolean('falsy'), False)
        self.assertEqual(self.config.getboolean('missing', True), True)
        with self.assertRaises(KeyError):
            self.config.getboolean('missing')
        with self.assertRaises(ValueError):
            self.config.getboolean('float')


class DummyObserver(object):

    def __init__(self):
        self.events = []

    def __call__(self, eventdict):
        self.events.append(eventdict)


class LoggerTestCase(PyBalTestCase):
    """Test case for `pybal.util.Logger`"""

    def setUp(self):
        super(LoggerTestCase, self).setUp()
        self.obs = DummyObserver()

    @mock.patch('twisted.python.log.addObserver')
    def testInit(self, mocker):
        """Test case for `Logger.__init__`"""
        l = pybal.util.Logger(self.obs)
        mocker.assert_called_with(self.obs)
        self.assertIn('info', dir(l))

    def test_to_str(self):
        """Test case for `Logger._to_str`"""
        self.assertEquals(
            'INFO',
            pybal.util.Logger._to_str(logging.INFO))
        self.assertEquals(
            'DEBUG',
            pybal.util.Logger._to_str('unicorn'))

    @mock.patch('twisted.python.log.msg')
    def testGenLogger(self, mocker):
        """Test case for `Logger._genLogger`"""
        l = pybal.util.Logger(self.obs)
        f = l._genLogger(logging.INFO)
        f('test message')
        mocker.assert_called_with('INFO: test message',
                                  logLevel=logging.INFO,
                                  system='pybal')

    @mock.patch('twisted.python.log.err')
    def testErr(self, mocker):
        """Test case for `Logger.err`"""
        exc = KeyError('test')
        msg = 'Not Found'
        pybal.util.Logger.err(exc, msg)
        mocker.assert_called_with(exc, msg)


class PyBalLogObserverTestCase(PyBalTestCase):
    """Test case for `python.util.PyBalLogObserver`"""

    def setUp(self):
        self.fd = mock.MagicMock(autospec=cStringIO.StringIO)
        self.obs = pybal.util.PyBalLogObserver(self.fd)
        self.log = pybal.util.Logger(self.obs)

    def testInit(self):
        """Test case for `util.PyBalLogObserver.__init__`"""
        self.assertEquals([], self.fd.mock_calls)

    def testCall(self):
        self.log.debug("test_message")
        self.assertEquals([], self.obs.write.mock_calls)
        self.log.error("test_message2")
        self.obs.write.assert_called_with('[test_util] ERROR: test_message2\n')
        self.obs.level = logging.DEBUG
        self.fd.write.reset_mock()
        self.log.debug("test_message3")
        self.obs.write.assert_called_with('[pybal] DEBUG: test_message3\n')
        self.fd.write.reset_mock()
        self.log.debug("test_message3", system='test')
        self.obs.write.assert_called_with('[test] DEBUG: test_message3\n')
