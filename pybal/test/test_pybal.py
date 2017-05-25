# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.pybal`.

"""
import sys
import mock
from .fixtures import PyBalTestCase
from pybal.main import parseCommandLine


class TestBaseUtils(PyBalTestCase):

    def test_parseCommandLine(self):
        """Test case for `pybal.pybal.parseCommandLine`"""
        testargs = ['pybal', '--dryrun', '--debug']
        config = {}
        with mock.patch.object(sys, 'argv', testargs):
            parseCommandLine(config)
            self.assertEquals(config, {'debug': True, 'dryrun': True,
                                       'conffile': '/etc/pybal/pybal.conf'})
        testargs.append('--badarg')
        # Bad argument exits with code 2
        with mock.patch.object(sys, 'argv', testargs):
            with self.assertRaises(SystemExit) as exc:
                parseCommandLine(config)
                self.assertEquals(exc.exception.code, 2)
        # Asking for the help exits with code 0
        testargs = ['pybal', '--help']
        with mock.patch.object(sys, 'argv', testargs):
            with self.assertRaises(SystemExit) as exc:
                parseCommandLine(config)
                self.assertEquals(exc.exception.code, 0)
