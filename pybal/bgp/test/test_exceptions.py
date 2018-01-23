# -*- coding: utf-8 -*-
"""
  bgp.exceptions unit tests
  ~~~~~~~~~~~~~~~~~~~~~~~~~

  This module contains tests for `bgp.exceptions`.

"""

import unittest
import mock

from .. import exceptions, bgp

class BGPExceptionTestCase(unittest.TestCase):
    def setUp(self):
        self.mockProtocol = mock.MagicMock()
        self.exception = exceptions.BGPException(self.mockProtocol)

    def testConstructor(self):
        self.assertEquals(self.exception.protocol, self.mockProtocol)

class NotificationSentTestCase(BGPExceptionTestCase):
    def setUp(self):
        self.mockProtocol = mock.MagicMock()
        self.exception = exceptions.NotificationSent(
            self.mockProtocol,
            bgp.ERR_MSG_OPEN,
            bgp.ERR_MSG_OPEN_UNSUP_VERSION,
            "Test case")

    def testConstructor(self):
        super(NotificationSentTestCase, self).testConstructor()
        self.assertEquals(self.exception.error, bgp.ERR_MSG_OPEN)
        self.assertEquals(self.exception.suberror, bgp.ERR_MSG_OPEN_UNSUP_VERSION)
        self.assertEquals(self.exception.data, "Test case")

    def test__str__(self):
        self.assertEquals(
            str(self.exception),
            repr((bgp.ERR_MSG_OPEN, bgp.ERR_MSG_OPEN_UNSUP_VERSION, "Test case")))

class BadMessageLengthTestCase(BGPExceptionTestCase):
    pass

class AttributeExceptionTestCase(BGPExceptionTestCase):
    def setUp(self):
        self.exception = exceptions.AttributeException(
            bgp.ERR_MSG_UPDATE_MALFORMED_ATTR_LIST, "Test case")

    def testConstructor(self):
        self.assertEquals(self.exception.error, bgp.ERR_MSG_UPDATE)
        self.assertEquals(self.exception.suberror, bgp.ERR_MSG_UPDATE_MALFORMED_ATTR_LIST)
        self.assertEquals(self.exception.data, "Test case")
