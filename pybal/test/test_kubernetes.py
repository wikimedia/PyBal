# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.kubernetes`.

"""

import attr
import copy
import json

from mock import patch
from treq.client import HTTPClient
from treq.testing import (HasHeaders, RequestSequence, StringStubbingResource,
                          StubTreq)
from twisted.internet import task
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.error import ConnectingCancelledError
from twisted.logger import Logger
from twisted.test.proto_helpers import MemoryReactorClock
from twisted.trial.unittest import SynchronousTestCase
from twisted.web import http
from twisted.web.client import Agent
from twisted.web.error import SchemeNotSupported
from twisted.web.iweb import IAgentEndpointFactory
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET
from zope.interface import implementer

import pybal
import pybal.kubernetes
from pybal.kubernetes import UNSCHEDULABLE_SPEC
from pybal.test.fixtures import StubCoordinator

log = Logger()

# minimal GET /v1/nodes response (version 1.7)
MOCKED_RESPONSE = {
    'items': [
        {
            'spec': {},
            'metadata':
            {
                'name': 'kubernetes1001.eqiad.wmnet'
            },
            'status':
            {
                'conditions': [
                    {
                        'type': 'Ready',
                        'status': 'True',
                    }
                ]
            }
        },
        {
            'spec': {},
            'metadata':
            {
                'name': 'kubernetes1002.eqiad.wmnet'
            },
            'status':
            {
                'conditions': [
                    {
                        'type': 'Ready',
                        'status': 'True',
                    }
                ]
            }
        },
        {
            'spec': {},
            'metadata':
            {
                'name': 'kubernetes1003.eqiad.wmnet'
            },
            'status':
            {
                'conditions': [
                    {
                        'type': 'OutOfDisk',
                        'status': 'False',
                    },
                    {
                        'type': 'Ready',
                        'status': 'True',
                    }
                ]
            }
        },
        {
            'spec':
            {
                UNSCHEDULABLE_SPEC: 'false',
            },
            'metadata':
            {
                'name': 'kubernetes1004.eqiad.wmnet'
            },
            'status':
            {
                'conditions': [
                    {
                        'type': 'Ready',
                        'status': 'True',
                    }
                ]
            }
        },
    ]
}

class _NonResponsiveTestResource(Resource):
    """Resource that returns NOT_DONE_YET and never finishes the request"""
    isLeaf = True

    def render(self, request):
        return NOT_DONE_YET


@implementer(IAgentEndpointFactory)
@attr.s
class _EndpointFactory(object):
    """
    An endpoint factory used by :class:`RequestTraversalAgent`.
    :ivar reactor: The agent's reactor.
    :type reactor: :class:`MemoryReactor`
    """

    reactor = attr.ib()

    def endpointForURI(self, uri):
        if uri.scheme not in {b'http', b'https'}:
            raise SchemeNotSupported("Unsupported scheme: %r" % (uri.scheme,))
        return TCP4ClientEndpoint(self.reactor, "127.0.0.1", uri.port)

class KubernetesConfigurationObserverTestCase(SynchronousTestCase):
    def setUp(self):
        url = "k8s://token@k8s.wmnet.test:1234"
        self.observer = pybal.config.ConfigurationObserver.fromUrl(StubCoordinator(),
                                                                   url)

    def testFromURL(self):
        self.assertIsInstance(self.observer,
                              pybal.kubernetes.KubernetesConfigurationObserver
        )

        self.assertEquals(self.observer.token, 'token')
        self.assertEquals(self.observer.host, 'k8s.wmnet.test')
        self.assertEquals(self.observer.port, 1234)

    def _requestSequenceGenerator(self, response, statusCode=http.OK):
        return RequestSequence([
            ((b'get', 'https://k8s.wmnet.test:1234/v1/nodes', {b'pretty': [b'false']},
              HasHeaders({
                  'Accept': ['application/json'],
                  'Authorization': ['Bearer token'],
              }), b''),
             (statusCode, {b'Content-Type': b'application/json'}, response))
        ], log.error)

    def _successfulRequestHelper(self, response, expectedConfig):
        req_seq = self._requestSequenceGenerator(response)

        treq_stub = StubTreq(StringStubbingResource(req_seq))
        with patch.object(self.observer, 'client', treq_stub):
            with patch.object(self.observer, 'onUpdate') as onUpdateMock:
                with req_seq.consume(self.fail):
                    result = self.successResultOf(self.observer.observe())
                    self.assertIsNone(result)
                onUpdateMock.assert_called_with(expectedConfig)

    def testSuccessfulRequest(self):
        expectedConfig = {
            'kubernetes1001.eqiad.wmnet': {'enabled': True, 'weight': 1},
            'kubernetes1002.eqiad.wmnet': {'enabled': True, 'weight': 1},
            'kubernetes1003.eqiad.wmnet': {'enabled': True, 'weight': 1},
            'kubernetes1004.eqiad.wmnet': {'enabled': True, 'weight': 1},
        }

        self._successfulRequestHelper(json.dumps(MOCKED_RESPONSE), expectedConfig)

    def testDisabledNode(self):
        response = copy.deepcopy(MOCKED_RESPONSE)
        response['items'][0]['status']['conditions'][0]['status'] = 'False'

        expectedConfig = {
            'kubernetes1001.eqiad.wmnet': {'enabled': False, 'weight': 1},
            'kubernetes1002.eqiad.wmnet': {'enabled': True, 'weight': 1},
            'kubernetes1003.eqiad.wmnet': {'enabled': True, 'weight': 1},
            'kubernetes1004.eqiad.wmnet': {'enabled': True, 'weight': 1},
        }

        self._successfulRequestHelper(json.dumps(response), expectedConfig)

    def testUnschedulableNode(self):
        response = copy.deepcopy(MOCKED_RESPONSE)
        response['items'][0]['spec'][UNSCHEDULABLE_SPEC] = 'true'

        expectedConfig = {
            'kubernetes1002.eqiad.wmnet': {'enabled': True, 'weight': 1},
            'kubernetes1003.eqiad.wmnet': {'enabled': True, 'weight': 1},
            'kubernetes1004.eqiad.wmnet': {'enabled': True, 'weight': 1},
        }

        self._successfulRequestHelper(json.dumps(response), expectedConfig)

    def testInvalidPayload(self):
        req_seqs = [
            self._requestSequenceGenerator(b'{[`'),
            self._requestSequenceGenerator(json.dumps({'k8s': False})),
        ]

        for seq in req_seqs:
            treq_stub = StubTreq(StringStubbingResource(seq))
            with patch.object(self.observer, 'client', treq_stub):
                with patch.object(self.observer, 'onUpdate') as onUpdateMock:
                    with seq.consume(self.fail):
                        failure = self.failureResultOf(self.observer.observe())
                        self.assertEquals('Invalid payload', failure.getErrorMessage())
                    onUpdateMock.assert_not_called()

    def testNon200StatusCode(self):
        req_seq = self._requestSequenceGenerator(json.dumps(MOCKED_RESPONSE), statusCode=418)
        treq_stub = StubTreq(StringStubbingResource(req_seq))
        with patch.object(self.observer, 'client', treq_stub):
            with patch.object(self.observer, 'onUpdate') as onUpdateMock:
                with req_seq.consume(self.fail):
                    failure = self.failureResultOf(self.observer.observe())
                    self.assertEquals('Unexpected status code: 418', failure.getErrorMessage())
                onUpdateMock.assert_not_called()

    def testOnUpdate(self):
        config = {
            'kubernetes1001.eqiad.wmnet': {'enabled': False, 'weight': 1},
            'kubernetes1002.eqiad.wmnet': {'enabled': True, 'weight': 1},
            'kubernetes1003.eqiad.wmnet': {'enabled': True, 'weight': 1},
            'kubernetes1004.eqiad.wmnet': {'enabled': True, 'weight': 1},
        }

        with patch.object(self.observer.coordinator, 'onConfigUpdate') as mockOnConfigUpdate:
            self.observer.onUpdate(config)
            mockOnConfigUpdate.assert_called_with(config)

        with patch.object(self.observer, 'lastConfig', config):
            with patch.object(self.observer.coordinator, 'onConfigUpdate') as mockOnConfigUpdate:
                self.observer.onUpdate(config)
                mockOnConfigUpdate.assert_not_called()

    def testObservingMethods(self):
        self.assertIsNone(self.observer.loop)

        with patch.object(self.observer, 'reactor', task.Clock()):
            with patch.object(self.observer, 'observe') as mockObserve:
                self.observer.startObserving()
                self.assertIsInstance(self.observer.loop, task.LoopingCall)
                self.assertTrue(self.observer.loop.running)
                mockObserve.assert_called_once_with()
                self.observer.reactor.advance(self.observer.reloadIntervalSeconds)
                self.assertEqual(mockObserve.call_count, 2)
                self.observer.stopObserving()
                self.assertFalse(self.observer.loop.running)

    def testTimeout(self):
        mrc = MemoryReactorClock()
        ef = _EndpointFactory(reactor=mrc)
        agent = Agent.usingEndpointFactory(reactor=mrc,
                                           endpointFactory=ef)

        with patch.object(self.observer, 'reactor', mrc):
            with patch.object(self.observer, 'client', HTTPClient(agent=agent)):
                with patch.object(self.observer, 'onFailure') as mockOnFailure:
                    # tcpClients instead of sslClients due to _EndpointFactory simplification
                    self.assertTrue(len(self.observer.reactor.tcpClients) == 0)
                    d = self.observer.observe()
                    self.observer.reactor.advance(self.observer.timeout-0.1)
                    self.assertTrue(len(self.observer.reactor.tcpClients) == 1)
                    mockOnFailure.assert_not_called()
                    self.observer.reactor.advance(0.1) # trigger the timeout
                    self.failureResultOf(d, ConnectingCancelledError)

    def testOnFailure(self):
        treq_stub = StubTreq(_NonResponsiveTestResource())
        with patch.object(self.observer, 'reactor', MemoryReactorClock()):
            with patch.object(self.observer, 'client', treq_stub):
                self.observer.startObserving()
                self.assertTrue(self.observer.loop.running)
                with patch.object(self.observer, 'startObserving') as mockStartObserving:
                    self.observer.reactor.advance(self.observer.timeout)
                    self.assertFalse(self.observer.loop.running)
                    mockStartObserving.assert_called_once_with(now=False)
