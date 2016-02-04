# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.etcd`.

"""

import copy
import json
import mock
import urlparse

import pybal
import pybal.config
import pybal.etcd
from .fixtures import PyBalTestCase


class EtcdConfigurationObserverTestCase(PyBalTestCase):
    def setUp(self):
        super(EtcdConfigurationObserverTestCase, self).setUp()
        self.observer = self.getObserver()

    def getObserver(self, url='etcd://example.com/config/text'):
        return pybal.etcd.EtcdConfigurationObserver(
            self.coordinator, url)

    def testParseConfigUrl(self):
        """Test initialization"""
        obs = self.getObserver()
        self.assertEquals(obs.host, 'example.com')
        self.assertEquals(obs.port, 2379)
        self.assertEquals(obs.key, '/config/text')
        self.assertEquals(obs.waitIndex, None)

    def testGetPath(self):
        self.assertEquals(self.observer.getPath(),
                          '/v2/keys/config/text?recursive=true')
        self.observer.waitIndex = 4
        url = urlparse.urlparse(self.observer.getPath())
        self.assertEquals(url.path, '/v2/keys/config/text')
        self.assertDictEqual(dict(urlparse.parse_qsl(url.query)),
                             {'wait': 'true', 'waitIndex': '4',
                              'recursive': 'true' })

    def testGetMaxModifiedIndex(self):
        nodes = {
            'modifiedIndex': 40,
            'nodes': [
                {'modifiedIndex': 4},
                {'modifiedIndex': 3},
                {'modifiedIndex': 15},
            ]
        }
        self.assertEquals(40, self.observer.getMaxModifiedIndex(nodes))

    def testOnUpdate(self):
        create = {
            "action":"set",
            "node":
            {
                "key": "/testdir/1",
                "value": "{\"pooled\": \"yes\", \"weight\": 10}",
                "modifiedIndex": 11,
                "createdIndex": 11,
            }
        }
        create_another = copy.deepcopy(create)
        create_another['node']['key'] = "/testdir/2"
        depool = {
            "action": "set",
            "node": {
                "key": "/testdir/1",
                "value": "{\"pooled\": \"no\", \"weight\": 10}",
                "modifiedIndex": 12,
                "createdIndex": 12
            },
            "prevNode": {
                "key": "/testdir/1",
                "value": "{\"pooled\": \"yes\", \"weight\": 10}",
                "modifiedIndex": 11,
                "createdIndex": 11
            }
        }
        inactive = copy.deepcopy(depool)
        inactive['node']['value'] = "{\"pooled\": \"inactive\", \"weight\": 10}"
        delete = {
            "action": "delete",
            "node": {
                "key": "/testdir/1",
                "modifiedIndex": 13,
                "createdIndex": 12
            },
            "prevNode": {
                "key": "/testdir/1",
                "value": "{\"pooled\": \"no\", \"weight\": 10}",
                "modifiedIndex": 12,
                "createdIndex": 12
            }
        }
        self.observer.coordinator.onConfigUpdate = mock.MagicMock()
        self.observer.lastConfig = {}
        # Add a node
        self.observer.onUpdate(create, 0)
        self.observer.coordinator.onConfigUpdate.assert_called_with({'1': {'enabled': True, u'weight': 10}})
        # Add another one
        self.observer.onUpdate(create_another, 11)
        self.observer.coordinator.onConfigUpdate.assert_called_with(
            {'1': {'enabled': True, u'weight': 10},
             '2': {'enabled': True, u'weight': 10}}
        )

        # Depool a server
        self.observer.onUpdate(depool, 12)
        self.observer.coordinator.onConfigUpdate.assert_called_with(
            {'1': {'enabled': False, u'weight': 10},
             '2': {'enabled': True, u'weight': 10}}
        )

        # Set it to inactive
        self.observer.onUpdate(inactive, 12)
        self.observer.coordinator.onConfigUpdate.assert_called_with(
            {'2': {'enabled': True, u'weight': 10}}
        )

        # repool it
        self.observer.onUpdate(create, 11)

        # Delete a server
        self.observer.onUpdate(delete, 13)
        self.observer.coordinator.onConfigUpdate.assert_called_with(
            {'2': {'enabled': True, u'weight': 10}}
        )


class EtcdClientTestCase(PyBalTestCase):

    def setUp(self):
        super(EtcdClientTestCase, self).setUp()
        self.protocol = pybal.etcd.EtcdClient()
        # mock factory
        self.protocol.factory = pybal.etcd.EtcdConfigurationObserver(
            self.coordinator,
            'etcd://example.com/config/text'
        )
        self.protocol.factory.onFailure =  mock.MagicMock()
        # mock transport
        self.protocol.transport = mock.MagicMock()
        self.protocol.transport.loseConnection = mock.MagicMock()

    def testHandleStatus(self):
        self.protocol.handleStatus('1.1', '200', 'OK')
        self.assertEquals(self.protocol.status, '200')
        self.assertEquals(self.protocol.version, '1.1')
        self.assertEquals(self.protocol.message, 'OK')

    def testHandleResponse(self):
        # Test failures
        for status, resp in [
                ('404', ''), # Bad status
                ('200', '{Not Valid'), # non-json response
                ('200', '{"key": true}') # invalid json
        ]:
            # Bad Status
            self.protocol.handleStatus('1.1', status, 'OK')
            self.protocol.handleResponse(resp)
            assert self.protocol.factory.onFailure.called
            # We definitely want to call loseConnection
            # if a failure happens, that will instantiate a
            # new connection to etcd
            assert self.protocol.transport.loseConnection.called
            self.protocol.factory.onFailure.reset_mock()
            self.protocol.transport.loseConnection.reset_mock()

        # Test happy path!
        resp = """
{"action":"get","node":{"dir":true,"nodes":[{"key":"/testdir","dir":true,"nodes":[{"key":"/testdir/1","value":"a","modifiedIndex":5,"createdIndex":5}],"modifiedIndex":4,"createdIndex":4}]}}"""
        self.protocol.factory.onUpdate = mock.MagicMock()
        self.protocol.handleStatus('1.1', '200', 'OK')
        self.protocol.handleResponse(resp)
        self.protocol.factory.onUpdate.assert_called_with(json.loads(resp), 0)
