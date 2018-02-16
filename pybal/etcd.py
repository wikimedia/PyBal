# -*- coding: utf-8 -*-
"""
  PyBal etcd client
  ~~~~~~~~~~~~~~~~~

  This module allows PyBal to be configured via etcd.

"""
from __future__ import absolute_import

import copy
import json
import urllib

from twisted.internet import defer, reactor, ssl
from twisted.python import failure
from twisted.web import error
from twisted.web.client import HTTPClientFactory
from twisted.web.http import HTTPClient, urlparse
from twisted.internet.error import ConnectionDone

from .config import ConfigurationObserver
from .version import USER_AGENT_STRING
from .util import log

def decode_node(node):
    """Decode an individual node from an etcd response."""
    key = node['key'].rsplit('/', 1)[-1]
    # handle deletions by returning the key and a value of None
    if 'value' not in node:
        return key, None
    value = json.loads(node['value'])
    pooled = value.pop('pooled', None)
    if pooled == 'inactive':
        return key, None
    if pooled is not None:
        value['enabled'] = pooled == 'yes'
    return key, value


def decode_etcd_data(data):
    """Simplify an etcd response by stripping leading path components
    from key names, decoding JSON values, and removing etcd metadata."""
    node = data['node']
    if node.get('dir'):
        return dict(decode_node(child) for child in node['nodes'])
    else:
        key, value = decode_node(node)
        return {key: value}


class EtcdClient(HTTPClient):
    """Represents a client for the etcd HTTP API."""
    etcdIndex = 0

    def connectionMade(self):
        log.info("connected to %s" % self.factory.configUrl, system="config-etcd")

        self.sendCommand('GET', self.factory.getPath())
        self.sendHeader('Host', self.factory.host)
        self.sendHeader('User-Agent', self.factory.agent)
        self.endHeaders()

    def handleStatus(self, version, status, message):
        self.version = version
        self.status = status
        self.message = message

    def handleResponse(self, response):
        log.debug("%s response: %s" % (self.status, response), system="config-etcd")

        if self.status != '200':
            err = error.Error(self.status, self.message, response)
            self.factory.onFailure(failure.Failure(err))
        elif response is not None and len(response):
            try:
                config = json.loads(response)
                self.factory.onUpdate(config, self.etcdIndex)
            except Exception, err:
                msg = "Error: %s Etcd response: %s" % (err, response)
                self.factory.onFailure(msg)
        else:
            log.warn("empty response from server", system="config-etcd")

        self.transport.loseConnection()

    def handleHeader(self, key, val):
        if key == 'X-Etcd-Index':
            self.etcdIndex = int(val)

    def timeout(self):
        err = defer.TimeoutError(
            'Retrieving key %s from %s took longer than %s seconds.' %
            (self.factory.key, self.factory.host, self.factory.timeout))
        self.factory.onFailure(err)
        self.transport.loseConnection()


class EtcdConfigurationObserver(ConfigurationObserver, HTTPClientFactory):
    """A factory that will continuously monitor an etcd key for changes."""

    urlScheme = 'etcd://'

    agent = USER_AGENT_STRING
    method = 'GET'
    protocol = EtcdClient
    scheme = 'https'
    timeout = 0
    reconnectTimeout = 1
    followRedirect = False
    afterFoundGet = False

    def __init__(self, coordinator, configUrl, mock_reactor=None):
        if mock_reactor is None:
            self.reactor = reactor
        else:
            self.reactor = mock_reactor

        self.coordinator = coordinator
        self.configUrl = configUrl
        self.host, self.port, self.key = self.parseConfigUrl(configUrl)
        self.waitIndex = None
        self.lastConfig = {}

    def startObserving(self):
        """Start (or re-start) watching etcd for changes."""
        self.reactor.connectSSL(self.host, self.port, self,
                                ssl.ClientContextFactory())

    def parseConfigUrl(self, configUrl):
        parsed = urlparse(configUrl)
        return parsed.hostname, parsed.port or 2379, parsed.path

    def getPath(self):
        path = '/v2/keys/%s' % self.key.lstrip('/')
        params = {'recursive': 'true'}
        if self.waitIndex is not None:
            params['waitIndex'] = self.waitIndex
            params['wait'] = 'true'
        path = '%s?%s' % (path, urllib.urlencode(params))
        return path

    def reconnect(self, connector):
        log.info("reconnecting to etcd in %d seconds" % self.reconnectTimeout,
                 system="config-etcd")
        self.reactor.callLater(self.reconnectTimeout, connector.connect)

    def clientConnectionFailed(self, connector, reason):
        log.error("client connection failed: reason=%s" % reason, system="config-etcd")
        self.waitIndex = None
        self.reconnect(connector)

    def clientConnectionLost(self, connector, reason):
        r = reason.trap(ConnectionDone)
        if r == ConnectionDone:
            log.info("client connection closed cleanly", system="config-etcd")
        else:
            log.error("client connection lost: reason=%s" % reason, system="config-etcd")
            self.waitIndex = None
        self.reconnect(connector)

    def getMaxModifiedIndex(self, root):
        root = root.get('node', root)
        index = root['modifiedIndex']
        for node in root.get('nodes', ()):
            index = max(index, self.getMaxModifiedIndex(node))
        return index

    def onUpdate(self, update, etcdIdx):
        if self.waitIndex is not None:
            # This is already the result yielded by a watch operation
            self.waitIndex = self.getMaxModifiedIndex(update) + 1
        else:
            self.waitIndex = etcdIdx + 1
        config = copy.deepcopy(self.lastConfig)

        # Read new data
        new_data = decode_etcd_data(update)
        config.update(new_data)

        # Remove deleted/inactive nodes
        to_remove = [k for k, v in new_data.items() if v is None]
        for k in to_remove:
            if k in config:
                del config[k]

        # Now update pybal config
        if config != self.lastConfig:
            self.coordinator.onConfigUpdate(copy.deepcopy(config))
            self.lastConfig = config

    def onFailure(self, reason):
        log.error('failed: %s' % reason, system="config-etcd")
