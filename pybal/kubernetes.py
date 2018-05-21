# -*- coding: utf-8 -*-
"""
  PyBal kubernetes client
  ~~~~~~~~~~~~~~~~~~~~~~~

  This module allows PyBal to generate config based on k8s services.

"""

from __future__ import absolute_import

import copy

import treq.client
from twisted.internet import defer, reactor, task
from twisted.web import http
from twisted.web.client import Agent
from twisted.web.http import urlparse

from .config import ConfigurationObserver
from .util import log

UNSCHEDULABLE_SPEC = 'unschedulable'


class KubernetesConfigurationObserver(ConfigurationObserver):

    urlScheme = 'k8s://'
    connectTimeout = 1
    timeout = 3

    def __init__(self, coordinator, configUrl, reloadIntervalSeconds=60):
        self.loop = None
        self.lastConfig = None
        self.reactor = reactor
        self.coordinator = coordinator
        self.reloadIntervalSeconds = reloadIntervalSeconds
        self.configUrl = configUrl
        self.host, self.port, self.token = self.parseConfigUrl(configUrl)
        self.client = treq.client.HTTPClient(agent=self.getAgent())

    @staticmethod
    def parseConfigUrl(configUrl):
        parsed = urlparse(configUrl)
        # k8s API uses an authorization token, so no password on the URL, only username
        return parsed.hostname, parsed.port or 443, parsed.username

    def getNodesURL(self):
        return 'https://%s:%s/v1/nodes' % (self.host, self.port)

    def getAgent(self):
        return Agent(reactor=self.reactor,
                     connectTimeout=self.connectTimeout)

    def getParams(self):
        return {'pretty': 'false'}

    def getHeaders(self):
        return {
            'Accept': 'application/json',
            'Authorization': 'Bearer %s' % self.token,
        }

    def parseKubernetesPayload(self, payload):
        ret = {}

        try:
            for item in payload['items']:
                hostname = item['metadata']['name']
                enabled = False
                if UNSCHEDULABLE_SPEC in item['spec']:
                    if item['spec'][UNSCHEDULABLE_SPEC] == 'true':
                        continue

                for condition in item['status']['conditions']:
                    if condition['type'] == 'Ready':
                        if condition['status'] == 'True':
                            enabled = True
                        break

                ret[hostname] = {
                    'weight': 1,
                    'enabled': enabled
                }
            return ret
        except KeyError as e:
            log.error("Invalid API response: %s" % e, system="config-kubernetes")
            raise Exception('Invalid payload')

    @defer.inlineCallbacks
    def observe(self):
        response = yield self.client.get(self.getNodesURL(),
                                         params=self.getParams(),
                                         headers=self.getHeaders(),
                                         reactor=self.reactor,
                                         timeout=self.timeout)
        if response.code != http.OK:
            raise Exception("Unexpected status code: %d" % response.code)
        try:
            payload = yield response.json()
        except ValueError as e:
            log.error("Invalid response format: %s" % e,
                      system="config-kubernetes")
            raise Exception('Invalid payload')

        newConfig = self.parseKubernetesPayload(payload)
        self.onUpdate(newConfig)

    def onUpdate(self, config):
        if config != self.lastConfig:
            self.coordinator.onConfigUpdate(copy.deepcopy(config))
            self.lastConfig = config

    def onFailure(self, failure):
        log.error("failed: %s" % failure, system="config-kubernetes")
        if not self.loop.running:
            self.startObserving(now=False)

    def startObserving(self, now=True):
        self.loop = task.LoopingCall(self.observe)
        self.loop.clock = self.reactor
        self.loop.start(self.reloadIntervalSeconds,
                        now=now).addErrback(self.onFailure)

    def stopObserving(self):
        if self.loop is not None:
            self.loop.stop()
