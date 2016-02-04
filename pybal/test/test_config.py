# -*- coding: utf-8 -*-
"""
  PyBal unit tests
  ~~~~~~~~~~~~~~~~

  This module contains tests for `pybal.config`.

"""
import mock
import json

import pybal
import pybal.config
import pybal.etcd

from .fixtures import PyBalTestCase, MockClientGetPage


class DummyConfigurationObserver(pybal.config.ConfigurationObserver):
    urlScheme = 'dummy://'

    def __init__(self, *args, **kwargs):
        pass


class ConfigurationObserverTestCase(PyBalTestCase):
    """Test case for `pybal.config.ConfigurationObserver`."""

    def testFromUrl(self):
        """Test `ConfigurationObserver.fromUrl`."""
        self.assertIsInstance(
            pybal.config.ConfigurationObserver.fromUrl(None, 'dummy://'),
            DummyConfigurationObserver
        )


class FileConfigurationObserverTestCase(PyBalTestCase):
    """Test case for `pybal.config.FileConfigurationObserver`."""

    def setUp(self):
        super(FileConfigurationObserverTestCase, self).setUp()
        self.observer = self.getObserver()

    def getObserver(self, filename='file:///something/here'):
        return pybal.config.FileConfigurationObserver(
            self.coordinator, filename)

    def testInit(self):
        """Test `FileConfigurationObserver.__init__`"""
        self.assertEquals(self.observer.filePath, '/something/here')
        self.assertEquals(self.observer.reloadIntervalSeconds, 1)

    @mock.patch('os.stat')
    def testReloadConfig(self, mock_stat):
        """Test `FileConfigurationObserver.reloadConfig`"""
        self.observer.lastFileStat = 'WMF'
        mock_stat.return_value = 'WMF'
        self.observer.parseConfig = mock.MagicMock(return_value="some_config")
        # No stat changes mean no config parsing
        self.observer.reloadConfig()
        mock_stat.assert_called_with('/something/here')
        self.observer.parseConfig.assert_not_called()
        # Stat change means we open the file and parse the configuration
        mock_stat.reset_mock()
        mock_stat.return_value = 'WMF!'
        m = mock.mock_open(read_data="123")
        with mock.patch('__builtin__.open', m, True) as mock_open:
            self.observer.reloadConfig()
        mock_stat.assert_called_with('/something/here')
        mock_open.assert_called_with('/something/here', 'rt')
        self.observer.parseConfig.assert_called_with('123')
        self.assertEquals(self.observer.lastConfig, 'some_config')
        self.assertEquals(self.observer.coordinator.config, 'some_config')

    def testParseConfig(self):
        """Test `FileConfigurationObserver.parseConfig`"""
        self.observer.parseLegacyConfig = mock.MagicMock(return_value='legacy_config')
        self.observer.parseJsonConfig = mock.MagicMock(return_value='json_config')
        self.assertEquals(self.observer.parseConfig("I am legacy"), 'legacy_config')
        self.observer.parseLegacyConfig.assert_called_with("I am legacy")
        self.observer.configUrl += '.json'
        self.assertEquals(self.observer.parseConfig("I am json"), 'json_config')
        self.observer.parseJsonConfig.assert_called_with("I am json")

    def testParseJsonConfig(self):
        """Test `FileConfigurationObserver.parseJsonConfig`"""
        json_config = """
        {
          "mw1200": { "enabled": true, "weight": 10 },
          "mw1201": {"enabled": false, "weight": 1 }
        }
        """
        expected_config = {
            'mw1200': {'enabled': True, 'weight': 10},
            'mw1201': {'enabled': False, 'weight': 1},
        }
        self.assertEquals(self.observer.parseJsonConfig(json_config),
                          expected_config)
        invalid_config = "{[]"
        self.assertRaises(Exception, self.observer.parseJsonConfig,
                          invalid_config)

    def testParseLegacyConfig(self):
        """Test `FileConfigurationObserver.parseLegacyConfig`"""
        legacy_config = '\n'.join((
            "{'host': 'mw1200', 'weight': 10, 'enabled': True }",
            "{'host': 'mw1201', 'weight': 1, 'enabled': False }",
        ))
        expected_config = {
            'mw1200': {'enabled': True, 'weight': 10},
            'mw1201': {'enabled': False, 'weight': 1},
        }
        self.assertEquals(self.observer.parseLegacyConfig(legacy_config),
                          expected_config)

        invalid_config= "{'host': 'something'}\n"

        # Needed for nose to pass... it doesn't really get raised
        self.assertEquals(self.observer.parseLegacyConfig(invalid_config), {})
        self.flushLoggedErrors(KeyError)


class HttpConfigurationObserverTestCase(PyBalTestCase):
    data = """
    {
    "mw1200": { "enabled": true, "weight": 10 },
    "mw1201": {"enabled": false, "weight": 1 }
    }
    """

    def setUp(self):
        super(HttpConfigurationObserverTestCase, self).setUp()
        self.observer = self.getObserver()

    def getObserver(self, url='http://example.com/pybal-config/example.json'):
        return pybal.config.HttpConfigurationObserver(
            self.coordinator, url)

    def testReloadConfig(self):
        """Test `HttpConfigurationObserver.reloadConfig`"""
        m = MockClientGetPage(self.data)
        with mock.patch('twisted.web.client.getPage', m.getPage):
            self.observer.reloadConfig()
        self.assertEquals(self.coordinator.config, json.loads(self.data))

        errMsg = 'Hamsters!'
        m.addErr(errMsg)
        self.observer.logError = mock.MagicMock()
        with mock.patch('twisted.web.client.getPage', m.getPageError):
            self.observer.reloadConfig()
        # Configuration hasn't changed
        self.assertEquals(self.coordinator.config, json.loads(self.data))
        # Error was logged
        self.assertTrue(self.observer.logError.called)

    def testOnConfigReceived(self):
        """Test `HttpConfigurationObserver.OnConfigReceived`"""
        self.observer.lastConfig = json.loads(self.data)
        self.coordinator.config = None
        # No change in config means no onConfigUpdate
        self.observer.onConfigReceived(self.data)
        self.assertEquals(self.coordinator.config, None)
        # Config gets updated
        self.observer.lastConfig['mw1201']["enabled"] = True
        self.observer.onConfigReceived(self.data)
        self.assertEquals(self.coordinator.config, json.loads(self.data))
