import unittest

from pybal.metrics import (
    DummyCounter,
    DummyGauge,
)


class BasicMetricsTestCase(unittest.TestCase):
    def setUp(self):
        metric_labelnames = {'dummy_label'}
        metric_keywords = {
            'labelnames': metric_labelnames,
            'namespace': 'pybal',
            'subsystem': 'test'
        }
        self.metrics = {
            'dummy_gauge': DummyGauge('dummy_gauge',
                                      'A dummy Gauge',
                                      **metric_keywords),
            'dummy_counter': DummyCounter('dummy_counter',
                                          'A dummy counter',
                                          **metric_keywords),
        }
        self.metric_labels = {
            'dummy_label': 'dummy_value',
        }

    def testGauge(self):
        self.metrics['dummy_gauge'].labels(**self.metric_labels).set(1)

    def testCounter(self):
        self.metrics['dummy_counter'].labels(**self.metric_labels).inc()
        self.metrics['dummy_counter'].labels(**self.metric_labels).inc(2)
