"""
metrics.py

Metrics class implementations for PyBal
"""

try:
    import prometheus_client
    metrics_implementation = 'prometheus'
except ImportError:
    metrics_implementation = 'dummy'

class DummyMetric(object):
    def __init__(self, **kwargs):
        pass

    def labels(self, **kwargs):
        return self

class DummyCounter(DummyMetric):
    def inc(self, **kwargs):
        pass

if metrics_implementation == 'prometheus':
    Counter = prometheus_client.Counter
else:
    Counter = DummyCounter
