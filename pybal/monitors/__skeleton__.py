"""
__skeleton__.py
Copyright (C) 2006-2014 by Mark Bergsma <mark@nedworks.org>

Copy and modify this file to write a new PyBal monitor.
It contains the minimum imports and base methods that need
to be implemented.
"""

from pybal import monitor

class SkeletonMonitoringProtocol(monitor.MonitoringProtocol):
    """
    Description.
    """

    __name__ = 'Skeleton'

    def __init__(self, coordinator, server, configuration):
        """Constructor"""

        # Call ancestor constructor
        super(SkeletonMonitoringProtocol, self).__init__(coordinator, server, configuration)

    def run(self):
        """Start the monitoring"""
        super(SkeletonMonitoringProtocol, self).run()

    def stop(self):
        """Stop the monitoring"""
        super(SkeletonMonitoringProtocol, self).stop()
