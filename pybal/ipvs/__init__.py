"""
pybal.ipvs

Copyright (c) 2006-2016 Mark Bergsma <mark@nedworks.org>

LVS service interface for PyBal
"""
from pybal.ipvs.interface import LVSService
from pybal.ipvs.manager import NetlinkServiceManager


def get_service(section, cfgtuple, config):
        if config.getboolean('netlink', False):
            return NetlinkServiceManager(section, cfgtuple, configuration=config)
        else:
            return LVSService(section, cfgtuple, configuration=config)
