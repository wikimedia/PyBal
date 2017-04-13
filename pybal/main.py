#!/usr/bin/python

"""
PyBal
Copyright (C) 2006-2014 by Mark Bergsma <mark@nedworks.org>

LVS Squid balancer/monitor for managing the Wikimedia Squid servers using LVS
"""

from __future__ import absolute_import

import argparse
import logging
import signal

from ConfigParser import SafeConfigParser

from twisted.internet import reactor

from pybal import util, ipvs, instrumentation
from pybal.bgpfailover import BGPFailover
from pybal.coordinator import Coordinator

log = util.log


def parseCommandLine(configuration):
    """
    Parses the command line arguments, and sets configuration options
    in dictionary configuration.
    """
    parser = argparse.ArgumentParser(
        description="Load Balancer manager script.",
        epilog="See <https://wikitech.wikimedia.org/wiki/PyBal> for more."
    )
    parser.add_argument("-c", dest="conffile", help="Configuration file",
                        default="/etc/pybal/pybal.conf")
    parser.add_argument("-n", "--dryrun", action="store_true",
                        help="Dry Run mode, do not actually update.")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Debug mode, run in foreground, "
                        "log to stdout LVS configuration/state, "
                        "print commands")
    args = parser.parse_args()
    configuration.update(args.__dict__)


def sighandler(signum, frame):
    """
    Signal handler
    """
    if signum == signal.SIGHUP:
        # TODO: reload config
        pass
    else:
        # Stop the reactor if it's running
        if reactor.running:
            reactor.stop()


def installSignalHandlers():
    """
    Installs Unix signal handlers, e.g. to run terminate() on TERM
    """

    signals = [signal.SIGTERM, signal.SIGHUP, signal.SIGINT]

    for sig in signals:
        signal.signal(sig, sighandler)


def main():
    services, cliconfig = {}, {}

    # Parse the command line
    parseCommandLine(cliconfig)

    # Read the configuration file
    config = SafeConfigParser()
    config.read(cliconfig['conffile'])

    try:
        # Install signal handlers
        installSignalHandlers()

        for section in config.sections():
            if section != 'global':
                cfgtuple = (
                    config.get(section, 'protocol'),
                    config.get(section, 'ip'),
                    config.getint(section, 'port'),
                    config.get(section, 'scheduler'))

            # Read the custom configuration options of the LVS section
            configdict = util.ConfigDict(config.items(section))

            # Override with command line options
            configdict.update(cliconfig)

            if section != 'global':
                services[section] = ipvs.LVSService(section, cfgtuple, configuration=configdict)
                crd = Coordinator(services[section],
                    configUrl=config.get(section, 'config'))
                log.info("Created LVS service '{}'".format(section))
                instrumentation.PoolsRoot.addPool(crd.lvsservice.name, crd)

        # Set up BGP
        try:
            configdict = util.ConfigDict(config.items('global'))
        except Exception:
            configdict = util.ConfigDict()
        configdict.update(cliconfig)

        # Set the logging level
        if configdict.get('debug', False):
            util.PyBalLogObserver.level = logging.DEBUG
        else:
            util.PyBalLogObserver.level = logging.INFO

        bgpannouncement = BGPFailover(configdict)

        # Run the web server for instrumentation
        if configdict.getboolean('instrumentation', False):
            from twisted.web.server import Site
            factory = Site(instrumentation.ServerRoot())

            port = configdict.getint('instrumentation_port', 9090)

            # Bind on the IPs listed in 'instrumentation_ips'. Default to
            # localhost v4 and v6 if no IPs have been specified in the
            # configuration.
            instrumentation_ips = eval(configdict.get(
                'instrumentation_ips', '["127.0.0.1", "::1"]'))

            for ipaddr in instrumentation_ips:
                reactor.listenTCP(port, factory, interface=ipaddr)

        reactor.run()
    finally:
        log.info("Exiting...")

if __name__ == '__main__':
    main()
