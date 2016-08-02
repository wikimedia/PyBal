"""
ipvsadm.py
Copyright (C) 2006-2016 by Mark Bergsma <mark@nedworks.org>

Ipvsadm-based ipvs manager for PyBal
"""
import os


class IPVSADMManager(object):
    """Class that provides a mapping from abstract LVS commands / state
    changes to ipvsadm command invocations."""

    ipvsPath = '/sbin/ipvsadm'

    DryRun = True

    Debug = False

    @classmethod
    def modifyState(cls, cmdList):
        """
        Changes the state using a supplied list of commands (by invoking ipvsadm)
        """

        if cls.Debug:
            print cmdList
        if cls.DryRun:
            return

        command = [cls.ipvsPath, '-R']
        stdin = os.popen(" ".join(command), 'w')
        for line in cmdList:
            stdin.write(line + '\n')
        stdin.close()

    @staticmethod
    def subCommandService(service):
        """Returns a partial command / parameter list as a single
        string, that describes the supplied LVS service, ready for
        passing to ipvsadm.

        Arguments:
            service:    tuple(protocol, address, port, ...)
        """

        protocol = {'tcp': '-t',
                    'udp': '-u'}[service[0]]

        if ':' in service[1]:
            # IPv6 address
            service = ' [%s]:%d' % service[1:3]
        else:
            # IPv4
            service = ' %s:%d' % service[1:3]

        return protocol + service

    @staticmethod
    def subCommandServer(server):
        """Returns a partial command / parameter list as a single
        string, that describes the supplied server, ready for passing
        to ipvsadm.

        Arguments:
            server:    PyBal server object
        """

        return '-r %s' % (server.ip or server.host)

    @staticmethod
    def commandClearServiceTable():
        """Returns an ipvsadm command to clear the current service
        table."""
        return '-C'

    @classmethod
    def commandRemoveService(cls, service):
        """Returns an ipvsadm command to remove a single service."""
        return '-D ' + cls.subCommandService(service)

    @classmethod
    def commandAddService(cls, service):
        """Returns an ipvsadm command to add a specified service.

        Arguments:
            service:    tuple(protocol, address, port, ...)
        """

        cmd = '-A ' + cls.subCommandService(service)

        # Include scheduler if specified
        if len(service) > 3:
            cmd += ' -s ' + service[3]

        return cmd

    @classmethod
    def commandRemoveServer(cls, service, server):
        """Returns an ipvsadm command to remove a server from a service.

        Arguments:
            service:   tuple(protocol, address, port, ...)
            server:    Server
        """

        return " ".join(['-d', cls.subCommandService(service),
                         cls.subCommandServer(server)])

    @classmethod
    def commandAddServer(cls, service, server):
        """Returns an ipvsadm command to add a server to a service.

        Arguments:
            service:   tuple(protocol, address, port, ...)
            server:    Server
        """

        cmd = " ".join(['-a', cls.subCommandService(service),
                        cls.subCommandServer(server)])

        # Include weight if specified
        if server.weight:
            cmd += ' -w %d' % server.weight

        return cmd

    @classmethod
    def commandEditServer(cls, service, server):
        """Returns an ipvsadm command to edit the parameters of a
        server.

        Arguments:
            service:   tuple(protocol, address, port, ...)
            server:    Server
        """

        cmd = " ".join(['-e', cls.subCommandService(service),
                        cls.subCommandServer(server)])

        # Include weight if specified
        if server.weight:
            cmd += ' -w %d' % server.weight

        return cmd
