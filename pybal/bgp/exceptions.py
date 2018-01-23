# exceptions.py
# Copyright (c) 2007-2018 by Mark Bergsma <mark@nedworks.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import bgp

# Exception classes

class BGPException(Exception):
    def __init__(self, protocol=None):
        self.protocol = protocol

class NotificationSent(BGPException):
    def __init__(self, protocol, error, suberror, data=''):
        BGPException.__init__(self, protocol)

        self.error = error
        self.suberror = suberror
        self.data = data

    def __str__(self):
        return repr((self.error, self.suberror, self.data))

class BadMessageLength(BGPException):
    pass

class AttributeException(BGPException):
    def __init__(self, suberror, data=''):
        BGPException.__init__(self)

        self.error = bgp.ERR_MSG_UPDATE
        self.suberror = suberror
        self.data = data
