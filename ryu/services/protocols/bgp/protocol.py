# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
 Module defines protocol based classes and utils.
"""

from abc import ABCMeta
from abc import abstractmethod
import six


@six.add_metaclass(ABCMeta)
class Protocol(object):
    """Interface for various protocols.

    Protocol usually encloses a transport/connection/socket to
    peer/client/server and encodes and decodes communication/messages. Protocol
    can also maintain any related state machine, protocol message encoding or
    decoding utilities. This interface identifies minimum methods to support to
    facilitate or provide hooks to sub-classes to override behavior as
    appropriate.
    """

    @abstractmethod
    def data_received(self, data):
        """Handler for date received over connection/transport.

        Here *data* is in raw bytes. This *data* should further be converted to
        protocol specific messages and as appropriate transition to new state
        machine state or send appropriate response.
        """
        pass

    @abstractmethod
    def connection_made(self):
        """Called when connection has been established according to protocol.

        This is the right place to do some initialization or sending initial
        hello messages.
        """
        pass

    @abstractmethod
    def connection_lost(self, reason):
        """Handler called when connection to peer/remote according to protocol
        has been lost.

        Here we can do any clean-up related to connection/transport/timers/etc.
        """
        pass


@six.add_metaclass(ABCMeta)
class Factory(object):
    """This is a factory which produces protocols.

    Can also act as context for protocols.
    """

    # Put a subclass of Protocol here:
    protocol = None

    @abstractmethod
    def build_protocol(self, socket):
        """Create an instance of a subclass of Protocol.

        Override this method to alter how Protocol instances get created.
        """
        raise NotImplementedError()

    @abstractmethod
    def start_protocol(self, socket):
        """Launch protocol instance to handle input on an incoming connection.
        """
        raise NotImplementedError()
