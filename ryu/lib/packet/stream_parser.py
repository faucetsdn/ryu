# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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


from abc import ABCMeta, abstractmethod
import six


@six.add_metaclass(ABCMeta)
class StreamParser(object):
    """Streaming parser base class.

    An instance of a subclass of this class is used to extract messages
    from a raw byte stream.

    It's designed to be used for data read from a transport which doesn't
    preserve message boundaries.  A typical example of such a transport
    is TCP.

    """
    class TooSmallException(Exception):
        pass

    def __init__(self):
        self._q = bytearray()

    def parse(self, data):
        """Tries to extract messages from a raw byte stream.

        The data argument would be python bytes newly read from the input
        stream.

        Returns an ordered list of extracted messages.
        It can be an empty list.

        The rest of data which doesn't produce a complete message is
        kept internally and will be used when more data is come.
        I.e. next time this method is called again.
        """
        self._q.append(data)
        msgs = []
        while True:
            try:
                msg, self._q = self.try_parse(self._q)
            except self.TooSmallException:
                break
            msgs.append(msg)
        return msgs

    @abstractmethod
    def try_parse(self, q):
        """Try to extract a message from the given bytes.

        This is an override point for subclasses.

        This method tries to extract a message from bytes given by the
        argument.

        Raises TooSmallException if the given data is not enough to
        extract a complete message but there's still a chance to extract
        a message if more data is come later.
        """
        pass
