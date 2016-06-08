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

import weakref


#
# Internable
#
class Internable(object):
    """Class that allows instances to be 'interned'. That is, given an
    instance of this class, one can obtain a canonical (interned)
    copy.

    This saves memory when there are likely to be many identical
    instances of the class -- users hold references to a single
    interned object instead of references to different objects that
    are identical.

    The interned version of a given instance is created on demand if
    necessary, and automatically cleaned up when nobody holds a
    reference to it.

    Instances of sub-classes must be usable as dictionary keys for
    Internable to work.
    """

    _internable_stats = None
    _internable_dict = None

    def __init__(self):
        self._interned = False

    class Stats(object):

        def __init__(self):
            self.d = {}

        def incr(self, name):
            self.d[name] = self.d.get(name, 0) + 1

        def __repr__(self):
            return repr(self.d)

        def __str__(self):
            return str(self.d)

    @classmethod
    def _internable_init(cls):
        # Objects to be interned are held as keys in a dictionary that
        # only holds weak references to keys. As a result, when the
        # last reference to an interned object goes away, the object
        # will be removed from the dictionary.
        cls._internable_dict = weakref.WeakKeyDictionary()
        cls._internable_stats = Internable.Stats()

    @classmethod
    def intern_stats(cls):
        return cls._internable_stats

    def intern(self):
        """Returns either itself or a canonical copy of itself."""

        # If this is an interned object, return it
        if hasattr(self, '_interned'):
            return self._internable_stats.incr('self')

        #
        # Got to find or create an interned object identical to this
        # one. Auto-initialize the class if need be.
        #
        cls = self.__class__

        if not cls._internable_dict:
            cls._internable_init()

        obj = cls._internable_dict.get(self)
        if (obj):
            # Found an interned copy.
            cls._internable_stats.incr('found')
            return obj

        # Create an interned copy. Take care to only keep a weak
        # reference to the object itself.
        def object_collected(obj):
            cls._internable_stats.incr('collected')
            # print("Object %s garbage collected" % obj)
            pass

        ref = weakref.ref(self, object_collected)
        cls._internable_dict[self] = ref
        self._interned = True
        cls._internable_stats.incr('inserted')
        return self
