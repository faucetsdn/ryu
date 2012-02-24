# Copyright (C) 2012 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This is mixin class to track instances of a given class
#
# http://docs.python.org/faq/programming.html#how-do-i-get-a-list-of-all-instances-of-a-given-class
# How do I get a list of all instances of a given class?
# Python does not keep track of all instances of a class (or of a
# built-in type). You can program the class's constructor to keep
# track of all instances by keeping a list of weak references to each
# instance.


from collections import defaultdict

# Although WeakSet can be used directory, WeakValueDictionary is used instead
# for python 2.6 which is used by REHL6 because WeakSet is supported by
# python 2.7+.
# Correspondence:
# wvd = WeakValueDictionary()           ws = WeakSet()
# wvd[id(value)] = value                ws = value
# wvd.values()                          ws: iterator

from weakref import WeakValueDictionary


class TrackInstances(object):
    # weak reference is needed in order to make instances freeable by avoiding
    # refrence count. Otherwise, instances will never be freed.
    __refs__ = defaultdict(WeakValueDictionary)

    def __init__(self):
        self.__refs__[self.__class__][id(self)] = self

    @classmethod
    def all_instances(cls):
        return cls.__refs__[cls].values()
