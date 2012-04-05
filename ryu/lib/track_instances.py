# Copyright (C) 2012 Isaku Yamahata <yamahata at valinux co jp>
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
