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

# convenient classes to manipulate OF-Config XML
# in a little more pythonic way.
# currently assuming OF-Config 1.1.1.

from ryu.lib import stringify

from lxml import objectify
import lxml.etree as ET


_ns_of111 = 'urn:onf:of111:config:yang'
_ns_netconf = 'urn:ietf:params:xml:ns:netconf:base:1.0'
_nsmap = {
    'of111': _ns_of111,
    'nc': _ns_netconf,
}


def _pythonify(name):
    return name.replace('-', '_')


class _e(object):
    def __init__(self, name, is_list):
        self.name = name
        self.cls = None
        self.is_list = is_list


# complexType
class _ct(_e):
    def __init__(self, name, cls, is_list):
        super(_ct, self).__init__(name, is_list)
        self.cls = cls


class _Base(stringify.StringifyMixin):
    _M = objectify.ElementMaker(annotate=False,
                                namespace=_ns_of111,
                                nsmap=_nsmap)

    def __init__(self, **kwargs):
        for e in self._ELEMENTS:
            k = _pythonify(e.name)
            try:
                v = kwargs.pop(k)
                assert e.name not in kwargs
            except KeyError:
                k = e.name
                try:
                    v = kwargs.pop(k)
                except KeyError:
                    if e.is_list:
                        v = []
                    else:
                        v = None
            setattr(self, k, v)
        if kwargs:
            raise TypeError('unknown kwargs %s' % kwargs)

    def to_et(self, tag):
        def convert(v):
            if isinstance(v, _Base):
                return v.to_et(e.name)
            elif isinstance(v, objectify.ObjectifiedElement):
                assert ET.QName(v.tag).localname == itag
                return v
            return self._M(itag, v)

        args = []
        for e in self._ELEMENTS:
            itag = e.name
            k = _pythonify(itag)
            v = getattr(self, k)
            if v is None:
                continue
            if isinstance(v, list):
                assert e.is_list
                ele = list(map(convert, v))
            else:
                assert not e.is_list
                ele = [convert(v)]
            args.extend(ele)
        return self._M(tag, *args)

    def to_xml(self, tag):
        e = self.to_et(tag)
        return ET.tostring(e, pretty_print=True)

    @classmethod
    def from_xml(cls, xmlstring):
        et = objectify.fromstring(xmlstring)
        return cls.from_et(et)

    @classmethod
    def from_et(cls, et):
        def convert(v):
            if e.cls is not None:
                return e.cls.from_et(v)
            return v

        kwargs = {}
        for e in cls._ELEMENTS:
            try:
                v = et[e.name]
            except AttributeError:
                continue
            assert isinstance(v, objectify.ObjectifiedElement)
            if len(v) == 1:
                v = convert(v)
                if e.is_list:
                    v = [v]
            else:
                assert e.is_list
                v = list(map(convert, v))
            k = _pythonify(e.name)
            assert k not in kwargs
            kwargs[k] = v
        return cls(**kwargs)

    def __getattribute__(self, k):
        return stringify.StringifyMixin.__getattribute__(self, _pythonify(k))

    def __setattr__(self, k, v):
        stringify.StringifyMixin.__setattr__(self, _pythonify(k), v)


class _Unimpl(_Base):
    _ELEMENTS = [
        _e('raw_et', is_list=False),
    ]

    def to_et(self, tag):
        assert self.raw_et.tag == tag
        return self.raw_et

    @classmethod
    def from_et(cls, et):
        return cls(raw_et=et)
