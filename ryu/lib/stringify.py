#!/usr/bin/env python
#
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

import base64
import collections
import inspect


# Some arguments to __init__ is mungled in order to avoid name conflicts
# with builtin names.
# The standard mangling is to append '_' in order to avoid name clashes
# with reserved keywords.
#
# PEP8:
# Function and method arguments
#   If a function argument's name clashes with a reserved keyword,
#   it is generally better to append a single trailing underscore
#   rather than use an abbreviation or spelling corruption. Thus
#   class_ is better than clss. (Perhaps better is to avoid such
#   clashes by using a synonym.)
#
# grep __init__ *.py | grep '[^_]_\>' showed that
# 'len', 'property', 'set', 'type'
# A bit more generic way is adopted
import __builtin__
_RESERVED_KEYWORD = dir(__builtin__)


_mapdict = lambda f, d: dict([(k, f(v)) for k, v in d.items()])
_mapdict_key = lambda f, d: dict([(f(k), v) for k, v in d.items()])
_mapdict_kv = lambda f, d: dict([(k, f(k, v)) for k, v in d.items()])


class TypeDescr(object):
    pass


class AsciiStringType(TypeDescr):
    @staticmethod
    def encode(v):
        return unicode(v, 'ascii')

    @staticmethod
    def decode(v):
        return v.encode('ascii')


class Utf8StringType(TypeDescr):
    @staticmethod
    def encode(v):
        return unicode(v, 'utf-8')

    @staticmethod
    def decode(v):
        return v.encode('utf-8')


_types = {
    'ascii': AsciiStringType,
    'utf-8': Utf8StringType,
}


class StringifyMixin(object):

    _TYPE = {}
    """_TYPE class attribute is used to annotate types of attributes.

    This type information is used to find an appropriate conversion for
    a JSON style dictionary.

    Currently the following types are implemented.

    ===== ==========
    Type  Descrption
    ===== ==========
    ascii US-ASCII
    utf-8 UTF-8
    ===== ==========

    Example::
        _TYPE = {
            'ascii': [
                'hw_addr',
            ],
            'utf-8': [
                'name',
            ]
        }
    """

    _class_prefixes = []

    def stringify_attrs(self):
        """an override point for sub classes"""
        return obj_python_attrs(self)

    def __str__(self):
        # repr() to escape binaries
        return self.__class__.__name__ + '(' + \
            ','.join("%s=%s" % (k, repr(v)) for k, v in
                     self.stringify_attrs()) + ')'
    __repr__ = __str__  # note: str(list) uses __repr__ for elements

    @classmethod
    def _is_class(cls, dict_):
        # we distinguish a dict like OFPSwitchFeatures.ports
        # from OFPxxx classes using heuristics.
        # exmples of OFP classes:
        #   {"OFPMatch": { ... }}
        #   {"MTIPv6SRC": { ... }}
        assert isinstance(dict_, dict)
        if len(dict_) != 1:
            return False
        k = dict_.keys()[0]
        if not isinstance(k, (bytes, unicode)):
            return False
        for p in cls._class_prefixes:
            if k.startswith(p):
                return True
        return False

    @classmethod
    def _get_type(cls, k):
        if hasattr(cls, '_TYPE'):
            for t, attrs in cls._TYPE.iteritems():
                if k in attrs:
                    return _types[t]
        return None

    @classmethod
    def _get_encoder(cls, k, encode_string):
        t = cls._get_type(k)
        if t:
            return t.encode
        return cls._get_default_encoder(encode_string)

    @classmethod
    def _encode_value(cls, k, v, encode_string=base64.b64encode):
        return cls._get_encoder(k, encode_string)(v)

    @classmethod
    def _get_default_encoder(cls, encode_string):
        def _encode(v):
            if isinstance(v, (bytes, unicode)):
                json_value = encode_string(v)
            elif isinstance(v, list):
                json_value = map(_encode, v)
            elif isinstance(v, dict):
                json_value = _mapdict(_encode, v)
                # while a python dict key can be any hashable object,
                # a JSON object key should be a string.
                json_value = _mapdict_key(str, json_value)
                assert not cls._is_class(json_value)
            else:
                try:
                    json_value = v.to_jsondict()
                except:
                    json_value = v
            return json_value
        return _encode

    def to_jsondict(self, encode_string=base64.b64encode):
        """
        This method returns a JSON style dict to describe this object.

        The returned dict is compatible with json.dumps() and json.loads().

        Suppose ClassName object inherits StringifyMixin.
        For an object like the following::

            ClassName(Param1=100, Param2=200)

        this method would produce::

            { "ClassName": {"Param1": 100, "Param2": 200} }

        This method takes the following arguments.

        =============  =====================================================
        Argument       Description
        =============  =====================================================
        encode_string  (Optional) specify how to encode attributes which has
                       python 'str' type.
                       The default is base64.
                       This argument is used only for attributes which don't
                       have explicit type annotations in _TYPE class attribute.
        =============  =====================================================
        """
        dict_ = {}
        encode = lambda k, x: self._encode_value(k, x, encode_string)
        for k, v in obj_attrs(self):
            dict_[k] = encode(k, v)
        return {self.__class__.__name__: dict_}

    @classmethod
    def cls_from_jsondict_key(cls, k):
        # find a class with the given name from our class' module.
        import sys
        mod = sys.modules[cls.__module__]
        return getattr(mod, k)

    @classmethod
    def obj_from_jsondict(cls, jsondict):
        assert len(jsondict) == 1
        for k, v in jsondict.iteritems():
            obj_cls = cls.cls_from_jsondict_key(k)
            return obj_cls.from_jsondict(v)

    @classmethod
    def _get_decoder(cls, k, decode_string):
        t = cls._get_type(k)
        if t:
            return t.decode
        return cls._get_default_decoder(decode_string)

    @classmethod
    def _decode_value(cls, k, json_value, decode_string=base64.b64decode):
        return cls._get_decoder(k, decode_string)(json_value)

    @classmethod
    def _get_default_decoder(cls, decode_string):
        def _decode(json_value):
            if isinstance(json_value, (bytes, unicode)):
                v = decode_string(json_value)
            elif isinstance(json_value, list):
                v = map(_decode, json_value)
            elif isinstance(json_value, dict):
                if cls._is_class(json_value):
                    v = cls.obj_from_jsondict(json_value)
                else:
                    v = _mapdict(_decode, json_value)
                    # XXXhack
                    # try to restore integer keys used by
                    # OFPSwitchFeatures.ports.
                    try:
                        v = _mapdict_key(int, v)
                    except ValueError:
                        pass
            else:
                v = json_value
            return v
        return _decode

    @staticmethod
    def _restore_args(dict_):
        def restore(k):
            if k in _RESERVED_KEYWORD:
                return k + '_'
            return k
        return _mapdict_key(restore, dict_)

    @classmethod
    def from_jsondict(cls, dict_, decode_string=base64.b64decode,
                      **additional_args):
        """Create an instance from a JSON style dict.

        Instantiate this class with parameters specified by the dict.

        This method takes the following arguments.

        =============== =====================================================
        Argument        Descrpition
        =============== =====================================================
        dict\_          A dictionary which describes the parameters.
                        For example, {"Param1": 100, "Param2": 200}
        decode_string   (Optional) specify how to decode strings.
                        The default is base64.
                        This argument is used only for attributes which don't
                        have explicit type annotations in _TYPE class
                        attribute.
        additional_args (Optional) Additional kwargs for constructor.
        =============== =====================================================
        """
        decode = lambda k, x: cls._decode_value(k, x, decode_string)
        kwargs = cls._restore_args(_mapdict_kv(decode, dict_))
        try:
            return cls(**dict(kwargs, **additional_args))
        except TypeError:
            #debug
            print "CLS", cls
            print "ARG", dict_
            print "KWARG", kwargs
            raise


def obj_python_attrs(msg_):
    """iterate object attributes for stringify purposes
    """

    # a special case for namedtuple which seems widely used in
    # ofp parser implementations.
    if hasattr(msg_, '_fields'):
        for k in msg_._fields:
            yield(k, getattr(msg_, k))
        return
    base = getattr(msg_, '_base_attributes', [])
    for k, v in inspect.getmembers(msg_):
        if k.startswith('_'):
            continue
        if callable(v):
            continue
        if k in base:
            continue
        if hasattr(msg_.__class__, k):
            continue
        yield (k, v)


def obj_attrs(msg_):
    """similar to obj_python_attrs() but deals with python reserved keywords
    """

    if isinstance(msg_, StringifyMixin):
        iter = msg_.stringify_attrs()
    else:
        # probably called by msg_str_attr
        iter = obj_python_attrs(msg_)
    for k, v in iter:
        if k.endswith('_') and k[:-1] in _RESERVED_KEYWORD:
            # XXX currently only StringifyMixin has restoring logic
            assert isinstance(msg_, StringifyMixin)
            k = k[:-1]
        yield (k, v)
