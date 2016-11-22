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

from __future__ import print_function

import base64
import inspect

import six

# Some arguments to __init__ is mangled in order to avoid name conflicts
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

_RESERVED_KEYWORD = dir(six.moves.builtins)

_mapdict = lambda f, d: dict([(k, f(v)) for k, v in d.items()])
_mapdict_key = lambda f, d: dict([(f(k), v) for k, v in d.items()])
_mapdict_kv = lambda f, d: dict([(k, f(k, v)) for k, v in d.items()])


class TypeDescr(object):
    pass


class AsciiStringType(TypeDescr):
    @staticmethod
    def encode(v):
        # TODO: AsciiStringType data should probably be stored as
        # text_type in class data.  This isinstance() check exists
        # because OFPDescStats violates this.
        if six.PY3 and isinstance(v, six.text_type):
            return v
        return six.text_type(v, 'ascii')

    @staticmethod
    def decode(v):
        if six.PY3:
            return v
        return v.encode('ascii')


class Utf8StringType(TypeDescr):
    @staticmethod
    def encode(v):
        return six.text_type(v, 'utf-8')

    @staticmethod
    def decode(v):
        return v.encode('utf-8')


class AsciiStringListType(TypeDescr):
    @staticmethod
    def encode(v):
        return [AsciiStringType.encode(x) for x in v]

    @staticmethod
    def decode(v):
        return [AsciiStringType.decode(x) for x in v]


class NXFlowSpecFieldType(TypeDescr):
    # ("field_name", 0) <-> ["field_name", 0]

    @staticmethod
    def encode(v):
        if not isinstance(v, tuple):
            return v
        field, ofs = v
        return [field, ofs]

    @staticmethod
    def decode(v):
        if not isinstance(v, list):
            return v
        field, ofs = v
        return field, ofs


_types = {
    'ascii': AsciiStringType,
    'utf-8': Utf8StringType,
    'asciilist': AsciiStringListType,
    'nx-flow-spec-field': NXFlowSpecFieldType,  # XXX this should not be here
}


class StringifyMixin(object):

    _TYPE = {}
    """_TYPE class attribute is used to annotate types of attributes.

    This type information is used to find an appropriate conversion for
    a JSON style dictionary.

    Currently the following types are implemented.

    ========= =============
    Type      Description
    ========= =============
    ascii     US-ASCII
    utf-8     UTF-8
    asciilist list of ascii
    ========= =============

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
    _class_suffixes = []

    # List of attributes ignored in the str and json representations.
    _base_attributes = []

    # Optional attributes included in the str and json representations.
    # e.g.) In case of attributes are property, the attributes will be
    # skipped in the str and json representations.
    # Then, please specify the attributes into this list.
    _opt_attributes = []

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
        # Examples of OFP classes:
        #   {"OFPMatch": { ... }}
        #   {"MTIPv6SRC": { ... }}
        assert isinstance(dict_, dict)
        if len(dict_) != 1:
            return False
        k = list(dict_.keys())[0]
        if not isinstance(k, (bytes, six.text_type)):
            return False
        for p in cls._class_prefixes:
            if k.startswith(p):
                return True
        for p in cls._class_suffixes:
            if k.endswith(p):
                return True
        return False

    @classmethod
    def _get_type(cls, k):
        if hasattr(cls, '_TYPE'):
            for t, attrs in cls._TYPE.items():
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
            if isinstance(v, (bytes, six.text_type)):
                if isinstance(v, six.text_type):
                    v = v.encode('utf-8')
                json_value = encode_string(v)
                if six.PY3:
                    json_value = json_value.decode('ascii')
            elif isinstance(v, list):
                json_value = [_encode(ve) for ve in v]
            elif isinstance(v, dict):
                json_value = _mapdict(_encode, v)
                # while a python dict key can be any hashable object,
                # a JSON object key should be a string.
                json_value = _mapdict_key(str, json_value)
                assert not cls._is_class(json_value)
            else:
                try:
                    json_value = v.to_jsondict()
                except Exception:
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

        .. tabularcolumns:: |l|L|

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
        encode = lambda key, val: self._encode_value(key, val, encode_string)
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
    def obj_from_jsondict(cls, jsondict, **additional_args):
        assert len(jsondict) == 1
        for k, v in jsondict.items():
            obj_cls = cls.cls_from_jsondict_key(k)
            return obj_cls.from_jsondict(v, **additional_args)

    @classmethod
    def _get_decoder(cls, k, decode_string):
        t = cls._get_type(k)
        if t:
            return t.decode
        return cls._get_default_decoder(decode_string)

    @classmethod
    def _decode_value(cls, k, json_value, decode_string=base64.b64decode,
                      **additional_args):
        # Note: To avoid passing redundant arguments (e.g. 'datapath' for
        # non OFP classes), we omit '**additional_args' here.
        return cls._get_decoder(k, decode_string)(json_value)

    @classmethod
    def _get_default_decoder(cls, decode_string):
        def _decode(json_value, **additional_args):
            if isinstance(json_value, (bytes, six.text_type)):
                v = decode_string(json_value)
            elif isinstance(json_value, list):
                v = [_decode(jv) for jv in json_value]
            elif isinstance(json_value, dict):
                if cls._is_class(json_value):
                    v = cls.obj_from_jsondict(json_value, **additional_args)
                else:
                    v = _mapdict(_decode, json_value)
                    # XXX: Hack
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

        .. tabularcolumns:: |l|L|

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
        decode = lambda k, x: cls._decode_value(k, x, decode_string,
                                                **additional_args)
        kwargs = cls._restore_args(_mapdict_kv(decode, dict_))
        try:
            return cls(**dict(kwargs, **additional_args))
        except TypeError:
            # debug
            print("CLS %s" % cls)
            print("ARG %s" % dict_)
            print("KWARG %s" % kwargs)
            raise

    @classmethod
    def set_classes(cls, registered_dict):
        cls._class_prefixes.extend([v.__name__ for v in
                                    registered_dict.values()])


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
    opt = getattr(msg_, '_opt_attributes', [])
    for k, v in inspect.getmembers(msg_):
        if k in opt:
            pass
        elif k.startswith('_'):
            continue
        elif callable(v):
            continue
        elif k in base:
            continue
        elif hasattr(msg_.__class__, k):
            continue
        yield (k, v)


def obj_attrs(msg_):
    """similar to obj_python_attrs() but deals with python reserved keywords
    """

    if isinstance(msg_, StringifyMixin):
        itr = msg_.stringify_attrs()
    else:
        # probably called by msg_str_attr
        itr = obj_python_attrs(msg_)
    for k, v in itr:
        if k.endswith('_') and k[:-1] in _RESERVED_KEYWORD:
            # XXX currently only StringifyMixin has restoring logic
            assert isinstance(msg_, StringifyMixin)
            k = k[:-1]
        yield (k, v)
