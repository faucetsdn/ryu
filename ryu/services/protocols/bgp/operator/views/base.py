"""
This module's purpose is to enable us to present internals of objects
in well-defined way to operator. To do this we can define "views"
on some objects. View is a definition of how to present object
and relations to other objects which also have their views defined.

By using views we can avoid making all interesting internal values
public. They will stay private and only "view" will access them
(think friend-class from C++)
"""
import logging

from ryu.services.protocols.bgp.operator.views import fields

LOG = logging.getLogger('bgpspeaker.operator.views.base')


class RdyToFlattenCollection(object):
    pass


class RdyToFlattenList(list, RdyToFlattenCollection):
    pass


class RdyToFlattenDict(dict, RdyToFlattenCollection):
    pass


class OperatorAbstractView(object):
    """Abstract base class for operator views. It isn't meant to be
    instantiated.
    """

    def __init__(self, obj, filter_func=None):
        """Init

        :param obj: data model for view. In other words object we
            are creating view for. In case of ListView it should be
            a list and in case of DictView it should be a dict.
        :param filter_func: function to filter models
        """
        self._filter_func = filter_func
        self._fields = self._collect_fields()
        self._obj = obj

    @classmethod
    def _collect_fields(cls):
        names = [attr for attr in dir(cls)
                 if isinstance(getattr(cls, attr), fields.Field)]
        return dict([(name, getattr(cls, name)) for name in names])

    def combine_related(self, field_name):
        """Combines related views. In case of DetailView it just returns
            one-element list containing related view wrapped in
            CombinedViewsWrapper.

            In case of ListView and DictView it returns a list of related views
            for every element of model collection also wrapped
            in CombinedViewsWrapper.

        :param field_name: field name of related view
        :returns: vectorized form of related views. You can access them
            as if you had only one view and you will receive flattened list
            of responses from related views. Look at docstring of
            CombinedViewsWrapper
        """
        raise NotImplementedError()

    def c_rel(self, *args, **kwargs):
        """Shortcut for combine_related. Look above
        """
        return self.combine_related(*args, **kwargs)

    def get_field(self, field_name):
        """Get value of data field.

        :return: value of data-field of this view
        """
        raise NotImplementedError()

    def encode(self):
        """Representation of view which is using only python standard types.

        :return: dict representation of this views data. However it
            doesn't have to be a dict. In case of ListView it would
            return a list. It should return wrapped types
            for list - RdyToFlattenList, for dict - RdyToFlattenDict
        """
        raise NotImplementedError()

    @property
    def model(self):
        """Getter for data model being presented by this view. Every view is
        associated with some data model.

        :return: underlaying data of this view
        """
        raise NotImplementedError()

    def apply_filter(self, filter_func):
        """Sets filter function to apply on model

        :param filter_func: function which takes the model and returns it
            filtered
        """
        self._filter_func = filter_func

    def clear_filter(self):
        self._filter_func = None


class OperatorDetailView(OperatorAbstractView):
    def combine_related(self, field_name):
        f = self._fields[field_name]
        return CombinedViewsWrapper([f.retrieve_and_wrap(self._obj)])

    def get_field(self, field_name):
        f = self._fields[field_name]
        return f.get(self._obj)

    def encode(self):
        encoded = {}
        for field_name, field in self._fields.items():
            if isinstance(field, fields.DataField):
                encoded[field_name] = field.get(self._obj)
        return encoded

    def rel(self, field_name):
        f = self._fields[field_name]
        return f.retrieve_and_wrap(self._obj)

    @property
    def model(self):
        return self._obj


class OperatorListView(OperatorAbstractView):
    def __init__(self, obj, filter_func=None):
        assert isinstance(obj, list)
        obj = RdyToFlattenList(obj)
        super(OperatorListView, self).__init__(obj, filter_func)

    def combine_related(self, field_name):
        f = self._fields[field_name]
        return CombinedViewsWrapper(RdyToFlattenList(
            [f.retrieve_and_wrap(obj) for obj in self.model]
        ))

    def get_field(self, field_name):
        f = self._fields[field_name]
        return RdyToFlattenList([f.get(obj) for obj in self.model])

    def encode(self):
        encoded_list = []
        for obj in self.model:
            encoded_item = {}
            for field_name, field in self._fields.items():
                if isinstance(field, fields.DataField):
                    encoded_item[field_name] = field.get(obj)
            encoded_list.append(encoded_item)
        return RdyToFlattenList(encoded_list)

    @property
    def model(self):
        if self._filter_func is not None:
            return RdyToFlattenList(filter(self._filter_func, self._obj))
        else:
            return self._obj


class OperatorDictView(OperatorAbstractView):
    def __init__(self, obj, filter_func=None):
        assert isinstance(obj, dict)
        obj = RdyToFlattenDict(obj)
        super(OperatorDictView, self).__init__(obj, filter_func)

    def combine_related(self, field_name):
        f = self._fields[field_name]
        return CombinedViewsWrapper(RdyToFlattenList(
            [f.retrieve_and_wrap(obj) for obj in self.model.values()])
        )

    def get_field(self, field_name):
        f = self._fields[field_name]
        dict_to_flatten = {}
        for key, obj in self.model.items():
            dict_to_flatten[key] = f.get(obj)
        return RdyToFlattenDict(dict_to_flatten)

    def encode(self):
        outer_dict_to_flatten = {}
        for key, obj in self.model.items():
            inner_dict_to_flatten = {}
            for field_name, field in self._fields.items():
                if isinstance(field, fields.DataField):
                    inner_dict_to_flatten[field_name] = field.get(obj)
            outer_dict_to_flatten[key] = inner_dict_to_flatten
        return RdyToFlattenDict(outer_dict_to_flatten)

    @property
    def model(self):
        if self._filter_func is not None:
            new_model = RdyToFlattenDict()
            for k, v in self._obj.items():
                if self._filter_func(k, v):
                    new_model[k] = v
            return new_model
        else:
            return self._obj


class CombinedViewsWrapper(RdyToFlattenList):
    """List-like wrapper for views. It provides same interface as any other
    views but enables as to access all views in bulk.
    It wraps and return responses from all views as a list. Be aware that
    in case of DictViews wrapped in CombinedViewsWrapper you loose
    information about dict keys.
    """

    def __init__(self, obj):
        super(CombinedViewsWrapper, self).__init__(obj)
        self._obj = obj

    def combine_related(self, field_name):
        return CombinedViewsWrapper(
            list(_flatten(
                [obj.combine_related(field_name) for obj in self._obj]
            ))
        )

    def c_rel(self, *args, **kwargs):
        return self.combine_related(*args, **kwargs)

    def encode(self):
        return list(_flatten([obj.encode() for obj in self._obj]))

    def get_field(self, field_name):
        return list(_flatten([obj.get_field(field_name) for obj in self._obj]))

    @property
    def model(self):
        return list(_flatten([obj.model for obj in self._obj]))

    def apply_filter(self, filter_func):
        for obj in self._obj:
            obj.apply_filter(filter_func)

    def clear_filter(self):
        for obj in self._obj:
            obj.clear_filter()


def _flatten(l, max_level=10):
    """Generator function going deep in tree-like structures
    (i.e. dicts in dicts or lists in lists etc.) and returning all elements as
    a flat list. It's flattening only lists and dicts which are subclasses of
    RdyToFlattenCollection. Regular lists and dicts are treated as a
    single items.

    :param l: some iterable to be flattened
    :return: flattened iterator
    """
    if max_level >= 0:
        _iter = l.values() if isinstance(l, dict) else l
        for el in _iter:
            if isinstance(el, RdyToFlattenCollection):
                for sub in _flatten(el, max_level=max_level - 1):
                    yield sub
            else:
                yield el
    else:
        yield l


def _create_collection_view(detail_view_class, name, encode=None,
                            view_class=None):
    assert issubclass(detail_view_class, OperatorDetailView)
    class_fields = detail_view_class._collect_fields()
    if encode is not None:
        class_fields.update({'encode': encode})
    return type(name, (view_class,), class_fields)


# function creating ListView from DetailView
def create_dict_view_class(detail_view_class, name):
    encode = None
    if 'encode' in dir(detail_view_class):
        def encode(self):
            dict_to_flatten = {}
            for key, obj in self.model.items():
                dict_to_flatten[key] = detail_view_class(obj).encode()
            return RdyToFlattenDict(dict_to_flatten)

    return _create_collection_view(
        detail_view_class, name, encode, OperatorDictView
    )


# function creating DictView from DetailView
def create_list_view_class(detail_view_class, name):
    encode = None
    if 'encode' in dir(detail_view_class):
        def encode(self):
            return RdyToFlattenList([detail_view_class(obj).encode()
                                     for obj in self.model])

    return _create_collection_view(
        detail_view_class, name, encode, OperatorListView
    )
