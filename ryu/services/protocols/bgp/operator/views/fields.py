import importlib
import inspect


class Field(object):
    def __init__(self, field_name):
        self.field_name = field_name

    def get(self, obj):
        return getattr(obj, self.field_name)


class RelatedViewField(Field):
    def __init__(self, field_name, operator_view_class):
        super(RelatedViewField, self).__init__(field_name)
        self.__operator_view_class = operator_view_class

    @property
    def _operator_view_class(self):
        if inspect.isclass(self.__operator_view_class):
            return self.__operator_view_class
        elif isinstance(self.__operator_view_class, basestring):
            try:
                module_name, class_name =\
                    self.__operator_view_class.rsplit('.', 1)
                return class_for_name(module_name, class_name)
            except (AttributeError, ValueError, ImportError):
                raise WrongOperatorViewClassError(
                    'There is no "%s" class' % self.__operator_view_class
                )

    def retrieve_and_wrap(self, obj):
        related_obj = self.get(obj)
        return self.wrap(related_obj)

    def wrap(self, obj):
        return self._operator_view_class(obj)


class RelatedListViewField(RelatedViewField):
    pass


class RelatedDictViewField(RelatedViewField):
    pass


class DataField(Field):
    pass


class OptionalDataField(DataField):
    def get(self, obj):
        if hasattr(obj, self.field_name):
            return getattr(obj, self.field_name)
        else:
            return None


class WrongOperatorViewClassError(Exception):
    pass


def class_for_name(module_name, class_name):
    # load the module, will raise ImportError if module cannot be loaded
    m = importlib.import_module(module_name)
    # get the class, will raise AttributeError if class cannot be found
    c = getattr(m, class_name)
    return c
