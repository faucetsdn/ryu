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
 Public API for BGPSpeaker.

 This API can be used by various services like RPC, CLI, IoC, etc.
"""
import inspect
import logging
import traceback

from ryu.services.protocols.bgp.base import add_bgp_error_metadata
from ryu.services.protocols.bgp.base import API_ERROR_CODE
from ryu.services.protocols.bgp.base import BGPSException
from ryu.services.protocols.bgp.core_manager import CORE_MANAGER
from ryu.services.protocols.bgp.rtconf.base import get_validator
from ryu.services.protocols.bgp.rtconf.base import MissingRequiredConf
from ryu.services.protocols.bgp.rtconf.base import RuntimeConfigError


LOG = logging.getLogger('bgpspeaker.api.base')

# Various constants used in API calls
ROUTE_DISTINGUISHER = 'route_dist'
PREFIX = 'prefix'
NEXT_HOP = 'next_hop'
VPN_LABEL = 'label'
API_SYM = 'name'
ORIGIN_RD = 'origin_rd'
ROUTE_FAMILY = 'route_family'

# API call registry
_CALL_REGISTRY = {}


@add_bgp_error_metadata(code=API_ERROR_CODE,
                        sub_code=1,
                        def_desc='Unknown API error.')
class ApiException(BGPSException):
    pass


@add_bgp_error_metadata(code=API_ERROR_CODE,
                        sub_code=2,
                        def_desc='API symbol or method is not known.')
class MethodNotFound(ApiException):
    pass


@add_bgp_error_metadata(code=API_ERROR_CODE,
                        sub_code=3,
                        def_desc='Error related to BGPS core not starting.')
class CoreNotStarted(ApiException):
    pass


def register(**kwargs):
    """Decorator for registering API function.

    Does not do any check or validation.
    """
    def decorator(func):
        _CALL_REGISTRY[kwargs.get(API_SYM, func.func_name)] = func
        return func

    return decorator


def register_method(name):
    """Decorator for registering methods that provide BGPS public API.
    """
    def decorator(func):
        setattr(func, '__api_method_name__', name)
        return func

    return decorator


def register_class(cls):
    """Decorator for the registering class whose instance methods provide BGPS
    public API.
    """
    old_init = cls.__init__

    def new_init(self, *args, **kwargs):
        old_init(self, *args, **kwargs)
        api_registered_methods = \
            [(m_name, m) for m_name, m in
             inspect.getmembers(cls, predicate=inspect.ismethod)
             if hasattr(m, '__api_method_name__')]

        for _, method in api_registered_methods:
            api_name = getattr(method, '__api_method_name__')

            def create_wrapper(method):
                def api_method_wrapper(*args, **kwargs):
                    return method(self, *args, **kwargs)
                return api_method_wrapper

            register(name=api_name)(create_wrapper(method))

    cls.__init__ = new_init
    return cls


class RegisterWithArgChecks(object):
    """Decorator for registering API functions.

    Does some argument checking and validation of required arguments.
    """
    def __init__(self, name, req_args=None, opt_args=None):
        self._name = name
        if not req_args:
            req_args = []
        self._req_args = req_args
        if not opt_args:
            opt_args = []
        self._opt_args = opt_args
        self._all_args = (set(self._req_args) | set(self._opt_args))

    def __call__(self, func):
        """Wraps given function and registers it as API.

            Returns original function.
        """
        def wrapped_fun(**kwargs):
            """Wraps a function to do validation before calling actual func.

            Wraps a function to take key-value args. only. Checks if:
            1) all required argument of wrapped function are provided
            2) no extra/un-known arguments are passed
            3) checks if validator for required arguments is available
            4) validates required arguments
            Raises exception if no validator can be found for required args.
            """
            # Check if we are missing arguments.
            if not kwargs and len(self._req_args) > 0:
                raise MissingRequiredConf(desc='Missing all required '
                                          'attributes.')

            # Check if we have unknown arguments.
            given_args = set(kwargs.keys())
            unknown_attrs = given_args - set(self._all_args)
            if unknown_attrs:
                raise RuntimeConfigError(desc=('Unknown attributes %r' %
                                               unknown_attrs))

            # Check if required arguments are missing
            missing_req_args = set(self._req_args) - given_args
            if missing_req_args:
                conf_name = ', '.join(missing_req_args)
                raise MissingRequiredConf(conf_name=conf_name)

            #
            # Prepare to call wrapped function.
            #
            # Collect required arguments in the order asked and validate it.
            req_values = []
            for req_arg in self._req_args:
                req_value = kwargs.get(req_arg)
                # Validate required value.
                validator = get_validator(req_arg)
                if not validator:
                    raise ValueError('No validator registered for function %s'
                                     ' and arg. %s' % (func, req_arg))
                validator(req_value)
                req_values.append(req_value)

            # Collect optional arguments.
            opt_items = {}
            for opt_arg, opt_value in kwargs.items():
                if opt_arg in self._opt_args:
                    opt_items[opt_arg] = opt_value

            # Call actual function
            return func(*req_values, **opt_items)

        # Register wrapped function
        _CALL_REGISTRY[self._name] = wrapped_fun
        return func


def is_call_registered(call_name):
    return call_name in _CALL_REGISTRY


def get_call(call_name):
    return _CALL_REGISTRY.get(call_name)


def call(symbol, **kwargs):
    """Calls/executes BGPS public API identified by given symbol and passes
    given kwargs as param.
    """
    LOG.info("API method %s called with args: %s", symbol, str(kwargs))

    # TODO(PH, JK) improve the way api function modules are loaded
    import all  # noqa
    if not is_call_registered(symbol):
        message = 'Did not find any method registered by symbol %s' % symbol
        raise MethodNotFound(message)

    if not symbol.startswith('core') and not CORE_MANAGER.started:
        raise CoreNotStarted(desc='CoreManager is not active.')

    call = get_call(symbol)
    try:
        return call(**kwargs)
    except BGPSException as r:
        LOG.error(traceback.format_exc())
        raise r
    except Exception as e:
        LOG.error(traceback.format_exc())
        raise ApiException(desc=str(e))
