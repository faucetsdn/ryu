# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

from __future__ import absolute_import

import functools
import logging

from sqlalchemy.ext.declarative import declarative_base


LOG = logging.getLogger(__name__)

Base = declarative_base()
"""
Base class for Zebra protocol database tables.
"""


def _repr(self):
    m = ', '.join(
        ['%s=%r' % (k, v)
         for k, v in self.__dict__.items() if not k.startswith('_')])
    return "%s(%s)" % (self.__class__.__name__, m)

Base.__repr__ = _repr


def sql_function(func):
    """
    Decorator for wrapping the given function in order to manipulate (CRUD)
    the records safely.

    For the adding/updating/deleting records function, this decorator
    invokes "Session.commit()" after the given function.
    If any exception while modifying records raised, this decorator invokes
    "Session.rollbacks()".
    """
    @functools.wraps(func)
    def _wrapper(session, *args, **kwargs):
        ret = None
        try:
            ret = func(session, *args, **kwargs)
            if session.dirty:
                # If the given function has any update to records,
                # commits them.
                session.commit()
        except Exception as e:
            # If any exception raised, rollbacks the transaction.
            LOG.error('Error in %s: %s', func.__name__, e)
            if session.dirty:
                LOG.error('Do rolling back %s table',
                          session.dirty[0].__tablename__)
                session.rollback()

        return ret

    return _wrapper
