# Copyright (C) 2013 Stratosphere Inc.
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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging

import nose
from nose.tools import eq_

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.lib import dpid as dpidlib

LOG = logging.getLogger('test_wsgi')


class _TestController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(_TestController, self).__init__(req, link, data, **config)
        eq_(data['test_param'], 'foo')

    @route('test', '/test/{dpid}',
           methods=['GET'], requirements={'dpid': dpidlib.DPID_PATTERN})
    def test_get_dpid(self, req, dpid, **_kwargs):
        return Response(status=200, body=dpid)

    @route('test', '/test')
    def test_root(self, req, **_kwargs):
        return Response(status=200, body='root')


class Test_wsgi(unittest.TestCase):

    """ Test case for wsgi
    """

    def setUp(self):
        controller_data = {
            'test_param': 'foo'
        }
        self.wsgi_app = WSGIApplication()
        self.wsgi_app.register(_TestController, controller_data)

    def tearDown(self):
        pass

    def test_wsgi_decorator_ok(self):
        r = self.wsgi_app({'REQUEST_METHOD': 'GET',
                           'PATH_INFO': '/test/0123456789abcdef'},
                          lambda s, _: eq_(s, '200 OK'))
        eq_(r[0], (b'0123456789abcdef'))

    def test_wsgi_decorator_ng_path(self):
        self.wsgi_app({'REQUEST_METHOD': 'GET',
                       'PATH_INFO': '/'},
                      lambda s, _: eq_(s, '404 Not Found'))

    def test_wsgi_decorator_ng_method(self):
        # XXX: If response code is "405 Method Not Allowed", it is better.
        self.wsgi_app({'REQUEST_METHOD': 'PUT',
                       'PATH_INFO': '/test/0123456789abcdef'},
                      lambda s, _: eq_(s, '404 Not Found'))

    def test_wsgi_decorator_ng_requirements(self):
        # XXX: If response code is "400 Bad Request", it is better.
        self.wsgi_app({'REQUEST_METHOD': 'GET',
                       'PATH_INFO': '/test/hogehoge'},
                      lambda s, _: eq_(s, '404 Not Found'))

    def test_wsgi_decorator_ok_any_method(self):
        self.wsgi_app({'REQUEST_METHOD': 'GET',
                       'PATH_INFO': '/test'},
                      lambda s, _: eq_(s, '200 OK'))
        self.wsgi_app({'REQUEST_METHOD': 'POST',
                       'PATH_INFO': '/test'},
                      lambda s, _: eq_(s, '200 OK'))
        self.wsgi_app({'REQUEST_METHOD': 'PUT',
                       'PATH_INFO': '/test'},
                      lambda s, _: eq_(s, '200 OK'))
        r = self.wsgi_app({'REQUEST_METHOD': 'DELETE',
                           'PATH_INFO': '/test'},
                          lambda s, _: eq_(s, '200 OK'))
        eq_(r[0], b'root')


if __name__ == '__main__':
    nose.main(argv=['nosetests', '-s', '-v'], defaultTest=__file__)
