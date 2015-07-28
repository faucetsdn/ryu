#!/usr/bin/env python
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

from argparse import ArgumentParser
import sys
import logging
import inspect
from gevent import pywsgi
from geventwebsocket.handler import WebSocketHandler
from flask import Flask, request, abort
from views.view_base import ViewBase


parser = ArgumentParser()
parser.add_argument('--host', dest='host', default='0.0.0.0')
parser.add_argument('--port', dest='port', type=int, default=8000)
args = parser.parse_args()

app = Flask(__name__.split('.')[0])
logging.basicConfig(level=logging.DEBUG,
                    stream=sys.stderr,
                    format="%(asctime)-15s [%(levelname)-4s] %(message)s")
#handler = logging.FileHandler("/tmp/ryu_gui.log", encoding="utf8")
#app.logger.addHandler(handler)


@app.before_request
def before_request_trigger():
    pass


@app.after_request
def after_request_trigger(response):
    return response


@app.route('/')
def index():
    return _view('topology')


@app.route('/stats/flow', methods=['POST'])
def flow_mod():
    return _view('flow', request.form.get('host'), request.form.get('port'),
                 request.form.get('dpid'), request.form.get('flows'))


@app.route('/websocket')
def websocket():
    if request.environ.get('wsgi.websocket'):
        ws = request.environ['wsgi.websocket']
        return _view('websocket', ws)
    abort(404)


def _view(view_name, *args, **kwargs):
    view_name = 'views.' + view_name
    try:
        __import__(view_name)
    except ImportError:
        app.logger.error('ImportError (%s)', view_name)
        abort(500)

    mod = sys.modules.get(view_name)
    clases = inspect.getmembers(mod, lambda cls: (inspect.isclass(cls) and
                                                  issubclass(cls, ViewBase)))
    try:
        view = clases[0][1](*args, **kwargs)
    except IndexError:
        app.logger.error('has not View class (%s)', view_name)
        abort(500)
    app.logger.debug('view loaded. %s', view_name)
    return view.run()


if __name__ == '__main__':
    server = pywsgi.WSGIServer((args.host, args.port),
                               app, handler_class=WebSocketHandler)
    app.logger.info('Running on %s', server.address)
    server.serve_forever()
