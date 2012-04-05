# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# This code is based on webservice.py from NOX project:
#   Copyright 2008 (C) Nicira, Inc.

import gflags
import logging
import re
import textwrap
import simplejson
from copy import copy
from gevent.pywsgi import WSGIServer
from webob import Request, Response

LOG = logging.getLogger('ryu.app.wsapi')

FLAGS = gflags.FLAGS
gflags.DEFINE_string('wsapi_host', '', 'webapp listen host')
gflags.DEFINE_integer('wsapi_port', 8080, 'webapp listen port')

### Response functions:
#
# The following functions can be used to generate various error responses.
# These should only ever be used for the web-services interface, not the
# user-facing web interface.


def forbidden(request, errmsg, otherInfo={}):
    """Return an error code indicating client is forbidden from accessing."""
    request.setResponseCode(403)
    request.setHeader("Content-Type", "application/json")
    d = copy(otherInfo)
    d["displayError"] = errmsg
    return simplejson.dumps(d)


def badRequest(request, errmsg, otherInfo={}):
    """Return an error indicating a problem in data from the client."""
    request.setResponseCode(400, "Bad request")
    request.setHeader("Content-Type", "application/json")
    d = copy(otherInfo)
    d["displayError"] = "The server did not understand the request."
    d["error"] = errmsg
    return simplejson.dumps(d)


def conflictError(request, errmsg, otherURI=None, otherInfo={}):
    """Return an error indicating something conflicts with the request."""
    if otherURI != None:
        request.setResponseCode(409, "Conflicts with another resource")
        request.setHeader("Location", otherURI.encode("utf-8"))
    else:
        request.setResponseCode(409, "Internal server conflict")
    request.setHeader("Content-Type", "application/json")
    d = copy(otherInfo)
    d["displayError"] = "Request failed due to simultaneous access."
    d["error"] = errmsg
    d["otherURI"] = otherURI
    return simplejson.dumps(d)


def internalError(request, errmsg, otherInfo={}):
    """Return an error code indicating an error in the server."""
    request.setResponseCode(500)
    request.setHeader("Content-Type", "application/json")
    d = copy(otherInfo)
    d["displayError"] = \
                      "The server failed while attempting to perform request."
    d["error"] = errmsg
    return simplejson.dumps(d)


def notFound(request, errmsg, otherInfo={}):
    """Return an error indicating a resource could not be found."""
    request.setResponseCode(404, "Resource not found")
    request.setHeader("Content-Type", "application/json")
    d = copy(otherInfo)
    d["displayError"] = "The server does not have data for the request."
    d["error"] = errmsg
    return simplejson.dumps(d)


def methodNotAllowed(request, errmsg, valid_methods, otherInfo={}):
    """Return an error indicating this request method is not allowed."""
    request.setResponseCode(405, "Method not allowed")
    method_txt = ", ".join(valid_methods)
    request.setHeader("Allow", method_txt)
    request.setHeader("Content-Type", "application/json")
    d = copy(otherInfo)
    d["displayError"] = "The server can not perform this operation."
    d["error"] = errmsg
    d["validMethods"] = valid_methods
    return simplejson.dumps(d)


def unauthorized(request, errmsg="", otherInfo={}):
    """Return an error indicating a client was not authorized."""
    request.setResponseCode(401, "Unauthorized")
    request.setHeader("Content-Type", "application/json")
    if errmsg != "":
        errmsg = ": " + errmsg
    d = copy(otherInfo)
    d["displayError"] = "Unauthorized%s\n\n" % (errmsg, )
    d["error"] = errmsg
    d["loginInstructions"] = \
        "You must login using 'POST /ws.v1/login' nd pass the resulting " + \
        "cookie with\neach equest."
    return simplejson.dumps(d)


### Message Body handling
#
def json_parse_message_body(request):
    content = request.content.read()
    content_type = request.getHeader("content-type")
    if content_type == None or content_type.find("application/json") == -1:
        e = ["The message body must have Content-Type application/json\n",
              "instead of %s. " % content_type]
        if content_type == "application/x-www-form-urlencoded":
            e.append("The web\nserver decoded the message body as:\n\n")
            e.append(str(request.args))
        else:
            e.append("The message body was:\n\n")
            e.append(content)
        LOG.error("".join(e))
        return None
    if len(content) == 0:
        LOG.error("Message body was empty.  "
                  "It should be valid JSON encoded data for this request.")
        return None
    try:
        data = simplejson.loads(content)
    except:
        LOG.error("Message body is not valid json data. "
                  "It was:\n\n%s" % (content,))
        return None
    return data


class WhitespaceNormalizer:
    def __init__(self):
        self._re = re.compile("\s+")

    def normalize_whitespace(self, s):
        return self._re.sub(" ", s).strip()


class WSPathTreeNode:
    _wsn = WhitespaceNormalizer()

    def __init__(self, parent, path_component):
        self.path_component = path_component
        self._handlers = {}
        self._parent = parent
        self._children = []
        self._tw = textwrap.TextWrapper()
        self._tw.width = 78
        self._tw.initial_indent = " " * 4
        self._tw.subsequent_indent = self._tw.initial_indent

    def parent(self):
        return self._parent()

    def _matching_child(self, path_component):
        for c in self._children:
            if str(c.path_component) == str(path_component):
                return c
        return None

    def has_child(self, path_component):
        return self._matching_child(path_component) != None

    def add_child(self, path_component):
        c = self._matching_child(path_component)
        if c == None:
            c = WSPathTreeNode(self, path_component)
            self._children.append(c)
        return c

    def path_str(self):
        if self._parent == None:
            return ""
        return self._parent.path_str() + "/" + str(self.path_component)

    def set_handler(self, request_method, handler, doc):
        if request_method in self._handlers:
            raise KeyError("%s %s is already handled by '%s'" %
                           (request_method, self.path_str(),
                            repr(self._handlers[request_method][0])))
        d = self._wsn.normalize_whitespace(doc)
        d = self._tw.fill(d)
        self._handlers[request_method] = (handler, d)

    def interface_doc(self, base_path):
        msg = []
        p = base_path + self.path_str()
        for k in self._handlers:
            msg.extend((k, " ", p, "\n"))
            doc = self._handlers[k][1]
            if doc != None:
                msg.extend((doc, "\n\n"))
        for c in self._children:
            msg.append(c.interface_doc(base_path))
        return "".join(msg)

    def handle(self, t):
        s = t.next_path_string()
        if s != None:
            r = None
            if len(self._children) == 0:
                t.request_uri_too_long()
            for c in self._children:
                r = c.path_component.extract(s, t.data)
                if r.error == None:
                    t.data[str(c.path_component)] = r.value
                    t.failed_paths = []
                    r = c.handle(t)
                    break
                else:
                    t.failed_paths.append((c.path_str(), r.error))
            if len(t.failed_paths) > 0:
                return t.invalid_request()
            return r
        else:
            try:
                h, d = self._handlers[t.request_method()]
            except KeyError:
                return t.unsupported_method(self._handlers.keys())
            return t.call_handler(h)


class WSPathTraversal:

    def __init__(self, request):
        self._request = request
        self._pathiter = iter(request.postpath)
        self.data = {}
        self.failed_paths = []

    def request_method(self):
        return self._request.method

    def next_path_string(self):
        try:
            return self._pathiter.next()
        except StopIteration:
            return None

    def call_handler(self, handler):
        try:
            return handler(self._request, self.data)
        except Exception, e:
            LOG.error("caught unhandled exception with path '%s' : %s" % \
                      (str(self._request.postpath), e))
            internalError(self._request, "Unhandled server error")

    def _error_wrapper(self, l):
        msg = []
        msg.append("You submitted the following request.\n\n")
        msg.append("    %s %s\n\n" %
                   (self._request.method, self._request.path))
        msg.append("This request is not valid. ")
        msg.extend(l)
        msg.append("\n\nYou can get a list of all valid requests with the ")
        msg.append("following request.\n\n    ")
        msg.append("GET /" + "/".join(self._request.prepath) + "/doc")
        return "".join(msg)

    def request_uri_too_long(self):
        e = ["The request URI path extended beyond all available URIs."]
        return notFound(self._request, self._error_wrapper(e))

    def unsupported_method(self, valid_methods):
        if len(valid_methods) > 0:
            e = ["This URI only supports the following methods.\n\n    "]
            e.append(", ".join(valid_methods))
        else:
            e = ["There are no supported request methods\non this URI. "]
            e.append("It is only used as part of longer URI paths.")
        return methodNotAllowed(self._request, self._error_wrapper(e),
                                valid_methods)

    def invalid_request(self):
        e = []
        if len(self.failed_paths) > 0:
            e.append("The following paths were evaluated and failed\n")
            e.append("for the indicated reason.")
            for p, m in self.failed_paths:
                e.append("\n\n    - %s\n      %s" % (p, m))
        return notFound(self._request, self._error_wrapper(e))


### Registering for requests
#
class WSRequestHandler:
    """Class to determine appropriate handler for a web services request."""

    def __init__(self):
        self._path_tree = WSPathTreeNode(None, None)

    def register(self, handler, request_method, path_components, doc=None):
        """Register a web services request handler.

        The parameters are:

            - handler: a function to be called when the specified request
                  method and path component list are matched.  It must
                  have the signature:

                       handler(request, extracted_data)

                  Here the 'request' parameter is a twisted request object
                  to be used to output the result and extracted_data is a
                  dictionary of data extracted by the WSPath subclass
                  instances in the 'path_components' parameter indexed
                  by str(path_component_instance).

            - request_method: the HTTP request method of the request to
                  be handled.

            - path_components: a list of 'WSPathComponent' subclasses
                  describing the path to be handled.

            - doc: a string describing the result of this request."""
        pn = self._path_tree
        for pc in path_components:
            pn = pn.add_child(pc)
        pn.set_handler(request_method.upper(), handler, doc)

    def handle(self, request):
        return self._path_tree.handle(WSPathTraversal(request))

    def interface_doc(self, base_path):
        """Text describing all current valid requests."""
        d = """\
This is a RESTful web interface to NOX network applications.  The applications
running on this NOX instance support the following requests.\n\n"""

        return d + self._path_tree.interface_doc(base_path)


class WSPathExtractResult:
    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error


class WSPathComponent:
    """Base class for WS path component extractors"""

    def __init__(self):
        """Initialize a path component extractor

        Currently this does nothing but that may change in the future.
        Subclasses should call this to be sure."""
        pass

    def __str__(self):
        """Get the string representation of the path component

        This is used in generating information about the available paths
        and conform to the following conventions:

            - If a fixed string is being matched, it should be that string.
            - In all other cases, it should be a description of what is
              being extracted within angle brackets, for example,
              '<existing database table name>'.

        This string is also the key in the dictionary callbacks registered
        with a WSPathParser instance receive to obtain the extracted
        information."""
        err = "The '__str__' method must be implemented by subclasses."
        raise NotImplementedError(err)

    def extract(self, pc, extracted_data):
        """Determine if 'pc' matches this path component type

        Returns a WSPathExtractResult object with value set to the
        extracted value for this path component if the extraction succeeded
        or error set to an error describing why it did not succeed.

        The 'pc' parameter may have the value 'None' if all path components
        have been exhausted during previous WS path parsing. This is
        to allow path component types that are optional at the end
        of a WS.

        The extracted_data parameter contains data extracted
        from earlier path components, which can be used during the
        extraction if needed.  It is a dictionary keyed by the
        str(path_component) for each previous path component."""
        err = "The 'extract' method must be implemented by subclasses."
        raise NotImplementedError(err)


class WSPathStaticString(WSPathComponent):
    """Match a static string in the WS path, possibly case insensitive."""

    def __init__(self, str, case_insensitive=False):
        WSPathComponent.__init__(self)
        self.case_insensitive = case_insensitive
        if case_insensitive:
            self.str = str.lower()
        else:
            self.str = str

    def __str__(self):
        return self.str

    def extract(self, pc, data):
        if pc == None:
            return WSPathExtractResult(error="End of requested URI")

        if self.case_insensitive:
            if pc.lower() == self.str:
                return WSPathExtractResult(value=pc)
        else:
            if pc == self.str:
                return WSPathExtractResult(value=pc)
        return WSPathExtractResult(error="'%s' != '%s'" % (pc, self.str))


class WSPathRegex(WSPathComponent):
    """Match a regex in the WS path.

    This can not be used directly but must be subclassed.  Typically
    the only thing a subclass must override is the '__str__'
    method.

    The value returned from the 'extract' method is the python regular
    expression match object, from subgroups in the expression can be
    examined, etc."""
    def __init__(self, regexp):
        WSPathComponent.__init__(self)
        self.re = re.compile(regexp)

    def extract(self, pc, data):
        if pc == None:
            return WSPathExtractResult(error="End of requested URI")
        m = re.match(pc)
        if m == None:
            return WSPathExtractResult(error="Regexp did not match: %s" %
                                       self.re.pattern)
        return WSPathExtractResult(value=m)


class WSPathTrailingSlash(WSPathComponent):
    """Match a null string at a location in the WS path.

    This is typically used at the end of a WS path to require a
    trailing slash."""

    def __init__(self):
        WSPathComponent.__init__(self)

    def __str__(self):
        return "/"

    def extract(self, pc, data):
        if pc == "":
            return WSPathExtractResult(True)
        else:
            return WSPathExtractResult(
                error="Data following expected trailing slash")


# match any string, and retrieve it by 'name'
# (e.g.,  WSPathArbitraryString('<hostname>')
class WSPathArbitraryString(WSPathComponent):
    def __init__(self, name):
        WSPathComponent.__init__(self)
        self._name = name

        def __str__(self):
            return self._name

    def extract(self, pc, data):
        if pc == None:
            return WSPathExtractResult(error="End of requested URI")
        return WSPathExtractResult(unicode(pc, 'utf-8'))


class WSRequest:

    def __init__(self, env, start_response):
        self.env = env
        self.start_response = start_response
        self.version = None

        req = Request(env)
        self.method = req.method
        self.path = req.path
        self.segs = [s for s in self.path.split('/') if s]

        self.rsp = Response(status=200)

        try:
            version_str = self.segs[0]
        except IndexError:
            return

        p = re.compile('^v(?P<ver>.+)$')
        m = p.match(version_str)
        if m:
            self.version = m.group('ver')

        self.prepath = [version_str]
        self.postpath = self.segs[1:]

    def setHeader(self, name, value):
        self.rsp.headers[name] = value

    def setResponseCode(self, code, message=None):
        if not isinstance(code, (int, long)):
            raise TypeError("HTTP response code must be int or long")
        if message:
            self.rsp.status = str(code) + " " + message
        else:
            self.rsp.status = code

    def sendResponse(self, body):
        self.rsp.body = body
        return self.rsp(self.env, self.start_response)


class WSRes:

    def _get_interface_doc(self, request, arg):
        request.setHeader("Content-Type", "text/plain")
        return self.mgr.interface_doc("/" + "/".join(request.prepath))

    def __init__(self, version='1.0'):
        self.version = version
        self.mgr = WSRequestHandler()
        self.register_request(self._get_interface_doc,
                              "GET", (WSPathStaticString("doc"),),
                              """Get a summary of requests supported by this
                                 web service interface.""")

    def register_request(self, handler, request_method, path_components, doc):
        self.mgr.register(handler, request_method, path_components, doc)

    def render(self, request):
        return self.mgr.handle(request)


class wsapi:

    _versions = {'1.0': WSRes('1.0')}

    @classmethod
    def get_version(cls, version):
        return cls._versions[version]

    def application(self, env, start_response):
        wsreq = WSRequest(env, start_response)
        if wsreq.version in wsapi._versions:
            body = wsapi._versions[wsreq.version].render(wsreq)
        else:
            body = notFound(wsreq, "")
        return wsreq.sendResponse(body)

    def __call__(self):
        server = WSGIServer((FLAGS.wsapi_host, FLAGS.wsapi_port),
                            self.application)
        server.serve_forever()
