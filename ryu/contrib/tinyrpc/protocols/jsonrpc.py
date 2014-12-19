#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .. import RPCBatchProtocol, RPCRequest, RPCResponse, RPCErrorResponse,\
               InvalidRequestError, MethodNotFoundError, ServerError,\
               InvalidReplyError, RPCError, RPCBatchRequest, RPCBatchResponse

import json

class FixedErrorMessageMixin(object):
    def __init__(self, *args, **kwargs):
        if not args:
            args = [self.message]
        super(FixedErrorMessageMixin, self).__init__(*args, **kwargs)

    def error_respond(self):
        response = JSONRPCErrorResponse()

        response.error = self.message
        response.unique_id = None
        response._jsonrpc_error_code = self.jsonrpc_error_code
        return response



class JSONRPCParseError(FixedErrorMessageMixin, InvalidRequestError):
    jsonrpc_error_code = -32700
    message = 'Parse error'


class JSONRPCInvalidRequestError(FixedErrorMessageMixin, InvalidRequestError):
    jsonrpc_error_code = -32600
    message = 'Invalid Request'


class JSONRPCMethodNotFoundError(FixedErrorMessageMixin, MethodNotFoundError):
    jsonrpc_error_code = -32601
    message = 'Method not found'


class JSONRPCInvalidParamsError(FixedErrorMessageMixin, InvalidRequestError):
    jsonrpc_error_code = -32602
    message = 'Invalid params'


class JSONRPCInternalError(FixedErrorMessageMixin, InvalidRequestError):
    jsonrpc_error_code = -32603
    message = 'Internal error'


class JSONRPCServerError(FixedErrorMessageMixin, InvalidRequestError):
    jsonrpc_error_code = -32000
    message = ''


class JSONRPCSuccessResponse(RPCResponse):
    def _to_dict(self):
        return {
            'jsonrpc': JSONRPCProtocol.JSON_RPC_VERSION,
            'id': self.unique_id,
            'result': self.result,
        }

    def serialize(self):
        return json.dumps(self._to_dict())


class JSONRPCErrorResponse(RPCErrorResponse):
    def _to_dict(self):
        return {
            'jsonrpc': JSONRPCProtocol.JSON_RPC_VERSION,
            'id': self.unique_id,
            'error': {
                'message': str(self.error),
                'code': self._jsonrpc_error_code,
            }
        }

    def serialize(self):
        return json.dumps(self._to_dict())


def _get_code_and_message(error):
    assert isinstance(error, (Exception, basestring))
    if isinstance(error, Exception):
        if hasattr(error, 'jsonrpc_error_code'):
            code = error.jsonrpc_error_code
            msg = str(error)
        elif isinstance(error, InvalidRequestError):
            code = JSONRPCInvalidRequestError.jsonrpc_error_code
            msg = JSONRPCInvalidRequestError.message
        elif isinstance(error, MethodNotFoundError):
            code = JSONRPCMethodNotFoundError.jsonrpc_error_code
            msg = JSONRPCMethodNotFoundError.message
        else:
            # allow exception message to propagate
            code = JSONRPCServerError.jsonrpc_error_code
            msg = str(error)
    else:
        code = -32000
        msg = error

    return code, msg


class JSONRPCRequest(RPCRequest):
    def error_respond(self, error):
        if not self.unique_id:
            return None

        response = JSONRPCErrorResponse()

        code, msg = _get_code_and_message(error)

        response.error = msg
        response.unique_id = self.unique_id
        response._jsonrpc_error_code = code
        return response

    def respond(self, result):
        response = JSONRPCSuccessResponse()

        if not self.unique_id:
            return None

        response.result = result
        response.unique_id = self.unique_id

        return response

    def _to_dict(self):
        jdata = {
            'jsonrpc': JSONRPCProtocol.JSON_RPC_VERSION,
            'method': self.method,
        }
        if self.args:
            jdata['params'] = self.args
        if self.kwargs:
            jdata['params'] = self.kwargs
        if self.unique_id != None:
            jdata['id'] = self.unique_id
        return jdata

    def serialize(self):
        return json.dumps(self._to_dict())


class JSONRPCBatchRequest(RPCBatchRequest):
    def create_batch_response(self):
        if self._expects_response():
            return JSONRPCBatchResponse()

    def _expects_response(self):
        for request in self:
            if isinstance(request, Exception):
                return True
            if request.unique_id != None:
                return True

        return False

    def serialize(self):
        return json.dumps([req._to_dict() for req in self])


class JSONRPCBatchResponse(RPCBatchResponse):
    def serialize(self):
        return json.dumps([resp._to_dict() for resp in self if resp != None])


class JSONRPCProtocol(RPCBatchProtocol):
    """JSONRPC protocol implementation.

    Currently, only version 2.0 is supported."""

    JSON_RPC_VERSION = "2.0"
    _ALLOWED_REPLY_KEYS = sorted(['id', 'jsonrpc', 'error', 'result'])
    _ALLOWED_REQUEST_KEYS = sorted(['id', 'jsonrpc', 'method', 'params'])

    def __init__(self, *args, **kwargs):
        super(JSONRPCProtocol, self).__init__(*args, **kwargs)
        self._id_counter = 0

    def _get_unique_id(self):
        self._id_counter += 1
        return self._id_counter

    def create_batch_request(self, requests=None):
        return JSONRPCBatchRequest(requests or [])

    def create_request(self, method, args=None, kwargs=None, one_way=False):
        if args and kwargs:
            raise InvalidRequestError('Does not support args and kwargs at '\
                                      'the same time')

        request = JSONRPCRequest()

        if not one_way:
            request.unique_id = self._get_unique_id()

        request.method = method
        request.args = args
        request.kwargs = kwargs

        return request

    def parse_reply(self, data):
        try:
            rep = json.loads(data)
        except Exception as e:
            raise InvalidReplyError(e)

        for k in rep.iterkeys():
            if not k in self._ALLOWED_REPLY_KEYS:
                raise InvalidReplyError('Key not allowed: %s' % k)

        if not 'jsonrpc' in rep:
            raise InvalidReplyError('Missing jsonrpc (version) in response.')

        if rep['jsonrpc'] != self.JSON_RPC_VERSION:
            raise InvalidReplyError('Wrong JSONRPC version')

        if not 'id' in rep:
            raise InvalidReplyError('Missing id in response')

        if ('error' in rep) == ('result' in rep):
            raise InvalidReplyError(
                'Reply must contain exactly one of result and error.'
            )

        if 'error' in rep:
            response = JSONRPCErrorResponse()
            error = rep['error']
            response.error = error['message']
            response._jsonrpc_error_code = error['code']
        else:
            response = JSONRPCSuccessResponse()
            response.result = rep.get('result', None)

        response.unique_id = rep['id']

        return response

    def parse_request(self, data):
        try:
            req = json.loads(data)
        except Exception as e:
            raise JSONRPCParseError()

        if isinstance(req, list):
            # batch request
            requests = JSONRPCBatchRequest()
            for subreq in req:
                try:
                    requests.append(self._parse_subrequest(subreq))
                except RPCError as e:
                    requests.append(e)
                except Exception as e:
                    requests.append(JSONRPCInvalidRequestError())

            if not requests:
                raise JSONRPCInvalidRequestError()
            return requests
        else:
            return self._parse_subrequest(req)

    def _parse_subrequest(self, req):
        for k in req.iterkeys():
            if not k in self._ALLOWED_REQUEST_KEYS:
                raise JSONRPCInvalidRequestError()

        if req.get('jsonrpc', None) != self.JSON_RPC_VERSION:
            raise JSONRPCInvalidRequestError()

        if not isinstance(req['method'], basestring):
            raise JSONRPCInvalidRequestError()

        request = JSONRPCRequest()
        request.method = str(req['method'])
        request.unique_id = req.get('id', None)

        params = req.get('params', None)
        if params != None:
            if isinstance(params, list):
                request.args = req['params']
            elif isinstance(params, dict):
                request.kwargs = req['params']
            else:
                raise JSONRPCInvalidParamsError()

        return request
