%% Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
%% Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%    http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
%% implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(x_of_protocol).
-export([message/3, message_extract/1, encode/1, decode/1]).

-include_lib("of_protocol/include/of_protocol.hrl").

message(OFPVersion, Xid, Body) ->
    #ofp_message{version=OFPVersion, xid=Xid, body=Body}.

message_extract(Msg) ->
    #ofp_message{version=OFPVersion, xid=Xid, body=Body} = Msg,
    {OFPVersion, Xid, Body}.

encode(Msg) ->
    of_protocol:encode(Msg).

decode(BinMsg) ->
    of_protocol:decode(BinMsg).
