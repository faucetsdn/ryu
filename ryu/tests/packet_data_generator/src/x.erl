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

-module(x).
-export([do/2, x/0]).

% eg. 1 -> of10
ofp_version_string(Vers) ->
    ["of", integer_to_list(9 + Vers)].

do(skip, {OFPVersion, N}) ->
    {OFPVersion, N + 1};
do(Body, {OFPVersion, N}) ->
    Mod = case OFPVersion of
        1 -> x_flower_packet;
        _ -> x_of_protocol
    end,
    Name = case Body of
        B when is_tuple(B) ->
            atom_to_list(element(1, B));
        _ ->
            atom_to_list(Body)
    end,
    io:format("processing ~B ~B ~s~n", [OFPVersion, N, Name]),
    Msg = Mod:message(OFPVersion, 0, Body),
    case Mod:encode(Msg) of
        {ok, BinMsg} -> ok;
        {error, Error} -> io:format("~p ~p~n", [Error, Msg]), BinMsg = hoge
    end,
    {ok, F} = file:open(["../packet_data/",
        ofp_version_string(OFPVersion), "/", integer_to_list(OFPVersion), "-",
        integer_to_list(N), "-", Name, ".packet"], [write, binary]),

    % sanity check
    % this is fragile because of order of flags.
    % ofp flags are unorderd but of_protocol keeps them in a list.
    {ok, Msg2, <<>>} = Mod:decode(BinMsg),
    {OFPVersion, 0, Body2} = Mod:message_extract(Msg2),
    case Body == Body2 of
        false -> io:format("~p~n", [Body]), io:format("~p~n", [Body2]);
        _ -> hoge
    end,
    Body = Body2,

    ok = file:write(F, BinMsg),
    ok = file:close(F),
    {OFPVersion, N + 1}.

x() ->
    lists:map(fun(Mod) -> Mod:x() end, [x1, x3, x4, x5]).
