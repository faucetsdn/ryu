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

-module(x1).
-export([x/0]).

-include_lib("flower/include/flower_packet.hrl").

cookie(Bin) ->
    <<Int:64>> = Bin,
    Int.

x() ->
    List = [
        skip,
        #ofp_packet_out{
            buffer_id = ?OFP_NO_BUFFER,in_port = controller,
            actions = 
                [#ofp_action_output{port = all,max_len = 65535}],
            data = 
                <<242,11,164,208,63,112,242,11,164,125,248,234,8,0,69,0,
                  0,84,248,26,0,0,255,1,175,139,10,0,0,1,10,0,0,2,8,0,2,
                  8,247,96,0,0,49,214,2,0,0,0,0,0,171,141,45,49,0,0,0,0,
                  16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,
                  34,35,36,37,38,39,40,41,42,43,44,45,46,47,0,0,0,0,0,0,
                  0,0>>},
        #ofp_flow_mod{
            cookie = cookie(<<0,0,0,0,0,0,0,0>>),
            command = add,idle_timeout = 0,
            hard_timeout = 0,priority = 123,buffer_id = 65535,
            out_port = all,flags = [],
            match =
                #ofp_match{
                    wildcards = 16#3ffff7,
                    dl_dst = <<"\362\v\244}\370\352">>,
                    % XXX ryu and flower have different defaults for the
                    % followin fields.
                    in_port = 0,
                    dl_src = <<0:6/unit:8>>
                },
            actions = [#ofp_action_output{port = 6,max_len = 65535}]},
        skip,
        #ofp_packet_in{
            buffer_id = 2,total_len=42,reason = action,in_port = 99,
            data =
                <<255,255,255,255,255,255,242,11,164,125,248,234,8,6,0,
                  1,8,0,6,4,0,1,242,11,164,125,248,234,10,0,0,1,0,0,0,0,
                  0,0,10,0,0,3>>},

        features_request,
        #ofp_switch_features{  % features_reply
            datapath_id = 16#ff12345678,n_buffers = 0,n_tables = 255,
            capabilities = 
                [arp_match_ip,ip_reasm,stp,flow_stats],
            actions =
                [enqueue,set_nw_src,set_vlan_vid,output],
            ports = 
                [#ofp_phy_port{
                     port_no = 7,hw_addr = <<"\362\v\244\320?p">>,
                     name = <<"Port7">>,
                     config = [],
                     state = [stp_block],
                     curr = [autoneg,copper,'100mb_fd'],
                     advertised = [autoneg,copper],
                     supported = [autoneg,copper,'100mb_fd'],
                     peer = [autoneg,copper,'100mb_fd']},
                 #ofp_phy_port{
                     port_no = 6,hw_addr = <<"\362\v\244}\370\352">>,
                     name = <<"Port6">>,
                     config = [],
                     state = [stp_listen],
                     curr = [autoneg,copper,'100mb_fd'],
                     advertised = [autoneg,copper],
                     supported = [autoneg,copper,'100mb_fd'],
                     peer = [autoneg,copper,'100mb_fd']}]}
    ],
    lists:foldl(fun x:do/2, {1, 0}, List).
