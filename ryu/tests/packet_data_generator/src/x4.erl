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

-module(x4).
-export([x/0]).

-include_lib("of_protocol/include/of_protocol.hrl").
-include_lib("of_protocol/include/ofp_v4.hrl").

x() ->
    AllFields = [
         #ofp_field{
             class = openflow_basic,name = in_port,
             has_mask = false,
             value = <<5,6,7,8>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = in_phy_port,
             has_mask = false,
             value = <<1,2,3,4>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = metadata,
             has_mask = false,
             value = <<0,1,2,3,4,5,6,7>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = eth_type,
             has_mask = false,
             value = <<8,6>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = eth_dst,
             has_mask = false,value = <<"\377\377\377\377\377\377">>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = eth_src,
             has_mask = false,value = <<"\362\v\244}\370\352">>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = vlan_vid,
             has_mask = false,value = <<999:13>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ip_dscp,
             has_mask = false,value = <<9:6>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ip_ecn,
             has_mask = false,value = <<3:2>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ip_proto,
             has_mask = false,value = <<99>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ipv4_src,
             has_mask = false,value = <<1,2,3,4>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ipv4_dst,
             has_mask = false,value = <<1,2,3,4>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = tcp_src,
             has_mask = false,value = <<8080:16>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = tcp_dst,
             has_mask = false,value = <<18080:16>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = udp_src,
             has_mask = false,value = <<28080:16>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = udp_dst,
             has_mask = false,value = <<318080:16>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = sctp_src,
             has_mask = false,value = <<48080:16>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = sctp_dst,
             has_mask = false,value = <<518080:16>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = icmpv4_type,
             has_mask = false,value = <<100>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = icmpv4_code,
             has_mask = false,value = <<101>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = arp_op,
             has_mask = false,
             value = <<0,1>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = arp_spa,
             has_mask = false,
             value = <<10,0,0,1>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = arp_tpa,
             has_mask = false,
             value = <<10,0,0,3>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = arp_sha,
             has_mask = false,value = <<"\362\v\244}\370\352">>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = arp_tha,
             has_mask = false,
             value = <<0,0,0,0,0,0>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ipv6_src,
             has_mask = false,
             % fe80::f00b:a4ff:fe48:28a5
             value = <<16#fe80000000000000f00ba4fffe4828a5:128>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ipv6_dst,
             has_mask = false,
             % fe80::f00b:a4ff:fe05:b7dc
             value = <<16#fe80000000000000f00ba4fffe05b7dc:128>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ipv6_flabel,
             has_mask = false,
             value = <<16#84321:20>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = icmpv6_type,
             has_mask = false,
             value = <<200>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = icmpv6_code,
             has_mask = false,
             value = <<201>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ipv6_nd_target,
             has_mask = false,
             % fe80::a60:6eff:fe7f:74e7
             value = <<16#fe800000000000000a606efffe7f74e7:128>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ipv6_nd_sll,
             has_mask = false,
             value = <<666:48>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ipv6_nd_tll,
             has_mask = false,
             value = <<555:48>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = mpls_label,
             has_mask = false,
             value = <<16#98765:20>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = mpls_tc,
             has_mask = false,
             value = <<5:3>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = mpls_bos,
             has_mask = false,
             value = <<1:1>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = pbb_isid,
             has_mask = false,
             value = <<16#abcdef:24>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = tunnel_id,
             has_mask = false,
             value = <<9,9,9,9,9,9,9,9>>,
             mask = undefined},
         #ofp_field{
             class = openflow_basic,name = ipv6_exthdr,
             has_mask = false,
             value = <<500:9>>,
             mask = undefined},
         #ofp_field{
             class = {experimenter, onf},name = pbb_uca,
             has_mask = false,
             value = <<1:1>>,
             mask = undefined},
         #ofp_field{
             class = nxm_1,name = 31,  % tun_ipv4_src
             has_mask = false,
             value = <<1,2,3,4>>,
             mask = undefined},
         #ofp_field{
             class = nxm_1,name = 32,  % tun_ipv4_dst
             has_mask = false,
             value = <<1,2,3,4>>,
             mask = undefined}
    ],
    List = [
        #ofp_desc_reply{flags = [], mfr_desc = <<"mfr">>,
                              hw_desc = <<"hw">>, sw_desc = <<"sw">>,
                              serial_num = <<"serial">>,
                              dp_desc = <<"dp">>},
        #ofp_packet_out{
            buffer_id = no_buffer,in_port = controller,
            actions = 
                [#ofp_action_output{port = all,max_len = no_buffer}],
            data = 
                <<242,11,164,208,63,112,242,11,164,125,248,234,8,0,69,0,
                  0,84,248,26,0,0,255,1,175,139,10,0,0,1,10,0,0,2,8,0,2,
                  8,247,96,0,0,49,214,2,0,0,0,0,0,171,141,45,49,0,0,0,0,
                  16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,
                  34,35,36,37,38,39,40,41,42,43,44,45,46,47,0,0,0,0,0,0,
                  0,0>>},
        #ofp_flow_mod{
            cookie = <<0,0,0,0,0,0,0,0>>,
            cookie_mask = <<0,0,0,0,0,0,0,0>>,
            table_id = 1,command = add,idle_timeout = 0,
            hard_timeout = 0,priority = 123,buffer_id = 65535,
            out_port = any,out_group = any,flags = [],
            match =
                #ofp_match{
                    fields =
                        [#ofp_field{
                             class = openflow_basic,name = eth_dst,
                             has_mask = false,
                             value = <<"\362\v\244}\370\352">>,
                             mask = undefined}]},
            instructions =
                [#ofp_instruction_write_actions{
                     actions =
                         [#ofp_action_set_field{
                             field = #ofp_field{name = vlan_vid,
                                                value = <<258:13>> }},
                          #ofp_action_copy_ttl_out{},
                          #ofp_action_copy_ttl_in{},
                          #ofp_action_copy_ttl_in{},
                          #ofp_action_pop_pbb{},
                          #ofp_action_push_pbb{ethertype = 16#1234},
                          #ofp_action_pop_mpls{ethertype= 16#9876},
                          #ofp_action_push_mpls{ethertype = 16#8847},
                          #ofp_action_pop_vlan{},
                          #ofp_action_push_vlan{ethertype = 16#8100},
                          #ofp_action_dec_mpls_ttl{},
                          #ofp_action_set_mpls_ttl{mpls_ttl = 10},
                          #ofp_action_dec_nw_ttl{},
                          #ofp_action_set_nw_ttl{nw_ttl = 10},
                          #ofp_action_experimenter{
                              experimenter = 101,
                              data = <<0,1,2,3,4,5,6,7>>},
                          #ofp_action_set_queue{queue_id = 3},
                          #ofp_action_group{group_id = 99},
                          #ofp_action_output{port = 6,max_len = no_buffer}]},
                 #ofp_instruction_apply_actions{
                     actions =
                         [#ofp_action_set_field{
                             field = #ofp_field{name = eth_src,
                                                value = <<1,2,3,4,5,6>> }},
                          #ofp_action_set_field{
                             field = #ofp_field{class = {experimenter, onf},
                                                name = pbb_uca,
                                                value = <<1:1>> }}]}]},
        #ofp_flow_mod{
            cookie = <<0,0,0,0,0,0,0,0>>,
            cookie_mask = <<0,0,0,0,0,0,0,0>>,
            table_id = 0,command = add,idle_timeout = 0,
            hard_timeout = 0,priority = 123,buffer_id = 65535,
            out_port = any,out_group = any,flags = [],
            match =
                #ofp_match{
                    fields =
                        [#ofp_field{
                             class = openflow_basic,name = in_port,
                             has_mask = false,
                             value = <<0,0,0,6>>,
                             mask = undefined},
                         #ofp_field{
                             class = openflow_basic,name = eth_src,
                             has_mask = false,
                             value = <<"\362\v\244}\370\352">>,
                             mask = undefined}]},
            instructions =
                [#ofp_instruction_goto_table{table_id = 1}]},
        #ofp_packet_in{
            buffer_id = 2,reason = action,table_id = 1,
            cookie = <<0,1,2,3,0,0,0,0>>,
            match =
                #ofp_match{
                    fields =
                        [#ofp_field{
                             class = openflow_basic,name = in_port,
                             has_mask = false,
                             value = <<0,0,0,6>>,
                             mask = undefined},
                         #ofp_field{
                             class = openflow_basic,name = eth_type,
                             has_mask = false,
                             value = <<8,6>>,
                             mask = undefined},
                         #ofp_field{
                             class = openflow_basic,name = eth_dst,
                             has_mask = false,value = <<"\377\377\377\377\377\377">>,
                             mask = undefined},
                         #ofp_field{
                             class = openflow_basic,name = eth_src,
                             has_mask = false,value = <<"\362\v\244}\370\352">>,
                             mask = undefined},
                         #ofp_field{
                             class = openflow_basic,name = arp_op,
                             has_mask = false,
                             value = <<0,1>>,
                             mask = undefined},
                         #ofp_field{
                             class = openflow_basic,name = arp_spa,
                             has_mask = false,
                             value = <<10,0,0,1>>,
                             mask = undefined},
                         #ofp_field{
                             class = openflow_basic,name = arp_tpa,
                             has_mask = false,
                             value = <<10,0,0,3>>,
                             mask = undefined},
                         #ofp_field{
                             class = openflow_basic,name = arp_sha,
                             has_mask = false,value = <<"\362\v\244}\370\352">>,
                             mask = undefined},
                         #ofp_field{
                             class = openflow_basic,name = arp_tha,
                             has_mask = false,
                             value = <<0,0,0,0,0,0>>,
                             mask = undefined}]},
            data =
                <<255,255,255,255,255,255,242,11,164,125,248,234,8,6,0,
                  1,8,0,6,4,0,1,242,11,164,125,248,234,10,0,0,1,0,0,0,0,
                  0,0,10,0,0,3>>},
        #ofp_features_request{},
        #ofp_features_reply{
            datapath_mac = <<8,96,110,127,116,231>>,
            datapath_id = 0,n_buffers = 0,n_tables = 255,
            auxiliary_id = 99,
            capabilities = 
                [flow_stats,table_stats,port_stats,group_stats,queue_stats]},
        #ofp_set_config{flags = [],miss_send_len = 128},
        #ofp_get_config_request{},
        #ofp_get_config_reply{flags = [],miss_send_len = 128},
        #ofp_hello{elements = [{versionbitmap, [30, 10, 9, 3, 2, 1]}]},
        #ofp_flow_stats_request{
            flags = [],table_id = 0,out_port = any,out_group = any,
            cookie = <<0,0,0,0,0,0,0,0>>,
            cookie_mask = <<0,0,0,0,0,0,0,0>>,
            match = #ofp_match{fields = []}},
        #ofp_flow_stats_reply{
            flags = [],
            body =
                [#ofp_flow_stats{
                     table_id = 0,duration_sec = 358,
                     duration_nsec = 115277000,priority = 65535,
                     idle_timeout = 0,hard_timeout = 0,
                     cookie = <<0,0,0,0,0,0,0,0>>,
                     packet_count = 0,byte_count = 0,
                     match = #ofp_match{fields = []},
                     instructions = []},
                 #ofp_flow_stats{
                     table_id = 0,duration_sec = 358,
                     duration_nsec = 115055000,priority = 65534,
                     idle_timeout = 0,hard_timeout = 0,
                     cookie = <<0,0,0,0,0,0,0,0>>,
                     packet_count = 0,byte_count = 0,
                     match =
                         #ofp_match{
                             fields =
                                 [#ofp_field{
                                      class = openflow_basic,name = eth_type,
                                      has_mask = false,
                                      value = <<8,6>>,
                                      mask = undefined}]},
                     instructions =
                         [#ofp_instruction_apply_actions{
                              actions =
                                  [#ofp_action_output{
                                       port = normal,max_len = 0}]}]},
                 #ofp_flow_stats{
                     table_id = 0,duration_sec = 316220,
                     duration_nsec = 511582000,priority = 123,
                     idle_timeout = 0,hard_timeout = 0,
                     cookie = <<0,0,0,0,0,0,0,0>>,
                     packet_count = 3,byte_count = 238,
                     match =
                         #ofp_match{
                             fields =
                                 [#ofp_field{
                                      class = openflow_basic,name = in_port,
                                      has_mask = false,
                                      value = <<0,0,0,6>>,
                                      mask = undefined},
                                  #ofp_field{
                                      class = openflow_basic,name = eth_src,
                                      has_mask = false,
                                      value = <<"\362\v\244}\370\352">>,
                                      mask = undefined}]},
                     instructions =
                         [#ofp_instruction_goto_table{table_id = 1}]},
                 #ofp_flow_stats{
                     table_id = 0,duration_sec = 313499,
                     duration_nsec = 980901000,priority = 0,
                     idle_timeout = 0,hard_timeout = 0,
                     cookie = <<0,0,0,0,0,0,0,0>>,
                     packet_count = 1,byte_count = 98,
                     match = #ofp_match{fields = []},
                     instructions =
                         [#ofp_instruction_write_actions{
                              actions =
                                  [#ofp_action_set_field{
                                      field = #ofp_field{name = vlan_vid,
                                                         value = <<258:13>> }},
                                   #ofp_action_copy_ttl_out{},
                                   #ofp_action_copy_ttl_in{},
                                   #ofp_action_copy_ttl_in{},
                                   #ofp_action_pop_pbb{},
                                   #ofp_action_push_pbb{ethertype = 16#1234},
                                   #ofp_action_pop_mpls{ethertype= 16#9876},
                                   #ofp_action_push_mpls{ethertype = 16#8847},
                                   #ofp_action_pop_vlan{},
                                   #ofp_action_push_vlan{ethertype = 16#8100},
                                   #ofp_action_dec_mpls_ttl{},
                                   #ofp_action_set_mpls_ttl{mpls_ttl = 10},
                                   #ofp_action_dec_nw_ttl{},
                                   #ofp_action_set_nw_ttl{nw_ttl = 10},
                                   #ofp_action_set_queue{queue_id = 3},
                                   #ofp_action_group{group_id = 99},
                                   #ofp_action_output{port = 6,
                                                      max_len = no_buffer},
                                   #ofp_action_experimenter{experimenter = 98765432,
                                                            data = <<"exp_data">>},
                                   #ofp_action_experimenter{experimenter = 8992,
                                                            data = <<"exp_data">>}
                                                            ]},
                          #ofp_instruction_apply_actions{
                              actions =
                                  [#ofp_action_set_field{
                                      field = #ofp_field{name = eth_src,
                                                         value = <<1,2,3,4,
                                                                   5,6>> }},
                                   #ofp_action_set_field{
                                      field = #ofp_field{class = {experimenter,
                                                                  onf},
                                                         name = pbb_uca,
                                                         value = <<1:1>> }}]},
                          #ofp_instruction_write_actions{
                              actions =
                                  [#ofp_action_output{
                                       port = controller,
                                       max_len = no_buffer}]}]}]},
        #ofp_echo_request{
            data = <<"hoge">>
        },
        #ofp_echo_reply{
            data = <<"hoge">>
        },
        #ofp_error_msg{
            type = bad_action,
            code = unsupported_order,
            data = <<"fugafuga">>
        },
        #ofp_experimenter{
            experimenter = 98765432,
            exp_type = 123456789,
            data = <<"nazo">>
        },
        #ofp_barrier_request{},
        #ofp_barrier_reply{},
        #ofp_role_request{
            role = master,
            generation_id = 16#f000f000f000f000},
        #ofp_role_reply{
            role = slave,
            generation_id = 16#f000f000f000f000},

        #ofp_group_mod{
            command = add,type = all,group_id = 1,
            buckets = 
                [#ofp_bucket{
                     weight = 1,watch_port = 1,watch_group = 1,
                     actions = 
                         [#ofp_action_output{port = 2,max_len = no_buffer}]}]},
        #ofp_port_mod{port_no = 1, hw_addr = <<0,17,0,0,17,17>>,
            config = [],mask = [], advertise = [fiber]},
        #ofp_table_mod{table_id = all},
        #ofp_desc_request{},
        #ofp_aggregate_stats_request{
            flags = [],table_id = all,out_port = any,out_group = any,
            cookie = <<0,0,0,0,0,0,0,0>>,
            cookie_mask = <<0,0,0,0,0,0,0,0>>,
            match = #ofp_match{fields = []}},
        #ofp_aggregate_stats_reply{flags = [],packet_count = 7,
                                   byte_count = 574,flow_count = 6},
        #ofp_table_stats_request{},

#ofp_table_stats_reply{
    flags = [],
    body =
        [#ofp_table_stats{
             table_id = 0,
             active_count = 4, lookup_count = 4,matched_count = 4},
         #ofp_table_stats{
             table_id = 1,
             active_count = 4, lookup_count = 4,matched_count = 4}]},

        #ofp_port_stats_request{flags = [],port_no = any},
        #ofp_port_stats_reply{
            flags = [],
            body = 
                [#ofp_port_stats{
                     port_no = 7,rx_packets = 0,tx_packets = 4,rx_bytes = 0,
                     tx_bytes = 336,rx_dropped = 0,tx_dropped = 0,
                     rx_errors = 0,
                     tx_errors = 0,rx_frame_err = 0,rx_over_err = 0,
                     rx_crc_err = 0,collisions = 0},
                 #ofp_port_stats{
                     port_no = 6,rx_packets = 4,tx_packets = 4,rx_bytes = 336,
                     tx_bytes = 336,rx_dropped = 0,tx_dropped = 0,
                     rx_errors = 0,
                     tx_errors = 0,rx_frame_err = 0,rx_over_err = 0,
                     rx_crc_err = 0,collisions = 0}]},
        #ofp_group_features_request{flags = []},
        #ofp_group_features_reply{
            flags = [],
            types = [all,select,indirect,ff],
            capabilities = [select_weight,chaining],
            max_groups = {16777216,16777216,16777216,16777216},
            actions =
                {[output,copy_ttl_out,copy_ttl_in,set_mpls_ttl,dec_mpls_ttl,push_vlan,pop_vlan,push_mpls,pop_mpls,set_queue,group,set_nw_ttl,dec_nw_ttl,set_field],
                 [output,copy_ttl_out,copy_ttl_in,set_mpls_ttl,dec_mpls_ttl,push_vlan,pop_vlan,push_mpls,pop_mpls,set_queue,group,set_nw_ttl,dec_nw_ttl,set_field],
                 [output,copy_ttl_out,copy_ttl_in,set_mpls_ttl,dec_mpls_ttl,push_vlan,pop_vlan,push_mpls,pop_mpls,set_queue,group,set_nw_ttl,dec_nw_ttl,set_field],
                 [output,copy_ttl_out,copy_ttl_in,set_mpls_ttl,dec_mpls_ttl,push_vlan,pop_vlan,push_mpls,pop_mpls,set_queue,group,set_nw_ttl,dec_nw_ttl,set_field]}},
        #ofp_group_desc_request{},
        #ofp_group_desc_reply{
            flags = [],
            body = 
                [#ofp_group_desc_stats{
                     type = all,group_id = 1,
                     buckets = 
                         [#ofp_bucket{
                              weight = 1,watch_port = 1,watch_group = 1,
                              actions = 
                                  [#ofp_action_output{
                                       port = 2, max_len = no_buffer}]}]}]},
        #ofp_queue_get_config_request{port = any},
        #ofp_queue_get_config_reply{port = any,queues = [
            #ofp_packet_queue{queue_id = 99, port_no = 77,
                properties = [
                    #ofp_queue_prop_min_rate{rate = 10},
                    #ofp_queue_prop_max_rate{rate = 900},
                    #ofp_queue_prop_experimenter{experimenter = 999,
                                                 data = <<>>}
                ]
            },
            #ofp_packet_queue{queue_id = 88, port_no = 77,
                properties = [
                    #ofp_queue_prop_min_rate{rate = 100},
                    #ofp_queue_prop_max_rate{rate = 200},
                    #ofp_queue_prop_experimenter{experimenter = 999,
                                                 data = <<1:8>>}
                ]
            },
            #ofp_packet_queue{queue_id = 77, port_no = 77,
                properties = [
                    #ofp_queue_prop_min_rate{rate = 200},
                    #ofp_queue_prop_max_rate{rate = 400},
                    #ofp_queue_prop_experimenter{experimenter = 999,
                                                 data = <<1:8,2:8>>}
                ]
            }
        ]},
        #ofp_queue_stats_request{flags = [],port_no = any,
                                 queue_id = all},
        #ofp_queue_stats_reply{
            flags = [],
            body = 
                [#ofp_queue_stats{
                     port_no = 7,queue_id = 1,tx_bytes = 0,tx_packets = 0,
                     tx_errors = 0},
                 #ofp_queue_stats{
                     port_no = 6,queue_id = 1,tx_bytes = 0,tx_packets = 0,
                     tx_errors = 0},
                 #ofp_queue_stats{
                     port_no = 7,queue_id = 2,tx_bytes = 0,tx_packets = 0,
                     tx_errors = 0}]},
        #ofp_port_status{
            reason = add,
            desc = #ofp_port{
                     port_no = 7,hw_addr = <<"\362\v\244\320?p">>,
                     name = <<"\xe7\xa7\x81\xe3\x81\xae\xe3\x83\x9d\xe3\x83\xbc\xe3\x83\x88">>,  % "my port" in japanese, utf-8
                     config = [],
                     state = [live],
                     curr = ['100mb_fd',copper,autoneg],
                     advertised = [copper,autoneg],
                     supported = ['100mb_fd',copper,autoneg],
                     peer = ['100mb_fd',copper,autoneg],
                     curr_speed = 5000,max_speed = 5000}
        },
        #ofp_flow_removed{
            cookie = <<0,0,0,0,0,0,0,0>>,
            priority = 65535,reason = idle_timeout,table_id = 0,
            duration_sec = 3,duration_nsec = 48825000,idle_timeout = 3,
            hard_timeout = 0,packet_count = 1,byte_count = 86,
            match = 
                #ofp_match{
                    fields = 
                        [#ofp_field{
                             class = openflow_basic,name = eth_dst,
                             has_mask = false,
                             value = <<"\362\v\244}\370\352">>,
                             mask = undefined}]}},
        #ofp_error_msg_experimenter{
            exp_type = 60000,
            experimenter = 999999,
            data = <<"jikken data">>
        },
        #ofp_get_async_request{},
        #ofp_get_async_reply{
            packet_in_mask = {[no_match, invalid_ttl], [no_match]},
            port_status_mask = {[add, delete, modify], [add, delete]},
            flow_removed_mask = {
                [idle_timeout, hard_timeout, delete, group_delete],
                [idle_timeout, hard_timeout]
            }
        },
        #ofp_set_async{
            packet_in_mask = {[no_match, invalid_ttl], [no_match]},
            port_status_mask = {[add, delete, modify], [add, delete]},
            flow_removed_mask = {
                [idle_timeout, hard_timeout, delete, group_delete],
                [idle_timeout, hard_timeout]
            }
        },

        #ofp_meter_mod{
            command = add,
            flags = [pktps, burst, stats],
            meter_id = 100,
            bands = [
                #ofp_meter_band_drop{rate = 1000, burst_size = 10},
                #ofp_meter_band_dscp_remark{rate = 1000, burst_size = 10,
                                            prec_level = 1},
                #ofp_meter_band_experimenter{rate = 1000, burst_size = 10,
                                             experimenter = 999}
            ]
        },

        #ofp_flow_mod{
            cookie = <<0,0,0,0,0,0,0,0>>,
            cookie_mask = <<0,0,0,0,0,0,0,0>>,
            table_id = 1,command = add,idle_timeout = 0,
            hard_timeout = 0,priority = 123,buffer_id = 65535,
            out_port = any,out_group = any,flags = [],
            match =
                #ofp_match{
                    fields =
                        [#ofp_field{
                             class = openflow_basic,name = eth_dst,
                             has_mask = false,
                             value = <<"\362\v\244}\370\352">>,
                             mask = undefined}]},
            instructions =
                [#ofp_instruction_meter{meter_id = 1},
                 #ofp_instruction_write_actions{
                     actions =
                         [#ofp_action_output{port = 6,max_len = no_buffer}]}]},

        #ofp_meter_config_request{meter_id = all},
        #ofp_meter_config_reply{
            body = 
                [#ofp_meter_config{
                     flags = [pktps,burst,stats],
                     meter_id = 100,
                     bands = 
                         [#ofp_meter_band_drop{
                              type = drop,rate = 1000,burst_size = 10}]}]},

        #ofp_meter_stats_request{meter_id = all},
        #ofp_meter_stats_reply{
            body = 
                [#ofp_meter_stats{
                     meter_id = 100,flow_count = 0,packet_in_count = 0,
                     byte_in_count = 0,duration_sec = 0,duration_nsec = 480000,
                     band_stats = 
                         [#ofp_meter_band_stats{
                              packet_band_count = 0,byte_band_count = 0}]}]},

        #ofp_meter_features_request{},
        #ofp_meter_features_reply{max_meter = 16777216,
                                  band_types = [drop,dscp_remark,experimenter],
                                  capabilities = [kbps,pktps,burst,stats],
                                  max_bands = 255,max_color = 0},
        #ofp_port_desc_request{flags = []},
        #ofp_port_desc_reply{flags = [],
                             body = [#ofp_port{port_no = 7,hw_addr = <<"\362\v\244\320?p">>,
                                               name = <<"Port7">>,config = [],
                                               state = [live],
                                               curr = ['100mb_fd',copper,autoneg],
                                               advertised = [copper,autoneg],
                                               supported = ['100mb_fd',copper,autoneg],
                                               peer = ['100mb_fd',copper,autoneg],
                                               curr_speed = 5000,max_speed = 5000},
                                     #ofp_port{port_no = 6,hw_addr = <<"\362\v\244}\370\352">>,
                                               name = <<"Port6">>,config = [],
                                               state = [live],
                                               curr = ['100mb_fd',copper,autoneg],
                                               advertised = [copper,autoneg],
                                               supported = ['100mb_fd',copper,autoneg],
                                               peer = ['100mb_fd',copper,autoneg],
                                               curr_speed = 5000,max_speed = 5000}]},


       #ofp_table_features_request{
           flags = [more],
           body =
               [#ofp_table_features{
                    table_id = 0,name = <<"Flow Table 0x00">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,
                                  18,19,20,21,22,23,24,25,26,27,28,29,30,31,
                                  32,33,34,35,36,37,38,39,40,41,42,43,44,45,
                                  46,47,48,49,50,51,52,53,54,55,56,57,58,59,
                                  60,61,62,63,64,65,66,67,68,69,70,71,72,73,
                                  74,75,76,77,78,79,80,81,82,83,84,85,86,87,
                                  88,89,90,91,92,93,94,95,96,97,98,99,100,
                                  101,102,103,104,105,106,107,108,109,110,
                                  111,112,113,114,115,116,117,118,119,120,
                                  121,122,123,124,125,126,127,128,129,130,
                                  131,132,133,134,135,136,137,138,139,140,
                                  141,142,143,144,145,146,147,148,149,150,
                                  151,152,153,154,155,156,157,158,159,160,
                                  161,162,163,164,165,166,167,168,169,170,
                                  171,172,173,174,175,176,177,178,179,180,
                                  181,182,183,184,185,186,187,188,189,190,
                                  191,192,193,194,195,196,197,198,199,200,
                                  201,202,203,204,205,206,207,208,209,210,
                                  211,212,213,214,215,216,217,218,219,220,
                                  221,222,223,224,225,226,227,228,229,230,
                                  231,232,233,234,235,236,237,238,239,240,
                                  241,242,243,244,245,246,247,248,249,250,
                                  251,252,253,254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_experimenter{
                             experimenter = 101,
                             exp_type = 0,
                             data = <<>>},
                         #ofp_table_feature_prop_experimenter{
                             experimenter = 101,
                             exp_type = 1,
                             data = <<1:32>>},
                         #ofp_table_feature_prop_experimenter{
                             experimenter = 101,
                             exp_type = 2,
                             data = <<1:32,2:32>>}]},
                #ofp_table_features{
                    table_id = 1,name = <<"Flow Table 0x01">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
                                  19,20,21,22,23,24,25,26,27,28,29,30,31,32,
                                  33,34,35,36,37,38,39,40,41,42,43,44,45,46,
                                  47,48,49,50,51,52,53,54,55,56,57,58,59,60,
                                  61,62,63,64,65,66,67,68,69,70,71,72,73,74,
                                  75,76,77,78,79,80,81,82,83,84,85,86,87,88,
                                  89,90,91,92,93,94,95,96,97,98,99,100,101,
                                  102,103,104,105,106,107,108,109,110,111,
                                  112,113,114,115,116,117,118,119,120,121,
                                  122,123,124,125,126,127,128,129,130,131,
                                  132,133,134,135,136,137,138,139,140,141,
                                  142,143,144,145,146,147,148,149,150,151,
                                  152,153,154,155,156,157,158,159,160,161,
                                  162,163,164,165,166,167,168,169,170,171,
                                  172,173,174,175,176,177,178,179,180,181,
                                  182,183,184,185,186,187,188,189,190,191,
                                  192,193,194,195,196,197,198,199,200,201,
                                  202,203,204,205,206,207,208,209,210,211,
                                  212,213,214,215,216,217,218,219,220,221,
                                  222,223,224,225,226,227,228,229,230,231,
                                  232,233,234,235,236,237,238,239,240,241,
                                  242,243,244,245,246,247,248,249,250,251,
                                  252,253,254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]}]},
                #ofp_table_features{
                    table_id = 2,name = <<"Flow Table 0x02">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
                                  19,20,21,22,23,24,25,26,27,28,29,30,31,32,
                                  33,34,35,36,37,38,39,40,41,42,43,44,45,46,
                                  47,48,49,50,51,52,53,54,55,56,57,58,59,60,
                                  61,62,63,64,65,66,67,68,69,70,71,72,73,74,
                                  75,76,77,78,79,80,81,82,83,84,85,86,87,88,
                                  89,90,91,92,93,94,95,96,97,98,99,100,101,
                                  102,103,104,105,106,107,108,109,110,111,
                                  112,113,114,115,116,117,118,119,120,121,
                                  122,123,124,125,126,127,128,129,130,131,
                                  132,133,134,135,136,137,138,139,140,141,
                                  142,143,144,145,146,147,148,149,150,151,
                                  152,153,154,155,156,157,158,159,160,161,
                                  162,163,164,165,166,167,168,169,170,171,
                                  172,173,174,175,176,177,178,179,180,181,
                                  182,183,184,185,186,187,188,189,190,191,
                                  192,193,194,195,196,197,198,199,200,201,
                                  202,203,204,205,206,207,208,209,210,211,
                                  212,213,214,215,216,217,218,219,220,221,
                                  222,223,224,225,226,227,228,229,230,231,
                                  232,233,234,235,236,237,238,239,240,241,
                                  242,243,244,245,246,247,248,249,250,251,
                                  252,253,254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]}]},
                #ofp_table_features{
                    table_id = 3,name = <<"Flow Table 0x03">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,
                                  20,21,22,23,24,25,26,27,28,29,30,31,32,33,
                                  34,35,36,37,38,39,40,41,42,43,44,45,46,47,
                                  48,49,50,51,52,53,54,55,56,57,58,59,60,61,
                                  62,63,64,65,66,67,68,69,70,71,72,73,74,75,
                                  76,77,78,79,80,81,82,83,84,85,86,87,88,89,
                                  90,91,92,93,94,95,96,97,98,99,100,101,102,
                                  103,104,105,106,107,108,109,110,111,112,
                                  113,114,115,116,117,118,119,120,121,122,
                                  123,124,125,126,127,128,129,130,131,132,
                                  133,134,135,136,137,138,139,140,141,142,
                                  143,144,145,146,147,148,149,150,151,152,
                                  153,154,155,156,157,158,159,160,161,162,
                                  163,164,165,166,167,168,169,170,171,172,
                                  173,174,175,176,177,178,179,180,181,182,
                                  183,184,185,186,187,188,189,190,191,192,
                                  193,194,195,196,197,198,199,200,201,202,
                                  203,204,205,206,207,208,209,210,211,212,
                                  213,214,215,216,217,218,219,220,221,222,
                                  223,224,225,226,227,228,229,230,231,232,
                                  233,234,235,236,237,238,239,240,241,242,
                                  243,244,245,246,247,248,249,250,251,252,
                                  253,254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]}]},
                #ofp_table_features{
                    table_id = 4,name = <<"Flow Table 0x04">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                                  21,22,23,24,25,26,27,28,29,30,31,32,33,34,
                                  35,36,37,38,39,40,41,42,43,44,45,46,47,48,
                                  49,50,51,52,53,54,55,56,57,58,59,60,61,62,
                                  63,64,65,66,67,68,69,70,71,72,73,74,75,76,
                                  77,78,79,80,81,82,83,84,85,86,87,88,89,90,
                                  91,92,93,94,95,96,97,98,99,100,101,102,103,
                                  104,105,106,107,108,109,110,111,112,113,
                                  114,115,116,117,118,119,120,121,122,123,
                                  124,125,126,127,128,129,130,131,132,133,
                                  134,135,136,137,138,139,140,141,142,143,
                                  144,145,146,147,148,149,150,151,152,153,
                                  154,155,156,157,158,159,160,161,162,163,
                                  164,165,166,167,168,169,170,171,172,173,
                                  174,175,176,177,178,179,180,181,182,183,
                                  184,185,186,187,188,189,190,191,192,193,
                                  194,195,196,197,198,199,200,201,202,203,
                                  204,205,206,207,208,209,210,211,212,213,
                                  214,215,216,217,218,219,220,221,222,223,
                                  224,225,226,227,228,229,230,231,232,233,
                                  234,235,236,237,238,239,240,241,242,243,
                                  244,245,246,247,248,249,250,251,252,253,
                                  254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]}]},
                #ofp_table_features{
                    table_id = 5,name = <<"Flow Table 0x05">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                                  21,22,23,24,25,26,27,28,29,30,31,32,33,34,
                                  35,36,37,38,39,40,41,42,43,44,45,46,47,48,
                                  49,50,51,52,53,54,55,56,57,58,59,60,61,62,
                                  63,64,65,66,67,68,69,70,71,72,73,74,75,76,
                                  77,78,79,80,81,82,83,84,85,86,87,88,89,90,
                                  91,92,93,94,95,96,97,98,99,100,101,102,103,
                                  104,105,106,107,108,109,110,111,112,113,
                                  114,115,116,117,118,119,120,121,122,123,
                                  124,125,126,127,128,129,130,131,132,133,
                                  134,135,136,137,138,139,140,141,142,143,
                                  144,145,146,147,148,149,150,151,152,153,
                                  154,155,156,157,158,159,160,161,162,163,
                                  164,165,166,167,168,169,170,171,172,173,
                                  174,175,176,177,178,179,180,181,182,183,
                                  184,185,186,187,188,189,190,191,192,193,
                                  194,195,196,197,198,199,200,201,202,203,
                                  204,205,206,207,208,209,210,211,212,213,
                                  214,215,216,217,218,219,220,221,222,223,
                                  224,225,226,227,228,229,230,231,232,233,
                                  234,235,236,237,238,239,240,241,242,243,
                                  244,245,246,247,248,249,250,251,252,253,
                                  254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]}]},
                #ofp_table_features{
                    table_id = 6,name = <<"Flow Table 0x06">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,
                                  22,23,24,25,26,27,28,29,30,31,32,33,34,35,
                                  36,37,38,39,40,41,42,43,44,45,46,47,48,49,
                                  50,51,52,53,54,55,56,57,58,59,60,61,62,63,
                                  64,65,66,67,68,69,70,71,72,73,74,75,76,77,
                                  78,79,80,81,82,83,84,85,86,87,88,89,90,91,
                                  92,93,94,95,96,97,98,99,100,101,102,103,
                                  104,105,106,107,108,109,110,111,112,113,
                                  114,115,116,117,118,119,120,121,122,123,
                                  124,125,126,127,128,129,130,131,132,133,
                                  134,135,136,137,138,139,140,141,142,143,
                                  144,145,146,147,148,149,150,151,152,153,
                                  154,155,156,157,158,159,160,161,162,163,
                                  164,165,166,167,168,169,170,171,172,173,
                                  174,175,176,177,178,179,180,181,182,183,
                                  184,185,186,187,188,189,190,191,192,193,
                                  194,195,196,197,198,199,200,201,202,203,
                                  204,205,206,207,208,209,210,211,212,213,
                                  214,215,216,217,218,219,220,221,222,223,
                                  224,225,226,227,228,229,230,231,232,233,
                                  234,235,236,237,238,239,240,241,242,243,
                                  244,245,246,247,248,249,250,251,252,253,
                                  254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]}]},
                #ofp_table_features{
                    table_id = 7,name = <<"Flow Table 0x07">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,
                                  23,24,25,26,27,28,29,30,31,32,33,34,35,36,
                                  37,38,39,40,41,42,43,44,45,46,47,48,49,50,
                                  51,52,53,54,55,56,57,58,59,60,61,62,63,64,
                                  65,66,67,68,69,70,71,72,73,74,75,76,77,78,
                                  79,80,81,82,83,84,85,86,87,88,89,90,91,92,
                                  93,94,95,96,97,98,99,100,101,102,103,104,
                                  105,106,107,108,109,110,111,112,113,114,
                                  115,116,117,118,119,120,121,122,123,124,
                                  125,126,127,128,129,130,131,132,133,134,
                                  135,136,137,138,139,140,141,142,143,144,
                                  145,146,147,148,149,150,151,152,153,154,
                                  155,156,157,158,159,160,161,162,163,164,
                                  165,166,167,168,169,170,171,172,173,174,
                                  175,176,177,178,179,180,181,182,183,184,
                                  185,186,187,188,189,190,191,192,193,194,
                                  195,196,197,198,199,200,201,202,203,204,
                                  205,206,207,208,209,210,211,212,213,214,
                                  215,216,217,218,219,220,221,222,223,224,
                                  225,226,227,228,229,230,231,232,233,234,
                                  235,236,237,238,239,240,241,242,243,244,
                                  245,246,247,248,249,250,251,252,253,254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]}]},
                #ofp_table_features{
                    table_id = 8,name = <<"Flow Table 0x08">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [9,10,11,12,13,14,15,16,17,18,19,20,21,22,
                                  23,24,25,26,27,28,29,30,31,32,33,34,35,36,
                                  37,38,39,40,41,42,43,44,45,46,47,48,49,50,
                                  51,52,53,54,55,56,57,58,59,60,61,62,63,64,
                                  65,66,67,68,69,70,71,72,73,74,75,76,77,78,
                                  79,80,81,82,83,84,85,86,87,88,89,90,91,92,
                                  93,94,95,96,97,98,99,100,101,102,103,104,
                                  105,106,107,108,109,110,111,112,113,114,
                                  115,116,117,118,119,120,121,122,123,124,
                                  125,126,127,128,129,130,131,132,133,134,
                                  135,136,137,138,139,140,141,142,143,144,
                                  145,146,147,148,149,150,151,152,153,154,
                                  155,156,157,158,159,160,161,162,163,164,
                                  165,166,167,168,169,170,171,172,173,174,
                                  175,176,177,178,179,180,181,182,183,184,
                                  185,186,187,188,189,190,191,192,193,194,
                                  195,196,197,198,199,200,201,202,203,204,
                                  205,206,207,208,209,210,211,212,213,214,
                                  215,216,217,218,219,220,221,222,223,224,
                                  225,226,227,228,229,230,231,232,233,234,
                                  235,236,237,238,239,240,241,242,243,244,
                                  245,246,247,248,249,250,251,252,253,254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]}]},
                #ofp_table_features{
                    table_id = 9,name = <<"Flow Table 0x09">>,
                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                    properties =
                        [#ofp_table_feature_prop_instructions{
                             instruction_ids =
                                 [goto_table,write_metadata,write_actions,
                                  apply_actions,clear_actions,meter]},
                         #ofp_table_feature_prop_next_tables{
                             next_table_ids =
                                 [10,11,12,13,14,15,16,17,18,19,20,21,22,23,
                                  24,25,26,27,28,29,30,31,32,33,34,35,36,37,
                                  38,39,40,41,42,43,44,45,46,47,48,49,50,51,
                                  52,53,54,55,56,57,58,59,60,61,62,63,64,65,
                                  66,67,68,69,70,71,72,73,74,75,76,77,78,79,
                                  80,81,82,83,84,85,86,87,88,89,90,91,92,93,
                                  94,95,96,97,98,99,100,101,102,103,104,105,
                                  106,107,108,109,110,111,112,113,114,115,
                                  116,117,118,119,120,121,122,123,124,125,
                                  126,127,128,129,130,131,132,133,134,135,
                                  136,137,138,139,140,141,142,143,144,145,
                                  146,147,148,149,150,151,152,153,154,155,
                                  156,157,158,159,160,161,162,163,164,165,
                                  166,167,168,169,170,171,172,173,174,175,
                                  176,177,178,179,180,181,182,183,184,185,
                                  186,187,188,189,190,191,192,193,194,195,
                                  196,197,198,199,200,201,202,203,204,205,
                                  206,207,208,209,210,211,212,213,214,215,
                                  216,217,218,219,220,221,222,223,224,225,
                                  226,227,228,229,230,231,232,233,234,235,
                                  236,237,238,239,240,241,242,243,244,245,
                                  246,247,248,249,250,251,252,253,254]},
                         #ofp_table_feature_prop_write_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_apply_actions{
                             action_ids =
                                 [output,group,set_queue,set_mpls_ttl,
                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                  copy_ttl_out,copy_ttl_in,push_vlan,
                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
                                  pop_pbb,set_field]},
                         #ofp_table_feature_prop_match{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_wildcards{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_write_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_apply_setfield{
                             oxm_ids =
                                 [in_port,metadata,eth_dst,eth_src,eth_type,
                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                  mpls_bos,pbb_isid]}]}]},
        #ofp_table_features_reply{
            flags = [more],
            body =
                [#ofp_table_features{
                     table_id = 0,name = <<"\xe7\xa7\x81\xe3\x81\xae\xe3\x83\x86\xe3\x83\xbc\xe3\x83\x96\xe3\x83\xab">>,  % "my table" in japanese, utf-8
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,
                                   18,19,20,21,22,23,24,25,26,27,28,29,30,31,
                                   32,33,34,35,36,37,38,39,40,41,42,43,44,45,
                                   46,47,48,49,50,51,52,53,54,55,56,57,58,59,
                                   60,61,62,63,64,65,66,67,68,69,70,71,72,73,
                                   74,75,76,77,78,79,80,81,82,83,84,85,86,87,
                                   88,89,90,91,92,93,94,95,96,97,98,99,100,
                                   101,102,103,104,105,106,107,108,109,110,
                                   111,112,113,114,115,116,117,118,119,120,
                                   121,122,123,124,125,126,127,128,129,130,
                                   131,132,133,134,135,136,137,138,139,140,
                                   141,142,143,144,145,146,147,148,149,150,
                                   151,152,153,154,155,156,157,158,159,160,
                                   161,162,163,164,165,166,167,168,169,170,
                                   171,172,173,174,175,176,177,178,179,180,
                                   181,182,183,184,185,186,187,188,189,190,
                                   191,192,193,194,195,196,197,198,199,200,
                                   201,202,203,204,205,206,207,208,209,210,
                                   211,212,213,214,215,216,217,218,219,220,
                                   221,222,223,224,225,226,227,228,229,230,
                                   231,232,233,234,235,236,237,238,239,240,
                                   241,242,243,244,245,246,247,248,249,250,
                                   251,252,253,254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                         #ofp_table_feature_prop_experimenter{
                             experimenter = 101,
                             exp_type = 0,
                             data = <<>>},
                         #ofp_table_feature_prop_experimenter{
                             experimenter = 101,
                             exp_type = 1,
                             data = <<1:32>>},
                         #ofp_table_feature_prop_experimenter{
                             experimenter = 101,
                             exp_type = 2,
                             data = <<1:32,2:32>>}]},
                 #ofp_table_features{
                     table_id = 1,name = <<"Flow Table 0x01">>,
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
                                   19,20,21,22,23,24,25,26,27,28,29,30,31,32,
                                   33,34,35,36,37,38,39,40,41,42,43,44,45,46,
                                   47,48,49,50,51,52,53,54,55,56,57,58,59,60,
                                   61,62,63,64,65,66,67,68,69,70,71,72,73,74,
                                   75,76,77,78,79,80,81,82,83,84,85,86,87,88,
                                   89,90,91,92,93,94,95,96,97,98,99,100,101,
                                   102,103,104,105,106,107,108,109,110,111,
                                   112,113,114,115,116,117,118,119,120,121,
                                   122,123,124,125,126,127,128,129,130,131,
                                   132,133,134,135,136,137,138,139,140,141,
                                   142,143,144,145,146,147,148,149,150,151,
                                   152,153,154,155,156,157,158,159,160,161,
                                   162,163,164,165,166,167,168,169,170,171,
                                   172,173,174,175,176,177,178,179,180,181,
                                   182,183,184,185,186,187,188,189,190,191,
                                   192,193,194,195,196,197,198,199,200,201,
                                   202,203,204,205,206,207,208,209,210,211,
                                   212,213,214,215,216,217,218,219,220,221,
                                   222,223,224,225,226,227,228,229,230,231,
                                   232,233,234,235,236,237,238,239,240,241,
                                   242,243,244,245,246,247,248,249,250,251,
                                   252,253,254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]}]},
                 #ofp_table_features{
                     table_id = 2,name = <<"Flow Table 0x02">>,
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
                                   19,20,21,22,23,24,25,26,27,28,29,30,31,32,
                                   33,34,35,36,37,38,39,40,41,42,43,44,45,46,
                                   47,48,49,50,51,52,53,54,55,56,57,58,59,60,
                                   61,62,63,64,65,66,67,68,69,70,71,72,73,74,
                                   75,76,77,78,79,80,81,82,83,84,85,86,87,88,
                                   89,90,91,92,93,94,95,96,97,98,99,100,101,
                                   102,103,104,105,106,107,108,109,110,111,
                                   112,113,114,115,116,117,118,119,120,121,
                                   122,123,124,125,126,127,128,129,130,131,
                                   132,133,134,135,136,137,138,139,140,141,
                                   142,143,144,145,146,147,148,149,150,151,
                                   152,153,154,155,156,157,158,159,160,161,
                                   162,163,164,165,166,167,168,169,170,171,
                                   172,173,174,175,176,177,178,179,180,181,
                                   182,183,184,185,186,187,188,189,190,191,
                                   192,193,194,195,196,197,198,199,200,201,
                                   202,203,204,205,206,207,208,209,210,211,
                                   212,213,214,215,216,217,218,219,220,221,
                                   222,223,224,225,226,227,228,229,230,231,
                                   232,233,234,235,236,237,238,239,240,241,
                                   242,243,244,245,246,247,248,249,250,251,
                                   252,253,254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]}]},
                 #ofp_table_features{
                     table_id = 3,name = <<"Flow Table 0x03">>,
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,
                                   20,21,22,23,24,25,26,27,28,29,30,31,32,33,
                                   34,35,36,37,38,39,40,41,42,43,44,45,46,47,
                                   48,49,50,51,52,53,54,55,56,57,58,59,60,61,
                                   62,63,64,65,66,67,68,69,70,71,72,73,74,75,
                                   76,77,78,79,80,81,82,83,84,85,86,87,88,89,
                                   90,91,92,93,94,95,96,97,98,99,100,101,102,
                                   103,104,105,106,107,108,109,110,111,112,
                                   113,114,115,116,117,118,119,120,121,122,
                                   123,124,125,126,127,128,129,130,131,132,
                                   133,134,135,136,137,138,139,140,141,142,
                                   143,144,145,146,147,148,149,150,151,152,
                                   153,154,155,156,157,158,159,160,161,162,
                                   163,164,165,166,167,168,169,170,171,172,
                                   173,174,175,176,177,178,179,180,181,182,
                                   183,184,185,186,187,188,189,190,191,192,
                                   193,194,195,196,197,198,199,200,201,202,
                                   203,204,205,206,207,208,209,210,211,212,
                                   213,214,215,216,217,218,219,220,221,222,
                                   223,224,225,226,227,228,229,230,231,232,
                                   233,234,235,236,237,238,239,240,241,242,
                                   243,244,245,246,247,248,249,250,251,252,
                                   253,254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]}]},
                 #ofp_table_features{
                     table_id = 4,name = <<"Flow Table 0x04">>,
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                                   21,22,23,24,25,26,27,28,29,30,31,32,33,34,
                                   35,36,37,38,39,40,41,42,43,44,45,46,47,48,
                                   49,50,51,52,53,54,55,56,57,58,59,60,61,62,
                                   63,64,65,66,67,68,69,70,71,72,73,74,75,76,
                                   77,78,79,80,81,82,83,84,85,86,87,88,89,90,
                                   91,92,93,94,95,96,97,98,99,100,101,102,103,
                                   104,105,106,107,108,109,110,111,112,113,
                                   114,115,116,117,118,119,120,121,122,123,
                                   124,125,126,127,128,129,130,131,132,133,
                                   134,135,136,137,138,139,140,141,142,143,
                                   144,145,146,147,148,149,150,151,152,153,
                                   154,155,156,157,158,159,160,161,162,163,
                                   164,165,166,167,168,169,170,171,172,173,
                                   174,175,176,177,178,179,180,181,182,183,
                                   184,185,186,187,188,189,190,191,192,193,
                                   194,195,196,197,198,199,200,201,202,203,
                                   204,205,206,207,208,209,210,211,212,213,
                                   214,215,216,217,218,219,220,221,222,223,
                                   224,225,226,227,228,229,230,231,232,233,
                                   234,235,236,237,238,239,240,241,242,243,
                                   244,245,246,247,248,249,250,251,252,253,
                                   254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]}]},
                 #ofp_table_features{
                     table_id = 5,name = <<"Flow Table 0x05">>,
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                                   21,22,23,24,25,26,27,28,29,30,31,32,33,34,
                                   35,36,37,38,39,40,41,42,43,44,45,46,47,48,
                                   49,50,51,52,53,54,55,56,57,58,59,60,61,62,
                                   63,64,65,66,67,68,69,70,71,72,73,74,75,76,
                                   77,78,79,80,81,82,83,84,85,86,87,88,89,90,
                                   91,92,93,94,95,96,97,98,99,100,101,102,103,
                                   104,105,106,107,108,109,110,111,112,113,
                                   114,115,116,117,118,119,120,121,122,123,
                                   124,125,126,127,128,129,130,131,132,133,
                                   134,135,136,137,138,139,140,141,142,143,
                                   144,145,146,147,148,149,150,151,152,153,
                                   154,155,156,157,158,159,160,161,162,163,
                                   164,165,166,167,168,169,170,171,172,173,
                                   174,175,176,177,178,179,180,181,182,183,
                                   184,185,186,187,188,189,190,191,192,193,
                                   194,195,196,197,198,199,200,201,202,203,
                                   204,205,206,207,208,209,210,211,212,213,
                                   214,215,216,217,218,219,220,221,222,223,
                                   224,225,226,227,228,229,230,231,232,233,
                                   234,235,236,237,238,239,240,241,242,243,
                                   244,245,246,247,248,249,250,251,252,253,
                                   254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]}]},
                 #ofp_table_features{
                     table_id = 6,name = <<"Flow Table 0x06">>,
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,
                                   22,23,24,25,26,27,28,29,30,31,32,33,34,35,
                                   36,37,38,39,40,41,42,43,44,45,46,47,48,49,
                                   50,51,52,53,54,55,56,57,58,59,60,61,62,63,
                                   64,65,66,67,68,69,70,71,72,73,74,75,76,77,
                                   78,79,80,81,82,83,84,85,86,87,88,89,90,91,
                                   92,93,94,95,96,97,98,99,100,101,102,103,
                                   104,105,106,107,108,109,110,111,112,113,
                                   114,115,116,117,118,119,120,121,122,123,
                                   124,125,126,127,128,129,130,131,132,133,
                                   134,135,136,137,138,139,140,141,142,143,
                                   144,145,146,147,148,149,150,151,152,153,
                                   154,155,156,157,158,159,160,161,162,163,
                                   164,165,166,167,168,169,170,171,172,173,
                                   174,175,176,177,178,179,180,181,182,183,
                                   184,185,186,187,188,189,190,191,192,193,
                                   194,195,196,197,198,199,200,201,202,203,
                                   204,205,206,207,208,209,210,211,212,213,
                                   214,215,216,217,218,219,220,221,222,223,
                                   224,225,226,227,228,229,230,231,232,233,
                                   234,235,236,237,238,239,240,241,242,243,
                                   244,245,246,247,248,249,250,251,252,253,
                                   254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]}]},
                 #ofp_table_features{
                     table_id = 7,name = <<"Flow Table 0x07">>,
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,
                                   23,24,25,26,27,28,29,30,31,32,33,34,35,36,
                                   37,38,39,40,41,42,43,44,45,46,47,48,49,50,
                                   51,52,53,54,55,56,57,58,59,60,61,62,63,64,
                                   65,66,67,68,69,70,71,72,73,74,75,76,77,78,
                                   79,80,81,82,83,84,85,86,87,88,89,90,91,92,
                                   93,94,95,96,97,98,99,100,101,102,103,104,
                                   105,106,107,108,109,110,111,112,113,114,
                                   115,116,117,118,119,120,121,122,123,124,
                                   125,126,127,128,129,130,131,132,133,134,
                                   135,136,137,138,139,140,141,142,143,144,
                                   145,146,147,148,149,150,151,152,153,154,
                                   155,156,157,158,159,160,161,162,163,164,
                                   165,166,167,168,169,170,171,172,173,174,
                                   175,176,177,178,179,180,181,182,183,184,
                                   185,186,187,188,189,190,191,192,193,194,
                                   195,196,197,198,199,200,201,202,203,204,
                                   205,206,207,208,209,210,211,212,213,214,
                                   215,216,217,218,219,220,221,222,223,224,
                                   225,226,227,228,229,230,231,232,233,234,
                                   235,236,237,238,239,240,241,242,243,244,
                                   245,246,247,248,249,250,251,252,253,254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]}]},
                 #ofp_table_features{
                     table_id = 8,name = <<"Flow Table 0x08">>,
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [9,10,11,12,13,14,15,16,17,18,19,20,21,22,
                                   23,24,25,26,27,28,29,30,31,32,33,34,35,36,
                                   37,38,39,40,41,42,43,44,45,46,47,48,49,50,
                                   51,52,53,54,55,56,57,58,59,60,61,62,63,64,
                                   65,66,67,68,69,70,71,72,73,74,75,76,77,78,
                                   79,80,81,82,83,84,85,86,87,88,89,90,91,92,
                                   93,94,95,96,97,98,99,100,101,102,103,104,
                                   105,106,107,108,109,110,111,112,113,114,
                                   115,116,117,118,119,120,121,122,123,124,
                                   125,126,127,128,129,130,131,132,133,134,
                                   135,136,137,138,139,140,141,142,143,144,
                                   145,146,147,148,149,150,151,152,153,154,
                                   155,156,157,158,159,160,161,162,163,164,
                                   165,166,167,168,169,170,171,172,173,174,
                                   175,176,177,178,179,180,181,182,183,184,
                                   185,186,187,188,189,190,191,192,193,194,
                                   195,196,197,198,199,200,201,202,203,204,
                                   205,206,207,208,209,210,211,212,213,214,
                                   215,216,217,218,219,220,221,222,223,224,
                                   225,226,227,228,229,230,231,232,233,234,
                                   235,236,237,238,239,240,241,242,243,244,
                                   245,246,247,248,249,250,251,252,253,254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]}]},
                 #ofp_table_features{
                     table_id = 9,name = <<"Flow Table 0x09">>,
                     metadata_match = <<"\377\377\377\377\377\377\377\377">>,
                     metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
                     properties =
                         [#ofp_table_feature_prop_instructions{
                              instruction_ids =
                                  [goto_table,write_metadata,write_actions,
                                   apply_actions,clear_actions,meter]},
                          #ofp_table_feature_prop_next_tables{
                              next_table_ids =
                                  [10,11,12,13,14,15,16,17,18,19,20,21,22,23,
                                   24,25,26,27,28,29,30,31,32,33,34,35,36,37,
                                   38,39,40,41,42,43,44,45,46,47,48,49,50,51,
                                   52,53,54,55,56,57,58,59,60,61,62,63,64,65,
                                   66,67,68,69,70,71,72,73,74,75,76,77,78,79,
                                   80,81,82,83,84,85,86,87,88,89,90,91,92,93,
                                   94,95,96,97,98,99,100,101,102,103,104,105,
                                   106,107,108,109,110,111,112,113,114,115,
                                   116,117,118,119,120,121,122,123,124,125,
                                   126,127,128,129,130,131,132,133,134,135,
                                   136,137,138,139,140,141,142,143,144,145,
                                   146,147,148,149,150,151,152,153,154,155,
                                   156,157,158,159,160,161,162,163,164,165,
                                   166,167,168,169,170,171,172,173,174,175,
                                   176,177,178,179,180,181,182,183,184,185,
                                   186,187,188,189,190,191,192,193,194,195,
                                   196,197,198,199,200,201,202,203,204,205,
                                   206,207,208,209,210,211,212,213,214,215,
                                   216,217,218,219,220,221,222,223,224,225,
                                   226,227,228,229,230,231,232,233,234,235,
                                   236,237,238,239,240,241,242,243,244,245,
                                   246,247,248,249,250,251,252,253,254]},
                          #ofp_table_feature_prop_write_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_apply_actions{
                              action_ids =
                                  [output,group,set_queue,set_mpls_ttl,
                                   dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
                                   copy_ttl_out,copy_ttl_in,push_vlan,
                                   pop_vlan,push_mpls,pop_mpls,push_pbb,
                                   pop_pbb,set_field]},
                          #ofp_table_feature_prop_match{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_wildcards{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_write_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]},
                          #ofp_table_feature_prop_apply_setfield{
                              oxm_ids =
                                  [in_port,metadata,eth_dst,eth_src,eth_type,
                                   vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
                                   ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
                                   udp_dst,sctp_src,sctp_dst,icmpv4_type,
                                   icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
                                   arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
                                   icmpv6_type,icmpv6_code,ipv6_nd_target,
                                   ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
                                   mpls_bos,pbb_isid]}]}]},
        #ofp_group_stats_request{flags = [],group_id = all},
        #ofp_group_stats_reply{
            flags = [],
            body = 
                [#ofp_group_stats{
                     group_id = 1,ref_count = 2,packet_count = 123,
                     byte_count = 12345,duration_sec = 9,
                     duration_nsec = 609036000,
                     bucket_stats = 
                         [#ofp_bucket_counter{
                              packet_count = 234,byte_count = 2345}]}]},
        #ofp_packet_in{
            buffer_id = 16#f0000000,reason = no_match,table_id = 200,
            cookie = <<0,1,2,3,0,0,0,0>>,
            match = #ofp_match{fields = AllFields},
            data = <<>>},
        #ofp_flow_mod{
            cookie = <<0,0,0,0,0,0,0,0>>,
            cookie_mask = <<0,0,0,0,0,0,0,0>>,
            table_id = 1,command = add,idle_timeout = 0,
            hard_timeout = 0,priority = 123,buffer_id = 65535,
            out_port = any,out_group = any,flags = [],
            match = #ofp_match{fields = AllFields},
            instructions = []},
        #ofp_experimenter_request{
            experimenter = 16#deadbeaf,
            exp_type = 16#cafe8888,
            data = <<"hogehoge">>
        },
        #ofp_experimenter_reply{
            experimenter = 16#deadbeaf,
            exp_type = 16#cafe7777,
            data = <<"testdata99999999">>
        },
        #onf_flow_monitor_request{
            flags = [],
            body = [
                #onf_flow_monitor{
                    id = 100000000,
                    flags = [initial, add, delete, modify],
                    out_port = 22,
                    table_id = 33,
                    fields = []
                },
                #onf_flow_monitor{
                    id = 999,
                    flags = [initial, actions, own],
                    out_port = any,
                    table_id = all,
                    fields = AllFields
                }
            ]
        }
    ],
    lists:foldl(fun x:do/2, {4, 0}, List).
