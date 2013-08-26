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
    List = [
        #ofp_desc_reply{flags = [], mfr_desc = <<"mfr">>,
                              hw_desc = <<"hw">>, sw_desc = <<"sw">>,
                              serial_num = <<"serial">>,
                              dp_desc = <<"dp">>},
        #ofp_packet_out{
            buffer_id = no_buffer,in_port = controller,
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
                                                value = <<1,2>> }},
                          #ofp_action_output{port = 6,max_len = 65535}]}]},
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
                                  [#ofp_action_output{
                                       port = controller,
                                       max_len = 65535}]}]}]},
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
                         [#ofp_action_output{port = 2,max_len = 65535}]}]},
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
                                       port = 2, max_len = 65535}]}]}]},
        #ofp_queue_get_config_request{port = any},
        #ofp_queue_get_config_reply{port = any,queues = [
            #ofp_packet_queue{queue_id = 99, port_no = 77,
                properties = [
                    #ofp_queue_prop_min_rate{rate = 10},
                    #ofp_queue_prop_max_rate{rate = 900}
                ]
            },
            #ofp_packet_queue{queue_id = 88, port_no = 77,
                properties = [
                    #ofp_queue_prop_min_rate{rate = 100},
                    #ofp_queue_prop_max_rate{rate = 200}
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
                     name = <<"Port7">>,
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

% ryu doesn't have the implementation
%       #ofp_error_msg_experimenter{
%           exp_type = 60000,
%           experimenter = 999999,
%           data = <<"jikken data">>
%       }
        skip,

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
                         [#ofp_action_output{port = 6,max_len = 65535}]}]},

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


% skip this for now because ryu's OFPTableFeaturesStatsRequest doesn't
% have serializer or parser.
        skip,
%       #ofp_table_features_request{
%           flags = [more],
%           body =
%               [#ofp_table_features{
%                    table_id = 0,name = <<"Flow Table 0x00">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,
%                                  18,19,20,21,22,23,24,25,26,27,28,29,30,31,
%                                  32,33,34,35,36,37,38,39,40,41,42,43,44,45,
%                                  46,47,48,49,50,51,52,53,54,55,56,57,58,59,
%                                  60,61,62,63,64,65,66,67,68,69,70,71,72,73,
%                                  74,75,76,77,78,79,80,81,82,83,84,85,86,87,
%                                  88,89,90,91,92,93,94,95,96,97,98,99,100,
%                                  101,102,103,104,105,106,107,108,109,110,
%                                  111,112,113,114,115,116,117,118,119,120,
%                                  121,122,123,124,125,126,127,128,129,130,
%                                  131,132,133,134,135,136,137,138,139,140,
%                                  141,142,143,144,145,146,147,148,149,150,
%                                  151,152,153,154,155,156,157,158,159,160,
%                                  161,162,163,164,165,166,167,168,169,170,
%                                  171,172,173,174,175,176,177,178,179,180,
%                                  181,182,183,184,185,186,187,188,189,190,
%                                  191,192,193,194,195,196,197,198,199,200,
%                                  201,202,203,204,205,206,207,208,209,210,
%                                  211,212,213,214,215,216,217,218,219,220,
%                                  221,222,223,224,225,226,227,228,229,230,
%                                  231,232,233,234,235,236,237,238,239,240,
%                                  241,242,243,244,245,246,247,248,249,250,
%                                  251,252,253,254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]},
%                #ofp_table_features{
%                    table_id = 1,name = <<"Flow Table 0x01">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
%                                  19,20,21,22,23,24,25,26,27,28,29,30,31,32,
%                                  33,34,35,36,37,38,39,40,41,42,43,44,45,46,
%                                  47,48,49,50,51,52,53,54,55,56,57,58,59,60,
%                                  61,62,63,64,65,66,67,68,69,70,71,72,73,74,
%                                  75,76,77,78,79,80,81,82,83,84,85,86,87,88,
%                                  89,90,91,92,93,94,95,96,97,98,99,100,101,
%                                  102,103,104,105,106,107,108,109,110,111,
%                                  112,113,114,115,116,117,118,119,120,121,
%                                  122,123,124,125,126,127,128,129,130,131,
%                                  132,133,134,135,136,137,138,139,140,141,
%                                  142,143,144,145,146,147,148,149,150,151,
%                                  152,153,154,155,156,157,158,159,160,161,
%                                  162,163,164,165,166,167,168,169,170,171,
%                                  172,173,174,175,176,177,178,179,180,181,
%                                  182,183,184,185,186,187,188,189,190,191,
%                                  192,193,194,195,196,197,198,199,200,201,
%                                  202,203,204,205,206,207,208,209,210,211,
%                                  212,213,214,215,216,217,218,219,220,221,
%                                  222,223,224,225,226,227,228,229,230,231,
%                                  232,233,234,235,236,237,238,239,240,241,
%                                  242,243,244,245,246,247,248,249,250,251,
%                                  252,253,254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]},
%                #ofp_table_features{
%                    table_id = 2,name = <<"Flow Table 0x02">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
%                                  19,20,21,22,23,24,25,26,27,28,29,30,31,32,
%                                  33,34,35,36,37,38,39,40,41,42,43,44,45,46,
%                                  47,48,49,50,51,52,53,54,55,56,57,58,59,60,
%                                  61,62,63,64,65,66,67,68,69,70,71,72,73,74,
%                                  75,76,77,78,79,80,81,82,83,84,85,86,87,88,
%                                  89,90,91,92,93,94,95,96,97,98,99,100,101,
%                                  102,103,104,105,106,107,108,109,110,111,
%                                  112,113,114,115,116,117,118,119,120,121,
%                                  122,123,124,125,126,127,128,129,130,131,
%                                  132,133,134,135,136,137,138,139,140,141,
%                                  142,143,144,145,146,147,148,149,150,151,
%                                  152,153,154,155,156,157,158,159,160,161,
%                                  162,163,164,165,166,167,168,169,170,171,
%                                  172,173,174,175,176,177,178,179,180,181,
%                                  182,183,184,185,186,187,188,189,190,191,
%                                  192,193,194,195,196,197,198,199,200,201,
%                                  202,203,204,205,206,207,208,209,210,211,
%                                  212,213,214,215,216,217,218,219,220,221,
%                                  222,223,224,225,226,227,228,229,230,231,
%                                  232,233,234,235,236,237,238,239,240,241,
%                                  242,243,244,245,246,247,248,249,250,251,
%                                  252,253,254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]},
%                #ofp_table_features{
%                    table_id = 3,name = <<"Flow Table 0x03">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,
%                                  20,21,22,23,24,25,26,27,28,29,30,31,32,33,
%                                  34,35,36,37,38,39,40,41,42,43,44,45,46,47,
%                                  48,49,50,51,52,53,54,55,56,57,58,59,60,61,
%                                  62,63,64,65,66,67,68,69,70,71,72,73,74,75,
%                                  76,77,78,79,80,81,82,83,84,85,86,87,88,89,
%                                  90,91,92,93,94,95,96,97,98,99,100,101,102,
%                                  103,104,105,106,107,108,109,110,111,112,
%                                  113,114,115,116,117,118,119,120,121,122,
%                                  123,124,125,126,127,128,129,130,131,132,
%                                  133,134,135,136,137,138,139,140,141,142,
%                                  143,144,145,146,147,148,149,150,151,152,
%                                  153,154,155,156,157,158,159,160,161,162,
%                                  163,164,165,166,167,168,169,170,171,172,
%                                  173,174,175,176,177,178,179,180,181,182,
%                                  183,184,185,186,187,188,189,190,191,192,
%                                  193,194,195,196,197,198,199,200,201,202,
%                                  203,204,205,206,207,208,209,210,211,212,
%                                  213,214,215,216,217,218,219,220,221,222,
%                                  223,224,225,226,227,228,229,230,231,232,
%                                  233,234,235,236,237,238,239,240,241,242,
%                                  243,244,245,246,247,248,249,250,251,252,
%                                  253,254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]},
%                #ofp_table_features{
%                    table_id = 4,name = <<"Flow Table 0x04">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
%                                  21,22,23,24,25,26,27,28,29,30,31,32,33,34,
%                                  35,36,37,38,39,40,41,42,43,44,45,46,47,48,
%                                  49,50,51,52,53,54,55,56,57,58,59,60,61,62,
%                                  63,64,65,66,67,68,69,70,71,72,73,74,75,76,
%                                  77,78,79,80,81,82,83,84,85,86,87,88,89,90,
%                                  91,92,93,94,95,96,97,98,99,100,101,102,103,
%                                  104,105,106,107,108,109,110,111,112,113,
%                                  114,115,116,117,118,119,120,121,122,123,
%                                  124,125,126,127,128,129,130,131,132,133,
%                                  134,135,136,137,138,139,140,141,142,143,
%                                  144,145,146,147,148,149,150,151,152,153,
%                                  154,155,156,157,158,159,160,161,162,163,
%                                  164,165,166,167,168,169,170,171,172,173,
%                                  174,175,176,177,178,179,180,181,182,183,
%                                  184,185,186,187,188,189,190,191,192,193,
%                                  194,195,196,197,198,199,200,201,202,203,
%                                  204,205,206,207,208,209,210,211,212,213,
%                                  214,215,216,217,218,219,220,221,222,223,
%                                  224,225,226,227,228,229,230,231,232,233,
%                                  234,235,236,237,238,239,240,241,242,243,
%                                  244,245,246,247,248,249,250,251,252,253,
%                                  254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]},
%                #ofp_table_features{
%                    table_id = 5,name = <<"Flow Table 0x05">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
%                                  21,22,23,24,25,26,27,28,29,30,31,32,33,34,
%                                  35,36,37,38,39,40,41,42,43,44,45,46,47,48,
%                                  49,50,51,52,53,54,55,56,57,58,59,60,61,62,
%                                  63,64,65,66,67,68,69,70,71,72,73,74,75,76,
%                                  77,78,79,80,81,82,83,84,85,86,87,88,89,90,
%                                  91,92,93,94,95,96,97,98,99,100,101,102,103,
%                                  104,105,106,107,108,109,110,111,112,113,
%                                  114,115,116,117,118,119,120,121,122,123,
%                                  124,125,126,127,128,129,130,131,132,133,
%                                  134,135,136,137,138,139,140,141,142,143,
%                                  144,145,146,147,148,149,150,151,152,153,
%                                  154,155,156,157,158,159,160,161,162,163,
%                                  164,165,166,167,168,169,170,171,172,173,
%                                  174,175,176,177,178,179,180,181,182,183,
%                                  184,185,186,187,188,189,190,191,192,193,
%                                  194,195,196,197,198,199,200,201,202,203,
%                                  204,205,206,207,208,209,210,211,212,213,
%                                  214,215,216,217,218,219,220,221,222,223,
%                                  224,225,226,227,228,229,230,231,232,233,
%                                  234,235,236,237,238,239,240,241,242,243,
%                                  244,245,246,247,248,249,250,251,252,253,
%                                  254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]},
%                #ofp_table_features{
%                    table_id = 6,name = <<"Flow Table 0x06">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,
%                                  22,23,24,25,26,27,28,29,30,31,32,33,34,35,
%                                  36,37,38,39,40,41,42,43,44,45,46,47,48,49,
%                                  50,51,52,53,54,55,56,57,58,59,60,61,62,63,
%                                  64,65,66,67,68,69,70,71,72,73,74,75,76,77,
%                                  78,79,80,81,82,83,84,85,86,87,88,89,90,91,
%                                  92,93,94,95,96,97,98,99,100,101,102,103,
%                                  104,105,106,107,108,109,110,111,112,113,
%                                  114,115,116,117,118,119,120,121,122,123,
%                                  124,125,126,127,128,129,130,131,132,133,
%                                  134,135,136,137,138,139,140,141,142,143,
%                                  144,145,146,147,148,149,150,151,152,153,
%                                  154,155,156,157,158,159,160,161,162,163,
%                                  164,165,166,167,168,169,170,171,172,173,
%                                  174,175,176,177,178,179,180,181,182,183,
%                                  184,185,186,187,188,189,190,191,192,193,
%                                  194,195,196,197,198,199,200,201,202,203,
%                                  204,205,206,207,208,209,210,211,212,213,
%                                  214,215,216,217,218,219,220,221,222,223,
%                                  224,225,226,227,228,229,230,231,232,233,
%                                  234,235,236,237,238,239,240,241,242,243,
%                                  244,245,246,247,248,249,250,251,252,253,
%                                  254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]},
%                #ofp_table_features{
%                    table_id = 7,name = <<"Flow Table 0x07">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,
%                                  23,24,25,26,27,28,29,30,31,32,33,34,35,36,
%                                  37,38,39,40,41,42,43,44,45,46,47,48,49,50,
%                                  51,52,53,54,55,56,57,58,59,60,61,62,63,64,
%                                  65,66,67,68,69,70,71,72,73,74,75,76,77,78,
%                                  79,80,81,82,83,84,85,86,87,88,89,90,91,92,
%                                  93,94,95,96,97,98,99,100,101,102,103,104,
%                                  105,106,107,108,109,110,111,112,113,114,
%                                  115,116,117,118,119,120,121,122,123,124,
%                                  125,126,127,128,129,130,131,132,133,134,
%                                  135,136,137,138,139,140,141,142,143,144,
%                                  145,146,147,148,149,150,151,152,153,154,
%                                  155,156,157,158,159,160,161,162,163,164,
%                                  165,166,167,168,169,170,171,172,173,174,
%                                  175,176,177,178,179,180,181,182,183,184,
%                                  185,186,187,188,189,190,191,192,193,194,
%                                  195,196,197,198,199,200,201,202,203,204,
%                                  205,206,207,208,209,210,211,212,213,214,
%                                  215,216,217,218,219,220,221,222,223,224,
%                                  225,226,227,228,229,230,231,232,233,234,
%                                  235,236,237,238,239,240,241,242,243,244,
%                                  245,246,247,248,249,250,251,252,253,254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]},
%                #ofp_table_features{
%                    table_id = 8,name = <<"Flow Table 0x08">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [9,10,11,12,13,14,15,16,17,18,19,20,21,22,
%                                  23,24,25,26,27,28,29,30,31,32,33,34,35,36,
%                                  37,38,39,40,41,42,43,44,45,46,47,48,49,50,
%                                  51,52,53,54,55,56,57,58,59,60,61,62,63,64,
%                                  65,66,67,68,69,70,71,72,73,74,75,76,77,78,
%                                  79,80,81,82,83,84,85,86,87,88,89,90,91,92,
%                                  93,94,95,96,97,98,99,100,101,102,103,104,
%                                  105,106,107,108,109,110,111,112,113,114,
%                                  115,116,117,118,119,120,121,122,123,124,
%                                  125,126,127,128,129,130,131,132,133,134,
%                                  135,136,137,138,139,140,141,142,143,144,
%                                  145,146,147,148,149,150,151,152,153,154,
%                                  155,156,157,158,159,160,161,162,163,164,
%                                  165,166,167,168,169,170,171,172,173,174,
%                                  175,176,177,178,179,180,181,182,183,184,
%                                  185,186,187,188,189,190,191,192,193,194,
%                                  195,196,197,198,199,200,201,202,203,204,
%                                  205,206,207,208,209,210,211,212,213,214,
%                                  215,216,217,218,219,220,221,222,223,224,
%                                  225,226,227,228,229,230,231,232,233,234,
%                                  235,236,237,238,239,240,241,242,243,244,
%                                  245,246,247,248,249,250,251,252,253,254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]},
%                #ofp_table_features{
%                    table_id = 9,name = <<"Flow Table 0x09">>,
%                    metadata_match = <<"\377\377\377\377\377\377\377\377">>,
%                    metadata_write = <<"\377\377\377\377\377\377\377\377">>,max_entries = 16777216,
%                    properties =
%                        [#ofp_table_feature_prop_instructions{
%                             instruction_ids =
%                                 [goto_table,write_metadata,write_actions,
%                                  apply_actions,clear_actions,meter]},
%                         #ofp_table_feature_prop_next_tables{
%                             next_table_ids =
%                                 [10,11,12,13,14,15,16,17,18,19,20,21,22,23,
%                                  24,25,26,27,28,29,30,31,32,33,34,35,36,37,
%                                  38,39,40,41,42,43,44,45,46,47,48,49,50,51,
%                                  52,53,54,55,56,57,58,59,60,61,62,63,64,65,
%                                  66,67,68,69,70,71,72,73,74,75,76,77,78,79,
%                                  80,81,82,83,84,85,86,87,88,89,90,91,92,93,
%                                  94,95,96,97,98,99,100,101,102,103,104,105,
%                                  106,107,108,109,110,111,112,113,114,115,
%                                  116,117,118,119,120,121,122,123,124,125,
%                                  126,127,128,129,130,131,132,133,134,135,
%                                  136,137,138,139,140,141,142,143,144,145,
%                                  146,147,148,149,150,151,152,153,154,155,
%                                  156,157,158,159,160,161,162,163,164,165,
%                                  166,167,168,169,170,171,172,173,174,175,
%                                  176,177,178,179,180,181,182,183,184,185,
%                                  186,187,188,189,190,191,192,193,194,195,
%                                  196,197,198,199,200,201,202,203,204,205,
%                                  206,207,208,209,210,211,212,213,214,215,
%                                  216,217,218,219,220,221,222,223,224,225,
%                                  226,227,228,229,230,231,232,233,234,235,
%                                  236,237,238,239,240,241,242,243,244,245,
%                                  246,247,248,249,250,251,252,253,254]},
%                         #ofp_table_feature_prop_write_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_apply_actions{
%                             action_ids =
%                                 [output,group,set_queue,set_mpls_ttl,
%                                  dec_mpls_ttl,set_nw_ttl,dec_nw_ttl,
%                                  copy_ttl_out,copy_ttl_in,push_vlan,
%                                  pop_vlan,push_mpls,pop_mpls,push_pbb,
%                                  pop_pbb,set_field]},
%                         #ofp_table_feature_prop_match{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_wildcards{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_write_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]},
%                         #ofp_table_feature_prop_apply_setfield{
%                             oxm_ids =
%                                 [in_port,metadata,eth_dst,eth_src,eth_type,
%                                  vlan_vid,vlan_pcp,ip_dscp,ip_ecn,ip_proto,
%                                  ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,
%                                  udp_dst,sctp_src,sctp_dst,icmpv4_type,
%                                  icmpv4_code,arp_op,arp_spa,arp_tpa,arp_sha,
%                                  arp_tha,ipv6_src,ipv6_dst,ipv6_flabel,
%                                  icmpv6_type,icmpv6_code,ipv6_nd_target,
%                                  ipv6_nd_sll,ipv6_nd_tll,mpls_label,mpls_tc,
%                                  mpls_bos,pbb_isid]}]}]},

% ryu's OFPTableFeaturesStats is incomplete. (doesn't parse properties at all)
        #ofp_table_features_reply{
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
                                   mpls_bos,pbb_isid]}]},
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
                                   mpls_bos,pbb_isid]}]}]}

    ],
    lists:foldl(fun x:do/2, {4, 0}, List).
