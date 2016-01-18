/*
 * Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
 * Copyright (C) 2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <lib/learn.h>
#include <lib/list.h>
#include <lib/ofpbuf.h>
#include <lib/ofp-actions.h>
#include <lib/ofp-errors.h>
#include <lib/ofp-msgs.h>
#include <lib/ofp-util.h>
#include <lib/packets.h>

#include <assert.h>
#include <err.h>
#include <stdio.h>

/*
 * OpenFlow Common
 */

void
clear_xid(struct ofpbuf *buf)
{
    /*
     * some of libofproto message encoding routines automatically
     * allocate XID for the message.  e.g. ofputil_encode_flow_mod
     * zero-out the XID so that test_parser can perform a simple
     * bit-wise comparison.
     */

    struct ofp_header *oh = ofpbuf_at_assert(buf, 0, sizeof(*oh));

    oh->xid = htonl(0);
}

void
fill_match(struct match *match)
{
    const struct eth_addr dl_dst =
        { { { 0xaa, 0xbb, 0xcc, 0x99, 0x88, 0x77 } } };
    match_init_catchall(match);
    match_set_in_port(match, 0xabcd);
    match_set_dl_vlan(match, htons(999));
    match_set_dl_dst(match, dl_dst);
    match_set_dl_type(match, htons(ETH_TYPE_IP));
    match_set_nw_dst(match, inet_addr("192.168.2.1"));
    match_set_tun_src(match, inet_addr("192.168.2.3"));
    match_set_tun_dst(match, inet_addr("192.168.2.4"));
    match_set_tun_id(match, htonll(50000));
}

/*
 * Controller-to-Switch Messages
 */

/*
 * Handshake
 */

struct ofpbuf *
features_reply(enum ofputil_protocol proto)
{
    struct ofputil_switch_features sf;

    memset(&sf, 0, sizeof(sf));
    sf.datapath_id = 1;
    sf.n_buffers = 255;
    sf.n_tables = 255;
    sf.auxiliary_id = 0;
    sf.capabilities = OFPUTIL_C_FLOW_STATS | OFPUTIL_C_TABLE_STATS |
                      OFPUTIL_C_PORT_STATS | OFPUTIL_C_GROUP_STATS |
                      OFPUTIL_C_QUEUE_STATS;
    // sf.ofpacts is for only OFP10

    ovs_be32 xid = 0;

    return ofputil_encode_switch_features(&sf, proto, xid);
}

/*
 * Switch Configuration
 */

struct ofpbuf *
set_config(enum ofputil_protocol proto)
{
    struct ofputil_switch_config sc;

    memset(&sc, 0, sizeof(sc));
    sc.frag = OFPUTIL_FRAG_NORMAL;
    // sc.invalid_ttl_to_controller is for only OFP11 and OFP12
    sc.miss_send_len = 128;  // The default of OpenFlow Spec

    return ofputil_encode_set_config(
        &sc, ofputil_protocol_to_ofp_version(proto));
}

struct ofpbuf *
get_config_reply(enum ofputil_protocol proto)
{
    struct ofputil_switch_config sc;
    struct ofp_header oh;

    memset(&oh, 0, sizeof(oh));
    oh.xid = 0;
    oh.version = ofputil_protocol_to_ofp_version(proto);
    memset(&sc, 0, sizeof(sc));
    sc.frag = OFPUTIL_FRAG_NORMAL;
    // sc.invalid_ttl_to_controller is for only OFP11 and OFP12
    sc.miss_send_len = 128;  // The default of OpenFlow Spec

    return ofputil_encode_get_config_reply(&oh, &sc);
}

/*
 * Modify State Messages
 */

struct ofpbuf *
table_mod(enum ofputil_protocol proto)
{
    struct ofputil_table_mod tm;

    memset(&tm, 0, sizeof(tm));
    tm.table_id = 0xff;  // OFPTT_ALL
    // OpenFlow 1.1 and 1.2 only.
    // For other versions, ignored on encoding.
    tm.miss = OFPUTIL_TABLE_MISS_DEFAULT;  // Protocol default behavior.
    // OpenFlow 1.4+ only.
    // For other versions, ignored on encoding.
    tm.eviction = OFPUTIL_TABLE_EVICTION_ON;    // Enable eviction.
    tm.eviction_flags = OFPTMPEF14_IMPORTANCE;  // Using flow entry importance.

    return ofputil_encode_table_mod(&tm, proto);
}

struct ofpbuf *
flow_mod(enum ofputil_protocol proto)
{
    struct ofputil_flow_mod fm;
    struct ofpbuf acts;
    struct ofpact_ipv4 *a_set_field;
    struct ofpact_goto_table *a_goto;
    char *error;

    /*
     * Taken from neutron OVS-agent,
     * modified for OF>=1.3. (NXM -> OXM)
     * NOTE(yamamoto): This needs to be writable.  learn_parse() modifies it.
     */
    char learn_args[] =
        "table=99,"
        "priority=1,"
        "hard_timeout=300,"
        "OXM_OF_VLAN_VID[0..11],"
        "OXM_OF_ETH_DST[]=OXM_OF_ETH_SRC[],"
        "load:0->OXM_OF_VLAN_VID[],"
        "load:OXM_OF_TUNNEL_ID[]->OXM_OF_TUNNEL_ID[],"
        "output:OXM_OF_IN_PORT[]";

    memset(&fm, 0, sizeof(fm));
    fm.command = OFPFC_ADD;
    fm.table_id = 2;
    fm.new_cookie = htonll(0x123456789abcdef0);
    fm.cookie_mask = OVS_BE64_MAX;
    fm.importance = 0x9878;

    fill_match(&fm.match);

    ofpbuf_init(&acts, 64);
    ofpact_put_STRIP_VLAN(&acts);
    a_set_field = ofpact_put_SET_IPV4_DST(&acts);
    a_set_field->ipv4 = inet_addr("192.168.2.9");
    error = learn_parse(learn_args, &acts);
    assert(error == NULL);
    a_goto = ofpact_put_GOTO_TABLE(&acts);
    a_goto->table_id = 100;

    fm.ofpacts = acts.data;
    fm.ofpacts_len = acts.size;
    return ofputil_encode_flow_mod(&fm, proto);
}

struct ofpbuf *
flow_mod_match_conj(enum ofputil_protocol proto)
{
    struct ofputil_flow_mod fm;
    struct ofpbuf acts;
    struct ofpact_ipv4 *a_set_field;
    struct ofpact_goto_table *a_goto;

    memset(&fm, 0, sizeof(fm));
    fm.command = OFPFC_ADD;
    fm.table_id = 3;
    fm.new_cookie = htonll(0x123456789abcdef0);
    fm.cookie_mask = OVS_BE64_MAX;
    fm.importance = 0x9878;

    match_init_catchall(&fm.match);
    match_set_conj_id(&fm.match, 0xabcdef);

    ofpbuf_init(&acts, 64);
    ofpact_put_STRIP_VLAN(&acts);
    a_set_field = ofpact_put_SET_IPV4_DST(&acts);
    a_set_field->ipv4 = inet_addr("192.168.2.9");
    a_goto = ofpact_put_GOTO_TABLE(&acts);
    a_goto->table_id = 100;

    fm.ofpacts = acts.data;
    fm.ofpacts_len = acts.size;
    return ofputil_encode_flow_mod(&fm, proto);
}

struct ofpbuf *
flow_mod_conjunction(enum ofputil_protocol proto)
{
    struct ofputil_flow_mod fm;
    struct ofpbuf acts;
    struct ofpact_conjunction *a_conj;

    memset(&fm, 0, sizeof(fm));
    fm.command = OFPFC_ADD;
    fm.table_id = 4;
    fm.new_cookie = htonll(0x123456789abcdef0);
    fm.cookie_mask = OVS_BE64_MAX;
    fm.importance = 0x9878;

    fill_match(&fm.match);

    ofpbuf_init(&acts, 64);
    a_conj = ofpact_put_CONJUNCTION(&acts);
    a_conj->id = 0xabcdef;
    a_conj->clause = 1;
    a_conj->n_clauses = 2;

    fm.ofpacts = acts.data;
    fm.ofpacts_len = acts.size;
    return ofputil_encode_flow_mod(&fm, proto);
}

struct ofpbuf *
group_mod(enum ofputil_protocol proto)
{
    struct ofputil_group_mod gm;
    struct ofpbuf acts;
    struct ofpact_ipv4 *a_set_field;
    struct ofpact_goto_table *a_goto;
    struct ofputil_bucket bckt;

    memset(&gm, 0, sizeof(gm));
    gm.command = OFPGC15_INSERT_BUCKET;
    gm.type = OFPGT11_SELECT;
    gm.group_id = 0xaaaaaaaa;
    gm.command_bucket_id = 0xbbbbbbbb;

    ofpbuf_init(&acts, 0x18);
    ofpact_put_STRIP_VLAN(&acts);
    a_set_field = ofpact_put_SET_IPV4_DST(&acts);
    a_set_field->ipv4 = inet_addr("192.168.2.9");

    bckt.weight = 0xcccc;
    bckt.watch_port = 0xdddd;
    bckt.watch_group = 0xeeeeeeee;
    bckt.bucket_id = 0x12345678;
    bckt.ofpacts = acts.data;
    bckt.ofpacts_len = acts.size;

    list_init(&(gm.buckets));
    list_push_back(&(gm.buckets), &(bckt.list_node));

    return ofputil_encode_group_mod(
        ofputil_protocol_to_ofp_version(proto), &gm);
}

struct ofpbuf *
port_mod(enum ofputil_protocol proto)
{
    struct ofputil_port_mod pm;
    const struct eth_addr hw_addr =
        { { { 0xaa, 0xbb, 0xcc, 0x99, 0x88, 0x77 } } };

    memset(&pm, 0, sizeof(pm));
    pm.port_no = 1;
    pm.hw_addr = hw_addr;
    pm.config = OFPPC_PORT_DOWN;
    pm.mask = OFPPC_PORT_DOWN;
    pm.advertise = 10248;  // OFPPF_100MB_FD, OFPPF_COPPER, OFPPF_AUTONEG

    return ofputil_encode_port_mod(&pm, proto);
}

struct ofpbuf *
meter_mod(enum ofputil_protocol proto)
{
    const int N_BANDS = 2;
    struct ofputil_meter_mod mm;
    struct ofputil_meter_band bands[N_BANDS];

    memset(bands, 0, sizeof(*bands)*2);
    bands[0].type = 1;         // OFPMBT_DROP
    bands[0].rate = 1000;
    bands[0].burst_size = 10;
    bands[1].type = 2;         // OFPMBT_DSCP_REMARK
    bands[1].prec_level = 1;
    bands[1].rate = 1000;
    bands[1].burst_size = 10;

    memset(&mm, 0, sizeof(mm));
    mm.command = 0;              // OFPMC_ADD
    mm.meter.meter_id = 100;
    mm.meter.flags = 14;         // OFPMF_PKTPS, OFPMF_BURST, OFPMF_STATS
    mm.meter.n_bands = N_BANDS;
    mm.meter.bands = bands;

    return ofputil_encode_meter_mod(
        ofputil_protocol_to_ofp_version(proto), &mm);
}

/*
 * Multipart Messages
 */

struct ofpbuf *
aggregate_stats_request(enum ofputil_protocol proto)
{
    struct ofputil_flow_stats_request fsr;

    memset(&fsr, 0, sizeof(fsr));
    fsr.aggregate = true;
    match_init_catchall(&fsr.match);
    fsr.out_port = OFPP_ANY;
    fsr.out_group = OFPG_ANY;
    fsr.table_id = OFPTT_ALL;
    fsr.cookie = fsr.cookie_mask = htonll(0);

    return ofputil_encode_flow_stats_request(&fsr, proto);
}

struct ofpbuf *
port_stats_request(enum ofputil_protocol proto)
{
    uint32_t port_no = 0xffffffff;
    return ofputil_encode_dump_ports_request(
        ofputil_protocol_to_ofp_version(proto), port_no);
}

struct ofpbuf *
port_desc_request(enum ofputil_protocol proto)
{
    uint32_t port_no = 0xbcda;

    return ofputil_encode_port_desc_stats_request(
        ofputil_protocol_to_ofp_version(proto), port_no);
}

struct ofpbuf *
queue_stats_request(enum ofputil_protocol proto)
{
    struct ofputil_queue_stats_request oqsr;
    memset(&oqsr, 0, sizeof(oqsr));
    oqsr.port_no = 0xabcd;
    oqsr.queue_id = 0xffffffff;
    return ofputil_encode_queue_stats_request(
        ofputil_protocol_to_ofp_version(proto), &oqsr);
}

struct ofpbuf *
group_stats_request(enum ofputil_protocol proto)
{
    uint32_t group_id = 0xfffffffc;
    return ofputil_encode_group_stats_request(
        ofputil_protocol_to_ofp_version(proto), group_id);
}

struct ofpbuf *
group_desc_request(enum ofputil_protocol proto)
{
    uint32_t group_id = 0xcdab;

    return ofputil_encode_group_desc_request(
        ofputil_protocol_to_ofp_version(proto), group_id);
}

struct ofpbuf *
group_features_request(enum ofputil_protocol proto)
{
    return ofputil_encode_group_features_request(
        ofputil_protocol_to_ofp_version(proto));
}

struct ofpbuf *
meter_stats_request(enum ofputil_protocol proto)
{
    uint32_t meter_id = 0xffffffff;
    return ofputil_encode_meter_request(
        ofputil_protocol_to_ofp_version(proto),
        OFPUTIL_METER_STATS, meter_id);
}

struct ofpbuf *
table_desc_request(enum ofputil_protocol proto)
{
    return ofputil_encode_table_desc_request(
        ofputil_protocol_to_ofp_version(proto));
}

/*
 * Barrier Message
 */

struct ofpbuf *
barrier_request(enum ofputil_protocol proto)
{
    return ofputil_encode_barrier_request(
        ofputil_protocol_to_ofp_version(proto));
}

/*
 * Bundle messages
 */

struct ofpbuf *
bundle_ctrl(enum ofputil_protocol proto)
{
    struct ofputil_bundle_ctrl_msg msg;
    struct ofp_header oh;

    memset(&oh, 0, sizeof(oh));
    oh.xid = 0;
    oh.version = ofputil_protocol_to_ofp_version(proto);
    memset(&msg, 0, sizeof(msg));
    msg.bundle_id = 99999999;
    msg.type = OFPBCT_OPEN_REPLY;
    msg.flags = OFPBF_ATOMIC;
    return ofputil_encode_bundle_ctrl_reply(&oh, &msg);
}

struct ofpbuf *
bundle_add(enum ofputil_protocol proto)
{
    struct ofputil_bundle_add_msg msg;
    struct ofpbuf *fm;
    struct ofpbuf *add;

    memset(&msg, 0, sizeof(msg));
    msg.bundle_id = 99999999;
    msg.flags = OFPBF_ATOMIC;
    fm = flow_mod(proto);
    clear_xid(fm);
    msg.msg = fm->data;
    add = ofputil_encode_bundle_add(
        ofputil_protocol_to_ofp_version(proto), &msg);
    ofpbuf_delete(fm);
    return add;
}

/*
 * Asynchronous Messages
 */

struct ofpbuf *
packet_in(enum ofputil_protocol proto)
{
    struct ofputil_packet_in pin;
    struct match match;
    struct ofpbuf *buf;

    memset(&pin, 0, sizeof(pin));
    pin.packet = "hoge";
    pin.packet_len = 4;
    pin.total_len = 1000;
    pin.table_id = 100;
    pin.buffer_id = 200;

    fill_match(&match);
    flow_get_metadata(&match.flow, &pin.flow_metadata);

    return ofputil_encode_packet_in(&pin, proto, NXPIF_OPENFLOW10);
}

struct ofpbuf *
flow_removed(enum ofputil_protocol proto)
{
    struct ofputil_flow_removed fr;

    memset(&fr, 0, sizeof(fr));
    fill_match(&fr.match);
    fr.cookie = htonll(0x123456789abcdef0);
    fr.priority = 100;
    fr.reason = 0;           // OFPRR_IDLE_TIMEOUT
    fr.table_id = 1;
    fr.duration_sec = 600;
    fr.duration_nsec = 500;
    fr.idle_timeout = 400;
    fr.hard_timeout = 300;
    fr.packet_count = 200;
    fr.byte_count = 100;

    return ofputil_encode_flow_removed(&fr, proto);
}

struct ofpbuf *
port_status(enum ofputil_protocol proto)
{
    struct ofputil_port_status ps;

    memset(&ps, 0, sizeof(ps));
    ps.reason = 2;               // OFPPR_MODIFY
    ps.desc.port_no = 1;
    memset(&ps.desc.hw_addr, 0xff, sizeof(ps.desc.hw_addr));
    sprintf(ps.desc.name, "eth0");
    ps.desc.config = 0;
    ps.desc.state = 4;
    ps.desc.curr = 10248;        // OFPPF_100MB_FD, OFPPF_COPPER, OFPPF_AUTONEG
    ps.desc.advertised = 10248;
    ps.desc.supported = 10248;
    ps.desc.peer = 10248;
    ps.desc.curr_speed = 50000;  // kbps
    ps.desc.max_speed = 100000;  // kbps

    return ofputil_encode_port_status(&ps, proto);
}


struct ofpbuf *
role_status(enum ofputil_protocol proto)
{
    struct ofputil_role_status rs;

    memset(&rs, 0, sizeof(rs));
    rs.role = OFPCR12_ROLE_SLAVE;       // OFPCR_ROLE_SLAVE
    rs.reason = OFPCRR_MASTER_REQUEST;  // OFPCRR_MASTER_REQUEST
    rs.generation_id = htonll(0x123456789abcdef0);

    return ofputil_encode_role_status(&rs, proto);
}


struct ofpbuf *
requestforward(enum ofputil_protocol proto)
{
    struct ofputil_requestforward rf;

    memset(&rf, 0, sizeof(rf));
    rf.reason = OFPRFR_GROUP_MOD;

    struct ofputil_group_mod gm;
    struct ofpbuf acts;
    struct ofpact_ipv4 *a_set_field;
    struct ofpact_goto_table *a_goto;
    struct ofputil_bucket bckt;

    memset(&gm, 0, sizeof(gm));
    gm.command = OFPGC15_INSERT_BUCKET;
    gm.type = OFPGT11_SELECT;
    gm.group_id = 0xaaaaaaaa;
    gm.command_bucket_id = 0xbbbbbbbb;

    ofpbuf_init(&acts, 0x18);
    ofpact_put_STRIP_VLAN(&acts);
    a_set_field = ofpact_put_SET_IPV4_DST(&acts);
    a_set_field->ipv4 = inet_addr("192.168.2.9");

    bckt.weight = 0xcccc;
    bckt.watch_port = 0xdddd;
    bckt.watch_group = 0xeeeeeeee;
    bckt.bucket_id = 0x12345678;
    bckt.ofpacts = acts.data;
    bckt.ofpacts_len = acts.size;

    list_init(&(gm.buckets));
    list_push_back(&(gm.buckets), &(bckt.list_node));

    rf.group_mod = &gm;

    return ofputil_encode_requestforward(&rf, proto);
}

/*
 * Symmetric Messages
 */

struct ofpbuf *
hello(enum ofputil_protocol proto)
{
    return ofputil_encode_hello(ofputil_protocols_to_version_bitmap(proto));
}

struct ofpbuf *
echo_request(enum ofputil_protocol proto)
{
    return make_echo_request(ofputil_protocol_to_ofp_version(proto));
}

struct ofpbuf *
echo_reply(enum ofputil_protocol proto)
{
    struct ofp_header oh;

    memset(&oh, 0, sizeof(oh));
    oh.version = ofputil_protocol_to_ofp_version(proto);
    oh.type = 3;           // OFPT_ECHO_REPLY
    oh.length = htons(8);  // lenght of ofp_header
    oh.xid = 0;

    return make_echo_reply(&oh);
}

struct ofpbuf *
error_msg(enum ofputil_protocol proto)
{
    struct ofp_header oh;

    memset(&oh, 0, sizeof(oh));
    oh.version = ofputil_protocol_to_ofp_version(proto);
    oh.type = 14;          // OFPT_FLOW_MOD
    oh.length = htons(8);  // lenght of ofp_header
    oh.xid = 0;

    // OFPERR_OFPBMC_BAD_FIELD means
    // "Unsupported field in the match."
    //  - type: OFPET_BAD_MATCH = 4
    //  - code: OFPBMC_BAD_FIELD = 6
    return ofperr_encode_reply(OFPERR_OFPBMC_BAD_FIELD, &oh);
}

/*
 * Utilities
 */

void
dump_ofpbuf(const char *name, const struct ofpbuf *buf)
{
    FILE *fp;
    size_t written;

    fp = fopen(name, "wb");
    if (fp == NULL) {
        err(1, "fopen");
    }
    written = fwrite(buf->data, buf->size, 1, fp);
    if (written != 1) {
        err(1, "fwrite");
    }
    if (fclose(fp) != 0) {
        err(1, "fclose");
    }
}

void
dump_message(const char *name, struct ofpbuf *buf)
{

    ofpmsg_update_length(buf);
    dump_ofpbuf(name, buf);
}

struct protocol_version {
    const char *name;
    const char *dir_name;
    enum ofp_version version;
};

#define P(v) {.name = "OFP" #v, .dir_name = "of" #v, \
              .version = OFP ## v ## _VERSION,}

const struct protocol_version p13 = P(13);
const struct protocol_version p15 = P(15);

struct message {
    const char *name;
    struct ofpbuf *(*gen)(enum ofputil_protocol);
    const struct protocol_version **protocols;
};

#define M(m, p) {.name = #m, .gen = m, .protocols = p,}

const struct message messages[] = {
    /* Controller-to-Switch Messages */
    /* Handshake */
    // TODO:
    // The following messages are not supported in Open vSwitch 2.5.90,
    // re-generate the packet data, later.
    //  - OFP10+ Features Request Message
    // M(features_request,
    //   ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(features_reply,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    /* Switch Configuration */
    // TODO:
    // The following messages are not supported in Open vSwitch 2.5.90,
    // re-generate the packet data, later.
    //  - OFP10+ Get Switch Configuration Request Message
    M(set_config,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    // M(get_config_request,
    //   ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(get_config_reply,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    /* Modify State Messages */
    // TODO:
    // The following messages are not supported in Open vSwitch 2.4.90,
    // re-generate the packet data, later.
    //  - OFP14+ Port Modification Message [EXT-154]
    M(table_mod,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(flow_mod,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(flow_mod_match_conj,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(flow_mod_conjunction,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(group_mod,
      ((const struct protocol_version *[]){&p15, NULL})),
    M(port_mod,
      ((const struct protocol_version *[]){&p13, NULL})),
    M(meter_mod,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    /* Multipart Messages */
    // TODO:
    // The following messages are not supported in Open vSwitch 2.4.90,
    // re-generate the packet data, later.
    // - OFP10+ Desc Stats Request Message
    // - OFP10+ Desc Stats Reply Message
    // - OFP15+ Flow Desc Request Message [EXT-334]
    // - OFP15+ Flow Desc Reply Message [EXT-334]
    // - OFP15+ Flow Stats Request Message [EXT-302]
    // - OFP15+ Flow Stats Reply Message [EXT-334]
    // - OFP15+ Aggregate Stats Reply Message [EXT-334]
    // - OFP14+ Port Stats Reply Message [EXT-262]
    // - OFP14+ Port Desc Reply Message [EXT-262]
    // - OFP14+ Queue Stats Reply Message [EXT-262]
    // - OFP14+ Queue Desc Request Message [EXT-262]
    // - OFP14+ Queue Desc Reply Message [EXT-262]
    // - OFP13+ Group Stats Reply Message [EXT-102]
    // - OFP15+ Group Desc Reply Message [EXT-350]
    // - OFP12+ Group Features Reply Message [EXT-61]
    // - OFP15+ Meter Stats Reply Message [EXT-374]
    // - OFP15+ Meter Desc Request Message [EXT-302]
    // - OFP15+ Meter Desc Reply Message [EXT-302]
    // - OFP13+ Meter Features Stats Request Message [EXT-14]
    // - OFP13+ Meter Features Stats Reply Message [EXT-14]
    // - OFP15+ Controller Status Stats Request Message [EXT-454]
    // - OFP15+ Controller Status Stats Reply Message [EXT-454]
    // - OFP14+ Table Desc Reply Message [EXT-262]
    // - OFP15+ Table Features Stats Request Message [EXT-306]
    // - OFP15+ Table Features Stats Reply Message [EXT-306]
    // - OFP14+ Flow Monitor Request Message [EXT-187]
    // - OFP14+ Flow Monitor Reply Message [EXT-187]
    // - OFP15+ Bundle Features Stats Request Message [EXT-340]
    // - OFP15+ Bundle Features Stats Reply Message [EXT-340]
    // - OFP11+ Experimenter Stats Request
    // - OFP11+ Experimenter Stats Reply
    // M(desc_stats_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(desc_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(flow_desc_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(flow_desc_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(flow_stats_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(flow_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    M(aggregate_stats_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(aggregate_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    M(port_stats_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(port_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    M(port_desc_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(port_desc_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    M(queue_stats_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(queue_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(queue_desc_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(queue_desc_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    M(group_stats_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(group_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    M(group_desc_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(group_desc_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    M(group_features_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(group_features_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    M(meter_stats_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(meter_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(meter_desc_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(meter_desc_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(meter_features_stats_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(meter_features_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(controller_status_stats_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(controller_status_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    M(table_desc_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(table_desc_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(table_features_stats_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(table_features_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(flow_monitor_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(flow_monitor_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(bundle_features_stats_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(bundle_features_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(experimenter_stats_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(experimenter_stats_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    /* Packet-Out Message */
    // TODO:
    // The following message are not supported in Open vSwitch 2.4.90,
    // re-generate the packet data, later.
    // - OFP15+ Packet Out Message [EXT-427]
    // M(packet_out,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    /* Barrier Message */
    // TODO:
    // The following message are not supported in Open vSwitch 2.4.90,
    // re-generate the packet data, later.
    // - OFP10+ Barrier Reply Message
    M(barrier_request,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(barrier_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    /* Role Request Message */
    // TODO:
    // The following messages are not supported in Open vSwitch 2.4.90,
    // re-generate the packet data, later.
    // - OFP15+ Role Request Message [EXT-275]
    // - OFP15+ Role Reply Message [EXT-275]
    // M(role_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(role_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    /* Bundle messages */
    M(bundle_ctrl,
      ((const struct protocol_version *[]){&p15, NULL})),
    M(bundle_add,
      ((const struct protocol_version *[]){&p15, NULL})),
    /* Set Asynchronous Configuration Message */
    // TODO:
    // The following messages are not supported in Open vSwitch 2.4.90,
    // re-generate the packet data, later.
    // - OFP14+ Set Async Message [EXT-262]
    // - OFP14+ Get Async Request Message [EXT-262]
    // - OFP14+ Get Async Reply Message [EXT-262]
    // M(set_async,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(get_async_request,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    // M(get_async_reply,
    //   ((const struct protocol_version *[]){&p15, NULL})),
    /* Asynchronous Messages */
    // TODO:
    // The following messages are not supported in Open vSwitch 2.4.90,
    // re-generate the packet data, later.
    //  - OFP15 Flow Removed Message [EXT-334]
    //  - OFP14+ Port Status Message [EXT-154]
    //  - OFP14+ Table Status Message [EXT-232]
    //  - OFP15+ Controller Status Message [EXT-454]
    M(packet_in,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(flow_removed,
      ((const struct protocol_version *[]){&p13, NULL})),
    M(port_status,
      ((const struct protocol_version *[]){&p13, NULL})),
    // M(table_status,
    //  ((const struct protocol_version *[]){&p15, NULL})),
    M(role_status,
      ((const struct protocol_version *[]){&p15, NULL})),
    M(requestforward,
      ((const struct protocol_version *[]){&p15, NULL})),
    // M(controller_status,
    //  ((const struct protocol_version *[]){&p15, NULL})),
    /* Symmetric Messages */
    M(hello,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(echo_request,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(echo_reply,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(error_msg,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
};

#if !defined(__arraycount)
#define __arraycount(a) (sizeof(a) / sizeof(a[0]))
#endif

/*
 * Main
 */

int
main(int argc, char *argv[])
{
    struct ofpbuf *buf;
    unsigned int i, j;

    for (i = 0; i < __arraycount(messages); i++) {
        const struct message * const m = &messages[i];
        char name[255];

        for (j = 0;; j++) {
            const struct protocol_version * const p = m->protocols[j];

            if (p == NULL) {
                break;
            }
            const enum ofputil_protocol proto =
                ofputil_protocol_from_ofp_version(p->version);

            buf = (*m->gen)(proto);
            snprintf(name, sizeof(name),
                "../packet_data/%s/libofproto-%s-%s.packet",
                p->dir_name, p->name, m->name);
            printf("generating %s ...\n", name);
            clear_xid(buf);
            dump_message(name, buf);
            ofpbuf_delete(buf);
        }
    }
}
