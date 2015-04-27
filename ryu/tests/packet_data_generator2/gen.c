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

#include <lib/ofpbuf.h>
#include <lib/ofp-actions.h>
#include <lib/ofp-msgs.h>
#include <lib/ofp-util.h>
#include <lib/packets.h>

#include <err.h>
#include <stdio.h>

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

void
fill_match(struct match *match)
{
    match_init_catchall(match);
    match_set_in_port(match, 0xabcd);
    match_set_dl_vlan(match, htons(999));
    match_set_dl_dst(match, "\xaa\xbb\xcc\x99\x88\x77");
    match_set_dl_type(match, htons(ETH_TYPE_IP));
    match_set_nw_dst(match, inet_addr("192.168.2.1"));
    match_set_tun_src(match, inet_addr("192.168.2.3"));
    match_set_tun_dst(match, inet_addr("192.168.2.4"));
    match_set_tun_id(match, htonll(50000));
}

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
    flow_get_metadata(&match.flow, &pin.fmd);

    return ofputil_encode_packet_in(&pin, proto, NXPIF_OPENFLOW10);
}

struct ofpbuf *
flow_mod(enum ofputil_protocol proto)
{
    struct ofputil_flow_mod fm;
    struct ofpbuf acts;
    struct ofpact_ipv4 *a_set_field;
    struct ofpact_goto_table *a_goto;

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
    a_goto = ofpact_put_GOTO_TABLE(&acts);
    a_goto->table_id = 100;

    fm.ofpacts = acts.data;
    fm.ofpacts_len = acts.size;
    return ofputil_encode_flow_mod(&fm, proto);
}

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
    M(packet_in,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(flow_mod,
      ((const struct protocol_version *[]){&p13, &p15, NULL})),
    M(bundle_ctrl,
      ((const struct protocol_version *[]){&p15, NULL})),
    M(bundle_add,
      ((const struct protocol_version *[]){&p15, NULL})),
};

#if !defined(__arraycount)
#define __arraycount(a) (sizeof(a) / sizeof(a[0]))
#endif

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
