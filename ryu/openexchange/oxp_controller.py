"""
This file define the super in OXP communication.
Author:www.muzixing.com

    register cli for oxp.

"""

import contextlib
from ryu import cfg
import logging
import ssl
import random
from ryu.openexchange import oxproto
from ryu.lib import hub
from ryu.lib.hub import StreamServer
import eventlet
from ryu.controller import handler
from ryu.openexchange import oxproto_common
from socket import IPPROTO_TCP, TCP_NODELAY


LOG = logging.getLogger('ryu.openexchange.oxp_super')

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.StrOpt(
        'oxp-role', default='', help='open exchange role setting'),
    cfg.StrOpt(
        'oxp-server-ip', default='', help='oxp server ip'),
    cfg.IntOpt('oxp-server-port', default=oxproto.OXP_TCP_PORT,
               help='oxp server port'),
    cfg.StrOpt(
        'oxp-listen-host', default='127.0.0.1',
        help='open exchange listen host'),
    cfg.IntOpt('oxp-tcp-listen-port', default=oxproto.OXP_TCP_PORT,
               help='openexchange tcp listen port'),
    cfg.IntOpt('oxp-ssl-listen-port', default=oxproto.OXP_SSL_PORT,
               help='openexchange ssl listen port'),
    cfg.StrOpt(
        'oxp-ctl-privkey', default=None, help='oxp controller private key'),
    cfg.StrOpt(
        'oxp-ctl-cert', default=None, help='oxp controller certificate'),
    cfg.StrOpt(
        'oxp-ca-certs', default=None, help='oxp CA certificates')
])
