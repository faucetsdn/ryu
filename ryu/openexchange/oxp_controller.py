"""
This file define the super in OXP communication.
Author:www.muzixing.com

    register cli for oxp.

"""
from ryu import cfg
import logging

from ryu.openexchange import oxproto_v1_0
from ryu.lib import hub
from ryu.lib.hub import StreamServer
from ryu.openexchange import oxproto_common


LOG = logging.getLogger('ryu.openexchange.oxp_super')

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.StrOpt(
        'oxp-role', default='', help='open exchange role setting'),
    cfg.StrOpt(
        'oxp-server-ip', default='', help='oxp server ip'),
    cfg.IntOpt('oxp-server-port', default=oxproto_common.OXP_TCP_PORT,
               help='oxp server port'),

    cfg.StrOpt(
        'oxp-listen-host', default='127.0.0.1',
        help='open exchange listen host'),
    cfg.IntOpt('oxp-tcp-listen-port', default=oxproto_common.OXP_TCP_PORT,
               help='openexchange tcp listen port'),
    cfg.IntOpt('oxp-ssl-listen-port', default=oxproto_common.OXP_SSL_PORT,
               help='openexchange ssl listen port'),

    cfg.IntOpt('oxp-domain-id', default=oxproto_common.OXP_DEFAULT_DOMAIN_ID,
               help='openexchange domain id'),
    cfg.IntOpt('sbp-proto-type', default=oxproto_v1_0.OXPS_OPENFLOW,
               help='openexchange Southbound protocol type'),
    cfg.IntOpt('sbp-proto-version', default=4,
               help='version of Southbound protocol'),
    cfg.IntOpt('oxp-capabilities',
               default=oxproto_common.OXP_DEFAULT_CAPABILITIES,
               help='domain capabilities'),

    cfg.IntOpt('oxp-flags',
               default=oxproto_common.OXP_DEFAULT_FLAGS,
               help='oxp flags'),
    cfg.IntOpt('oxp-period',
               default=oxproto_common.OXP_DEFAULT_PERIOD,
               help='oxp period'),
    cfg.IntOpt('oxp-miss-send-len',
               default=oxproto_common.OXP_DEFAULT_MISS_SEND_LEN,
               help='oxp miss send len'),

    cfg.StrOpt(
        'oxp-ctl-privkey', default=None, help='oxp controller private key'),
    cfg.StrOpt(
        'oxp-ctl-cert', default=None, help='oxp controller certificate'),
    cfg.StrOpt(
        'oxp-ca-certs', default=None, help='oxp CA certificates')
])
