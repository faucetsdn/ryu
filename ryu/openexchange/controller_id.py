"""
This file define the translate functions of controller id.
Author:www.muzixing.com

"""
# TODO: OXP controller id
_DPID_LEN = 16
_DPID_LEN_STR = str(_DPID_LEN)
_DPID_FMT = '%0' + _DPID_LEN_STR + 'x'
DPID_PATTERN = r'[0-9a-f]{%d}' % _DPID_LEN


def dpid_to_str(dpid):
    return _DPID_FMT % dpid


def str_to_dpid(dpid_str):
    assert len(dpid_str) == _DPID_LEN
    return int(dpid_str, 16)
