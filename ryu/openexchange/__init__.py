"""

This module is about Open Exchange Protocol.
Author:www.muzixing.com

"""
import glob
import inspect
import os.path

from ryu.openexchange import oxproto_protocol


def get_oxp_modules():
    """get modules pair for the constants and parser of OX-wire of
    a given OX version.
    """
    return oxproto_protocol._versions


def get_oxp_module(oxp_version):
    """get modules pair for the constants and parser of OX-wire of
    a given OX version.
    """
    return get_oxp_modules()[oxp_version]
