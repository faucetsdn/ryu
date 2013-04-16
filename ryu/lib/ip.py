import struct


def ipv4_arg_to_bin(w, x, y, z):
    """Generate unsigned int from components of IP address
       returns: w << 24 | x << 16 | y << 8 | z"""
    return (w << 24) | (x << 16) | (y << 8) | z


def ipv4_to_bin(ip):
    '''
        Parse an IP address and return an unsigned int.
        The IP address is in dotted decimal notation.
    '''
    args = [int(arg) for arg in ip.split('.')]
    return ipv4_arg_to_bin(*args)


def ipv4_to_str(ip):
    """Generate IP address string from an unsigned int.
       ip: unsigned int of form w << 24 | x << 16 | y << 8 | z
       returns: ip address string w.x.y.z"""
    w = (ip >> 24) & 0xff
    x = (ip >> 16) & 0xff
    y = (ip >> 8) & 0xff
    z = ip & 0xff
    return "%i.%i.%i.%i" % (w, x, y, z)

IPV6_PACK_STR = '!8H'


def ipv6_to_arg_list(ipv6):
    '''
        convert ipv6 string to a list of 8 different parts
    '''
    args = []
    if '::' in ipv6:
        h, t = ipv6.split('::')
        h_list = [int(x, 16) for x in h.split(':')]
        t_list = [int(x, 16) for x in t.split(':')]
        args += h_list
        zero = [0]
        args += ((8 - len(h_list) - len(t_list)) * zero)
        args += t_list
    else:
        args = [int(x, 16) for x in ipv6.split(':')]

    return args


def ipv6_to_bin(ipv6):
    '''
        convert ipv6 string to binary representation
    '''
    args = ipv6_to_arg_list(ipv6)
    return struct.pack(IPV6_PACK_STR, *args)


def ipv6_to_str(bin_addr):
    '''
        convert binary representation to human readable string
    '''
    args = struct.unpack_from(IPV6_PACK_STR, bin_addr)
    return ':'.join('%x' % x for x in args)
