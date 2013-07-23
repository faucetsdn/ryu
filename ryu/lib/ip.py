from ryu.lib import addrconv


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


def ipv6_to_bin(ipv6):
    '''
        convert ipv6 string to binary representation
    '''
    return addrconv.ipv6.text_to_bin(ipv6)


def ipv6_to_str(bin_addr):
    '''
        convert binary representation to human readable string
    '''
    return addrconv.ipv6.bin_to_text(bin_addr)
