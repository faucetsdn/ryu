from ryu.lib import addrconv


def ipv4_to_bin(ip):
    '''
        Parse an IP address and return an unsigned int.
        The IP address is in dotted decimal notation.
    '''
    return addrconv.ipv4.text_to_bin(ip)


def ipv4_to_str(ip):
    """Generate IP address string from an unsigned int.
       ip: unsigned int of form w << 24 | x << 16 | y << 8 | z
       returns: ip address string w.x.y.z"""
    return addrconv.ipv4.bin_to_text(ip)


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
