def bytes2hex(given_bytes):
    return ''.join(["%02X " % ord(x) for x in given_bytes]).strip()


def hex2byte(given_hex):
    given_hex = ''.join(given_hex.split())
    result = []
    for offset in range(0, len(given_hex), 2):
        result.append(chr(int(given_hex[offset:offset + 2], 16)))

    return ''.join(result)
