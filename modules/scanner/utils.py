import struct


def get_port_from_data(data: bytes) -> int:
    ip_header_len = (data[0] & 0b1111) * 4

    return struct.unpack('!H', data[ip_header_len: ip_header_len + 2])[0]