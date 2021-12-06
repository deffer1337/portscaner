import struct


class ICMP:
    """ ICMP Package """
    def __init__(self, data):
        self.data = data

    def decode_icmp_type(self) -> int:
        """
        Decoding the ICMP packet type

        :returns: ICMP package type.
        :rtype: int
        """
        type = struct.unpack('B', self.data[20:][0:1])
        return type[0]

    def get_distanation_port(self) -> int:
        """
        Decoding the UDP packet destination port

        :returns: UDP package destination port
        :rtype: int
        """
        port = struct.unpack('!H', self.data[50:][0:2])
        return port[0]

