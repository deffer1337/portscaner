import array
import struct
from socket import inet_aton, IPPROTO_TCP
from dataclasses import dataclass


FLAG_SYN = 2


@dataclass
class _TCPData:
    """ TCP package data """
    from_port: int
    to_port: int
    sequence: int
    acknowledgment: int
    flag_urg: int
    flag_ack: int
    flag_psh: int
    flag_rst: int
    flag_syn: int
    flag_fin: int


class TCPPackage:
    def __init__(self, from_host: str, from_port: int, to_host: str, to_port: int, flags: int = 0):
        self.from_host = from_host
        self.from_port = from_port
        self.to_host = to_host
        self.to_port = to_port
        self.flags = flags

    def build(self) -> bytes:
        """
        Build tcp package
        """
        packege = struct.pack('!HHIIBBHHH', self.from_port, self.to_port, 0, 0, 5 << 4, self.flags, 8192, 0, 0)

        header = struct.pack('!4s4sHH',
                             inet_aton(self.from_host),
                             inet_aton(self.to_host),
                             IPPROTO_TCP,
                             len(packege)
                             )

        checksum = self._check_sum(header + packege)
        packege = packege[:16] + struct.pack('H', checksum) + packege[18:]

        return packege

    @staticmethod
    def tcp_head_parse(data: bytes) -> _TCPData:
        """
        Parse tcp header

        :param data: Tcp package
        """
        (from_port, to_port, sequence, acknowledgment, offset_reserved_flags) = \
            struct.unpack('! H H L L H', data[:14])
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return _TCPData(from_port, to_port, sequence, acknowledgment, flag_urg, flag_ack,
                        flag_psh, flag_rst, flag_syn, flag_fin)

    def _check_sum(self, package: bytes) -> int:
        if len(package) % 2 != 0:
            package += b'\0'
        res = sum(array.array("H", package))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16
        return (~res) & 0xffff
