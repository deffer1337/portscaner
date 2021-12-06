import socket
import selectors
import time
from typing import Set, List

from modules.scanner.base_scanner import BaseScanner
from modules.protocols.icmp import ICMP


class UdpPortScanner(BaseScanner):
    def __init__(self, ip: str, ports: Set[int], timeout: float):
        super().__init__(ip, ports, timeout)
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self._udp_socket.setblocking(False)
        self._icmp_socket.setblocking(False)
        self._closed_ports = set()
        self._answer = ports.copy()

    def _read_package(self, sock: selectors.SelectorKey.fileobj):
        data, address = sock.recvfrom(1024)
        if address[0] == self._ip:
            icmp = ICMP(data)
            icmp_type = icmp.decode_icmp_type()
            port = icmp.get_distanation_port()
            if icmp_type == 3 and port in self._port_states:
                self._closed_ports.add(port)

    def _write_package(self, sock: selectors.SelectorKey.fileobj):
        if len(self._ports) > 0:
            current_port = self._ports.pop()
            sock.sendto(b'', (self._ip, current_port))
            self._port_states[current_port] = time.perf_counter()

    def start_scan(self) -> List[int]:
        """
        Start scan tcp ports.

        :returns: Open ports.
        :rtype: Set[int]
        """
        sel = selectors.DefaultSelector()
        sel.register(self._udp_socket, selectors.EVENT_WRITE, self._write_package)
        sel.register(self._icmp_socket, selectors.EVENT_READ, self._read_package)

        while True:
            events = sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj)

                if len(self._ports) == 0 and len(self._port_states) == 0:
                    self._port_states.destroy()
                    self._udp_socket.close()
                    self._icmp_socket.close()
                    return sorted(list(self._answer - self._closed_ports))
