import socket
import selectors
import time
import sys
from typing import Set, List, Tuple

from modules.scanner.base_scanner import BaseScanner
from modules.protocols.icmp import ICMP
from modules.scanner.utils import get_port_from_data


class UdpPortScanner(BaseScanner):
    def __init__(self, ip: str, ports: Set[int], timeout: float):
        super().__init__(ip, ports, timeout)
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._icmp_socket = self._create_raw_icmp_socket()
        self._udp_socket.setblocking(False)
        self._icmp_socket.setblocking(False)
        self._closed_ports = set()
        self._open_ports = set()
        self._answer = ports.copy()

    def _create_raw_icmp_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError as e:
            print('You requested a scan type which requires root privileges.')
            sys.exit()

        return sock

    def _read_package(self, sock: selectors.SelectorKey.fileobj):
        data, address = sock.recvfrom(1024)
        if address[0] == self._ip:
            if sock == self._udp_socket:
                port = get_port_from_data(data)
                if port in self._port_states:
                    self._open_ports.add(port)
            elif sock == self._icmp_socket:
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

    def start_scan(self) -> Tuple[List[int], List[int]]:
        """
        Start scan udp ports.

        :returns: Filtered and Open ports.
        :rtype: Tuple[List[int], List[int]]
        """
        sel = selectors.DefaultSelector()
        sel.register(self._udp_socket, selectors.EVENT_WRITE | selectors.EVENT_READ)
        sel.register(self._icmp_socket, selectors.EVENT_READ)

        while True:
            events = sel.select()
            for key, mask in events:
                if mask & selectors.EVENT_READ:
                    self._read_package(key.fileobj)
                elif mask & selectors.EVENT_WRITE:
                    self._write_package(key.fileobj)

                if len(self._ports) == 0 and len(self._port_states) == 0:
                    self._port_states.destroy()
                    self._udp_socket.close()
                    self._icmp_socket.close()
                    return sorted(list(self._answer - self._closed_ports - self._open_ports)), \
                           sorted(list(self._open_ports))
