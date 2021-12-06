import socket
import selectors
import time
import sys
from random import randint
from typing import Tuple, Set, List

from modules.protocols.tcp_package import TCPPackage, FLAG_SYN
from modules.scanner.base_scanner import BaseScanner


class TcpPortScanner(BaseScanner):
    """ Asynchronous tcp port scanner. """

    def __init__(self, ip: str, ports: Set[int], timeout: float):
        """
        :param ip: IP address from which you need to scan the ports.
        :param ports: Ports to scan.
        :param timeout: Timeout waiting for a response from (ip, port)
        """
        super().__init__(ip, ports, timeout)
        self._tcp_socket = self._create_raw_tcp_socket()
        self._tcp_socket.setblocking(False)
        self._answer = set()

    def _create_raw_tcp_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except PermissionError as e:
            print('You requested a scan type which requires root privileges.')
            sys.exit()

        return sock

    def _write_package(self, sock: selectors.SelectorKey.fileobj):
        if len(self._ports) > 0:
            current_port = self._ports.pop()
            package = TCPPackage(self._my_ip, randint(35000, 40000), self._ip, current_port, FLAG_SYN).build()
            sock.sendto(package, (self._ip, current_port))
            self._port_states[current_port] = time.perf_counter()

    def _read_package(self, sock: selectors.SelectorKey.fileobj):
        data, address = sock.recvfrom(1024)
        finish = time.perf_counter()
        if address[0] == self._ip:
            tcp_package = TCPPackage.tcp_head_parse(data[20:])
            if tcp_package.from_port in self._port_states:
                if tcp_package.flag_syn and tcp_package.flag_ack:
                    time_to_answer = finish - self._port_states[tcp_package.from_port]
                    if self._timeout - time_to_answer > 0:
                        self._answer.add((tcp_package.from_port, round(time_to_answer * 1000)))
                        self._port_states.__delitem__(tcp_package.from_port)
                elif tcp_package.flag_rst and tcp_package.flag_ack:
                    self._port_states.__delitem__(tcp_package.from_port)

    def start_scan(self) -> List[Tuple[int, float]]:
        """
        Start scan tcp ports.

        :returns: Open ports with their scan time.
        :rtype: Set[Tuple[int, float]]
        """
        sel = selectors.DefaultSelector()
        sel.register(self._tcp_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)

        while True:
            events = sel.select()
            for key, mask in events:
                if mask & selectors.EVENT_READ:
                    self._read_package(key.fileobj)
                elif mask & selectors.EVENT_WRITE:
                    self._write_package(key.fileobj)

                if len(self._ports) == 0 and len(self._port_states) == 0:
                    self._port_states.destroy()
                    self._tcp_socket.close()
                    return sorted(list(self._answer))

