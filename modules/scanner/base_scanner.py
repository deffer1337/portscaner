import selectors
import socket
from abc import ABC, abstractmethod
from typing import Set

from time_dict import TimeDict


class BaseScanner(ABC):
    """
    Abstract scanner class
    """

    def __init__(self, ip: str, ports: Set[int], timeout: float):
        """
        :param ip: IP address from which you need to scan the ports.
        :param ports: Ports to scan.
        :param timeout: Timeout waiting for a response from (ip, port)
        """
        self._my_ip = \
        [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1],
                     [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in
                       [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
        self._port_states = TimeDict(timeout, timeout)
        self._timeout = timeout
        self._ip = ip
        self._ports = ports

    @abstractmethod
    def _write_package(self, sock: selectors.SelectorKey.fileobj):
        """
        Send package to (ip, port)

        :param sock: Socket
        """
        pass

    @abstractmethod
    def _read_package(self, sock: selectors.SelectorKey.fileobj):
        """
        Recv package from (ip, port)

        :param sock: Socket
        """
        pass

    @abstractmethod
    def start_scan(self):
        pass
