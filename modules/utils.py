import socket


_DNS_PACKAGE = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
_DNS_RESPONSE_PACKAGE = b'\x00\x00\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00'
_HTTP_REQUESTS = b'GET / HTTP/1.1\r\n\r\n'


def is_http_protocol_on_port(ip: str, port: int) -> bool:
    """
    Checking to http

    :param ip: IP address
    :param port: Port on tcp
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.send(_HTTP_REQUESTS)
        data = sock.recv(1024)
        return data.decode().find('HTTP') != -1


def is_echo_protocol_on_udp_port(ip: str, port: int) -> bool:
    """
    Checking to echo protocol on udo port

    :param ip: IP address
    :param port: Port on udp
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b'echo', (ip, port))
        data = sock.recv(1024)
        return data == b'echo'


def is_echo_protocol_on_tcp_port(ip: str, port: int) -> bool:
    """
    Checking to echo protocol on tcp port

    :param ip: IP address
    :param port: Port on tcp
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.send(b'echo')
        data = sock.recv(1024)
        return data == b'echo'


def is_dns_protocol_on_port_udp(ip: str, port: int) -> bool:
    """
    Checking to dns protocol on udp port

    :param ip: IP address
    :param port: Port on udp
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(_DNS_PACKAGE, (ip, port))
        data = sock.recv(1024)
        return data == _DNS_RESPONSE_PACKAGE


def is_dns_protocol_on_port_tcp(ip: str, port: int) -> bool:
    """
    Checking to dns protocol on tcp port

    :param ip: IP address
    :param port: Port on tcp
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.send(_DNS_PACKAGE)
        data = sock.recv(1024)
        return data == _DNS_RESPONSE_PACKAGE


def get_protocols_to_tcp_port(port: int, ip: str) -> str:
    """
    Get protocol on tcp port

    :param ip: IP address
    :param port: Port on tcp
    :returns: Protocol name
    :rtype: str
    """
    if is_echo_protocol_on_tcp_port(ip, port):
        return 'echo'
    elif is_http_protocol_on_port(ip, port):
        return 'http'
    elif is_dns_protocol_on_port_tcp(ip, port):
        return 'dns'
    else:
        return ''


def get_protocols_to_udp_port(port: int, ip: str) -> str:
    """
    Get protocol on udp port

    :param ip: IP address
    :param port: Port on udp
    :returns: Protocol name
    :rtype: str
    """
    if is_dns_protocol_on_port_udp(ip, port):
        return 'dns'
    elif is_echo_protocol_on_udp_port(ip, port):
        return 'echo'
    else:
        return ''
