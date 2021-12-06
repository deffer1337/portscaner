import sys
import time

from modules.console_handler.argparser import PortScanArgumentParser
from modules.scanner.udp_port_scanner import UdpPortScanner
from modules.scanner.tcp_port_scanner import TcpPortScanner
from modules.console_handler.console_ui import ConsoleUI
from modules.utils import get_protocols_to_tcp_port, get_protocols_to_udp_port


def add_data_to_console_column_ui(console_ui, transport_protocol, get_protocol_func, port_scan_args, port, t=''):
    console_ui.add_value_to_column('TCP|UDP', transport_protocol)
    console_ui.add_value_to_column('PORT', port)
    if port_scan_args.verbose:
        console_ui.add_value_to_column('[TIME, ms]', t)

    if port_scan_args.guess:
        protocol = get_protocol_func(port, port_scan_args.ip)
        console_ui.add_value_to_column('PROTOCOL', protocol)


def get_args():
    port_scan_argument_parser = PortScanArgumentParser(sys.argv[1:])
    try:
        port_scan_args = port_scan_argument_parser.parse()
    except ValueError as e:
        print(str(e))
        sys.exit()

    return port_scan_args


def start_portscanner():
    start = time.perf_counter()
    console_ui = ConsoleUI()
    port_scan_args = get_args()

    console_ui.add_start_msg('Starting portscan\n')
    console_ui.add_column('TCP|UDP')
    console_ui.add_column('PORT')
    if port_scan_args.verbose:
        console_ui.add_column('[TIME, ms]')

    if port_scan_args.guess:
        console_ui.add_column('PROTOCOL')

    if 'udp' in port_scan_args.ports:
        udp_ports = UdpPortScanner(port_scan_args.ip, port_scan_args.ports['udp'], port_scan_args.timeout).start_scan()
        for port in udp_ports:
            add_data_to_console_column_ui(console_ui, 'UDP', get_protocols_to_udp_port, port_scan_args, port)

    if 'tcp' in port_scan_args.ports:
        tcp_ports = TcpPortScanner(port_scan_args.ip, port_scan_args.ports['tcp'], port_scan_args.timeout).start_scan()
        for port, t in tcp_ports:
            add_data_to_console_column_ui(console_ui, 'TCP', get_protocols_to_tcp_port, port_scan_args, port, f'{t}')

    console_ui.add_end_msg(f'portscan done: scanned in {round(time.perf_counter() - start)} seconds')
    console_ui.print()


if __name__ == '__main__':
    start_portscanner()
