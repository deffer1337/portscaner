import argparse
import re
import sys
from typing import List

from ping3 import ping

from modules.scanner.data_args import _DataArgs


class PortScanArgumentParser:
    """ Console Parser """
    def __init__(self, args):
        """
        :param args: Console arguments
        """
        self._parser = argparse.ArgumentParser(description='This is portscan\n')
        self._args = args
        self._ports_regex = re.compile(r'^(tcp|udp)\/\d+(-\d+)?')
        self._add_options()

    def _add_options(self):
        self._parser.add_argument('ip', type=str,
                                  help='IP address')

        self._parser.add_argument('ports', type=str, nargs='*', default=['tcp', 'udp'],
                                  help='Ports to scan')

        self._parser.add_argument('--timeout', type=float, default=2.0,
                                  help='Waiting time for a response from the server')

        self._parser.add_argument('-v', '--verbose', action='store_true',
                                  help='Showing response time from tcp port')

        self._parser.add_argument('-g', '--guess', action='store_true',
                                  help='Showing protocol(http, dns or echo) on port')

    def _is_correct_ip(self, ip: str):
        """
        Checking to correct ip

        :param ip: IP address
        """
        numbers = ip.split('.')
        if len(numbers) != 4:
            return False

        for number in numbers:
            if not (0 <= int(number) <= 255 and number):
                raise False

        return True

    def _parse_ports(self, ports: List[str]):
        """
        Parsing ports of the form: tcp/*, tcp/*-*, * - number

        :param ports: Ports of the form: tcp/*, tcp/*-*, * - number
        """
        exception_msg = 'Port should be less 65536 and more 0'
        new_ports = {}
        for p in ports:
            if p.find('/') == -1:
                new_ports[p] = {x for x in range(1, 1001)}
            else:
                temp = p.split('/')
                if temp[0] not in new_ports:
                    new_ports[temp[0]] = set()
                if temp[1].find('-') == -1:
                    if not 0 < int(temp[1]) < 65536:
                        raise ValueError('Port should be less 65536 and more 0')
                    new_ports[temp[0]].add(int(temp[1]))
                else:
                    number_one, number_two = map(int, temp[1].split('-'))
                    if not(0 < number_one < 65536 and 0 < number_two < 65536):
                        raise ValueError(exception_msg)
                    for port in range(number_one, number_two + 1):
                        new_ports[temp[0]].add(port)

        return new_ports

    def _is_correct_port(self, port: str):
        """
        Checking to correct port

        :param port: Port of the form: tcp/*, tcp/*-*, * - number
        """
        return self._ports_regex.match(port) or port == 'tcp' or port == 'udp'

    def parse(self):
        parameters = self._parser.parse_args(self._args)
        if not self._is_correct_ip(parameters.ip):
            raise ValueError('IP address {ip} not correct. IP address should be is written as four decimal numbers '
                             'with a value from 0 to 255, separated by dots.')

        if not ping(parameters.ip):
            raise ValueError(f'Host {parameters.ip} seems down. Try again if it doesn"t')

        for port in parameters.ports:
            if not self._is_correct_port(port):
                raise ValueError(f'Port {port} not correct')

        try:
            ports = self._parse_ports(parameters.ports)
        except ValueError as e:
            print(str(e))
            sys.exit()

        return _DataArgs(parameters.ip, ports, parameters.timeout, parameters.verbose,
                         parameters.guess)
