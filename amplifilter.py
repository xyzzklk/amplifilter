#!/usr/bin/env python3

import logging
import datetime
from rich.logging import RichHandler
from rich.text import Text
from rich.highlighter import NullHighlighter
import argparse
from pathlib import Path
import socket
import os
import sys
from dataclasses import dataclass

def format_time_with_ms(dt: datetime.datetime) -> Text:
    return Text(dt.isoformat(sep=' ', timespec='milliseconds'))

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        RichHandler(
            rich_tracebacks=True,
            log_time_format=format_time_with_ms,
            show_path=False,
            markup=True,
        )
    ]
)

def positive_int(value: str) -> int:
    int_value = int(value)
    if int_value < 0:
        raise argparse.ArgumentTypeError(f'Invalid value {value}: cannot be less than 0!')
    return int_value

def legal_output_str(value: str) -> str:
    if '[ip]' not in value:
        raise argparse.ArgumentTypeError('Output must at least contain detected host ([ip])!')
    return value

class ArgExampleDefaultFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawDescriptionHelpFormatter
):
    pass

def arg_parser(argv: list=None) -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        prog='amplifilter.py',
        description='A filtering tool for detecting DRDoS reflectors.',
        formatter_class=ArgExampleDefaultFormatter,
        epilog='''Examples:
  %(prog)s -i dns_up_wan_hosts.txt -o reflectors.txt -p dns
  %(prog)s -i ntp_up_wan_hosts.txt -o amplifiers.txt -p ntp -b 100 -t 10 -s "[ip], [bytes]"
        '''
    )

    parser.add_argument(
        '-i', '--input-file',
        required=True,
        type=Path,
        help='File containing a list of IP addresses to detect',
    )

    parser.add_argument(
        '-o', '--output-file',
        required=True,
        type=Path,
        help='File to output filtered IPs to',
    )

    parser.add_argument(
        '-p', '--protocol',
        required=True,
        choices=[
            'chargen', 'ntp', 'quake', 'ssdp', 'ldap', 'dns', 'snmp', 'mdns',
            'tftp', 'portmap', 'netbios', 'coap', 'memcached',
        ],
        help='Protocol to use when filtering',
    )

    parser.add_argument(
        '-b', '--response-size-threshold',
        type=positive_int,
        default=None,
        help='Threshold of response size in bytes. Any hosts replying with a'
             'response under this size will be discarded as it is useless for'
             'amplification. Defaults to be equal to the request payload size if not set.'
    )

    parser.add_argument(
        '-t', '--timeout',
        type=positive_int,
        default=3,
        help='Maximum time in seconds to wait before a host responds',
    )

    parser.add_argument(
        '-s', '--output-syntax',
        type=legal_output_str,
        default='[ip]',
        help='Formatting syntax for output file. Variables: [ip], [bytes], where [ip] '
             'is IP of host and [bytes] is the recorded response size.'
             "Like: \"[ip] [bytes]\", \"[ip], [bytes]\", \"[ip]\"",
    )

    return parser.parse_args(argv)

# Bigger than max IPv4 UDP payload size 65507, but safe anyway
UDP_MAX_RECV_SIZE = 65535

PROTOCOL_CONFIGS = {
    'chargen': (19, b'A'),
    'ntp': (123, b'\x17\x00\x03\x2a\x00\x00\x00\x00'),
    'quake': (27960, b'\xFF\xFF\xFF\xFF\x67\x65\x74\x73\x74\x61\x74\x75\x73\x10'),
    'ssdp': (
        1900,
        b'\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0D\x0A\x48\x6f\x73\x74\x3a\x32\x33\x39\x2e\x32\x55\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x0D\x0A\x53\x54\x3a\x73\x73\x64\x70\x3a\x61\x6c\x6c\x0D\x0A\x4d\x61\x6e\x3a\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0D\x0A\x4d\x58\x3a\x33\x0D\x0A\x0D\x0A'
    ),
    'snmp':(
        161, 
        b'\x30\x37\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x2a\x02\x04\x06\x29\x07\x31\x02\x01\x00\x02\x01\x0a\x30\x1c\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x05\x00\x30\x0d\x06\x09\x2b\x06\x01\x02\x01\x01\x09\x01\x03\x05\x00'
    ),
    'dns': (
        53,
        b'\xc4\x75\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\xff\x00\x01\x00\x00\x29\x23\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    ),
    'ldap': (
        389,
        b'\x30\x84\x00\x00\x00\x2d\x02\x01\x01\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00\x00'
    ),
    'mdns': (
        5353, 
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x5F\x73\x65\x72\x76\x69\x63\x65\x73\x07\x5F\x64\x6E\x73\x2D\x73\x64\x04\x5F\x75\x64\x70\x05\x6C\x6F\x63\x61\x6C\x00\x00\x0C\x00\x01'
    ),
    'tftp': (69, b'\x00\x01\x2f\x78\x00\x6e\x65\x74\x61\x73\x63\x69\x69\x00'),
    'portmap': (
        111, 
        b'\x65\x72\x0A\x37\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA0\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    ),
    'netbios': (
        137,
        b'\xE5\xD8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4B\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
    ),
    'coap': (
        5683,
        b'\x40\x01\x7d\x70\xbb\x2e\x77\x65\x6c\x6c\x2d\x6b\x6e\x6f\x77\x6e\x04\x63\x6f\x72\x65'
    ),
    'memcached': (11211, b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n'),
}

@dataclass
class FilterMetrics:
    num_total_hosts: int = 0
    num_up_hosts: int = 0
    num_amps: int = 0
    max_payload_af: float = 0.0
    max_wire_af: float = 0.0

    @property
    def amp_hosts_pct(self) -> float:
        return self.num_amps / self.num_total_hosts

    @property
    def up_hosts_pct(self) -> float:
        return self.num_up_hosts / self.num_total_hosts

def main(argv: list=None):
    parsed_args = arg_parser(argv)
    inp_f_path: Path = parsed_args.input_file
    out_f_path: Path = parsed_args.output_file
    proto: str = parsed_args.protocol
    port: int
    payload: bytes
    port, payload = PROTOCOL_CONFIGS[proto]
    r_threshold: int = parsed_args.response_size_threshold
    if r_threshold is None:
        r_threshold = len(payload)
        logging.warning(
            'Response size threshold not specified! Defaulting to same as '
            'payload size of %s: %s!',
            proto.title(), r_threshold
        )
    timeout: int = parsed_args.timeout
    out_syntax: str = parsed_args.output_syntax

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)

    sum_metrics = FilterMetrics()

    with(
        inp_f_path.open('r') as inp_file,
        out_f_path.open('w') as out_file,
    ):
        for line in inp_file:
            # Just in case the file is output from a previous scan result,
            # where a line is like `1.1.1.1   528\n`
            host_ip = line.strip().split()[0]
            sum_metrics.num_total_hosts += 1
            try:
                s.sendto(payload, (host_ip, port))
                data, resp_src_ip = s.recvfrom(65535)
                req_payload_size, resp_payload_size = len(payload), len(data)
                sum_metrics.num_up_hosts += 1
                if resp_payload_size < r_threshold:
                    logging.info(
                        '[bright_yellow]%s: SKIPPING. Responded, but response payload size '
                        '%s < threshold %s[/]', host_ip, resp_payload_size, r_threshold
                    )
                    continue
                payload_af = resp_payload_size / req_payload_size
                wire_af = (resp_payload_size + 28) / (req_payload_size + 28)
                logging.info(
                    '[green]%s: WORKING amplifier! | Resp Size: %s bytes | '
                    'AF (Payload): %.2f | AF (IPv4 Wire): %.2f |[/]',
                    host_ip, resp_payload_size, payload_af, wire_af
                )
                out_file.write(
                    out_syntax.replace('[ip]', host_ip)
                    .replace('[bytes]', str(resp_payload_size)) + '\n'
                )
                out_file.flush()
                os.fsync(out_file.fileno())

                sum_metrics.num_amps += 1
                if payload_af > sum_metrics.max_payload_af:
                    sum_metrics.max_payload_af = payload_af
                if wire_af > sum_metrics.max_wire_af:
                    sum_metrics.max_wire_af = wire_af

            except (socket.error, socket.timeout) as e:
                logging.info(
                    '[red]%s: NETWORK ERROR - %s: %s[/]', host_ip, type(e).__name__, e,
                )
            except Exception as e:
                logging.warning('[bold red]%s: UNHANDLED EXCEPTION:[/]', exc_info=True)

    if sum_metrics.num_total_hosts == 0:
        logging.warning('No hosts provided! Quitting.')
    else:
        logging.warning(
            '[bright_yellow bold]FILTERING FINISHED. | Total Scanned Hosts: %s | Amplifying Hosts: %s | '
            'Total Up Hosts: %s | '
            'Highest Payload Amplification Factor: %.2f | Highest Wire-Level (IPv4) '
            'Amplification Factor: %.2f | Amplifiers out of All Scanned Hosts: %.2f%% | '
            'Up hosts out of All Scanned Hosts: %.2f%% |[/]',
            sum_metrics.num_total_hosts, sum_metrics.num_amps, sum_metrics.num_up_hosts,
            sum_metrics.max_payload_af, sum_metrics.max_wire_af,
            sum_metrics.amp_hosts_pct * 100, sum_metrics.up_hosts_pct * 100,
        )

main()