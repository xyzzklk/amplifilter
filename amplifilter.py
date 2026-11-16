#!/usr/bin/env python3

import logging
import datetime
from rich.logging import RichHandler
from rich.text import Text
import argparse
from pathlib import Path
import socket
import sys

def format_time_with_ms(dt: datetime.datetime) -> Text:
    return Text(dt.isoformat(sep=' ', timespec='milliseconds'))

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        RichHandler(
            rich_tracebacks=True,
            log_time_format=format_time_with_ms,
            show_path=False
        )
    ]
)

def positive_int(value: str) -> int:
    int_value = int(value)
    if int_value < 0:
        raise argparse.ArgumentTypeError('Response size threshold cannot be less than 0 bytes!')
    return int_value

def legal_output_str(value: str) -> str:
    if '[ip]' not in value:
        raise argparse.ArgumentTypeError('Output must at least contain detected host ([ip])!')
    return value

def arg_parser(argv: list=None) -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        prog='amplifilter.py',
        description='A filtering tool for DRDoS reflectors',
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
        '-s', '--output-syntax',
        type=legal_output_str,
        default='[ip]',
        help='Formatting syntax for output file. Variables: [ip], [bytes]. '
             "Like: \"[ip] [bytes]\", \"[ip], [bytes]\", \"[ip]\"",
    )

    return parser.parse_args(argv)


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
    out_syntax = parsed_args.output_syntax
    logging.warning('%s %s %s %s %s %s %s', inp_f_path, out_f_path, proto, port, payload, r_threshold, out_syntax)

main()
input()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(10)

inp_file = sys.argv[1]
out_file = sys.argv[2]
proto = sys.argv[3]
size = int(sys.argv[4])
out_syntax = sys.argv[5]

with open(inp_file) as inp_file_hand:
    ip_list = inp_file_hand.readlines()

out_file_hand = open(out_file, 'w')

if proto == 'tftp':
    port = 69
    payload = tftp
elif proto == 'portmap':
    port = 111 
    payload = portmap
elif proto == 'netbios':
    port = 137
    payload = netbios
elif proto == 'ntp':
    port = 123
    payload = ntp
elif proto == 'mdns':
    port = 5353
    payload = mdns
elif proto == 'chargen':
    port = 19
    payload = chargen
elif proto == 'snmp':
    port = 161
    payload = snmp
elif proto == 'dns':
    port = 53
    payload = dns
elif proto == 'quake':
    port = 27960
    payload = quake
elif proto == 'ssdp':
    port = 1900
    payload = ssdp
elif proto == 'ldap':
    port = 389
    payload = ldap
elif proto == 'coap':
    port = 5683
    payload = coap
elif proto == 'memcache':
    port = 11211
    payload = memcached
else:
    print('[!] Protocol is not available')
    sys.exit()

# Start Loop
idx = 0
up_hosts = []
while idx < len(ip_list):
    split = ip_list[idx].strip().split(' ') # Bytes ones, and non bytes ones
    try:
        s.sendto(payload, (split[0], port))
        data, addr = s.recvfrom(65500)
        syntax_output = ''

        if len(data) >= size:
            if any(addr[0] in item for item in up_hosts):
                # Already Exists
                print('[!] Duplicated host {addr[0]}!')
            else:
                # Add so.
                print(f'[!] Recived Working Server: {addr[0]} Recived Bytes: {len(data)}')
                syntax_output = out_syntax.replace("[space]", " ", 5) # 5 is fine.
                syntax_output = syntax_output.replace("[bytes]", str(len(data)), 5) # 5 is fine.
                syntax_output = syntax_output.replace("[ip]", str(addr[0]), 5) # 5 is fine.
                out_file_hand.write(str(syntax_output) + '\n')
                up_hosts.append(addr[0])
        else:
            print(f'[!] {addr[0]}: {len(data)} is smaller than {size}, so skipping entirely!')
    except (Exception, socket.error, socket.timeout) as e:
        print(f'[!] Error: {type(e).__name__}: {e}')
    idx += 1

out_file_hand.close()
print(f'[!] Finished Filter saved to {out_file} with {len(up_hosts)} working servers.')