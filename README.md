<p align="center">
  <h1 align="center">AmpliFilter</h1>
</p>

<p align="center">
  <strong>A modern, lightweight Python 3 utility for discovering UDP-based DRDoS amplifiers and reflectors.</strong>
</p>

<p align="center">
  <a href="#introduction">Introduction</a> •
  <a href="#supported-protocols">Protocols</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="/docs/">Documentation</a> •
  <a href="#license">License</a> •
  <a href="/CONTRIBUTING.md">Contributing</a>
</p>

***

# Introduction
<big><big><big><big>_A_</big></big></big></big>_mpliFilter_ is a light-weight security tool for detecting UDP-based services vulnerable to becoming reflectors of amplification DDoS attacks, forked from EasyFilter v1.0 by Alemalakra and fully re-written from Python 2 to Python 3.

<figure style="text-align: center;">
    <img src="docs/assets/Demo.png" alt="AmpliFilter CLI output example">
    <figcaption><sub><i>AmpliFilter CLI output example, detecing DNS reflectors</i></sub></figcaption>
</figure>

Currently, it automates scanning of a list of user-specified IPs to filter out ones that are vulnerable, and logs their amplification status for further processing.

<span style="color: red;">It is _strongly_ recommended to use **AmpliFilter** as a downstream tool to process the preliminary scan results generated from our recommended tool and probe pack [**UDP Scanning Probe Templates**](https://github.com/xyzzklk/udp_scanning_probe_templates), using it to further filter a list of hosts that are already confirmed to be running the intended service, as this is standard practice. For more, see our [Usage](/docs/usage.md) documentation.</span>

> [!NOTE]
> **AmpliFilter** is undergoing major changes of switching from the current single-threaded approach, directly borrowed from **EasyFilter**, to a more efficient asynchronous scanning mechanism. This is already planned, and will be the main feature change in the next major release (v2.0). For more info, see the current [Internal Implementation](/docs/internal-implementation.md) documentation.

> [!WARNING]
> **AmpliFilter** is designed and provided for **authorised security auditing, educational purposes and defensive research only**. Unauthorised scanning, probing or testing of systems without explicit prior written permission from the system owner is illegal and violates international computer crime laws.
>
> The author assumes **no liability** and is not responsible for any misuse or damage caused by this software. Use at your own risk.

# Features
- Currently has out-of-the-box support for 13 common reflection protocols (DNS, NTP, SSDP, SNMP, LDAP, Memcached, and more).
- Auto calculates amplification and summary metrics, with key information recording supported.
- Easily run on any modern Python environment.

Fore more, see our [documentation](/docs).

# Supported Protocols

| Protocol | Default Port | Default Probe Payload |
| :--- | :---: | :--- |
| **DNS** | 53 | ANY query to root zone (`.`) with EDNS0 |
| **NTP** | 123 | NTP V2 mode 7 (Private/Control - classic `monlist`) |
| **Memcached** | 11211 | `stats` command |
| **SNMP** | 161 | SNMPv2c GetBulk query (`public` community string) |
| **LDAP** | 389 | CLDAP search request (`objectclass=*`) |
| **SSDP** | 1900 | M-SEARCH discovery packet |
| **Chargen** | 19 | Character generator test payload |
| **Quake** | 27960 | `getstatus` connectionless packet |
| **mDNS** | 5353 | Multicast pointer record query |
| **TFTP** | 69 | Read request to `/x` (NETASCII decode) |
| **Portmap** | 111 | ONC RPC DUMP request (AUTH_NULL) |
| **NetBIOS** | 137 | NBSTAT query for domain/WORKGROUP info |
| **CoAP** | 5683 | CoAP v1 `GET /.well-known/core` |

Note that currently there's only one default payload (which might not be optimised) for each protocol. Whether this will change in the future is unknown. For more, see our [documentation](/docs/internal-implementation.md).

If you have better payloads that you want to provide, feel welcome to [contribute](/CONTRIBUTING.md).

# Quick Start
## Before You Start
As indicated before, it is _strongly_ recommended that you only feed AmpliFilter the results produced from a preliminary scan, especially with one of our recommended probes and `zmap`. For example, using [this](https://github.com/xyzzklk/udp_scanning_probe_templates/blob/main/example_scan_dns_lan_range.sh) pre-built quick-scan script with [this](https://github.com/xyzzklk/udp_scanning_probe_templates/blob/main/probe_templates/dns_53.pkt) probe payload.

## Installing
First, clone the repository.
```shell
git clone "https://github.com/xyzzklk/amplifilter.git"
```

Then install dependencies.
```shell
cd amplifilter
python -m pip install -r requirements.txt
```

Then run the following command to confirm that the script can execute normally.
```shell
python amplifilter.py --help
```

## Basic Usage
```shell
usage: amplifilter.py [-h] -i INPUT_FILE -o OUTPUT_FILE
                      -p {chargen,ntp,quake,ssdp,ldap,dns,snmp,mdns,tftp,portmap,netbios,coap,memcached}
                      [-b RESPONSE_SIZE_THRESHOLD] [-t TIMEOUT] [-s OUTPUT_SYNTAX]
                      [-v {DEBUG,INFO,WARNING,ERROR,CRITICAL}]

A filtering tool for detecting DRDoS reflectors.

options:
  -h, --help            show this help message and exit
  -i, --input-file INPUT_FILE
                        File containing a list of IP addresses to detect.
  -o, --output-file OUTPUT_FILE
                        File to output filtered IPs & results to.
  -p, --protocol {chargen,ntp,quake,ssdp,ldap,dns,snmp,mdns,tftp,portmap,netbios,coap,memcached}
                        Protocol to use when filtering.
  -b, --response-size-threshold RESPONSE_SIZE_THRESHOLD
                        Threshold of response size in bytes. Any hosts replying with a response
                        under this size will be discarded as it is useless for amplification.
                        Defaults to be equal to the request payload size if not set. (default:
                        None)
  -t, --timeout TIMEOUT
                        Maximum time in seconds to wait before a host responds. (default: 3)
  -s, --output-syntax OUTPUT_SYNTAX
                        Formatting syntax for output file. Variables: [ip], [bytes], where [ip] is
                        IP of host and [bytes] is the recorded response size.Like: "[ip] [bytes]",
                        "[ip], [bytes]", "[ip]" (default: [ip])
  -v, --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Log level to display when program is running. (default: 20)

Examples:
  amplifilter.py -i dns_up_wan_hosts.txt -o reflectors.txt -p dns
  amplifilter.py -i ntp_up_wan_hosts.txt -o amplifiers.txt -p ntp -b 100 -t 10 -s "[ip], [bytes]"
```

## Examples:
Before scanning, put your target IPs (e.g. generated from our [preliminary scanning script](https://github.com/xyzzklk/udp_scanning_probe_templates/blob/main/example_scan_dns_lan_range.sh)) in a text file, one line each. For example, `targets.txt`:
```txt
192.168.0.1
192.168.0.2
127.0.0.53
192.168.231.2
192.168.231.128
192.168.231.254
192.168.231.1
```

Then instruct the tool to scan them. Basic DNS scan:
```shell
python amplifilter.py -i targets.txt -o reflectors.txt -p dns
```

NTP scan with custom response size threshold (`-b`), socket timeout (`-t`), output format (`-s "[syntax here]"`) and log level (`-v`) set:
```shell
python amplifilter.py -i targets.txt -o amplifiers.txt -p ntp -b 100 -t 10 -s "[ip], [bytes]" -v DEBUG
```
# License
AmpliFilter is distributed under the MIT License. See [LICENSE.md](/LICENSE.md) for more information.