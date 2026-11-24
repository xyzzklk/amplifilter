# AmpliFilter Usage Guide

## Preliminary Scan
To ensure optimised performance, it is recommended to use Zmap to perform a preliminary scan to filter out target hosts with the target UDP service running first in your envionment, then use AmpliFilter to further detect ones that can be exploited as working DRDoS amplifiers.

It is recommended to pair Zmap with probes in the [UDP Scanning Probe Templates](https://github.com/xyzzklk/udp_scanning_probe_templates) repo.

### Selecting a Probe
Make sure you have Zmap installed on your machine. Choose a probe from the repository for the service you are scanning for. For example, we are scanning DNS servers, so we will pick the [`dns_53.pkt`](https://github.com/xyzzklk/udp_scanning_probe_templates/blob/main/probe_templates/dns_53.pkt) probe.

### Initiating a Scan with Zmap
After probe selection, configure Zmap properly to scan your target environment for up hosts of the target service. Using scanning for DNS servers on the entire WAN as an example, the configuration could be as the following, as shown in the [corresponding pre-built example](https://github.com/xyzzklk/udp_scanning_probe_templates/blob/main/example_scan_dns_entire_wan.sh) in the [UDP Scanning Probe Templates](https://github.com/xyzzklk/udp_scanning_probe_templates) repository.
```shell
sudo zmap \
    -M udp -p 53 \
    --probe-args=file:"./probe_templates/dns_53.pkt" \
    -o dns_up_wan_hosts.txt
```

Zmap's default output format (to `dns_up_wan_hosts.txt`, in this example) would be something like
```txt
192.168.0.1
192.168.0.2
```

One IP each line. AmpliFilter is designed to pick up this text-file format automatically.

Simply wait until Zmap finishes its job.

## Detailed Usage
### Install
The current latest version, 1.1 is compatible with Python 3.14.

#### Option 1: Cloning the Repo
Clone the entire repository
```shell
git clone "https://github.com/xyzzklk/amplifilter.git"
```

Enter the repository's working folder, and install dependencies.
```shell
cd amplifilter
python -m pip install -r requirements.txt
```

Confirm that the script can execute normally by displaying its help menu.
```shell
python amplifilter.py -h
```

#### Option 2: Choosing a Compiled Release
Go to the [Releases](https://github.com/xyzzklk/amplifilter/releases) page to select the latest version of release compatible with your OS.

Download and extract the archive, then use the following command to test if the binary runs.

Windows:
```powrshell
./amplifilter.exe -h
```

Linux:
```shell
./amplifilter -h
```

### Command-line Syntax
The main executable is run from command line with arguments.