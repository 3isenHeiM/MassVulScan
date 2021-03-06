# MassVulScan :alien:

[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/3isenHeiM/MassVulScan)](https://github.com/3isenHeiM/MassVulScan/releases/latest) [![GitHub last commit (branch)](https://img.shields.io/github/last-commit/3isenHeiM/MassVulScan/master)](https://github.com/3isenHeiM/MassVulScan/commits) [![GitHub stars](https://img.shields.io/github/stars/3isenHeiM/MassVulScan)](https://github.com/3isenHeiM/MassVulScan/stargazers)

[![Twitter Follow](https://img.shields.io/twitter/follow/3isenHeiM?style=social)](https://twitter.com/3isenHeiM)


# Description
This is a bash script which combines :
- the power of the [Masscan](https://github.com/robertdavidgraham/masscan) scanner to find open ports,
- the efficiency of the [Nmap](https://nmap.org) scanner to identify open services and their version

An HTML report will be generated containing the result of the analysis, as well as a TXT file allowing to focus on the vulnerable hosts.

![Example Menu](screenshots/help.png)

# Prerequisites
- Package ``xsltproc`` (for the conversion of an XML file to HTML, for the final report)
- Masscan, version >= 1.0.5 (https://github.com/robertdavidgraham/masscan)
- Nmap (https://nmap.org)

**I invite you to read the file "requirements.txt" if you have difficulties. It will tell you how to install each of the prerequisites.**

The script can install for you all the necessary prerequisites (Debian OS family only).


# How the script works?
The main steps of the script:
1) Express identification of hosts that are online (nmap) (optional)
2) For each of these hosts, extremely fast identification of open TCP/UDP ports (masscan)
3) The result is sorted to gather all ports to be scanned by host
4) Identification of services (nmap), multiple sessions in parallel, one session per host
5) Generation of two reports:
   - a global HTML report will be created containing all the details for each of the hosts, vulnerable or not
   - a TXT file allowing to focus on hosts (potentially) vulnerable with the details

The HTML report uses a bootstrap style sheet (https://github.com/honze-net/nmap-bootstrap-xsl) for more convenience.

# How to use it?
All you have to do is indicate the file (``-f | --include-file``) containing a list of networks, IP or hostnames (version 1.9.0) to scan:

```
git clone https://github.com/choupit0/MassVulScan.git
cd MassVulScan
chmod +x MassVulScan.sh
(root user or sudo) ./MassVulScan.sh -f [input file]
```
List of available parameters/arguments:
```
-f (input file) = mandatory parameter that will contain the list of networks, IP or hostnames to scan
-e (exclude file) = optional parameter to exclude a list of networks or IP (no hostnames) to scan
-a (all ports) = optional parameter to scan all 65535 ports (TCP and UDP)
-r (rate) = maximum packet rate (in packets/second). Default is 2500 pkts/sec.
-c (check) = optional parameter which perform a pre-scanning to identify online hosts and scan only them
-k (keep files) = optional parameter to keep all the IPs scanned in 2 files (with and without ports)
-ns (no Nmap scan) = optional parameter to detect the hosts with open ports only
```
By default, the script will scan only the  **100 most common TCP/UDP ports**. You can find the list here: ``/usr/local/share/nmap/nmap-services``. Similarly, the rate or number of packets per second is set to 2500 by default.

For the format of the files, you will find two examples in the dedicated directory.
The tool support single hosts as well as CIDR notation :
```
root@ubuntu:~/audit/MassVulScan# cat example/hosts.txt
# Private subnet
192.168.2.0/24
webmail.acme.corp
root@ubuntu:~/audit/MassVulScan# cat example/exclude.txt
# Gateway
192.168.2.254
```
**Note that the script will detect along the way if you are using multiple network interfaces.** This is important for Masscan, which will always default to the interface that has the default route. You will be asked to choose one (no problem with Nmap).

# Demo
[![asciicast](https://asciinema.org/a/SyGeaJ6s0ep1ncCh8171h4CaK.svg)](https://asciinema.org/a/SyGeaJ6s0ep1ncCh8171h4CaK)


# Compatibility
The script has only been tested on Debian family OS but should work on most Linux distributions (except for prerequisites installation). It can detect open ports on TCP and UDP protocols.
# Notes / Tips
## Nmap Categories
The script is compatible with Nmap's categories (https://nmap.org/book/nse-usage.html#nse-categories) to search for more vulnerabilities (the better known as ms17-010, EternalBlue).

## Built Nmap top ports
This command will output a list of the top ``<TOP>`` most used TCP ports. Replace the ``<TOP>``
with the number you want.
```
echo "# https://github.com/3isenHeiM/MassVulScan" > ./sources/custom_ports.txt
nmap --top-ports <TOP> localhost -v -oG - | grep TCP | cut -d ";" -f 2 | cut -d ")" -f 1 >> ./sources/custom_ports.txt
```

Then, modify the variable `source_top_tcp` in the script (line 32).

# Screenshots
## Run
![Run](screenshots/run.png)

## HTML report
![Example HTML](screenshots/html.png)
