# "PCAP IT OR IT DIDNT HAPPEN...its up to you if you need to"

## Host Scanning

Nmap:

```
# Nmap 7.92 scan initiated Thu Jun 23 18:15:12 2022 as: nmap -oA main/scan -sV -sC --min-rate 5000 --max-retries 3 --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl -vv -p22,80 poison.htb
Nmap scan report for poison.htb (10.129.91.148)
Host is up, received echo-reply ttl 63 (0.052s latency).
Scanned at 2022-06-23 18:15:13 CDT for 8s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFLpOCLU3rRUdNNbb5u5WlP+JKUpoYw4znHe0n4mRlv5sQ5kkkZSDNMqXtfWUFzevPaLaJboNBOAXjPwd1OV1wL2YFcGsTL5MOXgTeW4ixpxNBsnBj67mPSmQSaWcudPUmhqnT5VhKYLbPk43FsWqGkNhDtbuBVo9/BmN+GjN1v7w54PPtn8wDd7Zap3yStvwRxeq8E0nBE4odsfBhPPC01302RZzkiXymV73WqmI8MeF9W94giTBQS5swH6NgUe4/QV1tOjTct/uzidFx+8bbcwcQ1eUgK5DyRLaEhou7PRlZX6Pg5YgcuQUlYbGjgk6ycMJDuwb2D5mJkAzN4dih
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKXh613KF4mJTcOxbIy/3mN/O/wAYht2Vt4m9PUoQBBSao16RI9B3VYod1HSbx3PYsPpKmqjcT7A/fHggPIzDYU=
|   256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJrg2EBbG5D2maVLhDME5mZwrvlhTXrK7jiEI+MiZ+Am
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 23 18:15:22 2022 -- 1 IP address (1 host up) scanned in 9.27 seconds
```


Nmap Stealth: 
```
# Nmap 7.92 scan initiated Thu Jun 23 12:12:19 2022 as: nmap -oA stealth/scan -sS -p- --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl -vv poison.htb
Nmap scan report for poison.htb (10.129.91.38)
Host is up, received echo-reply ttl 63 (0.050s latency).
Scanned at 2022-06-23 12:12:19 CDT for 401s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Thu Jun 23 12:19:00 2022 -- 1 IP address (1 host up) scanned in 401.02 seconds
```


Nmap UDP: 
```
# Nmap 7.92 scan initiated Thu Jun 23 18:16:44 2022 as: nmap -oA udp/scan -sU -A -Pn --min-rate 5000 --max-retries 3 -T4 --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl -vv poison.htb
Nmap scan report for poison.htb (10.129.91.148)
Host is up, received user-set (0.054s latency).
Scanned at 2022-06-23 18:16:44 CDT for 363s
All 1000 scanned ports on poison.htb (10.129.91.148) are in ignored states.
Not shown: 801 open|filtered udp ports (no-response), 199 closed udp ports (port-unreach)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: FreeBSD 11.X|12.X
OS CPE: cpe:/o:freebsd:freebsd:11 cpe:/o:freebsd:freebsd:12
OS details: FreeBSD 11.0-RELEASE - 12.0-CURRENT, FreeBSD 11.0-STABLE, FreeBSD 11.1-RELEASE, FreeBSD 11.1-RELEASE or 11.2-STABLE, FreeBSD 11.1-STABLE, FreeBSD 11.2-RELEASE - 11.3 RELEASE or 11.2-STABLE, FreeBSD 11.3-RELEASE
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/23%OT=%CT=%CU=23%PV=Y%DS=2%DC=T%G=N%TM=62B4F5C7%P=x8
OS:6_64-pc-linux-gnu)SEQ(CI=Z%II=RI)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%
OS:S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=38%UN=0%RIPL=G%RID=G%RIPCK
OS:=G%RUCK=G%RUD=G)IE(R=Y%DFI=S%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 1019/udp)
HOP RTT      ADDRESS
1   55.45 ms 10.10.14.1
2   45.25 ms poison.htb (10.129.91.148)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 23 18:22:47 2022 -- 1 IP address (1 host up) scanned in 362.90 seconds
```

Nmap Vulns: 

```Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-23 18:30 CDT
NSE: Loaded 474 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 18:30
NSE: [broadcast-ataoe-discover] No interface supplied, use -e
NSE: [url-snarf] no network interface was supplied, aborting ...
NSE: [mtrace] A source IP must be provided through fromip argument.
NSE: [targets-xml] Need to supply a file name with the targets-xml.iX argument
NSE: [targets-ipv6-wordlist] Need to be executed for IPv6.
NSE: [targets-ipv6-map4to6] This script is IPv6 only.
NSE: [shodan-api] Error: Please specify your ShodanAPI key with the shodan-api.apikey argument
NSE: [broadcast-sonicwall-discover] No network interface was supplied, aborting.
NSE Timing: About 95.92% done; ETC: 18:30 (0:00:01 remaining)
Completed NSE at 18:31, 40.07s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 18:31
Completed NSE at 18:31, 0.00s elapsed
Pre-scan script results:
|_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| targets-asn: 
|_  targets-asn.asn is a mandatory parameter
|_eap-info: please specify an interface with -e
| broadcast-dhcp-discover: 
|   Response 1 of 1: 
|     Interface: eth0
|     IP Offered: 10.0.2.16
|     DHCP Message Type: DHCPOFFER
|     Subnet Mask: 255.255.255.0
|     Router: 10.0.2.2
|     Domain Name Server: 192.168.0.1
|     Domain Name: localdomain
|     IP Address Lease Time: 1d00h00m00s
|_    Server Identifier: 10.0.2.2
Initiating Ping Scan at 18:31
Scanning poison.htb (10.129.91.148) [4 ports]
Completed Ping Scan at 18:31, 0.08s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:31
Scanning poison.htb (10.129.91.148) [2 ports]
Discovered open port 80/tcp on 10.129.91.148
Discovered open port 22/tcp on 10.129.91.148
Completed SYN Stealth Scan at 18:31, 0.11s elapsed (2 total ports)
NSE: Script scanning 10.129.91.148.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 18:31
NSE Timing: About 99.45% done; ETC: 18:31 (0:00:00 remaining)
NSE Timing: About 99.78% done; ETC: 18:32 (0:00:00 remaining)
NSE Timing: About 99.78% done; ETC: 18:32 (0:00:00 remaining)
NSE Timing: About 99.78% done; ETC: 18:33 (0:00:00 remaining)
NSE Timing: About 99.78% done; ETC: 18:33 (0:00:00 remaining)
NSE Timing: About 99.89% done; ETC: 18:34 (0:00:00 remaining)
NSE Timing: About 99.89% done; ETC: 18:34 (0:00:00 remaining)
NSE Timing: About 99.89% done; ETC: 18:35 (0:00:00 remaining)
NSE Timing: About 99.89% done; ETC: 18:35 (0:00:00 remaining)
Completed NSE at 18:35, 275.06s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
Nmap scan report for poison.htb (10.129.91.148)
Host is up, received echo-reply ttl 63 (0.049s latency).
Scanned at 2022-06-23 18:31:04 CDT for 275s

Bug in http-security-headers: no string output.
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
| ssh2-enum-algos: 
|   kex_algorithms: (6)
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group14-sha1
|   server_host_key_algorithms: (5)
|       ssh-rsa
|       rsa-sha2-512
|       rsa-sha2-256
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (9)
|       chacha20-poly1305@openssh.com
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|       aes128-cbc
|       aes192-cbc
|       aes256-cbc
|   mac_algorithms: (10)
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
|_banner: SSH-2.0-OpenSSH_7.2 FreeBSD-20161230
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFLpOCLU3rRUdNNbb5u5WlP+JKUpoYw4znHe0n4mRlv5sQ5kkkZSDNMqXtfWUFzevPaLaJboNBOAXjPwd1OV1wL2YFcGsTL5MOXgTeW4ixpxNBsnBj67mPSmQSaWcudPUmhqnT5VhKYLbPk43FsWqGkNhDtbuBVo9/BmN+GjN1v7w54PPtn8wDd7Zap3yStvwRxeq8E0nBE4odsfBhPPC01302RZzkiXymV73WqmI8MeF9W94giTBQS5swH6NgUe4/QV1tOjTct/uzidFx+8bbcwcQ1eUgK5DyRLaEhou7PRlZX6Pg5YgcuQUlYbGjgk6ycMJDuwb2D5mJkAzN4dih
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKXh613KF4mJTcOxbIy/3mN/O/wAYht2Vt4m9PUoQBBSao16RI9B3VYod1HSbx3PYsPpKmqjcT7A/fHggPIzDYU=
|   256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJrg2EBbG5D2maVLhDME5mZwrvlhTXrK7jiEI+MiZ+Am
80/tcp open  http    syn-ack ttl 63
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-mobileversion-checker: No mobile version detected.
| http-headers: 
|   Date: Thu, 23 Jun 2022 23:31:36 GMT
|   Server: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|   X-Powered-By: PHP/5.6.32
|   Connection: close
|   Content-Type: text/html; charset=UTF-8
|   
|_  (Request type: HEAD)
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-errors: Couldn't find any error pages.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-trace: TRACE is enabled
| Headers:
| Date: Thu, 23 Jun 2022 23:31:22 GMT
| Server: Apache/2.4.29 (FreeBSD) PHP/5.6.32
| Connection: close
| Transfer-Encoding: chunked
|_Content-Type: message/http
|_http-drupal-enum: Nothing found amongst the top 100 resources,use --script-args number=<number|all> for deeper analysis)
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-date: Thu, 23 Jun 2022 23:31:18 GMT; +13s from local time.
| http-enum: 
|   /info.php: Possible information file
|_  /phpinfo.php: Possible information file
| http-sql-injection: 
|   Possible sqli for forms:
|     Form at path: /, form's action: /browse.php. Fields that might be vulnerable:
|_      file
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-comments-displayer: Couldn't find any comments.
|_http-devframework: Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.
|_http-feed: Couldn't find any feeds.
| http-vhosts: 
|_128 names had status 200
|_http-chrono: Request times for /; avg: 136.16ms; min: 99.68ms; max: 161.61ms
| http-sitemap-generator: 
|   Directory structure:
|     /
|       Other: 1; php: 1
|   Longest directory structure:
|     Depth: 0
|     Dir: /
|   Total files found (by extension):
|_    Other: 1; php: 1
| http-useragent-tester: 
|   Status for browser useragent: 200
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-wordpress-enum: Nothing found amongst the top 100 resources,use --script-args search-limit=<number|all> for deeper analysis)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=poison.htb
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://poison.htb:80/
|     Form id: 
|_    Form action: /browse.php
|_http-xssed: No previously reported XSS vuln.
|_http-malware-host: Host appears to be clean
| http-php-version: Logo query returned unknown hash 8030812e9e448ec93c40941154ba36bc
| Credits query returned unknown hash 8030812e9e448ec93c40941154ba36bc
|_Version from header x-powered-by: PHP/5.6.32
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

Host script results:
| unusual-port: 
|_  WARNING: this script depends on Nmap's service/version detection (-sV)
|_clock-skew: 12s
| dns-blacklist: 
|   SPAM
|     list.quorum.to - FAIL
|_    l2.apews.org - FAIL
| qscan: 
| PORT  FAMILY  MEAN (us)  STDDEV   LOSS (%)
| 22    0       50695.20   2622.95  0.0%
|_80    0       50739.30   3772.80  0.0%
|_path-mtu: PMTU == 1500
| resolveall: 
|   Host 'poison.htb' also resolves to:
|   Use the 'newtargets' script-arg to add the results as targets
|_  Use the --resolve-all option to scan all resolved addresses without using this script.
|_fcrdns: FAIL (No PTR record)
| port-states: 
|   tcp: 
|_    open: 22,80
|_ipidseq: ERROR: Script execution failed (use -d to debug)
| dns-brute: 
|_  DNS Brute-force hostnames: No results.

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
Post-scan script results:
| reverse-index: 
|   22/tcp: 10.129.91.148
|_  80/tcp: 10.129.91.148
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 316.91 seconds
           Raw packets sent: 29 (4.164KB) | Rcvd: 3 (116B)
```

Dig: 

```
; <<>> DiG 9.18.1-1-Debian <<>> poison.htb ANY
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOTIMP, id: 53327
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

;; WARNING: EDNS query returned status NOTIMP - retry with '+noedns'

;; QUESTION SECTION:
;poison.htb.			IN	ANY

;; Query time: 52 msec
;; SERVER: 192.168.0.1#53(192.168.0.1) (TCP)
;; WHEN: Thu Jun 23 18:21:09 CDT 2022
;; MSG SIZE  rcvd: 28
```
