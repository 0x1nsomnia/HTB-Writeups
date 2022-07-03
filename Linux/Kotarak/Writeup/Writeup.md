# Recon

I do my initial scan to see which ports are open.
## nmap
```
# Nmap 7.92 scan initiated Sun Jul  3 08:41:43 2022 as: nmap -oA first/scan --min-rate 5000 --max-retries 3 --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl -vv kotarak.htb
Nmap scan report for kotarak.htb (10.129.1.117)
Host is up, received echo-reply ttl 63 (0.063s latency).
Scanned at 2022-07-03 08:41:43 CDT for 1s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8009/tcp open  ajp13      syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sun Jul  3 08:41:44 2022 -- 1 IP address (1 host up) scanned in 0.55 seconds
```

Then run `nmap` again with default scripts (`-sC`) and service discovery (`-sV`) on the ports that were found from the first scan.
```
# Nmap 7.92 scan initiated Sun Jul  3 08:42:23 2022 as: nmap -oA main/scan -sV -sC --min-rate 5000 --max-retries 3 --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl -vv -p 22,8009,8080 kotarak.htb
Nmap scan report for kotarak.htb (10.129.1.117)
Host is up, received echo-reply ttl 63 (0.062s latency).
Scanned at 2022-07-03 08:42:24 CDT for 9s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:d7:ca:0e:b7:cb:0a:51:f7:2e:75:ea:02:24:17:74 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDfAOLS+7h/C5JtTGQ7mr9dM70qpnhrk8tFSZFncNSMFyfw3JTg16I2KddMFRr3a/+qv+aAfF1VxyUuJl+tXlgvjgH3pRG/mDCl90U6zhz/WVqPaeu8TIu/1ph+mUZHyss/bCVrt5mnbb1nG/AeDnX/+IiUINIdkgMB6aIOtC+B+zKV/aIrk84HgV4IwfC03a2R7FRPwVzjCv97jhWjvqBEYt4UudazAmkBjgEC9xlJ9r8MjV/DrJ6M66rjCTeuLmiB3a/qz+CbC4k/uey2b5D0p5nxMGkINjgL8X1t8BbGj1qOAS+HWWxQETuwYNVpTLeNuy1bev4kd2BZyewut/p
|   256 e8:f1:c0:d3:7d:9b:43:73:ad:37:3b:cb:e1:64:8e:e9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEvZEilkawbySka+4LZlqha3pjcW2T4wq8WM1cwg/DscLCxypOIh2bRkMitpUOz1kMftIZSGNdmERXvi0znPWFI=
|   256 6d:e9:26:ad:86:02:2d:68:e1:eb:ad:66:a0:60:17:b8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID8PURIGd2/vCi9d91JK1f8wlyKrIPLcBBVVFsP8YXQ3
8009/tcp open  ajp13   syn-ack ttl 63 Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE OPTIONS
|   Potentially risky methods: PUT DELETE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp open  http    syn-ack ttl 63 Apache Tomcat 8.5.5
|_http-title: Apache Tomcat/8.5.5 - Error report
|_http-favicon: Apache Tomcat
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
|_  Potentially risky methods: PUT DELETE
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul  3 08:42:33 2022 -- 1 IP address (1 host up) scanned in 9.82 seconds
```

I also ran a UDP scan, vuln scan and fuzzed for subdomains but didn't get anything back, so it looks like we are just working with Apache Tomcat on port 8080, Apache JServ Protocol which works in tandem with Tomcat, and then the classic port 22.

# Enumeration

## Nikto
We see the PUT method is allowed and some manager related interfaces are found. 
```
- Nikto v2.1.6/2.1.5
+ Target Host: kotarak.htb
+ Target Port: 8080
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-39272: GET /favicon.ico file identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community
+ OPTIONS Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: GET HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: GET HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ GET /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: GET /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ GET /manager/html: Default Tomcat Manager / Host Manager interface found
+ GET /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ GET /manager/status: Default Tomcat Server Status interface found
```

# Website

By just browsing around, we see that this seems to probably be a default installation of Tomcat. 
Looking through a cheatsheet for Tomcat pentesting, we know that if we can get access to the Application Manager we can probably upload a `.war` file to get RCE.
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat

I try to access the manager which is protected by authentication, although default credentials do not work here.
![7395c988200e9eb6bcb6a814cb3d1f1d.png](../_resources/7395c988200e9eb6bcb6a814cb3d1f1d.png)
![6eb1b94da28eb146090a7e71a4edb0e7.png](../_resources/6eb1b94da28eb146090a7e71a4edb0e7.png)