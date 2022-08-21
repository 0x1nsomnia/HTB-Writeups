# Recon

I do my initial scan to see which ports are open.

## nmap
```
# Nmap 7.92 scan initiated Fri Aug 19 17:44:03 2022 as: nmap -p- -oA first/scan --min-rate 5000 --max-retries 3 --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl -vv bart.htb
Nmap scan report for bart.htb (10.129.96.185)
Host is up, received echo-reply ttl 127 (0.057s latency).
Scanned at 2022-08-19 17:44:03 CDT for 26s
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
# Nmap done at Fri Aug 19 17:44:29 2022 -- 1 IP address (1 host up) scanned in 26.61 seconds
```

Then run `nmap` again with default scripts (`-sC`) and service discovery (`-sV`) on the ports that were found from the first scan.

```
# Nmap 7.92 scan initiated Fri Aug 19 17:44:43 2022 as: nmap -oA main/scan -sV -sC --min-rate 5000 --max-retries 3 --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl -vv -p 80 bart.htb
Nmap scan report for bart.htb (10.129.96.185)
Host is up, received echo-reply ttl 127 (0.066s latency).
Scanned at 2022-08-19 17:44:43 CDT for 9s

PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Did not follow redirect to http://forum.bart.htb/
|_http-favicon: Unknown favicon MD5: 50465238F8A85D0732CBCC8EB04920AA
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 19 17:44:52 2022 -- 1 IP address (1 host up) scanned in 9.09 seconds
```

We see IIS 1.0 is running on port 80 and that seems to be it for the services. We also see that it looks like nmap caught a redirect to `forum.bart.htb`, so I'll be sure to enumerate for other subdomains, but first we should add this domain to our `/etc/hosts` so that hopefully our redirect to the forum sub-domain will work.

![e36f175cfce5c695c2f5ee07b0a522a0.png](../_resources/e36f175cfce5c695c2f5ee07b0a522a0.png)



# wfuzz

```
Target: http://bart.htb/
Total requests: 19966
==================================================================
ID    Response   Lines      Word         Chars          Request    
==================================================================
00023:  C=200    548 L	    2412 W	  35529 Ch	  "forum - forum"
00099:  C=200     80 L	     221 W	   3423 Ch	  "monitor - monitor"
09532:  C=400      6 L	      26 W	    334 Ch	  "#www - #www"
10581:  C=400      6 L	      26 W	    334 Ch	  "#mail - #mail"

Total time: 0
Processed Requests: 19966
Filtered Requests: 19962
Requests/sec.: 0
```



![mailto-users.png](../_resources/mailto-users-1.png)

```
Samantha Brown
s.brown@bart.local

Daniel Simmons
d.simmons@bart.htb

Robert Hilton
r.hilton@bart.htb

Harvey Potter
h.potter@bart.htb
```



![forum-dir.png](../_resources/forum-dir-1.png)

![5639fc79902cd978eda72e19cbb9f40c.png](../_resources/5639fc79902cd978eda72e19cbb9f40c.png)

![27908187931ea255d3dd03b186f9b25a.png](../_resources/27908187931ea255d3dd03b186f9b25a.png)

![112e696f0c46eefd6c699b1406d74957.png](../_resources/112e696f0c46eefd6c699b1406d74957.png)

![29479ea2b374c2d4fd8373a4c6dcd882.png](../_resources/29479ea2b374c2d4fd8373a4c6dcd882.png)

![be16df24f072e3db59e4819a91e89aff.png](../_resources/be16df24f072e3db59e4819a91e89aff.png)

![a5862615f7d97275fe1bb568c0ca4b17.png](../_resources/a5862615f7d97275fe1bb568c0ca4b17.png)

![ebca88264c86b602ce7596192366da03.png](../_resources/ebca88264c86b602ce7596192366da03.png)

![3a373f9f76533838209bbff92227a60a.png](../_resources/3a373f9f76533838209bbff92227a60a.png)

![e9ef1ead58c20f16b471051e3f567f54.png](../_resources/e9ef1ead58c20f16b471051e3f567f54.png)



