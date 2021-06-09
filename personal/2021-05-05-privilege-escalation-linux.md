---
title: Privilege Escalation Linux
categories: [TryHackMe, WriteUp]
tags: [TryHackMe, WriteUp]
---

# Privilege Escalation Linux

Presi da https://hacktips.it/guida-privilege-escalation-sistemi-windows/
**CAMBIARE IMMAGINI E TESTO**

### Collect Information

 - **Distribuzione Linux e versione** (per cercare exploit del kernel):
   - ```cat /etc/issue```
   - ```cat /etc/*-release```


 - **Tipologia di architettura** (per adattare eventuali exploit):
   - ```cat /proc/version```
   - ```uname -a```
   - ```uname -mrs```
   - ```rpm -q kernel```
   - ```dmesg | grep Linux```


 - **Variabili d’ambiente** (potrebbero essere salvate informazioni utili):
   - ```cat /etc/profile```
   - ```cat /etc/bashrc```
   - ```cat ~/.bash_profile```
   - ```cat ~/.bashrc```
   - ```cat ~/.bash_logout```
   - ```cat ~/.nano_history```
   - ```cat ~/.atftp_history```
   - ```cat ~/.mysql_history```
   - ```cat ~/.php_history```
   - ```cat /var/mail/root```
   - ```cat /var/spool/mail/root```
   - ```env```


 - **Servizi attivi** (nel caso in cui qualche processo stia girando con permessi laschi):
   - ```ps aux```
   - ```ps -ef```
   - ```top```
   - ```cat /etc/services```
   - ```ps aux | grep root```
   - ```ps -ef | grep root```
   - ```dpkg -l```


 - **Applicazione installate:** (potrebbero esserci exploit pubblici per certi software installati)
   - ```ls -alh /usr/bin/```
   - ```ls -alh /sbin/```
   - ```dpkg -l```
   - ```rpm -qa```
   - ```ls -alh /var/cache/apt/archivesO```
   - ```ls -alh /var/cache/yum/```
   - ```yum list | grep installed```
   - ```Solaris: pkginfo```
   - ```Arch Linux: pacman -Q```


 - **Applicazioni utili:** (per compilare exploit o eseguire script)
   - ```gcc -v```
   - ```mysql --version```
   - ```java -version```
   - ```python --version```
   - ```ruby -v```
   - ```perl -v```


 - **Configurazioni di servizi:** (password in chiaro, misconfigurazioni, etc)
   - ```cat /etc/syslog.conf```
   - ```cat /etc/chttp.conf```
   - ```cat /etc/lighttpd.conf```
   - ```cat /etc/apache2/apache2.conf```
   - ```cat /etc/httpd/conf/httpd.conf```
   - ```cat /opt/lampp/etc/httpd.conf```
   - ```cat /etc/php5/apache2/php.ini```
   - ```cat /etc/cups/cupsd.conf```
   - ```cat /etc/my.conf```
   - ```cat /etc/inetd.conf```
   - ```ls -aRl /etc/ | awk '$1 ~ /^._r._/'```


 - **Jobs schedulati:** (nel caso in cui ci siano permessi laschi)
   - ```crontab -l ls -alh /var/spool/cron```
   - ```ls -al /etc/ | grep cron```
   - ```ls -al /etc/cron*```
   - ```cat /etc/cron*```
   - ```cat /etc/at.allow```
   - ```cat /etc/at.deny```
   - ```cat /etc/cron.allow```
   - ```cat /etc/cron.deny```
   - ```cat /etc/crontab```
   - ```cat /etc/anacrontab```
   - ```cat /var/spool/cron/crontabs/root```


 - **Configurazione di rete:** (per eventuali movimenti laterali successivi e/o per ricavare altre informazioni)
   - ```/sbin/ifconfig -a```
   - ```cat /etc/network/interfaces```
   - ```cat /etc/sysconfig/netw```
   - ```lsof -nPi```
   - ```lsof -i :80```
   - ```grep 80 /etc/services```
   - ```netstat -tunap```
   - ```netstat -antpx```
   - ```netstat -tulpn```
   - ```chkconfig --list```
   - ```chkconfig --list | grep 3:on last w```
   - ```arp -a```
   - ```route -n```
   - ```/sbin/route -nee```
   - ```ip ro show```
   - ```cat /etc/resolv.conf```
   - ```cat /etc/hosts```
   - ```cat /etc/sysconfig/network```
   - ```cat /etc/networks```
   - ```iptables -L```
   - ```iptables -t nat -L```
   - ```hostname```
   - ```dnsdomainname -I```


 - **Enumerazione degli utenti** (nel caso in cui ci siano utenti privilegiati sfruttabili per effettuare la scalata):
   - ```id```
   - ```who```
   - ```w```
   - ```last```
   - ```cat /etc/passwd | cut -d : -f 1 # List users```
   - ```grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}' # List of super users```
   - ```awk -F: '($3 == "0") {print}' /etc/passwd # List of super users```
   - ```cat /etc/sudoers```
   - ```sudo -``` #which command sudo i can run
   - ```cat /etc/passwd```
   - ```cat /etc/group```
   - ```cat /etc/shadow```
   - ```ls -alh /var/mail/```
   - ```ls -ahlR /root/```
   - ```ls -ahlR /home/```
   - ```cat /var/apache2/config.inc```
   - ```cat /var/lib/mysql/mysql/user.MYD```
   - ```cat /root/anaconda-ks.cfg```
   - ```getent passwd```
   - ```cat /etc/aliases```
   - ```getent aliases```
   - ```ls -la ~/.ssh/```
   - ```ls -la /etc/ssh/```


 - **File di log** (per ricavare informazioni utili):
   - ```ls -alh /var/log```
   - ```ls -alh /var/mail```
   - ```ls -alh /var/spool```
   - ```ls -alh /var/spool/lpd```
   - ```ls -alh /var/lib/pgsql```
   - ```ls -alh /var/lib/mysql```
   - ```cat /var/lib/dhcp3/dhclient.leases```



   Automatizzato: 
    - [LinEnum](https://github.com/rebootuser/LinEnum)
    - [LinuxPrivChecker](http://www.securitysift.com/download/linuxprivchecker.py)
    - [Unix-Privesc-Checker](http://pentestmonkey.net/tools/audit/unix-privesc-check)



