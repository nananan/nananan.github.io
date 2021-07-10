select lo_export(16425, '/tmp/exploit1.so');

create or replace function exec(char) returns char as '/tmp/exploit1.so','sys_eval' language c strict;

select exec(‘ifconfig’);




Leggere writeup:
<s>HackTheBox Canape</s>
<s>VulnHub’s Pluck</s>
<s>TryHackMe’s Thompson</s>
<s>HackTheBox’s October</s>
<s>HackTheBox’s Frolic</s>
<s>HackTheBox’s Haircut</s>
<s>TryHackMe’s Kenobi</s>
<s>HackTheBox’s Joker</s>
<s>HackTheBox’s RedCross</s>
<s>TryHackMe’s HackPark</s>
<s>HackTheBox’s Help</s>
<s>TryHackMe’s Ignite</s>
<s>HackThebox’s Jarvis</s>
<s>TryHackMe’s Steel Mountain</s>
<s>VulnHub’s Brainpan</s>
<s>VulnHub’s Sedna</s><

Code is similar to
https://github.com/lolypop55/html5_snmp

Providing Grounds:
   - <s>Clyde</s>
   - <s>Shifty</s>
   - <s>Vector</s> - Padding Oracle Attack
   - <s>Billyboss</s> - Privilege escalation con SMBGhost Exploitation ma a me non funzionava
   - <s>Dibble</s> - C'era il parametro userlevel da modificare per accedere alla sezione per aggiungere nuovi log così da caricargli una reverse shell in nodejs
	- <s>Nickel</s> - C'erano delle API che listavano dei servizi per avere i processi e richiamando un API con POST dava un processo in cui c'erano delle credenziali per ssh. Poi in ftp si ci poteva loggare e prendere un pdf, cracckarlo e dentro c'era un endpoint per il command injection e con questo si poteva iniettare comandi powershell per creare una reverse shell.
	- <s>Shifty</s> - C'era flask app + memcached + python pickle. Per privilege escalation c'era uno script che cifrava i dati in una cartella backup, quindi si prendeva lo script per cifrare e se ne creava uno per decifrare e poi si prendevano i file per decifrarli e in uno di quelli c'era una chiave privata che si usava per loggarsi come root.
HTB
	- <s>bounty</s>
	- <s>legacy</s>
	- <s>Blue</s>
	- <s>Devel</s> uso di Watson e dell'exploit MS11-046
	- <s>Optimum</s>
	- <s>Bastard</s>
	- <s>granny</s>
	- <s>Artic</s>
	- <s>grandpa</s>
	- <s>silo</s>
	- <s>jerry</s> spiega anche come è fatto un war
	- <s>bashed</s>
	- <s>nibbles</s>
	- <s>beep</s>
	- <s>nineveh</s>
	- <s>solidstate</s>
	- <s>kotarak</s>
	- <s>node</s>
	- <s>valentine</s> c'è anche una parte in cui parlava di heartbleed
	- <s>poison</s>
	- <s>sunday</s>
	- <s>tartarsauce</s> script complicato per privilege escalation
	- <s>Bart (Windows)</s>
	- <s>Tally (WIndows)</s>
	- <s>Active (Windows)</s>
	- <s>Jail (Linux)</s>
	- <s>falafel (Linux)</s>
	- <s>Devops (Linux)</s>
	- Hawk (Linux)



	#### TryeHackMe - Offensive Path:
(Scadenza 3/05/2021)
- Advanced Exploitation
	- <s>Game Zone</s>
	- <s>Skynet</s> -- possibile articolo
	- <s>Daily Bugle</s>
	- <s>Overpass 2 - Hacked</s>
	- <s>Relevant</s>
	- <s>Internal</s> -- possibile articolo (Port Forwarding)

- Buffer Overflow Exploitation
	- Buffer Overflow Prep
	- <s>Brainstorm</s>
	- <s>Gatepeeker</s>
	- <s>Brainpan 1</s>

- Active Directory
	- <s>Active Directory Basics</s>
 	- Attacking Kerberos
 	- Attacktive Directory
 	- <s>Post-Exploitation Basics</s>

 - Extra Credits
 	- Hacking with Powershell
 	- Corp
 	- <s>Mr Robot CTF</s>
 	- <s>Retro</s>



#### Vulnhub:
Beginner friendly
   - <s>Kioptrix: Level 1</s>
   - <s>Kioptrix: Level 1.1</s>
   - <s>Kioptrix: Level 1.2</s>
   - <s>Kioptrix: Level 1.3</s>
   - <s>FristiLeaks 1.3</s>
   - <s>Stapler 1</s>
   - <s>PwnLab: Init</s>
Intermediate
   - <s>Kioptrix: 2014</s>
   - <s>Brainpan: 1</s>
   - <s>Mr-Robot: 1</s>
   - <s>HackLAB: Vulnix</s>


   - VulnOS 2
   - SickOS 1.2
   - /dev/random:scream
   - pWnOS 2.0
   - SkyTower 1
   - IMF
   - Metasploitable 3
   - Lin. Security
   - Temple of Doom
   - Pinkys Palace v1
   - Pinkys Palace v2
   - Zico2
   - Wintermute
   - Lord of root 1.0.1
   - Tr0ll 1
   - Tr0ll 2
   - Web Developer 1
   - SoliState
 
   - OSCP (https://www.vulnhub.com/entry/infosec-prep-oscp,508/)
 

https://zayotic.com/posts/oscp-like-vulnhub-vms/


https://www.offensive-security.com/labs/individual/

#### Proving Grounds:
Windows
   - <s>Slort</s>
   - <s>Algernon</s> (magari rifare)
   - <s>Authby</s>
   - <s>Jacko</s>
   - <s>UT99</s> (rifare)
   - <s>MedJed</s> (era difficile, se vuoi rifarlo)
   - <s>MeatHead</s>
   - <s>Nickel</s>
   - Billyboss

Linux
   - <s>ClamAV</s>
   - <s>Wombo</s>
   - <s>Payday</s>
   - <s>Nibbles</s>
   - <s>Fail</s>
   - <s>Zino</s>
   - <s>Banzai</s>
   - <s>Hunit</s>
   - <s>Dibble</s> (rifare)
   - <s>Hetemit</s>
Other
   - <s>Bratarina</s>
   - <s>Internal</s>
   - <s>Clyde</s>
   - <s>Shifty</s>
   - Vector



#### Hack The Box:
- Linux
	- <s>Lame</s>
	- brainfuck
	- <s>shocker</s>
	- bashed
	- nibbles
	- beep
	- <s>cronos</s>
	- nineveh
	- <s>sense</s>
	- solidstate
	- kotarak
	- node
	- valentine
	- poison
	- sunday
	- tartarsauce

- Windows
	- bounty
	- legacy
	- Blue
	- Devel
	- Optimum
	- Bastard
	- granny
	- Artic
	- grandpa
	- silo
	- jerry

- Other
	- <s>Jeeves (Windows)</s>
	- Bart (Windows)
	- Tally (WIndows)
	- Active (Windows)
	- Jail (Linux)
	- falafel (Linux)
	- Devops (Linux)
	- Hawk (Linux)



Exam Prep
Your Practice Environment:
Buffer Overflow Machine (25 Points) ok
Jeeves (25 Points)
Chatterbox (20 Points)
Cronos (20 Points)
Sense (10 Points)



#### Macchine HTB/Vulnhub/Proving Grounds:
	https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159


SMB
Buffer Overflow
Privilege Escalation
	Windows
	Linux

Windows Task Scheduled

Port Forwarding
SSH Tunneling

Grep


Windows Task Scheduled
