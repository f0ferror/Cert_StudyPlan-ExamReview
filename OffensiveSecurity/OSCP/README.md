### automate VPN

tar xvzf file.tar.gz  <br />
echo 'OS-#####' > cred.txt <br />
echo ' #######' >> cred.txt <br />
vi auth-user-pass cred.txt <br />
openvpn OS-####-PWK.ovpn 


### Default Nmap Scanning<br />
nmap -sU -sV -n --top-ports 200 192.168.1.30  > /root/PWK-Lab/192.168.1.30/nmap-udp<br />
nmap -sT -sV -A -O -v -p 1-65535 192.168.1.30 > /root/PWK-Lab/192.168.1.30/nmap-tcp<br />

-sS stealth scanning<br />
nmap -vv -Pn -A -sC -sS -T 4 -p- 10.0.0.1<br />
nmap -p- -sS -A 192.168.88.155<br />

Vuln scan : nmap -sS -sV --script=vulscan/vulscan.nse 10.11.1.44<br />
OS detection : nmap -O -v 10.11.1.5<br />


- cf. Automated scanning tools<br />
[Reconnoitre : ](https://github.com/codingo/Reconnoitre)
python /root/Recon/Reconnoitre/reconnoitre.py -t 10.11.1.125 -o /root/PWK-Lab/10.11.1.125/ --services <br />
[OneTwoPunch : ](https://github.com/superkojiman/onetwopunch)
vi targets.txt; onetwopunch.sh -t targets.txt -p all -n "-sV -O --version-intensity=9" <br />
unicornscan -i tap0 -I -mT 10.11.1.252:a <br />
masscan -p0-65535 10.11.1.7 --rate 150000 -oL output.txt <br />

### Scanning per protocols
- **SSH(22)** <br />
Bruteforce : <br />
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=users.txt --script-args ssh-brute.timeout=4s 192.168.88.152<br />
hydra -l user -P /usr/share/wordlists/rockyou.txt  192.168.88.171 ssh -t 4<br />
ref : <br />
https://github.com/g0tmi1k/debian-ssh 
https://blog.g0tmi1k.com/2010/04/pwnos/
OpenF*** (Apache mod_ssl < 2.8.7 OpenSSL) 764.c <br />


- **FTP(21)** <br />
nmap -sV -Pn -vv -p 21  --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 10.11.1.226<br />
nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1
check windows OS files : https://www.quora.com/How-can-I-tell-what-version-of-Windows-is-installed-on-a-hard-drive-without-booting-it<br />
Bruteforce : <br />
medusa -h 192.168.88.152 -u user -P /root/SecLists/Passwords/bt4-password.txt -M ftp<br />
./root/PWK-Lab/FTP/ftp-user-enum-1.0/ftp-user-enum.pl -U /root/PWK-Lab/fuzzdb/bruteforce/names/simple-users.txt -t 10.11.1.116"<br />
**Default cred** (anonymous/anonymous) | (ftp/ftp) | (ftpuser|ftpuser)<br />


- **SMTP(25)**<br />
nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.11.1.227<br />
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.0.0.1<br />
nmap --script smtp-enum-users.nse 10.11.1.229<br />
smtp-user-enum -M VRFY -U users.txt -t 10.11.1.229<br />
smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t 192.168.88.171<br />
smtp-user-enum -M VRFY -U  /usr/share/seclists/Usernames/Names/names.txt -t 10.11.1.229<br />
telnet INSERTIPADDRESS 25<br />
nc -nvv INSERTIPADDRESS 25<br />
msf module : auxiliary/scanner/smtp/smtp_enum<br />

- **POP3(110)**<br />
**Bruteforce** : hydra -L usr.txt -P /usr/share/wordlists/fasttrack.txt -t20 192.168.88.183 -s55007 -I pop3<br />
POP3 command<br />
USER boris<br />
PASS *****<br />
LIST <br />
RETR 1 <br />


- **SNMP(161)**<br />
snmp-check -t [IP] -c public<br />
snmpwalk -c public -v1 10.0.0.0<br />
nmap -sU --open -p 161 10.11.1.0/24 -oG mega-snmp.txt<br />
sudo nmap -sU -p 161 --script default,snmp-sysdescr 10.11.1.0/24<br />
cf. for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips<br />
nmap 10.11.1.* -p161 --open -oG - | awk '/161\/open/{print $2}'<br />
**Default Community Strings** : public/private/manager<br />
onesixtyone -c community -i ips<br />

- **SMB(139,445)**<br />
nmap -A -p 139,445 10.11.1.1-254 -oG smb_service.txt; grep Up smb_service.txt | cut -d "" "" -f 2 <br />
nmap 10.11.1.* -p139,445 --open -oG - | awk '/139\/open.*445\/open/{print $2}' <br />
**vulnerability scsanning** : nmap -p 139,135,445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 10.x.x.x <br />
smbclient \\\\$ip\\$share<br />
-- nmap --script smb-enum-users.nse -p445 10.x.x.x  <br />
-- sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 10.x.x.x  <br />
smbclient -L //10.x.x.x/share -U user <br />
smbclient //10.x.x.x//IPC$ -N <br />
1. acccheck -v -t 10.11.1.223 -u user -P /usr/share/dirb/wordlists/common.txt <br />
acccheck -v -t 192.168.88.152 -U /root/Vulnhub/Stapler/user.txt  -P /usr/share/dirb/wordlists/common.txt <br />
2. smbmap -u user -p user -d share -H 10.11.1.227 <br />
smbmap -u user -p .bash_history -d share -H 10.11.1.227 <br />
smbmap -H 10.11.1.227\share -u user -p '.bash_history' -L <br />
ref : https://hackercool.com/2016/07/smb-enumeration-with-kali-linux-enum4linuxacccheck-smbmap/<br />


### MISC

- metasploit issue : <br />
sudo apt-get update <br />
service postgresql restart <br />
msfdb reinit  <br />
cf : https://github.com/rapid7/metasploit-framework/issues/9556 <br />
