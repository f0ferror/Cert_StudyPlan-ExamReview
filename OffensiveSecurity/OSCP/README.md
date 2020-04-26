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
OpenF*** (Apache mod_ssl < 2.8.7 OpenSSL) 764.c <br />
Bruteforce : <br />
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=users.txt --script-args ssh-brute.timeout=4s 192.168.88.152
hydra -l user -P /usr/share/wordlists/rockyou.txt  192.168.88.171 ssh -t 4
ref : <br />
https://github.com/g0tmi1k/debian-ssh 
https://blog.g0tmi1k.com/2010/04/pwnos/


- **FTP(21)** <br />
default cred ; (anonymous/anonymous) | (ftp/ftp) | (ftpuser|ftpuser)<br />
nmap -sV -Pn -vv -p 21  --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 10.11.1.226<br />
nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1
check windows OS files : https://www.quora.com/How-can-I-tell-what-version-of-Windows-is-installed-on-a-hard-drive-without-booting-it<br />
Bruteforce : <br />
medusa -h 192.168.88.152 -u user -P /root/SecLists/Passwords/bt4-password.txt -M ftp<br />
./root/PWK-Lab/FTP/ftp-user-enum-1.0/ftp-user-enum.pl -U /root/PWK-Lab/fuzzdb/bruteforce/names/simple-users.txt -t 10.11.1.116"<br />


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
Bruteforce : hydra -L usr.txt -P /usr/share/wordlists/fasttrack.txt -t20 192.168.88.183 -s55007 -I pop3<br />
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
Default community strings : public/private/manager<br />
onesixtyone -c community -i ips<br />
