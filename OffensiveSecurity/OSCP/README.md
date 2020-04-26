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


### SSH(22)
OpenFuck (Apache mod_ssl < 2.8.7 OpenSSL) 764.c <br />
Bruteforce : <br />
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=users.txt --script-args ssh-brute.timeout=4s 192.168.88.152
hydra -l user -P /usr/share/wordlists/rockyou.txt  192.168.88.171 ssh -t 4
ref : <br />
https://github.com/g0tmi1k/debian-ssh 
https://blog.g0tmi1k.com/2010/04/pwnos/


### FTP(21)
default cred ; (anonymous/anonymous) | (ftp/ftp) | (ftpuser|ftpuser)<br />
nmap -sV -Pn -vv -p 21  --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 10.11.1.226<br />
nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1
check windows OS files : https://www.quora.com/How-can-I-tell-what-version-of-Windows-is-installed-on-a-hard-drive-without-booting-it<br />
Bruteforce : <br />
medusa -h 192.168.88.152 -u user -P /root/SecLists/Passwords/bt4-password.txt -M ftp<br />
./root/PWK-Lab/FTP/ftp-user-enum-1.0/ftp-user-enum.pl -U /root/PWK-Lab/fuzzdb/bruteforce/names/simple-users.txt -t 10.11.1.116"<br />


### SMTP(25)
nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.11.1.227<br />
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.0.0.1<br />
nmap --script smtp-enum-users.nse 10.11.1.229<br />
smtp-user-enum -M VRFY -U users.txt -t 10.11.1.229<br />
smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t 192.168.88.171<br />
smtp-user-enum -M VRFY -U  /usr/share/seclists/Usernames/Names/names.txt -t 10.11.1.229<br />
telnet INSERTIPADDRESS 25<br />
nc -nvv INSERTIPADDRESS 25<br />
msf module : auxiliary/scanner/smtp/smtp_enum<br />
