### automate VPN

tar xvzf file.tar.gz <br />
echo 'OS-#####' > cred.txt <br />
echo ' #######' >> cred.txt <br />
vi auth-user-pass cred.txt <br />
openvpn OS-####-PWK.ovpn 


### nmap scanning
nmap -sU -sV -n --top-ports 200 10.11.1.72  > /root/PWK-Lab/10.11.1.72/nmap-udp
nmap -p 1-65535 -T4 -A -v 192.168.88.171
nmap -sV -sC -oA nmap 192.168.111.172
nmap -vv -Pn -A -sC -sS -T 4 -p- 10.0.0.1
nmap -sT -sV -A -O -v -p 1-65535 192.168.1.30
nmap -p- -sS -A 192.168.88.155

Vuln scan : nmap -sS -sV --script=vulscan/vulscan.nse 10.11.1.44
OS detection : nmap -O -v 10.11.1.5


### SSH(22)
OpenFuck (Apache mod_ssl < 2.8.7 OpenSSL) 764.c 
Bruteforce : 
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=users.txt --script-args ssh-brute.timeout=4s 192.168.88.152
hydra -l user -P /usr/share/wordlists/rockyou.txt  192.168.88.171 ssh -t 4
ref : 
https://github.com/g0tmi1k/debian-ssh 
https://blog.g0tmi1k.com/2010/04/pwnos/


### FTP(21)
default cred ; (anonymous/anonymous) | (ftp/ftp) | (ftpuser|ftpuser)
nmap -sV -Pn -vv -p 21  --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 10.11.1.226
nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1
check windows OS files : https://www.quora.com/How-can-I-tell-what-version-of-Windows-is-installed-on-a-hard-drive-without-booting-it
Bruteforce : 
medusa -h 192.168.88.152 -u user -P /root/SecLists/Passwords/bt4-password.txt -M ftp
./root/PWK-Lab/FTP/ftp-user-enum-1.0/ftp-user-enum.pl -U /root/PWK-Lab/fuzzdb/bruteforce/names/simple-users.txt -t 10.11.1.116"


### SMTP(25)
nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.11.1.227
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.0.0.1
nmap --script smtp-enum-users.nse 10.11.1.229
smtp-user-enum -M VRFY -U users.txt -t 10.11.1.229
smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t 192.168.88.171
smtp-user-enum -M VRFY -U  /usr/share/seclists/Usernames/Names/names.txt -t 10.11.1.229
telnet INSERTIPADDRESS 25
nc -nvv INSERTIPADDRESS 25
auxiliary/scanner/smtp/smtp_enum
