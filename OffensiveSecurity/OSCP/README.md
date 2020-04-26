nmap -sS -sV -sC -n 10.11.1.72 > /root/PWK-Lab/10.11.1.72/nmap-tcp
nmap -sU -sV -n --top-ports 200 10.11.1.72  > /root/PWK-Lab/10.11.1.72/nmap-udp
