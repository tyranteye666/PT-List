#!/bin/bash

read -p 'Enter target IP address: ' ip

# Validate if any input field is left blank. If an input field is left blank, display appropriate message and stop execution of script
if [ -z "$ip" ]
then
    echo 'Input cannot be blank please try again!'
    exit 0
fi
# Validate if the input is a number using regex (Integer or Float). If not, display appropriate message and stop execution of script
if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
then
    echo "Input must be a valid IP address!"
    exit 0
fi

# print commands
echo $'hey! remember to do nessus\n============================';

echo $'[ 21 ]\nnmap -p21 -sV -sC -oN '"$ip"'_p21_nmap.txt '"$ip";
echo $' -FTP Anonymous Enabled: login with anonymous or guest';
echo $'\n';

echo $'[ 22 ]\nnmap -p22 -sV -sC -oN '"$ip"'_p22_nmap.txt '"$ip";
echo $'nmap -p22 --script=ssh2-enum-algos -oN '"$ip"'_p22_nmap_algos.txt '"$ip";
echo $' -SSH Protocol v1 Supported: ssh -1 <ip_address> -v';
echo $' -SSH Weak Algorithms Supported or SSH Server CBC Mode Ciphers Enabled: ssh -oCiphers=<ciphers> '"$ip";
echo $' -SSH Weak MAC Algorithms Enabled: ssh -oMACs=<algorithm> '"$ip";
echo $'\n';

echo $'[ 23 ]\nnmap -p23 -sV -sC -oN '"$ip"'_p23_nmap.txt '"$ip";
echo $' -if "telnet is unencrypted", capture the session on wireshark.';
echo $'\n';

echo $'[ 25 ]'
echo $' -SMTP Service Cleartext Login Permitted:\n    telnet '"$ip"$' 25\n    EHLO '"$ip"$'\n    AUTH LOGIN\n';
echo $' -Mailserver answer to VRFY and EXPN requests:\n    nc '"$ip"$' 25\n    EXPN root\n    VRFY root';
echo $'\n';

echo $'[ http ]\nnmap -p80 -sV -sC -oN '"$ip"'_p80_nmap.txt '"$ip";
echo $'nmap -sV -sC -oN '"$ip"'_pPORT_nmap.txt '"$ip"$' -pPORT';
echo $'\n';

echo $'[ ntp ]\nnmap -p123 -sV --script=ntp-monlist,ntp-info -oN '"$ip"$'_p123_nmap.txt';
echo $' -to verify "ntp mode 6 queries" allowed:\n  $ ntpq -c rv';
echo $'\n';

echo $'[ https ]\n~/Desktop/tools/testssl.sh/testssl.sh --html --csv -9 '"$ip"':<port>';
echo $' -if its RDP / Port 3389, use this instead: sslscan --xml='$ip'_p3389_sslscan.xml --rdp '"$ip"$'\n';
echo $'  [HTTP TRACE/TRACK ENABLED] : curl -v -X TRACE https://'$ip' -k -i';
echo $'\n';

echo "[ SSL RELATED ]";
echo $' -SSL Version 2 and 3 Protocol Detection: openssl s_client -connect '$ip':<port> -ssl3';
echo $'\n';
echo $' -SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE):\n    echo | timeout 3 openssl s_client -connect '"$ip"$':<port> >/dev/null 2>&1; if [[ $? != 0 ]]; then echo "UNKNOWN: '$ip':<port> timeout or connection error"; else echo | openssl s_client -connect '$ip':<port> -ssl3 2>&1 | grep -qo "sslv3 alert handshake failure\|SSL3_GET_RECORD:wrong version number" && echo "OK: HOSTNAMEORIPADDRESS Not vulnerable" || echo "FAIL: '$ip':<port> vulnerable; sslv3 connection accepted"; fi';
echo $'\n';
echo $' -SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam):\n    openssl s_client -connect '$ip':<port> -cipher "EXP"';
echo $'\n';
echo $' -SSL Certificate Chain Contains RSA Keys Less Than 2048 bits<:\n    openssl s_client -connect '$ip':<port> 2>/dev/null | openssl x509 -text -noout | grep "Public-Key"';
echo $'\n';
echo $' -SSL Certificate Signed Using Weak Hashing Algorithm:\n    openssl s_client -connect '$ip':<port> 2>/dev/null | openssl x509 -text -noout | grep "Signature Algorithm"';
echo $'\n';
echo $' -SSL Certificate Expiry:\n    openssl s_client -connect '$ip':<port> | grep "notAfter"';
echo $'\n';
echo $' -SSL Certificate with Wrong Hostname: nmblookup -A '$ip':<port> | grep "<00" | grep -v GROUP | awk "{print $1}"';
echo $'\n';
echo $' -SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection: openssl s_client -connect '"$ip"$':<port> | grep "Renegotiation"\n    Vulnerable: Secure Renegotiation IS NOT supported';
echo $'\n';
echo $' -SSL 64-bit Block Size Cipher Suites Supported (SWEET32): openssl s_client -connect '$ip':<port> -cipher DES-CBC3-SHA';
echo $'\n';
echo $' -SSL RC4 Cipher Suites Supported (Bar Mitzvah):\n    openssl s_client -connect '"$ip"$':<port> -cipher RC4-MD5\n    openssl s_client -connect '"$ip"$':<port> -cipher RC4-SHA';
echo $'\n';

echo $'[ smb ]\nnmap -p139,445 -sV -sC '$ip' -oN '$ip'_p139,445_nmap.txt';
echo $'if its "smb signing not required":\n -run wireshark\n -run smbclient -L \\\\\\\\'$ip$'\n -in wireshark, filter smb2.sec_mode.sign_required == 0 or tcp.port==445\n -look for "Security Mode" in one of the Negotiate Protocol Responses & verify that "Signing Required" states False.';
echo $'\n';

echo $'[ 3389 ]\nnmap -p3389 --script=rdp-enum-encryption,rdp-ntlm-info -sV -oN '$ip'_p3389_nmap.txt '$ip;
echo $'\n';
echo $'[ SPECIFIC RDP ISSUES ]';
echo $' -Terminal Services Encryption Level is Medium or Low:\n    nmap -p3389 --script=rdp-enum-encryption -p3389 -oN '"$ip"$'_p3389_nmap_rdp-terminal-encryption-level.txt\n    Output should be "High"\n';
echo $' -Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness\n    perl rdp-sec-check.pl '"$ip"$'\n    cpan Encoding::BER';
echo $' -Terminal Services Doesnt Use Network Level Authentication (NLA) Only:\n    rdesktop '"$ip"$' and screenshot successfully connection along with console output. Vulnerable if successfully connected.\n -for more info: https://www.axcelsec.com/2018/11/remote-desktop-protocol-rdp-security.html';
echo $' -MS14-066: Vulnerability in Schannel Could Allow Remote Code Execution (2992611) (uncredentialed check):\n    git clone https://github.com/anexia-it/winshock-test.git\n    ./winshock_test.sh '$ip' <port>';
echo $'\n';

echo $'[ dns ]';
echo $' -DNS Query ID Field Prediction Cache Poisoning:\n    nmap -sU -p 53 --script=dns-random-srcport '$ip;
echo $'\n';
echo $' -DNS Server Cache Snooping Remote Information Disclosure:\n    nmap -sU -p 53 --script dns-cache-snoop '"$ip"$'\n    nslookup example.com '"$ip"$'\n';
echo $' -DNS Server Zone Transfer Information Disclosure (AXFR):\n    nmap -p53 --script dns-zone-transfer.nse --script-args dns-zone-transfer.domain=<domain> '"$ip"$'\n';
echo $'    dig axfr @'$ip' <domain.name>';
echo $'\n';
echo $' -DNS Server Recursive Query Cache Poisoning Weakness:\n    nmap -Pn -sU -p 53 --script=dns-recursion '$ip;
echo $'\n';
echo $' -DNS Server Spoofed Request Amplification DDoS:\n    msf > use auxiliary/scanner/dns/dns_amp\n    dig . NS @'$ip;
echo $'\n';
echo $' -MS11-058: Vulnerabilities in DNS Server Could Allow Remote Code Execution (2562485) (uncredentialed check) or \n  MS12-017: Vulnerability in DNS Server Could Allow Denial of Service (2647170) (uncredentialed check):\n    dig @@'$ip' version.bind txt chaos';
echo $'\n';
     
echo $'[ java rmi ]';
echo $'java -jar rmg-4.3.0-jar-with-dependencies.jar enum '$ip' pPORT --verbose';
echo $' -add --follow if it redirects';
echo $'\n';

echo $' [ TCP/1521 - Oracle ] ';
echo $'Oracle TNS Listener Remote Poisoning: msf > use auxiliary/scanner/oracle/tnspoison_checker';
echo $'\n';

echo $' [ TCP/2049: Network File System (NFS) ] ';
echo $' -NFS Shares World Readable:\n    nmap -sV --script=nfs-showmount <ip_address>\n    apt-get install nfs-common\n    showmount -e <ip_address>\n    mount -t nfs '"$ip"$':/<directory> <local directory> -o nolock';
echo $'\n';

echo $' [ UDP/161 - SNMP ] ';
echo $' -SNMP Agent Default Community Name (public):\n    onesixtyone '"$ip"$' -c /usr/share/doc/onesixtyone/dict.txt\n    ./snmpcheck-1.8.pl -t '"$ip"$' -c public';
