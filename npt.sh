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

echo '
if unable to ping, sudo nmap -sn -PE -PA80,443,3389,135,445 10.0.0.0/24
-sn: Ping-only, no port scan
-PE: ICMP echo (ping)
-PA: TCP ACK ping on common ports
(finds hosts even with ICMP blocked)

[ 21 || FTP ]
	// nmap //
		nmap -p21 -sV -sC -oN '"${ip}"'_p21_nmap.txt '"${ip}"'
 
	-FTP Anonymous Enabled: login with anonymous or guest


[ 22 ]	
	// nmap //
		nmap -p22 --script=ssh2-enum-algos -oN '"${ip}"'_p22_nmap_algos.txt '"${ip}"'
	
	-SSH Protocol v1 Supported:
		ssh -1 <ip_address> -v
		
	-SSH Weak Algorithms Supported or SSH Server CBC Mode Ciphers Enabled:
		ssh -oCiphers=<ciphers> '"${ip}"'
		
	-SSH Weak MAC Algorithms Enabled:
		ssh -oMACs=<algorithm> '"${ip}"'


[ 23 ]
	// nmap //
	nmap -p23 -sV -sC -oN '"${ip}"'_p23_nmap.txt '"${ip}"'
		
	-Unencrypted Telnet: 
		Capture the session on wireshark.


[ 25 ]
	-SMTP Service Cleartext Login Permitted:
		telnet '"${ip}"' 25
		EHLO '"${ip}"'
		AUTH LOGIN

	-Mailserver answer to VRFY and EXPN requests:
		nc '"${ip}"' 25
		EXPN root
		VRFY root


[ http ]
	// nmap //
		nmap -p80 -sV -sC -oN '"${ip}"'_p80_nmap.txt '"${ip}"'
		nmap -sV -sC -oN '"${ip}"'_pPORT_nmap.txt '"${ip}"' -pPORT


[ ntp ]
	// nmap //
		nmap -p123 -sV --script=ntp-monlist,ntp-info -oN '"${ip}"'_p123_nmap.txt
		
		
	-NTP Mode 6 Queries Allowed:
		$ ntpq -c rv


[ https ]
	// nmap //
		nmap '"${ip}"' -p443 --script ssl-enum-ciphers
		
	// testssl //
		testssl.sh --html -9 '"${ip}"':<port>
	
		testssl --color 3 --hints --html --wide 172.18.1.254:443
	
	-If its RDP (3389) SSL, can also:
		sslscan --xml='"${ip}"'_p3389_sslscan.xml --rdp '"${ip}"'

	-HTTP TRACE/TRACK ENABLED : 
		curl -v -X TRACE https://'"${ip}"' -k -i\n
		

[ SSL RELATED ]
	-SSL Version 2 and 3 Protocol Detection:
		openssl s_client -connect '"${ip}"':<port> -ssl3


	-SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE):
		echo | timeout 3 openssl s_client -connect '"${ip}"':<port> >/dev/null 2>&1; if [[ $? != 0 ]]; then echo "UNKNOWN: '"${ip}"':<port> timeout or connection error"; else echo | openssl s_client -connect '"${ip}"':<port> -ssl3 2>&1 | grep -qo "sslv3 alert handshake failure\|SSL3_GET_RECORD:wrong version number" && echo "OK: HOSTNAMEORIPADDRESS Not vulnerable" || echo "FAIL: '"${ip}"':<port> vulnerable; sslv3 connection accepted"; fi


	-SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam):
		openssl s_client -connect '"${ip}"':<port> -cipher "EXP"


	-SSL Certificate Chain Contains RSA Keys Less Than 2048 bits<:
		openssl s_client -connect '"${ip}"':<port> 2>/dev/null | openssl x509 -text -noout | grep "Public-Key"


	-SSL Certificate Signed Using Weak Hashing Algorithm:
		openssl s_client -connect '"${ip}"':<port> 2>/dev/null | openssl x509 -text -noout | grep "Signature Algorithm"


	-SSL Certificate Expiry:
		openssl s_client -connect '"${ip}"':<port> | grep "notAfter"


	-SSL Certificate with Wrong Hostname:
		nmblookup -A '"${ip}"':<port> | grep "<00" | grep -v GROUP | awk "{print $1}"


	-SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection:
		openssl s_client -connect '"${ip}"':<port> | grep "Renegotiation"
		
		Vulnerable: Secure Renegotiation IS NOT supported


	-SSL 64-bit Block Size Cipher Suites Supported (SWEET32):
		openssl s_client -connect '"${ip}"':<port> -cipher DES-CBC3-SHA


	-SSL RC4 Cipher Suites Supported (Bar Mitzvah):
		openssl s_client -connect '"${ip}"':<port> -cipher RC4-MD5
		openssl s_client -connect '"${ip}"':<port> -cipher RC4-SHA


	-SSL Certificate with Wrong Hostname:
		nmblookup -A '"${ip}"' | grep "<00"| grep -v GROUP | awk "{print $1}"


[ smb ]
	// nmap //		
		nmap --script "safe or smb-enum-*" -p445 '"${ip}"' -oN '"${ip}"'_p445_nmap_smbenum.txt


	-SMB Signing Not Required:
		-run wireshark
		-run smbclient -L \\\\'"${ip}"'
		-in wireshark, filter smb2.sec_mode.sign_required == 0 or tcp.port==445
		-look for "Security Mode" in one of the Negotiate Protocol Responses & verify that "Signing Required" states False.

[ smb - Bluekeep / EternalBlue ]
	-msfconsole 
		scanner/rdp/cve_2019_0708_bluekeep


[ 502 - Modbus ]
	// nmap //
  		nmap --script modbus-discover -p 502 -oN '"${ip}"'-p502-nmap-modbus-discover.txt '"${ip}"'
	
	// msfconsole // https://www.hackers-arise.com/post/2018/10/22/metasploit-basics-part-16-metasploit-scada-hacking //
		-Search for Modbus modules:
			msf > search modbus
		
  		-To check if target is running Modbus:
			msf > use auxiliary/scanner/scada/modbusdetect
   
		-To Grab Banner:
  			msf > use auxiliary/scanner/scada/modbus_banner_grabbing
  		-Next, find the Unit ID of the connected devices; its like a ping sweep:
			To communicate with any Modbus device, we need to have its Unit ID
			msf > use auxiliary/scanner/scada/modbus_findunitid
		
  		-Next, to read Modbus devices:
			msf > use auxiliary/scanner/scada/modbusclient
			Set ACTION to one of the below:
	   			1. READ_REGISTERS
		  		2. WRITE_REGISTERS
		 		3. READ_COILS
				4. WRITE_COILS
			Set UNIT_NUMBER (default: 1) for the starting unit.
   			Set NUMBER (default: 1) for the no. of units to take ACTION on (eg. set 100 to READ_REGISTERS 100 registers)
	  		msf > exploit
	 
	 	-Next, to write Modbus devices:
   			msf > set ACTION WRITE_COIL
	  		msf > set DATA 1
	 			(only 1 or 0 are valid values)
	 			(In SCADA/ICS, coils are devices that are either ON or OFF which are 1 or 0)
			msf > exploit
			
   			Then can check if its successfully modified with set ACTION READ_COILS.
			msf > set ACTION READ_COILS
   			msf > exploit
			
   		
	 	-To Write Values in the Registers:
   			[!] These are memory areas that hold values used in the device for settings like how long to run pump or what pressure would a valve open [!]
			[!] Changing these values could have dire repercussions! [!]
	  
   			msf > set ACTION WRITE_REGISTERS
			msf > set DATA 27,27,27,27,27
			msf > exploit
   			Check with set ACTION READ_REGISTERS
	  
		-Also, Check if can download the PLC Ladder Logic:
			msf > use auxiliary/admin/scada/modicon_stux_transfer
			msf > set MODE RECV
   			msf > set RHOST '"${ip}"'
	  		msf > exploit

		




[ 623 - IPMI ]
	-msfconsole 
		scanner/ipmi/ipmi_dumphashes


[ 3389 ]
	// nmap //	
		nmap -p3389 --script=rdp-enum-encryption,rdp-ntlm-info -sV -oN '"${ip}"'_p3389_nmap.txt '"${ip}"'


[ SPECIFIC RDP ISSUES ]
	-Terminal Services Encryption Level is Medium or Low:
		nmap -p3389 --script=rdp-enum-encryption -p3389 -oN '"${ip}"'_p3389_nmap_rdp-terminal-encryption-level.txt
		Output should be "High"

	-Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness
		perl rdp-sec-check.pl '"${ip}"'
		cpan Encoding::BER

	-Terminal Services Doesnt Use Network Level Authentication (NLA) Only:
		1. rdesktop '"${ip}"'
		2. Screenshot successful connection along with console output. 
		Vulnerable if successfully connected.
		
		-For more info: https://www.axcelsec.com/2018/11/remote-desktop-protocol-rdp-security.html

	-MS14-066: Vulnerability in Schannel Could Allow Remote Code Execution (2992611) (uncredentialed check):
		git clone https://github.com/anexia-it/winshock-test.git
		./winshock_test.sh '"${ip}"' <port>
	
	-MS12-020: Vulnerabilities in Remote Desktop Could Allow Remote Code Execution
		-msfconsole
			auxiliary/scanner/rdp/ms12_020_check


[ dns ]
	-DNS Query ID Field Prediction Cache Poisoning:
		nmap -sU -p 53 --script=dns-random-srcport '"${ip}"'

	-DNS Server Cache Snooping Remote Information Disclosure:
		nmap -sU -p 53 --script dns-cache-snoop '"${ip}"'
		
		nslookup example.com '"${ip}"'

	-DNS Server Zone Transfer Information Disclosure (AXFR):
		nmap -p53 --script dns-zone-transfer.nse --script-args dns-zone-transfer.domain=<domain> '"${ip}"'

		dig axfr @'"${ip}"' <domain.name>

	-DNS Server Recursive Query Cache Poisoning Weakness:
		nmap -Pn -sU -p 53 --script=dns-recursion '"${ip}"'


	-DNS Server Spoofed Request Amplification DDoS:
		msf > use auxiliary/scanner/dns/dns_amp
		
		dig . NS @'"${ip}"'


	-
	MS11-058: Vulnerabilities in DNS Server Could Allow Remote Code Execution (2562485) (uncredentialed check) or 
	MS12-017: Vulnerability in DNS Server Could Allow Denial of Service (2647170) (uncredentialed check):
		
		dig @@'"${ip}"' version.bind txt chaos


[ java rmi ]
	java -jar rmg-4.3.0-jar-with-dependencies.jar enum '"${ip}"' pPORT --verbose
		-add --follow if it redirects


[ TCP/1521 - Oracle ] 
	Oracle TNS Listener Remote Poisoning: msf > use auxiliary/scanner/oracle/tnspoison_checker


[ TCP/2049: Network File System (NFS) ] 
	-NFS Shares World Readable:
		nmap -sV --script=nfs-showmount <ip_address>
		apt-get install nfs-common
		showmount -e <ip_address>
		mount -t nfs '"${ip}"':/<directory> <local directory> -o nolock


[ UDP/161 - SNMP ]
	-SNMP Agent Default Community Name (public):
		onesixtyone '"${ip}"' -c /usr/share/doc/onesixtyone/dict.txt
		
		./snmpcheck-1.8.pl -t '"${ip}"' -c public

	//nmap//
		nmap -sU -p 161 -sV -sC '"${ip}"' -oN '"${ip}"'_p161_nmap.txt



'
