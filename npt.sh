#!/bin/bash

read -p 'Enter target IP address: ' ip

# Validate if any input field is left blank. If an input field is left blank, display appropriate message and stop execution of script
if [ -z "$ip" ]
then
    echo 'Input cannot be blank please try again!'
    exit 0
fi
# Validate if the input is a number using regex (Integer or Float). If not, display appropriate message and stop execution of script
if ! [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
then
    echo "Input must be a valid IP address!"
    exit 0
fi

# print commands
echo $'hey! remember to do nessus\n-----------------------------';

echo $'[ 21 ]\nnmap -p21 -sV -sC -oN '$ip'_p21_nmap.txt '$ip;
echo $'\n';

echo $'[ 22 ]\nnmap -p22 -sV -sC -oN '$ip'_p22_nmap.txt '$ip;
echo $'nmap -p22 --script=ssh2-enum-algos -oN '$ip'_p22_nmap_algos.txt '$ip;
echo $'\n';

echo $'[ 23 ]\nnmap -p23 -sV -sC -oN '$ip'_p23_nmap.txt '$ip;
echo $' -if "telnet is unencrypted", capture the session on wireshark.';
echo $'\n';

echo $'[ http ]\nnmap -p80 -sV -sC -oN '$ip'_p80_nmap.txt '$ip;
echo $'nmap -sV -sC -oN '$ip'_pPORT_nmap.txt '$ip' -pPORT';
echo $'\n';

echo $'[ ntp ]\nnmap -p123 -sV --script=ntp-monlist,ntp-info -oN '$ip'_p123_nmap.txt';
echo $' -to verify "ntp mode 6 queries" allowed:\n  $ ntpq -c rv';
echo $'\n';

echo $'[ https ]\n~/Desktop/tools/testssl.sh/testssl.sh --html --csv -9 '$ip':<port>';
echo $'\n';

echo $'[ smb ]\nnmap -p139,445 -sV -sC '$ip' -oN '$ip'_p139,445_nmap.txt';
echo $'if its "smb signing not required":\n -run wireshark\n -run smbclient -L \\\\\\\\'$ip$'\n -in wireshark, filter smb2.sec_mode.sign_required == 0 or tcp.port==445\n -look for "Security Mode" in one of the Negotiate Protocol Responses & verify that "Signing Required" states False.';
echo $'\n';

echo $'[ 3389 ]\nnmap -p3389 --script=rdp-enum-encryption,rdp-ntlm-info -sV -oN '$ip'_p3389_nmap.txt '$ip;
