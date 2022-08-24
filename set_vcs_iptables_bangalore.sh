#!/usr/bin/env bash
# if [ $# -lt 2 ]; then
# echo "USAGE: $0 <Dev Box IP> <VCS IP>"
# exit 1
# fi

set_ip_tables(){
    iptables -I INPUT 1 --src $1 -jACCEPT
    iptables -I INPUT 3 --src 127.0.0.1 -jACCEPT
    iptables -I INPUT 4 --src 10.196.5.235 -jACCEPT #Proxy
    iptables -I INPUT 5 --src 72.163.128.140 -jACCEPT  #DNS
    iptables -I INPUT 6 --src 10.64.58.51 -jACCEPT   #NTP
    iptables -I INPUT 7 --src 10.196.5.225 -jACCEPT  #CUCM
    iptables -I OUTPUT 1 --dst $1 -jACCEPT
    iptables -I OUTPUT 3 --dst 127.0.0.1 -jACCEPT
    iptables -I OUTPUT 4 --dst 10.196.5.235 -jACCEPT
    iptables -I OUTPUT 5 --dst 72.163.128.140 -jACCEPT
    iptables -I OUTPUT 6 --dst 10.64.58.51 -jACCEPT
    iptables -I OUTPUT 7 --dst 10.196.5.225 -jACCEPT
    iptables -I INPUT 8 -jDROP
    iptables -I OUTPUT 8 -jDROP
}

set_ip_tables $1