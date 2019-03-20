#!/usr/bin/env bash
if [ $# -lt 2 ]; then
echo "USAGE: $0 <Dev Box IP> <VCS IP>"
exit 1
fi

set_ip_tables(){
    iptables -I INPUT 1 --src $1 -jACCEPT
    iptables -I INPUT 2 --src $2 -jACCEPT
    iptables -I INPUT 3 --src 127.0.0.1 -jACCEPT
    iptables -I INPUT 4 --src 10.47.27.110 -jACCEPT
    iptables -I INPUT 5 --src 10.47.1.61 -jACCEPT
    iptables -I INPUT 6 --src 10.47.1.14 -jACCEPT
    iptables -I INPUT 7 --src 10.47.227.5 -jACCEPT
    iptables -I OUTPUT 1 --dst $1 -jACCEPT
    iptables -I OUTPUT 2 --dst $2 -jACCEPT
    iptables -I OUTPUT 3 --dst 127.0.0.1 -jACCEPT
    iptables -I OUTPUT 4 --dst 10.47.27.110 -jACCEPT
    iptables -I OUTPUT 5 --dst 10.47.1.61 -jACCEPT
    iptables -I OUTPUT 6 --dst 10.47.1.14 -jACCEPT
    iptables -I OUTPUT 7 --dst 10.47.227.5 -jACCEPT
    iptables -I INPUT 8 -jDROP
    iptables -I OUTPUT 8 -jDROP
}

set_ip_tables $1 $2
