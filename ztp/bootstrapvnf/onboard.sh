#!/bin/bash

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin"
export PATH

reverseip () {
    local IFS
    IFS=.
    set -- $1
    echo $4.$3.$2.$1
}

UP_STATE="up-client"

PLUTO_MY_ID=`printf "$PLUTO_MY_ID"`
PLUTO_PEER_ID=`printf "$PLUTO_PEER_ID"`

LOG_FILE="/home/spyroot/scripts/debug.log"

exec > >(tee -a ${LOG_FILE} )
exec 2> >(tee -a ${LOG_FILE} >&2)

if ! [[ $PLUTO_VERB == $UP_STATE ]]; then
 exit 0
else
 echo "Starting onboarding script"
fi

INTERNAL_NET="192.168.10.0/24"
INTERNAL_NIC="ens192"
OUTSIDE_NIC="ens160"
ESXI_IP="192.168.10.99"
ESXI_HOST="192.168.10.99/32"

#sleep 2
#server=$(ipsec status | grep /32 | gawk '{sub(/\//," "); print $2}')

server=$PLUTO_MY_SOURCEIP
reversed=$(reverseip $PLUTO_MY_SOURCEIP)

if [[ -z $server ]]; then
  echo "Server variable is empty."
  exit 0
fi

route=$(ip route show table 220 | grep $INTERNAL_NIC)
echo $server

if [[ -z $route ]]; then
  echo "Adding route to a table 220"
  ip route add table 220 $INTERNAL_NET dev $INTERNAL_NIC
  ip route add table 220 192.168.1.0/24 dev ens160
fi

echo "server 192.168.254.244
zone vmwaremybootstrap.com
update delete $HOSTNAME.sub.vmwaremybootstrap.com.  A
update add $HOSTNAME.sub.vmwaremybootstrap.com. 60 A $server
send" | nsupdate -k /home/spyroot/scripts/ddns.key

echo "server 192.168.254.244
update delete $reversed.in-addr.arpa. PTR
update add $reversed.in-addr.arpa. 60 PTR $HOSTNAME.sub.vmwaremybootstrap.com.
send" | nsupdate -k /home/spyroot/scripts/ddns.key -v
~

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t raw -F
iptables -t raw -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 2222 -j DNAT --to $ESXI_IP:22
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 22 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 22 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
#iptables -t nat -A POSTROUTING -o $INTERNAL_NIC -j MASQUERADE
iptables -t nat -A POSTROUTING -o ens160 -j MASQUERADE
iptables -A POSTROUTING -t nat -p icmp -s 192.168.10.99 -o ens160 -j SNAT --to $server


iptables -t nat -A PREROUTING -i ens192 -p udp --dport 902 -j DNAT --to 172.16.254.203
iptables -t nat -A POSTROUTING -o ens160 -p udp --dport 902 -j MASQUERADE



iptables -t nat -I PREROUTING -p tcp -d $server --dport 80 -j DNAT --to $ESXI_IP:80
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 80 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 80 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 443 -j DNAT --to $ESXI_IP:443
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 443 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 443 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 427 -j DNAT --to $ESXI_IP:427
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 427 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 427 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p udp -d $server --dport 427 -j DNAT --to $ESXI_IP:427
iptables -A FORWARD -s $ESXI_HOST -p udp -m udp --sport 427 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p udp -m udp --dport 427 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 902 -j DNAT --to $ESXI_IP:902
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 902 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 902 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p udp -d $server --dport 902 -j DNAT --to $ESXI_IP:902
iptables -A FORWARD -s $ESXI_HOST -p udp -m udp --sport 902 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p udp -m udp --dport 902 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 903 -j DNAT --to $ESXI_IP:903
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 903 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 903 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 3260 -j DNAT --to $ESXI_IP:3260
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 3260 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 3260 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 5900 -j DNAT --to $ESXI_IP:5900
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 5900 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 5900 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 5671 -j DNAT --to $ESXI_IP:5671
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 5671 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 5671 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 5988 -j DNAT --to $ESXI_IP:5988
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 5988 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 5988 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 5989 -j DNAT --to $ESXI_IP:5989
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 5989 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 5989 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 8889 -j DNAT --to $ESXI_IP:8889
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 8889 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 8889 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p udp -d 192.168.10.1 --dport 902 -j DNAT --to 172.16.254.203:902
#iptables -t nat -A PREROUTING -p udp --dport 902 -j DNAT --to-destination 172.16.254.203:902
iptables -t nat -A POSTROUTING -p udp -d 172.16.254.203 --dport 902 -j SNAT --to-source 192.168.10.1

iptables -t nat -I PREROUTING -p tcp -d 192.168.10.1 --dport 902 -j DNAT --to 172.16.254.203:902
iptables -t nat -A POSTROUTING -p tcp -d 172.16.254.203 --dport 902 -j SNAT --to-source 192.168.10.1

iptables -t nat -I PREROUTING -p tcp -d $server --dport 8000 -j DNAT --to $ESXI_IP:8000
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 8000 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 8000 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 8080 -j DNAT --to $ESXI_IP:8080
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 8080 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 8080 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 9000 -j DNAT --to $ESXI_IP:9000
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 9000 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 9000 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p tcp -d $server --dport 9080 -j DNAT --to $ESXI_IP:9080
iptables -A FORWARD -s $ESXI_HOST -p tcp -m tcp --sport 9080 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p tcp -m tcp --dport 9080 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p udp -d $server --dport 8301 -j DNAT --to $ESXI_IP:8301
iptables -A FORWARD -s $ESXI_HOST -p udp -m udp --sport 8301 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p udp -m udp --dport 8301 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t nat -I PREROUTING -p udp -d $server --dport 8302 -j DNAT --to $ESXI_IP:8302
iptables -A FORWARD -s $ESXI_HOST -p udp -m udp --sport 8302 -j ACCEPT
iptables -A FORWARD -d $ESXI_HOST -p udp -m udp --dport 8302 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT


/home/spyroot/scripts/set_vmk.py $server