#!/bin/bash
ports=""
while [ "x$1" != "x" ]
 do
  if [ "x$1" == "x--all-ports" ]
  then
    if [ "x$ports" != "x" ]
    then
       echo "Warning, --all-port specified with other port numbers, all ports are used!"
    fi
    ports="all"
    numtoshift=1
  fi
  if [ "x$1" == "x--port" ]
  then
    if [ "x$ports" == "x" ]
    then
	ports="$2"
    else
	ports="$2,$ports"
    fi
    numtoshift=2
  fi
  if [ "x${1:0:2}" != "x--" ]
  then
   echo "Wrong parameter!"
   exit 1
  fi
  shift $numtoshift
 done
if [ "x$ports" == "x" ]
then 
  ports="all"
fi
iptables -F
iptables -X
iptables -N newinqueue
iptables -N newoutqueue
iptables -N rejectoutqueue
iptables -A rejectoutqueue -j REJECT
iptables -A INPUT -m mark --mark 0x1/0xff -j newinqueue
iptables -A OUTPUT -m mark --mark 0x2/0xff -j newoutqueue
iptables -A OUTPUT -m mark --mark 0x3/0xff -j rejectoutqueue
iptables -A newinqueue -j NFQUEUE --queue-num 2
iptables -A newoutqueue -j NFQUEUE --queue-num 3
iptables -A INPUT -p tcp -m state --state NEW -j NFQUEUE --queue-num 1
#iptables -A OUTPUT -p tcp -m state --dport 2000 --state NEW -j NFQUEUE --queue-num 0
if [ "x$ports" == "xall" ]
then
  iptables -A OUTPUT -p tcp -m state --state NEW -j NFQUEUE --queue-num 0
else
  iptables -A OUTPUT -p tcp -m state --state NEW -m multiport --dports "$ports" -j NFQUEUE --queue-num 0
fi
