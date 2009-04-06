#!/bin/bash
iptables -F
iptables -X
iptables -N newinqueue
iptables -N newoutqueue
iptables -A INPUT -m mark --mark 1/1 -j newinqueue
iptables -A OUTPUT -m mark --mark 2/2 -j newoutqueue
iptables -A newinqueue -j NFQUEUE --queue-num 2
iptables -A newoutqueue -j NFQUEUE --queue-num 3
iptables -A INPUT -p tcp -m state --state NEW -j NFQUEUE --queue-num 1
iptables -A OUTPUT -p tcp -m state --state NEW -j NFQUEUE --queue-num 0

