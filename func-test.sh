#!/bin/bash
if [[ "`id | grep 'uid=0(' | wc -l`" == "0" ]]
 then
  echo "This program needs to be root!"
  exit 1
fi
iptables-save > iptables.backup
echo "Setting up iptables"
#./setup-iptables.sh --port 5000
./scripts/phxclient.py&
UIPID=$!
echo "Starting daemon" 
./src/phoenix&
DPID=$!
sleep 2
echo "Starting main testing loop"
for i in `seq 1 10`
 do
  echo "Starting netcat server..."
  netcat -l -p 5000 &
  echo "Starting netcat client..."
  echo hello | netcat localhost 5000 -q 0
  echo "Netcat session ended!"
  cat /proc/net/netfilter/nfnetlink_queue
 done
echo "Killing GUI"
kill $UIPID
echo "Printing nfnetlink_queue statistics"
cat /proc/net/netfilter/nfnetlink_queue
echo "Killing daemon"
kill $DPID
iptables -L -v
cat iptables.backup | iptables-restore
