#!/bin/bash
# Example script that modifies the routing table so that
# everything goes through TUNS except stuff going to the DNS
# servers.

set -x
DEFR=$(netstat -rn | grep "^0.0.0.0 " | awk '{print $2}')
sudo route delete default gw $DEFR
NS=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
for i in $NS; do
  sudo route add -host $i gw $DEFR
done
sudo route add default gw 192.168.53.2

