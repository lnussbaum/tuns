#!/bin/bash
# Modifies the routing table so that everything goes through
# TUNS except stuff going to the DNS servers.
# Should do "the right thing".

set -x
DEFR=$(netstat -rn | grep "^0.0.0.0 " | awk '{print $2}')
route delete default gw $DEFR
NS=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
for i in $NS; do
  route add -host $i gw $DEFR
done
route add default gw 192.168.53.2

