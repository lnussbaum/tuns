#!/bin/bash

set -x

DEFR=$(netstat -rn | grep "^0.0.0.0 " | awk '{print $2}')
sudo route delete default gw $DEFR
NS=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
for i in $NS; do
sudo route add -host $i gw $DEFR
done
sudo route add -host 80.248.208.235 gw $DEFR
sudo route add default gw 192.168.53.2

