#!/bin/bash
# Limits the MSS to the interface's MTU.

iptables -I OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
