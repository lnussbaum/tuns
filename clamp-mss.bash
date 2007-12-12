#!/bin/bash
# Example script to limit the MSS to the interface's MTU.

sudo iptables -I OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
