#!/usr/bin/ruby

require 'socket'
require 'timeout'
require 'Net/DNS'

TIMEOUT = 5
PKTSIZE=4096
$server = ARGV[0]
socket = UDPSocket.new

packet = Net::DNS::Packet::new_from_values('t-a.t.blop.info', 'A', 'IN')
#packet = Net::DNS::Packet::new_from_values('etoile.blop.info', 'A', 'IN')
ans = nil
response = ""
socket.send(packet.data,0,$server,53)
ans = socket.recvfrom(PKTSIZE)
response = Net::DNS::Packet.new_from_binary(ans[0],ans[1])
p response
