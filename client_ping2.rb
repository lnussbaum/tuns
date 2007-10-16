#!/usr/bin/ruby

require 'socket'
require 'timeout'
require 'Net/DNS'

TIMEOUT = 3
PSIZE = 512

server = ENV['DNS_SERVER']
socket = UDPSocket.new
socket.connect(server, 53)
ok = 0
(1..10).each do |i|
  packet = Net::DNS::Packet::new_from_values('t-cname.t.blop.info', 'CNAME', 'IN')
  socket.send(packet.data, 0)
end
(1..10).each do |i|
  ans, from = socket.recvfrom(PSIZE)
  resp = Net::DNS::Packet.new_from_binary(ans)
  p resp
end
