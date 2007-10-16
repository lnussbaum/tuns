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
(1..200).each do |i|
  packet = Net::DNS::Packet::new_from_values('t-cname.t.blop.info', 'CNAME', 'IN')
  ts = Time::now
  socket.send(packet.data, 0)
  ans, from = nil
  begin
    Timeout::timeout(1) do
      ans, from = socket.recvfrom(PSIZE)
    end
  rescue Timeout::Error
    puts "#{i} TIMEOUT"
    next
  end
  resp = Net::DNS::Packet.new_from_binary(ans)
  if resp.header.ancount != 1
    puts "Error ancount"
    exit(1)
  end
  if 'CNAME' != resp.answer[0].type
    puts "Error type"
    exit(1)
  end
  if 'a' * 63 + '.' + 'b' * 63 + '.' + 'c' * 63 + '.' + 'd' * 40 + '.com' != resp.answer[0].cname
    puts "Error content"
    exit(1)
  end
  tr = Time::now
  puts "#{i} #{tr - ts}"
  ok += 1
end
puts "OK: #{ok}/100"
