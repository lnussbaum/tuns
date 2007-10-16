#!/usr/bin/ruby

require 'socket'
require 'Net/DNS'


###
# 4.2.1 UDP usage
# Messages carried by UDP are restricted to 512 bytes (not counting the IP
# or UDP headers).  Longer messages are truncated and the TC bit is set in
# the header.
PKTSIZE=4096
SERVERADDR=ARGV[0]
number = 0

socket = UDPSocket.new
socket.bind(SERVERADDR, 53) 

def build_reply(q)
  quest = q.question[0]
  rep = Net::DNS::Packet::new_from_values(quest.qname, quest.qtype, 'IN')
  rep.header.id = q.header.id
  rep.header.opcode = q.header.opcode
  rep.header.aa = 1
  rep.header.qr = 1 # response
  rep.header.rd = q.header.rd
  rep.header.ra = 0
  rep
end
while true
  packet, sender = socket.recvfrom(PKTSIZE)
  dnsp = Net::DNS::Packet::new_from_binary(packet)
  q = dnsp.question[0]
  rep = build_reply(dnsp)
  if q.qtype == 'A' and q.qname == 't-a.t.blop.info'
    rep.answer << Net::DNS::RR::new_from_hash(
      :name => 't-a.t.blop.info',
      :ttl => 0,
      :type => 'A',
      :cls => 'IN',
      :address => "1.2.3.4"
    )
    rep.header.ancount = 1
  elsif q.qtype == 'CNAME' and q.qname == 't-cname.t.blop.info'
    rep.answer << Net::DNS::RR::new_from_hash(
      :name => 't-cname.t.blop.info',
      :ttl => 0,
      :type => 'CNAME',
      :cls => 'IN',
      :cname => 'a' * 63 + '.' + 'b' * 63 + '.' + 'c' * 63 + '.' + 'd' * 40 + '.com'
    )
    rep.header.ancount = 1
  elsif q.qtype == 'TXT' and q.qname == 't-txt.t.blop.info'
    rep.answer << Net::DNS::RR::new_from_hash(
      :name => 't-txt.t.blop.info',
      :ttl => 0,
      :type => 'TXT',
      :cls => 'IN',
      :txtdata => "\"#{'abcde' * 10} test!!\""
    )
    rep.header.ancount = 1
  else
    puts "Non matching packet:"
    p dnsp
  end
  puts "*" * 25 + 'SENDING' + '*' * 25
  p rep
  socket.send(rep.data, 0, sender[3], sender[1])
end

