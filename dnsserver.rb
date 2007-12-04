#!/usr/bin/ruby

require 'tun'
require 'socket'
require 'timeout'
require 'Net/DNS'
require 'thread'
require 'dns'

Thread::abort_on_exception = true

tun = File::new('/dev/net/tun', File::RDWR)
dev = tun_allocate(tun)
system("ifconfig #{dev} 192.168.53.2 mtu 140 up")
system("route add -net 192.168.53.0/24 dev #{dev}")

PKTSIZE=4096
SERVERADDR=ARGV[0]
socket = UDPSocket.new
socket.bind(SERVERADDR, 53) 

DEBUG = false

queue = []
qmutex = Mutex::new

th_readtun = Thread::new(socket, tun) do |socket, tun|
  while (s = tun.sysread(2000))
    if s.length > 160
      puts "Packet too long (#{s.length}) !!"
      exit(1)
    end
    packet = dns_encode(s)
    qmutex.synchronize do
      queue.push(packet)
    end
  end
end

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

th_read = Thread::new(socket, tun) do |socket, tun|
  while recvdata = socket.recvfrom(PKTSIZE)
    rpack, sender = recvdata
    dnsp = Net::DNS::Packet::new_from_binary(rpack)
    q = dnsp.question[0]
    if DEBUG
      puts "*" * 25 + 'RECEIVED' + '*' * 25
      p dnsp
    end
    rep = build_reply(dnsp)
    if q.qtype != 'CNAME'
      puts "Invalid packet type: #{q.qtype}"
      next
    end
    if q.qname =~ /\.t\.blop\.info$/
      # we are receiving a packet
      text = q.qname.gsub(/\.t\.blop\.info$/, '')
      pack = dns_decode(text)
      tun.syswrite(pack)
      length = qmutex.synchronize { queue.length }
      rep.answer << Net::DNS::RR::new_from_hash(
        :name => q.qname,
        :ttl => 0,
        :type => 'CNAME',
        :cls => 'IN',
        :cname => "length#{length}.t.blop.info"
      ) 
      rep.header.ancount = 1
    elsif q.qname =~ /\.u\.blop\.info$/
      qmutex.synchronize do
        # we are given the chance to send something!
        if queue.length > 0
          text = queue.shift
          rep.answer << Net::DNS::RR::new_from_hash(
            :name => q.qname,
            :ttl => 0,
            :type => 'CNAME',
            :cls => 'IN',
            :cname => "#{text}.u.blop.info"
          )
        else 
          rep.answer << Net::DNS::RR::new_from_hash(
            :name => q.qname,
            :ttl => 0,
            :type => 'CNAME',
            :cls => 'IN',
            :cname => "zero.u.blop.info"
          )
        end
      end
      rep.header.ancount = 1
    else
      puts "Unknown QNAME! #{q.qname}"
      next
    end
    if DEBUG
      puts "*" * 25 + 'SENDING' + '*' * 25
      p rep
    end
    socket.send(rep.data, 0, sender[3], sender[1])
  end
end

th_readtun.join
th_readdns.join

