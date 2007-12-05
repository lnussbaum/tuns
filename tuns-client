#!/usr/bin/ruby

require 'tun'
require 'socket'
require 'timeout'
require 'Net/DNS'
require 'base32'
require 'thread'
require 'dns'

Thread::abort_on_exception = true

RECV_TIMEOUT = 0.5
DELAY_MIN = 0
DELAY_INCR = 0.1
DELAY_MAX = 2
MIN_ONFLY=2
MAX_ONFLY=40
MTU=140

DEBUG = false

PKTSIZE=4096

tun = File::new('/dev/net/tun', File::RDWR)
dev = tun_allocate(tun)
system("ifconfig #{dev} 192.168.53.1 mtu #{MTU} up")
system("route add -net 192.168.53.0/24 dev #{dev}")
system("sudo sysctl -w net.ipv4.tcp_frto=1") # better for lossy links

server = ARGV[0]
UDPSocket.do_not_reverse_lookup = true
socket = UDPSocket.new
socket.connect(server, 53)
$smutex = Mutex::new

$schedmutex = Mutex::new
$onfly = 0

th_send = Thread::new(socket, tun) do |socket, tun|
  while (s = tun.sysread(2000))
    if s.length > 160
      puts "Packet too long (#{s.length}) !!"
      exit(1)
    end
    packet = dns_encode(s)
    dnspacket = Net::DNS::Packet::new_from_values("#{packet}.t.blop.info", 'CNAME', 'IN')
    $smutex.synchronize do
      if DEBUG
      puts "*" * 25 + ' SENDING DATA ' + '*' * 25
      p dnspacket
      end
      socket.send(dnspacket.data, 0)
    end
  end
end

$num_nothing = 0
$num_req = 0

def sendreq(socket)
  dnspacket = Net::DNS::Packet::new_from_values("d#{$num_req}.u.blop.info", 'CNAME', 'IN')
  $smutex.synchronize do
    $num_req += 1
    if DEBUG
      puts "*" * 25 + ' SENDING REQ ' + '*' * 25
    end
    socket.send(dnspacket.data,0)
    $schedmutex.synchronize do
      $onfly += 1
    end
    print '>'
    STDOUT.flush
  end
end

th_recv = Thread::new(socket, tun) do |socket, tun|
  sendreq(socket)
  while true
    ans, from = nil
    begin
      Timeout::timeout(RECV_TIMEOUT) do
        ans, from = socket.recvfrom(PKTSIZE/4)
      end
    rescue Timeout::Error
      print 'T'
      STDOUT.flush
      sendreq(socket)
      next
    end
    resp = Net::DNS::Packet.new_from_binary(ans)
    if DEBUG
      puts "*" * 25 + ' RECEIVED ' + '*' * 25
      p resp
    end
    if resp.header.ancount != 1
      print "#ANCOUNT#"
      sendreq(socket)
      next
    end
    if 'CNAME' != resp.answer[0].type
      puts "Error type"
      exit(1)
    end
    text = resp.answer[0].cname
    if text =~/t.blop.info$/
      print '.'
      STDOUT.flush
      length = text.gsub(/^length(\d+).t.blop.info$/, '\1').to_i
      diff = nil
      $schedmutex.synchronize do
        diff = length - $onfly + 1
        if $onfly + diff > MAX_ONFLY
          diff = MAX_ONFLY - $onfly
        end
      end
      (1..diff).each do
        # send reqs for additional packets
        print '+'
        STDOUT.flush
        sendreq(socket)
      end
      next
    elsif text !~ /u.blop.info$/
      puts "response unknown: #{text}"
      next
    end
    text.gsub!(/\.u\.blop\.info$/,'')
    $schedmutex.synchronize do
      $onfly -= 1
    end
    if text == 'zero'
      $num_nothing += 1
      delay = DELAY_MIN + ($num_nothing - 30) * DELAY_INCR
      if delay > DELAY_MAX
        delay = DELAY_MAX
      end
      if delay > 0
        print "S(#{delay})"
        STDOUT.flush
        sleep delay
        $schedmutex.lock
        if $onfly < MIN_ONFLY 
          $schedmutex.unlock
          sendreq(socket)
        else
          $schedmutex.unlock
        end
      end
    else
      sendreq(socket)
      $num_nothing = 0
      print '<'
      STDOUT.flush
      pack = dns_decode(text)
      tun.syswrite(pack)
    end
  end
end

th_recv.join
th_send.join
