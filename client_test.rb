#!/usr/bin/ruby

require 'test/unit'
require 'socket'
require 'timeout'
require 'Net/DNS'

TIMEOUT = 3
PSIZE = 512

class DNSTest < Test::Unit::TestCase

  def setup
    @server = ENV['DNS_SERVER']
    raise "Please set DNS_SERVER." if @server.nil?
    @socket = UDPSocket.new
    @socket.connect(@server, 53)
  end

  def test_a
    packet = Net::DNS::Packet::new_from_values('t-a.t.blop.info', 'A', 'IN')
    @socket.send(packet.data, 0)
    ans, from = @socket.recvfrom(PSIZE)
    resp = Net::DNS::Packet.new_from_binary(ans)
    assert_equal(1, resp.header.ancount)
    assert_equal('A', resp.answer[0].type)
    assert_equal('1.2.3.4', resp.answer[0].address)
  end

  def test_ma
    test_a
    test_a
    test_a
    test_a
    test_a
    test_a
  end
  def test_cname
    packet = Net::DNS::Packet::new_from_values('t-cname.t.blop.info', 'CNAME', 'IN')
    @socket.send(packet.data, 0)
    ans, from = @socket.recvfrom(PSIZE)
    resp = Net::DNS::Packet.new_from_binary(ans)
    assert_equal(1, resp.header.ancount)
    assert_equal('CNAME', resp.answer[0].type)
    assert_equal('a' * 63 + '.' + 'b' * 63 + '.' + 'c' * 63 + '.' + 'd' * 40 + '.com', resp.answer[0].cname)
  end

  def test_txt
    packet = Net::DNS::Packet::new_from_values('t-txt.t.blop.info', 'txt', 'IN')
    @socket.send(packet.data, 0)
    ans, from = @socket.recvfrom(PSIZE)
    resp = Net::DNS::Packet.new_from_binary(ans)
    assert_equal(1, resp.header.ancount)
    assert_equal('TXT', resp.answer[0].type)
    p resp.answer[0].txtdata.class
    assert_equal('abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcde test!!', resp.answer[0].txtdata)
  end
end
