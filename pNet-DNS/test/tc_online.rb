#--
#Copyright 2007 Nominet UK
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License. 
#You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0 
#
#Unless required by applicable law or agreed to in writing, software 
#distributed under the License is distributed on an "AS IS" BASIS, 
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#See the License for the specific language governing permissions and 
#limitations under the License.
#++
require 'rubygems'
require 'test/unit'
require 'Net/DNS'
require 'socket'
class TestOnline < Test::Unit::TestCase
  def test_online
    res = Net::DNS::Resolver.new
    rrs = [
    {
      :type   		=> 'A',
      :name   		=> 'a.t.net-dns.org',
      :address 	=> '10.0.1.128'
    },
    {
      :type		=> 'MX',
      :name		=> 'mx.t.net-dns.org',
      :exchange	=> 'a.t.net-dns.org',
      :preference 	=> 10
    },
    {
      :type		=> 'CNAME',
      :name		=> 'cname.t.net-dns.org',
      :cname		=> 'a.t.net-dns.org'
    },
    {
      :type		=> 'TXT',
      :name		=> 'txt.t.net-dns.org',
      :txtdata		=> 'Net-DNS'
    }		
    ]		
    
     (rrs.each do |data|
      packet = res.send(data[:name], data[:type], 'IN')
      
      assert(packet, "Got an answer for #{data[:name]} IN #{data[:type]}")
      assert_equal(1, packet.header.qdcount, 'Only one question')
      assert_equal(1, packet.header.ancount, 'Got single answer')
      
      question = (packet.question)[0]
      answer   = (packet.answer)[0]
      
      assert(question,                           'Got question'            )
      assert_equal(data[:name],  question.qname,  'Question has right name' )
      assert_equal(data[:type],  question.qtype,  'Question has right type' )
      assert_equal('IN',             question.qclass, 'Question has right class')
      
      assert(answer)
      assert_equal(answer.rrclass,    'IN',             'Class correct'           )
      
      
      #	foreach meth (keys %{data}) {
       (data.keys.each do |meth| 
        assert_equal(answer.send(meth), data[meth], "#{meth} correct (#{data[:name]})") 
        end)
        end) # do
      end # test_online
      
      def test_mx
        # Does the mx() function work.
        mx = Net::DNS.mx('mx2.t.net-dns.org')
        
        wanted_names = ['a.t.net-dns.org', 'a2.t.net-dns.org']
        names = mx.collect { |i| i.exchange } # $_.exchange)
        #names        = [ map { $_.exchange } @mx ]
        
        assert_equal(names, wanted_names, "mx() seems to be working")
        
        # some people seem to use mx() in scalar context
        assert_equal(2, Net::DNS.mx('mx2.t.net-dns.org').length,  "mx() works in scalar context")
        
        #
        # test that search() and query() DTRT with reverse lookups
        #
        tests = [
        {
          :ip => '198.41.0.4',
          :host => 'a.root-servers.net',
        },
        {
          :ip => '2001:500:1::803f:235',
          :host => 'h.root-servers.net',
        },
        ]
        
        res = Net::DNS::Resolver.new
        testWords = ['search', 'query']
        #	foreach test (@tests) {
        tests.each do |test| 
          #		foreach method (qw(search query)) {
          testWords.each do |method|
            packet = res.send_method(method, test[:ip])
            
            assert_instance_of(Net::DNS::Packet,packet)
            
            next unless packet
            
            assert_equal((packet.answer)[0].ptrdname, test[:host], "method(#{test[:ip]}) works")
          end # do
        end # do
      end # test_mx
      
      def test_search_query
        res = Net::DNS::Resolver.new(
                                     :domain     => 't.net-dns.org',
        :searchlist => ['t.net-dns.org', 'net-dns.org']
        )
        
        
        #
        # test the search() and query() append the default domain and 
        # searchlist correctly.
        #
        res.defnames=(1) 
        res.dnsrch=(1)
        res.persistent_udp=(0)
        
        tests = [
        {
          :method => 'search',
          :name   => 'a'
        },
        {
          :method => 'search',
          :name   => 'a.t'
        },
        {
          :method => 'query',
          :name   => 'a'
        }
        ]
        
        
        tests.each do |test|
          method = test[:method]
          
          ans = res.send_method(method,test[:name])
          
          assert_instance_of(Net::DNS::Packet, ans)
          
          assert_equal(ans.header.ancount, 1,"Correct answer count (with method)")
          a = ans.answer[0]
          
          assert_instance_of(Net::DNS::RR::A, a)
          assert_equal(a.name, 'a.t.net-dns.org',"Correct name (with method)")
        end
        socket=res.bgsend('a.t.net-dns.org','A')
        assert(socket.is_a?(UDPSocket),"Socket returned")
        
        # burn a little CPU to get the socket ready.
        sleep(0.1)
        res.debug=false
        
        assert(res.bgisready(socket),"Socket is ready")
        if res.bgisready(socket)
          
          ans= res.bgread(socket)
          socket = nil
          assert_equal(ans.header.ancount, 1,"Correct answer count")	
          a=ans.answer
          
          assert_instance_of(Net::DNS::RR::A,a[0])
          assert_equal(a[0].name, 'a.t.net-dns.org',"Correct name")
        else
          print "No socket to read from"
        end
      end
      
      
      def test_searchlist
        res = Net::DNS::Resolver.new(
	:domain     => 't.net-dns.org',
	:searchlist => ["t.net-dns.org", "net-dns.org"]
        )
        
        #
        # test the search() and query() append the default domain and 
        # searchlist correctly.
        #
        
        res.defnames=(1) 
        res.dnsrch=(1)
        res.persistent_udp=(1)
        #	res.debug(1)
        tests = [
        {
			:method => 'search',
			:name   => 'a'
        },
        {
			:method => 'search',
			:name   => 'a.t'
        },
        {
			:method => 'query',
			:name   => 'a'
        }
        ]
        
        #          res.send("a.t.net-dns.org A")
        res.send("a.t.net-dns.org",  "A")
        
        sock_id= res.sockets['AF_INET']["UDP"]
        assert(sock_id,"Persistent UDP socket identified")
        
         (tests.each do |test|
          method = test[:method]
          
          ans = res.send_method(method,test[:name])
          assert_equal(  res.sockets['AF_INET']["UDP"],sock_id,"Persistent socket matches")
          
          assert_instance_of(Net::DNS::Packet, ans)
          
          assert_equal(1, ans.header.ancount, "Correct answer count (with persistent socket and method)")
          
          a = ans.answer
          
          assert_instance_of(Net::DNS::RR::A, a[0])
          assert_equal(a[0].name, 'a.t.net-dns.org',"Correct name (with persistent socket and method)")
          end)
          
        end
      end
