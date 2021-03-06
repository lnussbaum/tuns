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
class TestPacket < Test::Unit::TestCase
  def test_packet
      domain = "example.com"
      type = "MX"
      klass = "IN"
      
      packet = Net::DNS::Packet.new_from_values(domain, type, klass)
      
      assert(packet,                                 'new() returned something');         #2
      assert(packet.header,                         'header() method works');            #3
      assert_instance_of(Net::DNS::Header,packet.header,'header() returns right thing');     #4
      
      
      question = packet.question;
      assert(question && question.length == 1,             'question() returned right number of items'); #5
      assert_instance_of(Net::DNS::Question,question[0], 'question() returned the right thing');       #6
      
      
      answer = packet.answer;
      assert(answer.length == 0,     'answer() works when empty');     #7
      
      
      authority = packet.authority;
      assert(authority.length == 0,  'authority() works when empty');  #8
      
      additional = packet.additional;
      assert(additional.length == 0, 'additional() works when empty'); #9
      
      packet.push(:answer, Net::DNS::RR.create(   { 
              :name    => "a1.example.com", 
		      :type    => "A",  
		      :address => "10.0.0.1"}));
      assert_equal(1, packet.header.ancount, 'First push into answer section worked');      #10
      
      
      packet.push(:answer, Net::DNS::RR.create({:name    => "a2.example.com",
		      :type    => "A", :address => "10.0.0.2"}));
      assert_equal(packet.header.ancount, 2, 'Second push into answer section worked');     #11
      
      
      packet.push(:authority, Net::DNS::RR.create({:name    => "a3.example.com",
		      :type    => "A",
		      :address => "10.0.0.3"}));
      assert_equal(1, packet.header.nscount, 'First push into authority section worked');   #12
      
      
      packet.push(:authority, Net::DNS::RR.create( {
		      :name    => "a4.example.com",
		      :type    => "A",
		      :address => "10.0.0.4"}));
      assert_equal(2, packet.header.nscount, 'Second push into authority section worked');  #13
      
      packet.push(:additional, Net::DNS::RR.create({
		      :name    => "a5.example.com",
		      :type    => "A",
		      :address => "10.0.0.5"}));
      assert_equal(1, packet.header.adcount, 'First push into additional section worked');  #14
      
      packet.push(:additional, Net::DNS::RR.create(  {
		      :name    => "a6.example.com",
		      :type    => "A",
		      :address => "10.0.0.6"}));
      assert_equal(2, packet.header.adcount, 'Second push into additional section worked'); #15
      
      data = packet.data;
      
      packet2 = Net::DNS::Packet.new_from_binary(data);
      
      assert(packet2, 'new() from data buffer works');   #16

      assert_equal(packet.inspect, packet2.inspect, 'inspect() works correctly');  #17
      
      
      string = packet2.inspect
      6.times do |count|
            	ip = "10.0.0.#{count+1}";
      	assert(string =~ /#{ip}/,  "Found #{ip} in packet");  # 18 though 23
      end
      
      assert_equal(1, packet2.header.qdcount, 'header question count correct');   #24
      assert_equal(2, packet2.header.ancount, 'header answer count correct');     #25
      assert_equal(2, packet2.header.nscount, 'header authority count correct');  #26 
      assert_equal(2, packet2.header.adcount, 'header additional count correct'); #27
      
      
      
      # Test using a predefined answer. This is an answer that was generated by a bind server.
      #
      
#      data=["22cc85000001000000010001056461636874036e657400001e0001c00c0006000100000e100025026e730472697065c012046f6c6166c02a7754e1ae0000a8c0000038400005460000001c2000002910000000800000050000000030"].pack("H*");
uuencodedPacket =%w{
22 cc 85 00 00 01 00 00 00 01 00 01 05 64 61 63 
68 74 03 6e 65 74 00 00 1e 00 01 c0 0c 00 06 00 
01 00 00 0e 10 00 25 02 6e 73 04 72 69 70 65 c0 
12 04 6f 6c 61 66 c0 2a 77 54 e1 ae 00 00 a8 c0 
00 00 38 40 00 05 46 00 00 00 1c 20 00 00 29 10 
00 00 00 80 00 00 05 00 00 00 00 30
}
    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')

#      packet3 = Net::DNS::Packet.new_from_binary(data);
      packet3 = Net::DNS::Packet.new_from_binary(packetdata);
      assert(packet3,                                 'new(\data) returned something');         #28
      
      assert_equal(packet3.header.qdcount, 1, 'header question count in syntetic packet correct');   #29
      assert_equal(packet3.header.ancount, 0, 'header answer count in syntetic packet correct');     #30
      assert_equal(packet3.header.nscount, 1, 'header authority count in syntetic packet  correct'); #31 
      assert_equal(packet3.header.adcount, 1, 'header additional in sytnetic  packet correct');      #32
      
      rr=packet3.additional;
      
      assert_equal('OPT', rr[0].type, "Additional section packet is EDNS0 type");                         #33
      assert_equal(4096, rr[0].rrclass, "EDNS0 packet size correct");                                     #34
      
      question2=Net::DNS::Question.new("bla.foo",'TXT','CHAOS');
      assert_instance_of(Net::DNS::Question,question2,"Proper type of object created");  #35
      
      # In theory its valid to have multiple questions in the question section.
      # Not many servers digest it though.
      
      packet.push(:question, question2);
      question = packet.question;
      assert_equal(2, question.length,             'question() returned right number of items poptest:2'); #36
      
      
      packet.pop(:question);
      
      question = packet.question;
      assert_equal(1, question.length,             'question() returned right number of items poptest:1'); #37
      
      packet.pop(:question);
      
      question = packet.question;
      
      
      assert_equal(0, question.length,              'question() returned right number of items poptest0'); #38
      
  end    
      
      
   def test_push
      packet=Net::DNS::Packet.new_from_values("254.9.11.10.in-addr.arpa","PTR","IN");
      
      packet.push(:answer, Net::DNS::RR.create(%q[254.9.11.10.in-addr.arpa 86400 IN PTR host-84-11-9-254.customer.example.com]));
      
      packet.push(:authority, Net::DNS::RR.create("9.11.10.in-addr.arpa 86400 IN NS autons1.example.com"));
      packet.push(:authority, Net::DNS::RR.create("9.11.10.in-addr.arpa 86400 IN NS autons2.example.com"));
      packet.push(:authority, Net::DNS::RR.create("9.11.10.in-addr.arpa 86400 IN NS autons3.example.com"));

      data=packet.data;
      packet2=Net::DNS::Packet.new_from_binary(data);

      assert_equal(packet.inspect,packet2.inspect,"Packet to data and back (failure indicates brasserten dn_comp)");  #39
      
    end
end
