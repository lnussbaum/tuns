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
class TestEscapedChars < Test::Unit::TestCase
  def test_one
    #
    # We test al sorts of escaped non-ascii characters. 
    # This is all to be protocol conform... so to speak.
    
    #
    # The collection of tests is somewhat of a hodgepodge that tried to
    # assess sensitivity to combinations of characters that the regular
    # expressions and perl itself are sensitive to. (like \\\\\.\..)
    # Development versions of the code tried to split a domain name in
    # invidual labels by a regular expression. It made no sense to remove
    # the more ackward tests as they have to pass anyway ...
    
    
    # @todo Net::DNS still to have this functionality
    #~ message="Using the "
    #~ message+= if (Net::DNS::HAVE_XS) then " XS compiled " else " perl implemented " end
    #~ message+="dn_expand function "
    #~ diag (message)
    
    
    #~ had_xs=Net::DNS::HAVE_XS 
    
    
    # Note that in perl the \\ in a presentation format can only be achieved
    # through \\\\ .
    
    # The hex codes are the names in wireformat:
    # length octet. content octets, length octet, content , NULL octet
    
    
    
    # Below are test combos, 1st and 2nd array elements are
    # representations of the name. The output of the perl functions should
    # yield the 2nd presentation (eg \037 gets presented as % )
    
    # The 3rd element is a label count.
    # The 4th element represents the number of octets per label
    # The 5th element is a hexdump of the domain name in wireformat
    
    # The optional 6th element is a boolean instructing to use the perl
    # based dn_expand.  This because the conversion between the native
    # dn_expand output to a perl varialbe provides some problems.
    
    
    testcombos=[
    [
	 'bla\255.foo.org', 
	 'bla\255.foo.org',
    3,
    [4,3,3],
    #Wire:            4 b l a 0xff 3 f o o 3 o r g 0		  
	 "04626c61ff03666f6f036f726700" 
    ],
    
    [
	 'bla.f\xa9oo.org', 
	 'bla.f\169oo.org',
    3,
    [3,4,3] ,
    #Wire:            3 b l a 4 f 0xa9 o o 3 o r g 0		  
	 "03626c610466a96f6f036f726700" 		 
    ],   # Note hex to decimal
    ['bla.fo\.o.org',
	 'bla.fo\.o.org',
    3,
    [3,4,3],
    #Wire:            3 b l a 4 f o . o 3 o r g 0		  
	 "03626c6104666f2e6f036f726700"
    ],
    
    ['bla\0000.foo.org',
	 'bla\0000.foo.org',
    3,
    [5,3,3],
    #Wire:            5 b l a 0x00 0 3 f o o 3 o r g 0		  
	 "05626c61003003666f6f036f726700"  ,
    ],
    
    ['bla.fo\o.org',
	 'bla.foo.org',
    3,
    [3,3,3],
    #Wire:            3 b l a 3 f o o 3 o r g 0   ignoring backslash on input	  
	 "03626c6103666f6f036f726700",
    ],
    #drops the \
    ['bla(*.foo.org',
	 'bla\(*.foo.org',
    3,
    [5,3,3],
    
    #Wire:            5 b l a ( * 3 f o o 3 o r g 0		  
	 "05626c61282a03666f6f036f726700" 
    ],
    
    [' .bla.foo.org',
	 '\032.bla.foo.org',
    4,
    [1,3,3,3],
	 "012003626c6103666f6f036f726700",
    ],
    
    ['\\\\a.foo',
	 '\\\\a.foo',
    2,
    [2,3],
    #Wire:            2 \ a  3 f o o 0		  
	 "025c6103666f6f00"
    ],
    
    
    ['\\\\.foo',
	 '\\\\.foo',
    2,
    [1,3],
    #Wire:            1 \   3 f o o 0		  
	 "015c03666f6f00",
    ],
    
    ['a\\..foo',
	 'a\\..foo',
    2, 
    [2,3],
    #Wire:            2 a  . 3 f o o 0		  
	 "02612e03666f6f00"
    ],
    
    ['a\\.foo.org',
	 'a\\.foo.org',
    2, [5,3],
    #Wire:            5 a . f o o 3 o r g 0		  
	 "05612e666f6f036f726700" ,
    ],
    
    ['\..foo.org',
	 '\..foo.org',
    3,
    [1,3,3],		 
    
    #Wire:            1  . 3 f o o 3 o r g 0		  
	 "012e03666f6f036f726700" ,
    ],
    
    [
	 '\046.\046',
	 '\..\.',
    2,
    [1,1],
	 '012e012e00',
    ],
    
    [ # all non \w characters :-) 
	  '\000\001\002\003\004\005\006\007\008\009\010\011\012\013\014\015\016\017\018\019\020\021\022\023\024\025\026\027\028\029\030\031\032.\033\034\035\036\037\038\039\040\041\042\043\044\045\046\047\048.\058\059\060\061\062\063\064\065.\091\092\093\094\095\096.\123\124\125\126\127\128\129',
	  '\000\001\002\003\004\005\006\007\008\009\010\011\012\013\014\015\016\017\018\019\020\021\022\023\024\025\026\027\028\029\030\031\032.!\"#\$%&\'\(\)*+,-\./0.:\;<=>?\@A.[\\\\]^_`.{|}~\127\128\129',
    5,
    [33,16,8,6,7],
	  "21000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20102122232425262728292a2b2c2d2e2f30083a3b3c3d3e3f4041065b5c5d5e5f60077b7c7d7e7f808100",
    ],
    
    ]
    
    
    #foreach my $testinput (@testcombos){
    testcombos.each do |testinput|
      # test back and forth
      
      labels=Net::DNS.name2labels( testinput[0])
      
      
      #	assert_equal(testinput[1], Net::DNS::labels2name(labels), "consistent name2labels labels2name for " + testinput[0])
      
      
      # test number of labels
      assert_equal(testinput[2],labels.length(),"consistent labelcount (#{testinput[2]})")
      # test number of elements within label.
      i=0
      # Test length of each individual label
      while i<testinput[2]
        assert_equal(labels[i].length, testinput[3][i],
		    "labellength for label #{i} equals " + testinput[3][i].to_s)
        i = i + 1
      end
      
      wire=Net::DNS::RR._name2wire(testinput[0]) 
      
      wireinhex=wire.unpack("H*")[0]
      assert_equal( wireinhex,testinput[4], "Wireinhex for " + testinput[0] )
      # And now call DN_EXPAND
      
      if (Net::DNS::HAVE_XS)
        
        #SKIP: {
        #	    skip "No dn_expand_xs available", 1 unless $had_xs
        name,offset=dn_expand(wire,0)    
        assert_equal(name,testinput[1],"DN_EXPAND (xs) consistent")
      end
      
      #	}
      
      # @todo Net::DNS does not yet have this functionality
      #~ Net::DNS::HAVE_XS=0
      name,offset=Net::DNS::Packet.dn_expand(wire,0)    
      assert_equal(name.to_s,testinput[1].to_s,"DN_EXPAND (pp) consistent")
      #~ Net::DNS::HAVE_XS=had_xs
    end
    
    # PERL_DN_EXPAND: { 
    #	if  ($had_xs  && !$Net::DNS::DN_EXPAND_ESCAPES ){
    #		diag ("\ndisabling XS based dns_expand for a moment.")
    #		$Net::DNS::HAVE_XS=0 
    #	}
    
    # QUESTION SECTION
    #\\.eg.secret-wg.org.		IN	TXT
    #
    # ANSWER SECTION:
    #\\.eg.secret-wg.org.	10	IN	TXT	"WildCard Match"
    #
    # AUTHORITY SECTION:
    #eg.secret-wg.org.	600	IN	NS	ns.eg.secret-wg.org.
    #
    # ADDITIONAL SECTION:
    #ns.eg.secret-wg.org.	600	IN	A	10.0.53.208
    #
    
    uuencodedPacket=%w{
c8 d5 85 00 00 01 00 01  00 01 00 01 02 5c 5c 02 
65 67 09 73 65 63 72 65  74 2d 77 67 03 6f 72 67 
00 00 10 00 01 c0 0c 00  10 00 01 00 00 00 0a 00 
0f 0e 57 69 6c 64 43 61  72 64 20 4d 61 74 63 68 
c0 0f 00 02 00 01 00 00  02 58 00 05 02 6e 73 c0 
0f c0 4c 00 01 00 01 00  00 02 58 00 04 0a 00 35 
d0                 
}
    
    #	uuEncodedPacket =~ s/\s*//g
    #	uuEncodedPacket =uuEncodedPacket.gsub("\s*", "")
    #	packetdata = [uuEncodedPacket].pack('H*')
    
    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packetdata = packetdata.gsub("\s*", "")
    
    packet     = Net::DNS::Packet.new_from_binary(packetdata)
    assert(packet, "nil packet returned from binary data")
    assert_equal( (packet.answer)[0].name,'\\\\\\\\.eg.secret-wg.org',"Correctly dealt escaped backslash from wireformat \\\\.eg.secret-wg.org")
  end
  
  def test_esoteric_stuff
    # Now testing for the real esotheric stuff.
    # domain names can contain NULL and space characters (on the wire)
    # these should be properly expanded
    
    # This only works if the dn_expand_XS()  is NOT used.
    
    # The UUencoded packet contains a captured packet with this content:
    
    # QUESTION SECTION:
    #\000.n\032ll.eg.secret-wg.org.	IN	TXT
    
    # ANSWER SECTION:
    #\000.n ll.eg.secret-wg.org. 0	IN	TXT	"NULL byte ownername"
    #      ^ SPACE !!!
    # AUTHORITY SECTION:
    #eg.secret-wg.org.	600	IN	NS	ns.eg.secret-wg.org.
    
    # ADDITIONAL SECTION:
    #ns.eg.secret-wg.org.	600	IN	A	10.0.53.208
    
    uuencodedPacket =%w{
 a6 58 85 00 00 01 00 01  00 01 00 01 01 00 04 6e  
 20 6c 6c 02 65 67 09 73  65 63 72 65 74 2d 77 67  
 03 6f 72 67 00 00 10 00  01 c0 0c 00 10 00 01 00  
 00 00 00 00 14 13 4e 55  4c 4c 20 62 79 74 65 20  
 6f 77 6e 65 72 6e 61 6d  65 c0 13 00 02 00 01 00  
 00 02 58 00 05 02 6e 73  c0 13 c0 55 00 01 00 01  
 00 00 02 58 00 04 0a 00  35 d0                    
}
    
    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packetdata = packetdata.gsub("\s*", "")
    packet     = Net::DNS::Packet.new_from_binary(packetdata)
    assert_equal( '\000.n\\032ll.eg.secret-wg.org',(packet.answer)[0].name,"Correctly dealt with NULL bytes in domain names")
    
    
    #slightly modified \\ .eg.secret-wg.org instead of \\\\.eg.secret-wg.org
    #  That is escaped backslash space
    uuencodedPacket=%w{
c8 d5 85 00 00 01 00 01  00 01 00 01 02 5c 20 02 
65 67 09 73 65 63 72 65  74 2d 77 67 03 6f 72 67 
00 00 10 00 01 c0 0c 00  10 00 01 00 00 00 0a 00 
0f 0e 57 69 6c 64 43 61  72 64 20 4d 61 74 63 68 
c0 0f 00 02 00 01 00 00  02 58 00 05 02 6e 73 c0 
0f c0 4c 00 01 00 01 00  00 02 58 00 04 0a 00 35 
d0                 
}
    
    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packetdata.gsub!("\s*", "")
    packet     = Net::DNS::Packet.new_from_binary(packetdata)
    
    
    assert_equal( '\\\\\\032.eg.secret-wg.org',(packet.answer)[0].name,"Correctly dealt escaped backslash from wireformat \\e.eg.secret-wg.org")
    # @todo Replace when Net::DNS does this!
    #	if ( had_xs && !Net::DNS::HAVE_XS )
    #		puts("\nContinuing to use the XS based dn_expand()\n") 
    #		Net::DNS::HAVE_XS=1		
    #	end
    
    
    
    #slightly modified \\e.eg.secret-wg.org instead of \\\\.eg.secret-wg.org
    uuencodedPacket=%w{
c8 d5 85 00 00 01 00 01  00 01 00 01 02 5c 65 02 
65 67 09 73 65 63 72 65  74 2d 77 67 03 6f 72 67 
00 00 10 00 01 c0 0c 00  10 00 01 00 00 00 0a 00 
0f 0e 57 69 6c 64 43 61  72 64 20 4d 61 74 63 68 
c0 0f 00 02 00 01 00 00  02 58 00 05 02 6e 73 c0 
0f c0 4c 00 01 00 01 00  00 02 58 00 04 0a 00 35 
d0                 
}
    
    #	uuEncodedPacket =~ s/\s*//g
    #        packetdata = uuEncodedPacket.pack('H*')
    #        packetdata = packetdata.gsub("\s*", "")
    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packet     = Net::DNS::Packet.new_from_binary(packetdata)
    
    
    assert_equal( (packet.answer)[0].name,'\\\\e.eg.secret-wg.org',"Correctly dealt escaped backslash from wireformat \\e.eg.secret-wg.org")
    
    
    #slightly modified \\\..eg.secret-wg.org instead of \\e.eg.secret-wg.org
    uuencodedPacket=%w{
c8 d5 85 00 00 01 00 01  00 01 00 01 02 5c 65 02 
65 67 09 73 65 63 72 65  74 2d 77 67 03 6f 72 67 
00 00 10 00 01 c0 0c 00  10 00 01 00 00 00 0a 00 
0f 0e 57 69 6c 64 43 61  72 64 20 4d 61 74 63 68 
c0 0f 00 02 00 01 00 00  02 58 00 05 02 6e 73 c0 
0f c0 4c 00 01 00 01 00  00 02 58 00 04 0a 00 35 
d0                 
}
    
    ##	uuEncodedPacket =~ s/\s*//g
    #        packetdata = uuEncodedPacket.pack('H*')
    #        packetdata = packetdata.gsub("\s*", "")
    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packet     = Net::DNS::Packet.new_from_binary(packetdata)
    assert_equal( (packet.answer)[0].name,'\\\\e.eg.secret-wg.org',"Correctly dealt escaped backslash from wireformat \\\..eg.secret-wg.org")
    
    testrr=Net::DNS::RR.create(
		:name => '\\e.eg.secret-wg.org',
		:type         => 'TXT',
		:txtdata      => '"WildCard Match"',
		:ttl          =>  10,
		:class        => "IN"
    )
    
    
    
    klass = "IN" 
    ttl = 43200 
    name = 'def0au&lt.example.com' 
    
    
    
    rrs = [
    { #[0] 
			:name => '\..bla\..example.com', 
			:type => 'A', 
			:address => '10.0.0.1', 
    }, { #[2]
			:name => name,
			:type => 'AFSDB', 
			:subtype => 1, 
			:hostname =>'afsdb-hostname.example.com', 
    }, 
    { #[3]
			:name => '\\.funny.example.com',
			:type         => 'CNAME',
			:cname        => 'cname-cn\244ame.example.com',
    }, 
    {   #[4]
			:name => name,
			:type         => 'DNAME',
			:dname        => 'dn\222ame.example.com',
    },
    {	#[9]
			:name => name,
			:type         => 'MINFO',
			:rmailbx      => 'minfo\.rmailbx.example.com',
			:emailbx      => 'minfo\007emailbx.example.com',
    }, 
    
    {	#[13]
			:name => name,
			:type         => 'NS',
			:nsdname      => '\001ns-nsdname.example.com',
    },
    
    {	#[19]
			:name => name,
			:type         => 'SOA',
			:mname        => 'soa-mn\001ame.example.com',
			:rname        => 'soa\.rname.example.com',
			:serial       => 12345,
			:refresh      => 7200,
			:retry        => 3600,
			:expire       => 2592000,
			:minimum      => 86400,
    },
    
    ]
    
    #------------------------------------------------------------------------------
    # Create the packet.
    #------------------------------------------------------------------------------
    packet = nil
    packet = Net::DNS::Packet.new_from_values(name)
    assert(packet,         'Packet created')
    
    #	foreach my $data (@rrs) {
    rrs.each do |data|
      
      data.update({:ttl  => ttl,})
      
      packet.push(:answer, Net::DNS::RR.create(data))
    end
    
    
    #------------------------------------------------------------------------------
    # Re-create the packet from data.
    #------------------------------------------------------------------------------
    
    data = packet.data
    assert(data,            'Packet has data after pushes')
    
    packet = nil
    packet = Net::DNS::Packet.new_from_binary(data)
    
    assert(packet,          'Packet reconstructed from data')
    
    answer = packet.answer
    
    #	assert(answer && answer == rrs, 'Packet returned correct answer section')
    rrs.each do |rr|
      record = nil
      answer.each do |ansrec|
        if (ansrec.type == rr[:type])
          record = ansrec
          break
        end
      end
      assert(record!=nil, "can't find answer record for #{rr}")
      rr.keys.each do |key|
        assert_equal(record.send(key.to_s), rr[key], "value not right for key #{key} for rr #{rr}")
      end
    end
    
    
    while (answer.size>0 and rrs.size>0)
      data = rrs.shift
      rr   = answer.shift
      type = data[:type]
      #		foreach my $meth (keys %{$data}) {
       (data.keys.each do |meth|
        assert_equal(rr.send(meth), data[meth], "#{type} - #meth() correct")
        end)
        
        rr2 = Net::DNS::RR.new_from_string(rr.inspect)
        assert_equal(rr2.inspect, rr.inspect,   "#{type} - Parsing from string works")
      end
      
    end
  end
