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
class TestRR < Test::Unit::TestCase
  # @todo Add DNSSEC stuff when DNSSEC exists
  def test_rr
    #------------------------------------------------------------------------------
    # Canned data.
    #------------------------------------------------------------------------------
    
    name			= "foo.example.com";
    klass			= "IN";
    ttl				= 43200;
    
    rrs = [
    {  	#[0]
		:type        => 'A',
	 	:address     => '10.0.0.1',  
    }, 
    {	#[1]
		:type      => 'AAAA',
		:address     => '102:304:506:708:90a:b0c:d0e:ff10',
    }, 
    {	#[2]
		:type         => 'AFSDB',
		:subtype      => 1,
		:hostname     => 'afsdb-hostname.example.com',
    }, 
    {	#[3]
		:type         => 'CNAME',
		:cname        => 'cname-cname.example.com',
    }, 
    {   #[4]
		:type         => 'DNAME',
		:dname        => 'dname.example.com',
    },
    {	#[5]
		:type         => 'HINFO',
		:cpu          => 'test-cpu',
		:os           => 'test-os',
    }, 
    {	#[6]
		:type         => 'ISDN',
		:address      => '987654321',
		:sa           => '001',
    }, 
    {	#[7]
		:type         => 'MB',
		:madname      => 'mb-madname.example.com',
    }, 
    {	#[8]
		:type         => 'MG',
		:mgmname      => 'mg-mgmname.example.com',
    }, 
    {	#[9]
		:type         => 'MINFO',
		:rmailbx      => 'minfo-rmailbx.example.com',
		:emailbx      => 'minfo-emailbx.example.com',
    }, 
    {	#[10]
		:type         => 'MR',
		:newname      => 'mr-newname.example.com',
    }, 
    {	#[11]
		:type         => 'MX',
		:preference   => 10,
		:exchange     => 'mx-exchange.example.com',
    },
    {	#[12]
		:type        => 'NAPTR',
		:order        => 100,
		:preference   => 10,
		:flags        => 'naptr-flags',
		:service      => 'naptr-service',
		:regexp       => 'naptr-regexp',
		:replacement  => 'naptr-replacement.example.com',
    },
    {	#[13]
		:type         => 'NS',
		:nsdname      => 'ns-nsdname.example.com',
    },
    {	#[14]
		:type         => 'NSAP',
		:afi          => '47',
		:idi          => '0005',
		:dfi          => '80',
		:aa           => '005a00',
		:rd           => '1000',
		:area         => '0020',
		:id           => '00800a123456',
		:sel          => '00',
    },
    {	#[15]
		:type         => 'PTR',
		:ptrdname     => 'ptr-ptrdname.example.com',
    },
    {	#[16] 
		:type         => 'PX',
		:preference   => 10,
		:map822       => 'px-map822.example.com',
		:mapx400      => 'px-mapx400.example.com',
    },
    {	#[17]
		:type         => 'RP',
		:mbox		 => 'rp-mbox.example.com',
		:txtdname     => 'rp-txtdname.example.com',
    },
    {	#[18]
		:type         => 'RT',
		:preference   => 10,
		:intermediate => 'rt-intermediate.example.com',
    },
    {	#[19]
		:type         => 'SOA',
		:mname        => 'soa-mname.example.com',
		:rname        => 'soa-rname.example.com',
		:serial       => 12345,
		:refresh      => 7200,
		:retry        => 3600,
		:expire       => 2592000,
		:minimum      => 86400,
    },
    {	#[20]
		:type         => 'SRV',
		:priority     => 1,
		:weight       => 2,
		:port         => 3,
		:target       => 'srv-target.example.com',
    },
    {	#[21]
		:type         => 'TXT',
		:txtdata      => 'txt-txtdata',
    },
    {	#[22]
		:type         => 'X25',
		:psdn         => 123456789,
    },
    {	#[23]
		:type        => 'LOC',
		:version      => 0,
		:size         => 3000,
		:horiz_pre    => 500000,
		:vert_pre     => 500,
		:latitude     => 2001683648,
		:longitude    => 1856783648,
		:altitude     => 9997600,
    }, 	#[24]
    {
		:type         => 'CERT',
		:format     => 3,
		:tag			 => 1,
		:algorithm    => 1,
		:certificate  => '123456789abcdefghijklmnopqrstuvwxyz',
    },
    
    {	#[25]
		:type         => 'SPF',
		:txtdata      => 'txt-txtdata',
    },
    ]
    
    
    
    
    
    #------------------------------------------------------------------------------
    # Create the packet
    #------------------------------------------------------------------------------
    
    packet = Net::DNS::Packet.new_from_values(name);
    assert(packet,         'Packet created');
    
    rrs.each do |data|
      data.update({	   :name => name,
	   :ttl  => ttl,
      })
      rr=Net::DNS::RR.create(data)
      
      packet.push('answer', rr );
    end
    
    
    #------------------------------------------------------------------------------
    # Re-create the packet from data.
    #------------------------------------------------------------------------------
    
    data = packet.data;
    assert(data,            'Packet has data after pushes');
    
    packet=nil;
    packet = Net::DNS::Packet.new_from_binary(data);
    
    assert(packet,          'Packet reconstructed from data');
    
    answer = packet.answer;
    
    puts(answer)
    
    i = 0
    rrs.each do |rec|
      ret_rr = answer[i]
      i += 1
      rec.each do |key, value|
        #        method = key+'=?'
        x = ret_rr.send(key)
        assert_equal(value, x, "Packet returned wrong answer section for #{ret_rr.to_s}, #{key}")
      end
    end
    
    
    
    while (!answer.empty? and !rrs.empty?)
      data = rrs.shift;
      rr   = answer.shift;
      type = data[:type];
      
      assert(rr,                         "#{type} - RR defined");    
      assert_equal(name,       	rr.name,    "#{type} - name() correct");         
      assert_equal(klass,      	rr.rrclass,   "#{type} - class() correct");  
      assert_equal(ttl,        	rr.ttl,     "#{type} - ttl() correct");                
      
      #	foreach my $meth (keys %{data}) {
      data.keys.each do |meth|
        
        assert_equal(data[meth], rr.send(meth), "#{type} - #{meth}() correct");
      end
      
      rr2 = Net::DNS::RR.create(rr.inspect);
      assert_equal(rr.inspect,   rr2.inspect, "#{type} - Parsing from string works");
    end
  end
end
