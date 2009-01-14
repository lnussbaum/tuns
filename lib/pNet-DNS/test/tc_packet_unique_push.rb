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
class TestPacketUniquePush < Test::Unit::TestCase
  def test_packUniquePush
    
    
    testProc('unique_push');
  end
  
  def test_packetSafePush
    # @todo RESTORE THIS
    #~ @warnings;
    #~ local $SIG{__WARN__} = sub { push(@warnings, "@_"); };
    begin
      testProc('safe_push');
      flunk("Shouldn't work!")
    rescue Exception
    end
    
    #~ assert(scalar @warnings, 72);
    
    #~ ok(!grep { $_ !~ m/deprecated/ } @warnings);
    
    
    
  end
  
  def testProc (method)
    domain = 'example.com';
    
    tests = [
    [ 
    1,
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    ],
    [
    2,
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    Net::DNS::RR.create('bar.example.com 60 IN A 10.0.0.1'),
    ],
    [ 
    2,
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    Net::DNS::RR.create('foo.example.com 90 IN A 10.0.0.1'),
    ],
    [ 
    3,
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.2'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.3'),
    ],
    [ 
    3,
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.2'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.3'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    ],
    [ 
    3,
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.2'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.1'),
    Net::DNS::RR.create('foo.example.com 60 IN A 10.0.0.4'),
    ],
    ]
    
    sections = {
		'answer'     => 'ancount',
		'authority'  => 'nscount',
		'additional' => 'arcount',
    }
    
    tests.each do | try |  
      count = try.shift;
      rrs = try;
      
      sections.each do |section, count_meth|
        
        packet = Net::DNS::Packet.new_from_values(domain);
        
        packet.send(method,section, rrs);
        
        assert_equal(count, packet.header.send(count_meth), "#{section} right for #{rrs.inspect}");
        
      end
      
      #
      # Now do it again calling safe_push() for each RR.
      # 
      sections.each do |section, count_meth|
        
        packet = Net::DNS::Packet.new_from_values(domain);
        
        #			foreach (rrs) {
        #        if rrs.class == Net::DNS::RR
        #          packet.send(method,section, rrs);
        #        else
        rrs.each do |rr|
          packet.send(method,section, [rr]);
        end
        #        end
        #			}
        
        assert_equal(count, packet.header.send(count_meth), "#{section} right for #{rrs.inspect}");
      end
    end
  end
end
