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
require 'Net/DNS/Resolver/Recurse'
class TestRecurse < Test::Unit::TestCase
 
  def test_recurse
    res = Net::DNS::Resolver::Recurse.new
    res.force_v4 = true
    
    assert_instance_of(Net::DNS::Resolver::Recurse, res)
    
    res.debug=false	
    res.udp_timeout=(20)
    
    setHints(res)
   
    # Try a domain that is a CNAME
    packet = res.query_dorecursion("www.netscape.com.",'A')
    assert(packet, 'got a packet')
    assert(packet.answer, 'answer has RRs')
    
    # Try a big hairy one
    packet = nil
    packet = res.query_dorecursion("www.rob.com.au.",'A')
    print packet.inspect
    assert(packet, 'got a packet')
    assert(packet.answer, 'anwer section had RRs')
  end
  
  def test_callback
    # test the callback
    res = Net::DNS::Resolver::Recurse.new 
    res.force_v4 = true
    setHints(res)
    count=0
    
    
    res.recursion_callback  = Proc.new { |packet| assert_instance_of(Net::DNS::Packet, packet)      
      count = count + 1
    }
    
    ret = res.query_dorecursion('a.t.net-dns.org', 'A')
#    print ret.inspect
    
    assert_equal(3, count)
  end
  
  def setHints(res)
    # Hard code A and K.ROOT-SERVERS.NET hint 
    res.hints=(["193.0.14.129", "198.41.0.4"])
    
    assert(res.hints.length>0, 'hints set')
  end
end
