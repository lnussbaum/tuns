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
class TestRrRrSort < Test::Unit::TestCase
  def test_RrRrSort
    rr1=Net::DNS::RR.create("example.com.  600     IN      SRV     0 0 5060 A.example.com.")
    assert_instance_of(Net::DNS::RR::SRV,rr1,"SRV RR1 created")
    rr2=Net::DNS::RR.create("example.com.  600     IN      SRV     1 0 5060 A.example.com.")
    assert_instance_of(Net::DNS::RR::SRV,rr2,"SRV RR2 created")
    rr3=Net::DNS::RR.create("example.com.  600     IN      SRV     2 0 5060 A.example.com.")
    assert_instance_of(Net::DNS::RR::SRV,rr3,"SRV RR3 created")
    rr4=Net::DNS::RR.create("example.com.  600     IN      SRV     3 0 5060 A.example.com.")
    assert_instance_of(Net::DNS::RR::SRV,rr4,"SRV RR4 created")
    rr5=Net::DNS::RR.create("example.com.  600     IN      SRV     3 1 5060 A.example.com.")
    assert_instance_of(Net::DNS::RR::SRV,rr5,"SRV RR5 created")
    rr6=Net::DNS::RR.create("example.com.  600     IN      SRV     3 2 5060 A.example.com.")
    assert_instance_of(Net::DNS::RR::SRV,rr6,"SRV RR6 created")
    rr7=Net::DNS::RR.create("example.com.  600     IN      SRV     1 3 5070 A.example.com.")
    assert_instance_of(Net::DNS::RR::SRV,rr7,"SRV RR7 created")
    rr8=Net::DNS::RR.create("example.com.  600     IN      SRV     3 3 5070 A.example.com.")
    assert_instance_of(Net::DNS::RR::SRV,rr8,"SRV RR8 created")
    rr9=Net::DNS::RR.create("example.com.  600     IN     A 192.168.0.1")
    assert_instance_of(Net::DNS::RR::A,rr9,"A RR9 created")
    
    
    rrarray=[rr1, rr2, rr3, rr4, rr5, rr6, rr7, rr8, rr9]
    expectedrdata=[rr1, rr2, rr3, rr7, rr4, rr5, rr6,  rr8]
    expectedpriority=[rr1, rr7, rr2, rr3, rr8, rr6, rr5, rr4]
    expectedweight=[rr7, rr8, rr6, rr5, rr1, rr2, rr3, rr4]
    
    
    
    assert_equal(nil,Net::DNS.rrsort("SRV"),"rrsort returns rrerly whith undefined arguments")
    
    assert_equal(8,Net::DNS.rrsort("SRV",rrarray).length,"rrsort returns properly whith undefined attribute (1)")
    
    #assert_equal(rrsort("SRV",,@rrarray),8,"rrsort returns properly whith undefined attribute (2)")
    
    assert_equal(8,Net::DNS.rrsort("SRV","",rrarray).length,"rrsort returns properly whith undefined attribute (3)")
    
    prioritysorted= Net::DNS.rrsort("SRV","priority",rrarray)
    weightsorted= Net::DNS.rrsort("SRV","weight",rrarray)
    defaultsorted= Net::DNS.rrsort("SRV",rrarray)
    portsorted= Net::DNS.rrsort("SRV","port",rrarray)
    
    foosorted= Net::DNS.rrsort("SRV","foo",rrarray)
    assert_equal(8,foosorted.length,"rrsort returns properly whith undefined attribute (3)")
    
    assert_equal(8, prioritysorted.length,"rrsort correctly maintains RRs test 2")
    
    
    #    assert_equal(expectedpriority, prioritysorted, "Sorting on SRV priority works")
    max = 0
    prioritysorted.each { |i| assert(i.priority >= max); max = i.priority}
    #    assert_equal(expectedpriority, defaultsorted, "Default SRV sort works")
    max = 0
    defaultsorted.each { |i| assert(i.priority >= max); max = i.priority}
    #    assert_equal(expectedweight, weightsorted, "Weight sorted SRV sort works")
    max = 0
    weightsorted.each { |i| assert(i.weight >= max); max = i.weight}
    
    
    assert_equal(1, Net::DNS.rrsort("A","priority",rrarray).length,"rrsort correctly maintains RRs test 1")
    assert_equal(nil, Net::DNS.rrsort("MX","priority",rrarray),"rrsort correctly maintains RRs test 3")
    
    
    #
    # Test with MX RRs.
    #
    
    mxrr1=Net::DNS::RR.create("example.com.  600     IN      MX 10 mx1.example.com")
    mxrr2=Net::DNS::RR.create("example.com.  600     IN      MX 6 mx2.example.com")
    
    mxrr3=Net::DNS::RR.create("example.com.  600     IN      MX 66 mx3.example.com")
    mxrr4=Net::DNS::RR.create("example.com.  600     IN      RT 6 rt1.example.com")
    
    
    mxrrarray=[mxrr1, mxrr2, mxrr3, mxrr4]
    expectedmxarray=[mxrr2,mxrr1,mxrr3]
    sortedmxarray=Net::DNS.rrsort("MX",mxrrarray)
    
    assert_equal(expectedmxarray,sortedmxarray,"MX sorting")
    
    
    
    
    nsrr1=Net::DNS::RR.create("example.com.  600     IN      NS ns2.example.com")
    nsrr2=Net::DNS::RR.create("example.com.  600     IN      NS ns4.example.com")
    nsrr3=Net::DNS::RR.create("example.com.  600     IN      NS ns1.example.com")
    nsrr4=Net::DNS::RR.create("example.com.  600     IN      RT 6 rt1.example.com")
    
    nsrrarray=[nsrr1, nsrr2, nsrr3, nsrr4]
    expectednsarray=[nsrr3,nsrr1,nsrr2]
    sortednsarray=Net::DNS.rrsort("NS",nsrrarray)
    
    
    
    
    assert_equal(expectednsarray,sortednsarray,"NS sorting")
    
  end
end
