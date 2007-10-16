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
class TestUpdate < Test::Unit::TestCase
  def is_empty(string)
    return true if string == nil || string.length == 0
    
    return (string == "; no data" || string == "; rdlength = 0");
  end
  
  def test_update
    #------------------------------------------------------------------------------
    # Canned data.
    #------------------------------------------------------------------------------
    
    zone	= "example.com";
    name	= "foo.example.com";
    klass	= "HS";
    klass2  = "CH";
    type	= "A";
    ttl	    = 43200;
    rdata	= "10.1.2.3";
    rr      = nil;
    
    #------------------------------------------------------------------------------
    # Packet creation.
    #------------------------------------------------------------------------------
    
    packet = Net::DNS::Update.new_from_values(zone, klass);
    z = (packet.zone)[0];
    
    assert(packet,                                'new() returned packet');  #2
    assert_equal(packet.header.opcode, 'UPDATE',      'header opcode correct');  #3 
    assert_equal(z.zname,  zone,                      'zname correct');          #4
    assert_equal(z.zclass, klass,                     'zclass correct');         #5
    assert_equal(z.ztype,  'SOA',                      'ztype correct');          #6       
    
    #------------------------------------------------------------------------------
    # RRset exists (value-independent).
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.yxrrset("#{name} #{klass} #{type}");
    
    assert(rr,                                    'yxrrset() returned RR');  #7
    assert_equal(name,                      rr.name,  'yxrrset - right name');   #8
    assert_equal(0,                          rr.ttl,   'yxrrset - right TTL');    #9
    assert_equal('ANY',                      rr.rrclass, 'yxrrset - right class');  #10
    assert_equal(type,                      rr.type,  'yxrrset - right type');   #11
    assert(is_empty(rr.rdatastr),                "yxrrset - data empty (#{rr.rdatastr})");   #12
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # RRset exists (value-dependent).
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.yxrrset("#{name} #{klass} #{type} #{rdata}");
    
    assert(rr,                                    'yxrrset() returned RR');  #13
    assert_equal(name,                   rr.name,     'yxrrset - right name');   #14
    assert_equal(0,                       rr.ttl,      'yxrrset - right TTL');    #15
    assert_equal(klass,                  rr.rrclass,    'yxrrset - right class');  #16
    assert_equal(type,                   rr.type,     'yxrrset - right type');   #17
    assert_equal(rdata,                  rr.rdatastr, 'yxrrset - right data');   #18
    
    rr=nil
    
    #------------------------------------------------------------------------------
    # RRset does not exist.
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.nxrrset("#{name} #{klass} #{type}");
    
    assert(rr,                                    'nxrrset() returned RR');  #19
    assert_equal(name,                      rr.name,  'nxrrset - right name');   #20
    assert_equal(0,                          rr.ttl,   'nxrrset - right ttl');    #21
    assert_equal('NONE',                     rr.rrclass, 'nxrrset - right class');  #22
    assert_equal(type,                      rr.type,  'nxrrset - right type');   #23
    assert(is_empty(rr.rdatastr),                'nxrrset - data empty');   #24
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # Name is in use.
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.yxdomain("#{name} #{klass}");
    
    assert(rr,                                    'yxdomain() returned RR'); #25
    assert_equal(rr.name,  name,                      'yxdomain - right name');  #26
    assert_equal(rr.ttl,   0,                          'yxdomain - right ttl');   #27
    assert_equal(rr.rrclass, 'ANY',                      'yxdomain - right class'); #28
    assert_equal(rr.type,  'ANY',                      'yxdomain - right type');  #29
    assert(is_empty(rr.rdatastr),                'yxdomain - data empty');  #30
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # Name is not in use.
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.nxdomain("#{name} #{klass}");
    
    assert(rr,                                    'nxdomain() returned RR'); #31
    assert_equal(rr.name,  name,                      'nxdomain - right name');  #32
    assert_equal(rr.ttl,   0,                          'nxdomain - right ttl');   #33
    assert_equal(rr.rrclass, 'NONE',                     'nxdomain - right class'); #34
    assert_equal(rr.type,  'ANY',                      'nxdomain - right type');  #35
    assert(is_empty(rr.rdatastr),                'nxdomain - data empty');  #36
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # Name is not in use. (No Class)
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.nxdomain("#{name}");
    
    assert(rr,                                    'nxdomain() returned RR'); #31
    assert_equal(rr.name,  name,                      'nxdomain - right name');  #32
    assert_equal(rr.ttl,   0,                          'nxdomain - right ttl');   #33
    assert_equal(rr.rrclass, 'NONE',                     'nxdomain - right class'); #34
    assert_equal(rr.type,  'ANY',                      'nxdomain - right type');  #35
    assert(is_empty(rr.rdatastr),                'nxdomain - data empty');  #36
    
    rr = nil
    
    
    
    #------------------------------------------------------------------------------
    # Add to an RRset.
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.rr_add("#{name} #{ttl} #{klass} #{type} #{rdata}");
    
    assert(rr,                                    'rr_add() returned RR');   #37
    assert_equal(rr.name,     name,                   'rr_add - right name');    #38
    assert_equal(rr.ttl,      ttl,                    'rr_add - right ttl');     #39
    assert_equal(rr.rrclass,    klass,                  'rr_add - right class');   #40
    assert_equal(rr.type,     type,                   'rr_add - right type');    #41
    assert_equal(rr.rdatastr, rdata,                  'rr_add - right data');    #42
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # Delete an RRset.
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.rr_del("#{name} #{klass} #{type}");
    
    assert(rr,                                    'rr_del() returned RR');   #43
    assert_equal(name,                      rr.name,  'rr_del - right name');    #44
    assert_equal(0,                          rr.ttl,   'rr_del - right ttl');     #45
    assert_equal('ANY',                      rr.rrclass, 'rr_del - right class');   #46
    assert_equal(type,                      rr.type,  'rr_del - right type');    #47
    assert(is_empty(rr.rdatastr),                'rr_del - data empty');    #48
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # Delete All RRsets From A Name.
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.rr_del("#{name} #{klass}");
    
    assert(rr,                                    'rr_del() returned RR');   #49
    assert_equal(name,                      rr.name,  'rr_del - right name');    #50
    assert_equal(0,                          rr.ttl,   'rr_del - right ttl');     #51
    assert_equal('ANY',                      rr.rrclass, 'rr_del - right class');   #52
    assert_equal('ANY',                      rr.type,  'rr_del - right type');    #53
    assert(is_empty(rr.rdatastr),                'rr_del - data empty');    #54
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # Delete An RR From An RRset.
    #------------------------------------------------------------------------------
    
    rr = Net::DNS.rr_del("#{name} #{klass} #{type} #{rdata}");
    
    assert(rr,                                    'rr_del() returned RR');   #55
    assert_equal(name,                   rr.name,     'rr_del - right name');    #56
    assert_equal(0,                       rr.ttl,      'rr_del - right ttl');     #57
    assert_equal('NONE',                  rr.rrclass,    'rr_del - right class');   #58
    assert_equal(type,                   rr.type,     'rr_del - right type');    #59
    assert_equal(rdata,                  rr.rdatastr, 'rr_del - right data');    #60
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # Make sure RRs in an update packet have the same class as the zone, unless
    # the class is NONE or ANY.
    #------------------------------------------------------------------------------
    
    packet = Net::DNS::Update.new_from_values(zone, klass);
    assert(packet,                               'packet created');          #61
    
    
    packet.push("pre", Net::DNS.yxrrset("#{name} #{klass} #{type} #{rdata}"));
    packet.push("pre", Net::DNS.yxrrset("#{name} #{klass2} #{type} #{rdata}"));
    packet.push("pre", Net::DNS.yxrrset("#{name} #{klass2} #{type}"));
    packet.push("pre", Net::DNS.nxrrset("#{name} #{klass2} #{type}"));
    
    pre = packet.pre;
    
    assert_equal(4,                     pre.size, 'pushed inserted correctly'); #62
    assert_equal(klass,              pre[0].rrclass, 'first class right');         #63
    assert_equal(klass,              pre[1].rrclass, 'second class right');        #64
    assert_equal('ANY',               pre[2].rrclass, 'third class right');         #65
    assert_equal('NONE',              pre[3].rrclass, 'forth class right');         #66
  end
end
