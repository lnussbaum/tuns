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
class TestHeader < Test::Unit::TestCase
  def test_header
    header = Net::DNS::Header.new();
    assert(header, "new() returned something")
    
    header.id=41
    assert_equal(header.id, 41, "id() works")
    
    header.qr=1
    assert_equal(header.qr, 1, "qr() works")
    
    header.opcode="QUERY"
    assert_equal(header.opcode, "QUERY", "opcode() works")
    
    header.aa=1
    assert_equal(header.aa, 1, "aa() works")
    
    header.tc=0
    assert_equal(header.tc, 0, "tc() works")
    
    header.rd=1
    assert_equal(header.rd, 1, "rd() works")
    
    header.ra=1
    assert_equal(header.ra, 1, "ra() works")
    
    header.qr=1
    assert_equal(header.qr, 1, "qr() works")
    
    header.rcode="NOERROR"
    assert_equal(header.rcode, "NOERROR", "rcode() works")
    
    header.qdcount=1
    header.ancount=2
    header.nscount=3
    header.arcount=3
    
    
    # Reenable when support for CD is there
    #header.cd=0
    #assert_equal(header.cd, 0, "cd() works")
    puts(header.inspect)
    data = header.data;
    
    header2 = Net::DNS::Header.new(data);
    puts(header2.inspect)
    
    assert(header==(header2), 'Headers are the same');
    
    #
    #  Is $header->string remotely sane?
    #
    assert(header.inspect =~ /opcode = QUERY/, 'string() has opcode correct');
    assert(header.inspect =~ /ancount = 2/,    'string() has ancount correct');
    
    header = Net::DNS::Header.new;
    
    #
    # Check that the aliases work properly.
    #
    header.zocount=(0);
    header.prcount=(1);
    header.upcount=(2);
    header.adcount=(3);
    
    assert_equal(header.zocount, 0, 'zocount works');
    assert_equal(header.prcount, 1, 'prcount works');
    assert_equal(header.upcount, 2, 'upcount works');
    assert_equal(header.adcount, 3, 'adcount works');
    
    
    
  end
end
