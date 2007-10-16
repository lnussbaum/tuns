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
class TestQuestion < Test::Unit::TestCase
  def test_question
    domain = "example.com"
    type = "MX"
    klass = "IN"
    
    q = Net::DNS::Question.new(domain, type, klass)
    assert(q, "new() returned something")
    assert_equal(q.qname, domain, "qName()")
    assert_equal(q.qtype, type, "qType()")
    assert_equal(q.qclass, klass, "qClass()")
    
    #
    # Check the aliases
    #
    assert_equal(q.zname,  domain, 'zName()'  );
    assert_equal(q.ztype,  type,   'zType()'  );
    assert_equal(q.zclass, klass,  'zClass()' );
    
    #
    # Check that we can change stuff
    #
    q.qname=('example.net');
    q.qtype=('A');
    q.qclass=('CH');
    
    assert_equal(q.qname,  'example.net', 'qName()'  );
    assert_equal(q.qtype,  'A',           'qType()'  );
    assert_equal(q.qclass, 'CH',          'qClass()' );
    
  end
end
