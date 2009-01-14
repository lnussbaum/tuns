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
class TestTcp < Test::Unit::TestCase
  def test_TCP
    res = Net::DNS::Resolver.new(:config_file=>"/etc/resolv.conf")
    res.debug=true
    res.usevc = true
    ret=res.query("example.com")
    assert(ret.is_a?(Net::DNS::Packet))
  end
  def test_TCP_port
    res = Net::DNS::Resolver.new(:config_file=>"/etc/resolv.conf")
    res.debug=true
    res.usevc = true
    res.srcport=rand(60000) + 1025
    ret=res.query("example.com")
    assert(ret.is_a?(Net::DNS::Packet))
  end
end
