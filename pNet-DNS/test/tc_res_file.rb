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
class TestAResolverFile < Test::Unit::TestCase
  def test_resFile
    #~ BEGIN { 
    #~ chdir 't/' || die "Couldn't chdir to t/\n"  
    #~ unshift(@INC, '../blib/lib', '../blib/arch')
    #~ use_ok('Net::DNS')	
    #~ }
    
    #~ SKIP: {
    
    #~ skip 'File parsing only supported on unix.', 7
    #~ unless $Net::DNS::Resolver::ISA[0] eq 'Net::DNS::Resolver::UNIX'
    
    #~ skip 'Could not read configuration file', 7
    #~ unless -r '.resolv.conf' && -o _
    
    res = Net::DNS::Resolver.new(:config_file => "test/resolv.conf")
    
    assert(res,                "new() returned something")
    assert(res.nameservers,   "nameservers() works")
    
    servers = res.nameservers
    
    assert_equal(servers[0], '10.0.1.128',  'Nameserver set correctly')
    assert_equal(servers[1], '10.0.2.128',  'Nameserver set correctly')
    
    
    search = res.searchlist
    assert_equal(search[0], 'net-dns.org',     'Search set correctly' )
    assert_equal(search[1], 'lib.net-dns.org', 'Search set correctly' )
    
    assert_equal(res.domain,  't.net-dns.org', 'Local domain works'  )
    #~ }
    
    
    
  end
end
