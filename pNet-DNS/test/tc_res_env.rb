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
class TestResolverEnv < Test::Unit::TestCase
  def test_res_env
    ENV['RES_NAMESERVERS'] = '10.0.1.128 10.0.2.128';
    ENV['RES_SEARCHLIST']  = 'net-dns.org lib.net-dns.org';
    ENV['LOCALDOMAIN']     = 't.net-dns.org';
    ENV['RES_OPTIONS']     = 'retrans:3 retry:2 debug';
    
    
    res = Net::DNS::Resolver.new;
    
    assert(res,                       "new() returned something");
    assert(res.nameservers,   "nameservers() works");
    
    servers = res.nameservers;
    
    assert_equal(servers[0], '10.0.1.128',  'Nameserver set correctly');
    assert_equal(servers[1], '10.0.2.128',  'Nameserver set correctly');
    
    
    search = res.searchlist;
    assert_equal(search[0], 'net-dns.org',     'Search set correctly' );
    assert_equal(search[1], 'lib.net-dns.org', 'Search set correctly' );
    
    assert_equal(res.domain,  't.net-dns.org', 'Local domain works'  );
    assert_equal(3, res.retrans,               'Retransmit works'    );
    assert_equal(2, res.retry,                 'Retry works'         );
    assert(res.debug,                    'Debug works'         );
    
    
    
    
    # @TODO Get these tests working!!
#    eval('$Net::DNS::DNSSEC=0;  \
#	local $SIG{__WARN__}=sub { ok ($_[0]=~/You called the Net::DNS::Resolver::dnssec\(\)/, "Correct warning in absense of Net::DNS::SEC") };	\
#	res.dnssec(1);')
#    
#    eval('$Net::DNS::DNSSEC=1;			\
#	local $SIG{__WARN__}=sub { diag "We are ignoring that Net::DNS::SEC not installed."	 }; \
#	res.dnssec(1);	 \
#	assert_equal(res.udppacketsize(),2048,"dnssec() sets udppacketsize to 2048");')
  end
end
