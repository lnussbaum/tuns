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
class TestResOpt < Test::Unit::TestCase
  def test_res_opt
    
    # .txt because this test will run under windows, unlike the other file
    # configuration tests.
    #test_file = File::Spec.catfile('t', 'custom.txt')
    
    #res = Net::DNS::Resolver.new(:config_file => :test_file)
    res = Net::DNS::Resolver.new(:config_file => 'test/custom.txt')
    
    assert(res,                           'new() returned something')
    assert_instance_of(Net::DNS::Resolver, res, 'new() returns an object of the correct class.')
    assert(res.nameservers,       'nameservers() works')
    
    servers = res.nameservers
    
    assert_equal(servers[0], '10.0.1.42',  'Nameserver set correctly')
    assert_equal(servers[1], '10.0.2.42',  'Nameserver set correctly')
    
    
    search = res.searchlist
    assert_equal(search[0],   'alt.net-dns.org', 'Search set correctly' )
    assert_equal(search[1],   'ext.net-dns.org', 'Search set correctly' )
    
    assert_equal(res.domain, 't2.net-dns.org',  'Local domain works'  )
  end
  
  def test_no_file
    res=nil
    begin
      res = Net::DNS::Resolver.new(:config_file => 'nosuch.txt')
      assert(false, "Should throw error trying to open non-existant file.")
    rescue Exception
      #assert($@,    'Error thrown trying to open non-existant file.')
      assert(res==nil, 'Net::DNS::Resolver->new returned undef')
    end
  end
  
  def test_config
    #
    # Check that we can set things in new()
    #
    res=nil
    
    test_config = {
	:nameservers	   => ['10.0.0.1', '10.0.0.2'],
	:port		   => 54,
	:srcaddr        => '10.1.0.1',
	:srcport        => 53,
	:domain	       => 'net-dns.org',
	:searchlist	   => ['net-dns.org', 't.net-dns.org'],
	:retrans	       => 6,
	:retry		   => 5,
	:usevc		   => 1,
	:stayopen       => 1,
	:igntc          => 1,
	:recurse        => 0,
	:defnames       => 0,
	:dnsrch         => 0,
	:debug          => 1,
	:tcp_timeout    => 60,
	:udp_timeout    => 60,
	:persistent_tcp => 1,
      #@todo Add dnssec when dnssec added to Net::DNS
      #	'dnssec'         => 1,
    }
    
    res = Net::DNS::Resolver.new(test_config)
    
    
    test_config.keys.each do |item|
      assert_equal(res.send_method(item), test_config[item], "#{item} is correct")
    end	
  end
  
  def test_bad_input
    #
    # Check that new() is vetting things properly.
    #
    
    [:nameservers, :searchlist].each do |test|
      [{}, 'string',1,'\1',nil].each do |input|
        res=nil
        begin
          res = Net::DNS::Resolver.new({test => input})
          assert(false, "Accepted invalid input")
        rescue
          assert(res==nil, 'No resolver should be returned for #{test} = #{input}')
        end
      end
    end
  end
  
  
  def test_bad_config
    res=nil
    
    bad_input = {
	:tsig_rr        => 'set',
	:errorstring    => 'set',
	:answerfrom     => 'set',
	:answersize     => 'set',
	:querytime      => 'set',
	:axfr_sel       => 'set',
	:axfr_rr        => 'set',
	:axfr_soa_count => 'set',
	:udppacketsize  => 'set',
	:cdflag         => 'set',
    }
    
    res = Net::DNS::Resolver.new(bad_input)
    
    bad_input.keys.each do |key|
      assert_not_equal(res.send_method(key), 'set', "#{key} is not set")
    end
    
  end
end
