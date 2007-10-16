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
class TestResolver < Test::Unit::TestCase
  def test_resolver
    res = Net::DNS::Resolver.new();
    assert(res, "new returned something");
    assert_instance_of(Net::DNS::Resolver, res, "new() returns an object of the correct class.");

    assert(res.nameservers,       'nameservers() works');
    
    searchlist = ["t.net-dns.org", "t2.net-dns.org"];
    assert_equal(res.searchlist=searchlist, searchlist, 'setting searchlist returns correctly.');
    assert_equal(res.searchlist,               searchlist, 'setting searchlist stickts.');


    good_input = {
	"port"		  => 54,
	"srcaddr"        => '10.1.0.1',
	"srcport"        => 53,
	"domain"	       => 'net-dns.org',
	"retrans"	       => 6,
	"retry"		   => 5,
	"usevc"		   => 1,
	"stayopen"       => 1,
	"igntc"          => 1,
	"recurse"        => 0,
	"defnames"       => 0,
	"dnsrch"         => 0,
	"debug"          => 1,
	"tcp_timeout"    => 60,
	"udp_timeout"    => 60,
	"persistent_tcp" => 1,
#	"dnssec"         => 1,
	"force_v4"       => 1,
    };

    #~ #diag "\n\nIf you do not have Net::DNS::SEC installed you will see a warning.\n";
    #~ #diag "It is safe to ignore this\n";

    good_input.each do | param, value |
#      puts("Setting " + param);
      assert_equal(res.send_method(param+"=",value), value, "setting " +  param +  " returns correctly");
      assert_equal(res.send_method(param), value,       "setting #param sticks");
    end;
    
    bad_input = {
	"tsig_rr"        => 'set',
	"errorstring"    => 'set',
	"answerfrom"     => 'set',
	"answersize"     => 'set',
	"querytime"      => 'set',
	"axfr_sel"       => 'set',
	"axfr_rr"        => 'set',
	"axfr_soa_count" => 'set',
	"udppacketsize"  => 'set',
	"cdflag"         => 'set',
    };	

    # Some people try to run these on private address space."

    #~ use Net::IP;

    #~ use IO::Socket::INET;
    #~ sock = IO::Socket::INET.new(PeerAddr => '193.0.14.129', # k.root-servers.net.
				 #~ PeerPort => '25',
				 #~ Proto    => 'udp');


    #~ ip=Net::IP.new(inet_ntoa(sock.sockaddr));
    
    # @todo Test whether we are online
    # If we are online, then run the next set of tests
    
       res = Net::DNS::Resolver.new
	
	res.nameservers=('a.t.net-dns.org')
	ip = res.nameservers()[0]
	print ip.inspect
	assert_equal('10.0.1.128', ip, 'Nameservers() looks up IP.')
	
	res.nameservers=('cname.t.net-dns.org')
	ip = (res.nameservers)[0]
	assert_equal(ip, '10.0.1.128', 'Nameservers() looks up cname.')
	    

  end
end
