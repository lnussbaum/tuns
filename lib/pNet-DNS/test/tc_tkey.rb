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
require "digest/md5"
class TestTKey < Test::Unit::TestCase
  def is_empty(string)
    return (string == "; no data" || string == "; rdlength = 0")
  end
  
  def test_tkey
    
    
    #------------------------------------------------------------------------------
    # Canned data.
    #------------------------------------------------------------------------------
    
    zone	= "example.com"
    name	= "123456789-test"
    klass	= "IN"
    type	= "TKEY"
    algorithm   = "fake.algorithm.example.com"
    key         = "fake key"
    inception   = 100000 # use a strange fixed inception time to give a fixed
    # checksum
    expiration  = inception + 24*60*60
    
    rr = nil
    
    #------------------------------------------------------------------------------
    # Packet creation.
    #------------------------------------------------------------------------------
    
    rr = Net::DNS::RR.create(
	:name       => name,
	:type       => "TKEY",
	:ttl        => 0,
	:rrclass      => "ANY",
	:algorithm  => algorithm,
	:inception  => inception,
	:expiration => expiration,
	:mode       => 3, # GSSAPI
	:key        => "fake key",
	:other_data => ""
    )
    
    packet = Net::DNS::Packet.new_from_values(name, "TKEY", "IN")
    packet.push("answer", rr)
    
    z = (packet.zone)[0]
    
    assert(packet,                                'new() returned packet')  #2
    assert_equal('QUERY',       packet.header.opcode, 'header opcode correct')  #3 
    assert_equal(name,                      z.zname,  'zname correct')          #4
    assert_equal("IN",                       z.zclass, 'zclass correct')         #5
    assert_equal('TKEY',                     z.ztype,  'ztype correct')          #6       
    
    
    #------------------------------------------------------------------------------
    # create a signed TKEY query packet using an external signing function
    # and compare it to a known good result. This effectively tests the
    # sign_func and sig_data methods of TSIG as well.
    #------------------------------------------------------------------------------
    
    
    tsig = Net::DNS::RR.create({
                               :name        => name,
                               :type        => "TSIG",
    :ttl         => 0,
    :rrclass       => "ANY",
    :algorithm   => algorithm,
    :time_signed => inception + 1,
    :fudge       => 36000,
    :mac_size    => 0,
    :mac         => "",
    :key         => key,
    :sign_func   => Proc.new { |key,data|     
   #         OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new("md5"), key, data) 
        hmac = Digest::MD5.new.update(key)
        hmac.update(data)
        return hmac.digest
        },
    :other_len   => 0,
    :other_data  => nil,
    :error       => 0
    })
    
    packet.push(:additional, tsig) 
    
    # use a fixed packet id so we get a known checksum
    packet.header.id=(1234)
    
    # create the packet - this will fill in the 'mac' field
    raw_packet = packet.data
    
    assert_equal(
   "6365643161343964663364643264656131306638303633626465366236643465",
     (packet.additional)[0].mac, 
   'MAC correct')
    
  end
end
