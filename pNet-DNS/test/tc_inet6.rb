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
require 'socket'
class TestInet6 < Test::Unit::TestCase
  def ip6ok?
    if (@checkedip6)
      if !@ip6ok
        return false
      end
    end
    @checkedip6 = true
    @ip6ok = true
    # First use the local resolver to query for the AAAA record of a 
    # well known nameserver, than use v6 transport to get to that record.
    puts ""
    puts ""
    puts "\tTesting for global IPv6 connectivity...\n"
    puts "\t\t preparing..."
    
    tstsock = UDPSocket.new() 
    begin
      tstsock.bind("::1", 8765)
    rescue Exception
      #      raise RuntimeError, "\n\n\t\tFailed to bind to ::1\n\t\t#{$!}\n\n\t\tWe assume there is no IPv6 connectivity and skip the tests\n\n"
      puts "\n\n\t\tFailed to bind to ::1\n\t\t#{$!}\n\n\t\tWe assume there is no IPv6 connectivity and skip the tests\n\n"
      @ip6ok=false
      return false
    ensure
      tstsock.close
    end
    return true
  end
  
  def test_inet6
    if (!ip6ok?)
      return
    end
    res=Net::DNS::Resolver.new
    #	res.debug(1)
    nsanswer=res.send("ripe.net",'NS','IN')
    assert_instance_of(Net::DNS::RR::NS, (nsanswer.answer)[0], "Preparing  for v6 transport, got NS records for ripe.net")
    
    #	foreach ns (nsanswer.answer){
    nsanswer.answer.each do |ns| 
      next if ns.nsdname !~ /ripe\.net/ # User ripe.net only
      a_answer=res.send(ns.nsdname, 'A','IN')
      next if (a_answer.header.ancount == 0)
      assert_instance_of(Net::DNS::RR::A, (a_answer.answer)[0], "Preparing  for v4 transport, got A records for " + ns.nsdname)
      a_address=(a_answer.answer)[0].address
      
      
      puts("\n\t\t Will try to connect to  " + ns.nsdname + " (#{a_address})")
      break
    end
    
    
    aaaa_address=""
    #	foreach ns (nsanswer.answer){
    nsanswer.answer.each do |ns| 
      next if ns.nsdname !~ /ripe\.net/ # User ripe.net only
      aaaa_answer=res.send(ns.nsdname,'AAAA','IN')
      next if (aaaa_answer.header.ancount == 0)
      assert_equal((aaaa_answer.answer)[0].type,"AAAA", "Preparing  for v6 transport, got AAAA records for " + ns.nsdname)
      aaaa_address=(aaaa_answer.answer)[0].address
      
      
      puts("\n\t\t Will try to connect to  #{ns.nsdname} (#{aaaa_address})")
      break
    end
    
    res.nameservers=(aaaa_address)
    # res.print
    answer=res.send("ripe.net",'SOA','IN')
    if(res.errorstring =~ /Send error: /)
      puts "\n\t\t Connection failed: " + res.errorstring 
      puts "\n\t\t It seems you do not have global IPv6 connectivity' \n" 
      puts "\t\t This is not an error in Net::DNS \n"
      
      puts "\t\t You can confirm this by trying 'ping6 " + aaaa_address + "' \n\n"
    end
    
    
    
    # answer.print
    assert_equal((answer.answer)[0].type, "SOA","Query over udp6 succeeded")
    
    res.usevc(1)
    res.force_v4(1)
    # res.print
    # res.debug(1)
    answer=res.send("ripe.net",'SOA','IN')
    assert_equal(res.errorstring,"no nameservers","Correct errorstring when forcing v4")
    
    
    res.force_v4(0)
    answer=res.send("ripe.net",'NS','IN')
    if (answer)
      assert_equal((answer.answer)[0].type, "NS","Query over tcp6  succeeded")
    else
      puts "You can safely ignore the following message:"
      puts(res.errorstring) if (res.errorstring != "connection failed(IPv6 socket failure)")
      puts("configuring " + aaaa_address + " " +  a_address + " as nameservers")
      res.nameservers(aaaa_address,a_address)
      answer = nil
      #	res.print
      answer=res.send("ripe.net",'NS','IN')
      assert_equal((answer.answer)[0].type, "NS","Fallback to V4 succeeded")
      
      
    end
    
  end 
  
  
  
  
  def test_axfr
    if (!ip6ok?)
      return
    end
    #  
    # Now test AXFR functionality.
    #
    #
    # First use the local resolver to query for the AAAA record of a 
    
    aaaa_address=""
    res2=Net::DNS::Resolver.new
    # res2.debug(1)
    nsanswer=res2.send("net-dns.org",'NS','IN')
    assert_equal((nsanswer.answer)[0].type, "NS","Preparing  for v6 transport, got NS records for net-dns.org")
    #	foreach ns (nsanswer.answer){
    nsanswer.answer.each do |ns|
      #	    next if ns.nsdname !~ /ripe\.net/ # User rupe.net only
      aaaa_answer=res2.send(ns.nsdname,'AAAA','IN')
      next if (aaaa_answer.header.ancount == 0)
      assert_equal((aaaa_answer.answer)[0].type,"AAAA", "Preparing  for v6 transport, got AAAA records for " + ns.nsdname)
      aaaa_address=(aaaa_answer.answer)[0].address
      
      puts("\n\t\t Trying to connect to  " + ns.nsdname + " (#{aaaa_address})")
      break
    end
    
    res2.nameservers=(aaaa_address)
    # res2.print
    
    socket=res2.axfr_start('example.com')
            
    assert_instance_of(Socket, socket,"axfr_start returns IPv6 Socket")
     (rr,err)=res2.axfr_next
    assert_equal(res2.errorstring,'Response code from server: NOTAUTH',"Transfer is not authorized (but our connection worked)")
    
  end
end
