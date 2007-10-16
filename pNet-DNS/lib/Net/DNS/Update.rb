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
module Net
  module DNS
    #= NAME
    #
    #Net::DNS::Update - Create a DNS update packet
    #
    #= DESCRIPTION
    #
    #Net::DNS::Update is a subclass of Net::DNS::Packet,
    #to be used for making DNS dynamic updates.  Programmers
    #should refer to RFC 2136 for the semantics of dynamic updates.
    #
    #WARNING:  This code is still under development.  Please use with
    #caution on production nameservers.
    #
    #
    #Future versions of Net::DNS may provide a simpler interface
    #for making dynamic updates.
    #
    #
    #
    #= EXAMPLES
    #
    #The first example below shows a complete program; subsequent examples
    #show only the creation of the update packet.
    #
    #== Add a new host
    #
    # require 'Net/DNS'
    # 
    # # Create the update packet.
    # update = Net::DNS::Update.new_from_values('example.com')
    # 
    # # Prerequisite is that no A records exist for the name.
    # update.push('pre', Net::DNS.nxrrset('foo.example.com. A'))
    # 
    # # Add two A records for the name.
    # update.push('update', Net::DNS.rr_add('foo.example.com. 86400 A 192.168.1.2'))
    # update.push('update', Net::DNS.rr_add('foo.example.com. 86400 A 172.16.3.4'))
    # 
    # # Send the update to the zone's primary master.
    # res = Net::DNS::Resolver.new
    # res.nameservers=('primary-master.example.com')
    # 
    # reply = res.send(update)
    # 
    # # Did it work?
    # if (reply)
    #     if (reply.header.rcode == 'NOERROR')
    #         print "Update succeeded\n"
    #     else
    #         print 'Update failed: ', reply.header.rcode, "\n"
    #     end
    # else
    #     print 'Update failed: ', res.errorstring, "\n"
    # end
    #
    #== Add an MX record for a name that already exists
    #
    #    update = Net::DNS::Update.new_from_values('example.com')
    #    update.push("pre", yxdomain('example.com'))
    #    update.push("update", Net::DNS.rr_add('example.com MX 10 mailhost.example.com'))
    #
    #== Add a TXT record for a name that doesn't exist
    #
    #    update = Net::DNS::Update.new_from_values('example.com')
    #    update.push("pre", nxdomain('info.example.com'))
    #    update.push("update", Net::DNS.rr_add('info.example.com TXT "yabba dabba doo"'))
    #
    #== Delete all A records for a name
    #
    #    update = Net::DNS::Update.new_from_values('example.com')
    #    update.push("pre", yxrrset('foo.example.com A'))
    #    update.push("update", Net::DNS.rr_del('foo.example.com A'))
    #
    #== Delete all RRs for a name
    #
    #    update = Net::DNS::Update.new_from_values('example.com')
    #    update.push("pre", yxdomain('byebye.example.com'))
    #    $update->push("update", Net::DNS.rr_del('byebye.example.com'))
    #
    #== Perform a signed update
    #
    #    key_name = 'tsig-key'
    #    key      = 'awwLOtRfpGE+rRKF2+DEiw=='
    #
    #    update = Net::DNS::Update.new_from_values('example.com')
    #    update.push('update', Net::DNS.rr_add('foo.example.com A 10.1.2.3'))
    #    update.push('update', Net::DNS.rr_add('bar.example.com A 10.4.5.6'))
    #    update.sign_tsig(key_name, key)
    #
    #== Another way to perform a signed update
    #
    #    key_name = 'tsig-key'
    #    key      = 'awwLOtRfpGE+rRKF2+DEiw=='
    #
    #    update = Net::DNS::Update.new_from_values('example.com')
    #    update.push('update',  Net::DNS.rr_add('foo.example.com A 10.1.2.3'))
    #    update.push('update',  Net::DNS.rr_add('bar.example.com A 10.4.5.6'))
    #    update.push('additional', Net::DNS::RR.create("#{key_name} TSIG #{key}"))
    #
    #== Perform a signed update with a customized TSIG record
    #
    #    key_name = 'tsig-key'
    #    key      = 'awwLOtRfpGE+rRKF2+DEiw=='
    #
    #    tsig = Net::DNS::RR.create("#{key_name} TSIG #{key}")
    #    tsig.fudge=(60)
    #
    #    update = Net::DNS::Update.new_from_values('example.com')
    #    update.push('update', Net::DNS.rr_add('foo.example.com A 10.1.2.3'))
    #    update.push('update', Net::DNS.rr_add('bar.example.com A 10.4.5.6'))
    #    update.push('additional', tsig)
    #
    #= BUGS
    #
    #This code is still under development.  Please use with caution on
    #production nameservers.
    #
    #= COPYRIGHT
    #
    #Copyright (c) 1997-2002 Michael Fuhr. 
    #
    #Portions Copyright (c) 2002-2004 Chris Reinhardt.
    #
    #Ruby version Copyright (c) 2006 AlexD (Nominet UK)
    #
    #All rights reserved.  This program is free software; you may redistribute
    #it and/or modify it under the same terms as Perl itself.
    #
    #= SEE ALSO
    #
    #Net::DNS, Net::DNS::Resolver, Net::DNS::Header,
    #Net::DNS::Packet, Net::DNS::Question, Net::DNS::RR, RFC 2136,
    #RFC 2845
    #
    class Update < Packet
      
      #Returns a Net::DNS::Update object suitable for performing a DNS
      #dynamic update.  Specifically, it creates a packet with the header
      #opcode set to UPDATE and the zone record type to SOA (per RFC 2136,
      #Section 2.3).
      #
      #Programs must use the push method to add RRs to the prerequisite,
      #update, and additional sections before performing the update.
      #
      #Arguments are the zone name and the class.  If the zone is omitted,
      #the default domain will be taken from the resolver configuration.
      #If the class is omitted, it defaults to IN.
      #    packet = Net::DNS::Update.new_from_values
      #    packet = Net::DNS::Update.new('example.com')
      #    packet = Net::DNS::Update.new('example.com', 'HS')
      #
      def Update.new_from_values(zone=nil, klass=nil)
        
        if (zone==nil)
          res = Net::DNS::Resolver.new
          zone = (res.searchlist)[0]
          return unless zone
        end
        
        type  = 'SOA'
        klass  ||= 'IN'
        
        packet = Packet.new_from_values(zone, type, klass) || return
        
        packet.header.opcode=('UPDATE')
        packet.header.rd=(0)
        
        return packet
      end
    end
  end
end
