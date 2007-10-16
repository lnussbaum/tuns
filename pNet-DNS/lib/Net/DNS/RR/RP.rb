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
    class RR
      #= NAME
      #
      #Net::DNS::RR::RP - DNS RP resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Responsible Person (RP) resource records.
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
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 1183 Section 2.2
      class RP < RR
        #Returns a domain name that specifies the mailbox for the responsible person.
        #
        #    print "mbox = ", rr.mbox, "\n"
        #
        attr_accessor :mbox
        #Returns a domain name that specifies a TXT record containing further
        #information about the responsible person.
        #
        #    print "txtdname = ", rr.txtdname, "\n"
        #
        attr_accessor :txtdname
        def new_from_data(data, offset)
          if (@rdlength > 0)
           (@mbox,     offset) = Net::DNS::Packet::dn_expand(data, offset);
           (@txtdname, offset) = Net::DNS::Packet::dn_expand(data, offset);
          end
        end
        
        def new_from_string(string)
          if (string && (string =~ /^(\S+)\s+(\S+)$/))
            @mbox     = $1;
            @txtdname = $2;
            @mbox.sub!(/\.+$/,"");
            @txtdname.sub!(/\.+$/,"");
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:mbox)
            @mbox = values[:mbox]
          end
          if values.has_key?(:txtdname)
            @txtdname = values[:txtdname]
          end
        end
        
        def rdatastr
          return @mbox ? "#{@mbox}. #{@txtdname}." : '';
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@mbox)
            rdata += packet.dn_comp(@mbox, offset);
            rdata += packet.dn_comp(@txtdname, offset + rdata.length);
          end
          
          return rdata;
        end
        
        
        def _canonicalRdata
          rdata = "";
          if (defined?@mbox)
            rdata += _name2wire(@mbox);
            rdata += _name2wire(@txtdname);
          end
          
          return rdata;
        end
      end
    end
  end
end
