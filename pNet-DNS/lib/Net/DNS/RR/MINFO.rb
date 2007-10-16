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
      #Net::DNS::RR::MINFO - DNS MINFO resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Mailbox Information (MINFO) resource records.
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
      #RFC 1035 Section 3.3.7
      class MINFO < RR
        #Returns the RR's responsible mailbox field.  See RFC 1035.
        #
        #    print "rmailbx = ", rr.rmailbx, "\n"
        #
        attr_accessor :rmailbx
        #Returns the RR's error mailbox field.
        #
        #    print "emailbx = ", rr.emailbx, "\n"
        #
        attr_accessor :emailbx
        def new_from_data(data, offset)
          if (@rdlength > 0)
           (@rmailbx, offset) = Net::DNS::Packet::dn_expand(data, offset);
           (@emailbx, offset) = Net::DNS::Packet::dn_expand(data, offset);
          end
        end
        
        def new_from_string(string)
          if (string && (string =~ /^(\S+)\s+(\S+)$/))
            @rmailbx = $1;
            @emailbx = $2;
            @rmailbx.sub!(/\.+$/, "");
            @emailbx.sub!(/\.+$/,"");
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:rmailbx)
            @rmailbx = values[:rmailbx]
          end
          if values.has_key?(:emailbx)
            @emailbx = values[:emailbx]
          end
        end
        
        def rdatastr
          return @rmailbx ? "#{@rmailbx}. #{@emailbx}." : '';
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@rmailbx)
            rdata += packet.dn_comp(@rmailbx, offset);
            
            rdata += packet.dn_comp(@emailbx, offset + rdata.length);
          end
          
          return rdata;
        end
        
        
        def _canonicalRdata(data, offset)
          rdata = "";
          
          if (defined?@rmailbx)
            rdata += _name2wire(@rmailbx);
            rdata +=  _name2wire(@emailbx);
          end
          
          return rdata;
        end
      end
    end
  end
end
