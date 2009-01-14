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
      #Net::DNS::RR::AFSDB - DNS AFSDB resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS AFS Data Base (AFSDB) resource records.
      #
      #= COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 1183 Section 1
      class AFSDB < RR
        #Returns the RR's subtype field.  Use of the subtype field is documented
        #in RFC 1183.
        #
        #    print "subtype = ", rr.subtype, "\n"
        #
        attr_accessor :subtype
        
        #Returns the RR's hostname field.  See RFC 1183.
        #
        #    print "hostname = ", rr.hostname, "\n"
        #
        attr_accessor :hostname
        def new_from_data (data, offset)
          if (@rdlength > 0)
            subtype = data.unpack("\@#{offset} n")[0];
            offset += Net::DNS::INT16SZ;
            hostname = Net::DNS::Packet::dn_expand(data, offset)[0];
            @subtype = subtype;
            @hostname = hostname;
          end
        end
        
        def new_from_string(string)
          if (string!=nil && (string =~ /^(\d+)\s+(\S+)$/o))
            @subtype  = $1;
            @hostname = $2;
            @hostname.sub!(/\.+$/o,"");
          end
        end
        
        def new_from_hash(values)
          if (values.has_key?(:subtype))
            @subtype=values[:subtype]
          end
          if (values.has_key?(:hostname))
            @hostname=values[:hostname]
          end
        end
        
        def rdatastr
          if defined?@subtype
            return "#{@subtype} #{@hostname}." 
          else
            return '';
          end
        end
        
        def rr_rdata (packet, offset)
          rdata = "";
          
          if (defined?@subtype)
            rdata += [@subtype].pack("n");
            rdata += packet.dn_comp(@hostname, offset + rdata.length);
          end
          
          return rdata;
        end
        
        
        
        def _canonicalRdata
          # rdata contains a compressed domainname... we should not have that.
          rdata="";
          if (defined?@subtype)
            rdata += @subtype.pack("n");
            rdata +=  _name2wire(@hostname);
          end
          return rdata;
        end
      end
    end
  end
end
