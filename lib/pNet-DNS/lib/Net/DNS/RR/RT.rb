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
      #Net::DNS::RR::RT - DNS RT resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Route Through (RT) resource records.
      #
      #= COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #Portions Copyright (c) 2005 Olaf Kolkman NLnet Labs.
      #Ruby version Copyright (c) 2006 AlexD, Nominet UK.
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 1183 Section 3.3
      class RT < RR
        #Returns the preference for this route.
        #
        #    print "preference = ", rr.preference, "\n"
        #
        attr_accessor :preference
        #Returns the domain name of the intermediate host.
        #
        #    print "intermediate = ", rr.intermediate, "\n"
        #
        attr_accessor :intermediate
        def init_rrsort_func 
          # Highest preference sorted first.
          set_rrsort_func("preference", Proc.new { |a,b|  a.preference <=> b.preference } )
          
          set_rrsort_func("default_sort", get_rrsort_func("preference") );
        end
        
        def new_from_data(data, offset)
          if (@rdlength > 0)
            @preference  = data.unpack("\@#{offset} n")[0];
            offset += Net::DNS::INT16SZ;
            
            @intermediate = Net::DNS::Packet::dn_expand(data, offset)[0];
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:intermediate)
            @intermediate = values[:intermediate]
          end
          if values.has_key?(:preference)
            @preference = values[:preference]
          end
        end
        
        def new_from_string(string)
          if (string && (string =~ /^(\d+)\s+(\S+)$/))
            @preference   = $1;
            @intermediate = $2;
            @intermediate.sub!(/\.+$/, "");
          end
        end
        
        def rdatastr
          return @preference ? "#{@preference} #{@intermediate}." : '';
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@preference)
            rdata += [@preference].pack("n");
            rdata += packet.dn_comp(@intermediate, offset + rdata.length);
          end
          
          return rdata;
        end
        
        def _canonicalRdata(packet, offset)
          rdata = "";
          
          if (defined?@preference)
            rdata += [@preference].pack("n");
            rdata += _name2wire(@intermediate);
          end
          
          return rdata;
        end
      end
    end
  end
end
