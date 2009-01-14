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
      #Net::DNS::RR::PX - DNS PX resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS X.400 Mail Mapping Information (PX) resource records.
      #
      #= COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #Portions Copyright (c) 2005 Olaf Kolkman NLnet Labs.
      #Ruby version Copyright (c) 2006 Alexd ( Nominet UK ).
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC822, RFC 1327, RFC 2163
      class PX < RR
        #Returns the preference given to this RR.
        #
        #    print "preference = ", rr.preference, "\n"
        #
        attr_accessor :preference
        #Returns the RFC822 part of the RFC1327 mapping information.
        #
        #    print "map822 = ", rr.map822, "\n"
        #
        attr_accessor :map822
        #Returns the X.400 part of the RFC1327 mapping information.
        #
        #    print "mapx400 = ", rr.mapx400, "\n"
        #
        attr_accessor :mapx400
        # Highest preference sorted first.
        
        def init_rrsort_func 
          set_rrsort_func("preference", Proc.new { |a,b|  a.preference <=> b.preference});                    
          set_rrsort_func("default_sort", get_rrsort_func("preference"));
        end        
        
        def new_from_data(data, offset)
          if (@rdlength > 0)
            @preference = data.unpack("\@#{offset} n")[0];
            offset += Net::DNS::INT16SZ;
            
             (@map822,  offset) = Net::DNS::Packet::dn_expand(data, offset);
             (@mapx400, offset) = Net::DNS::Packet::dn_expand(data, offset);
          end
        end
        
        def new_from_string(string)
          if (string && (string =~ /^(\d+)\s+(\S+)\s+(\S+)$/))
            @preference = $1;
            @map822     = $2;
            @mapx400    = $3;
            @map822.sub!(/\.+$/,"")
            @mapx400.sub!(/\.+$/,"")
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:preference)
            @preference = values[:preference]
          end
          if values.has_key?(:map822)
            @map822 = values[:map822]
          end
          if values.has_key?(:mapx400)
            @mapx400 = values[:mapx400]
          end
        end
        
        def rdatastr
          return @preference ? "#{@preference} #{@map822}. #{@mapx400}." : '';
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@preference)
            rdata += [@preference].pack("n");
            
            rdata += packet.dn_comp(@map822, offset + rdata.length);
            
            rdata += packet.dn_comp(@mapx400, offset + rdata.length);
          end
          
          return rdata;
        end
        
        
        def _canonicalRdata
          rdata = "";
          
          if (defined?@preference)
            rdata += [@preference].pack("n");
            rdata += _name2wire(@map822);					   
            rdata += _name2wire(@mapx400);
          end
          
          return rdata;
        end
      end
    end
  end
end
