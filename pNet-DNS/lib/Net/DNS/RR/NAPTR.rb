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
      #Net::DNS::RR::NAPTR - DNS NAPTR resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Naming Authority Pointer (NAPTR) resource records.
      #
      #= COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #
      #Portions Copyright (c) 2005 Olaf Kolkman NLnet Labs.
      #
      #Ruby version Copyright (c) 2006 AlexD (Nominet UK)
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #Net::DNS::RR::NAPTR is based on code contributed by Ryan Moats.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 2168
      class NAPTR < RR
        #Returns the order field.
        #
        #    print "order = ", rr.order, "\n"
        #
        attr_accessor :order
        #Returns the preference field.
        #
        #    print "preference = ", rr.preference, "\n"
        #
        attr_accessor :preference
        #Returns the flags field.
        #
        #    print "flags = ", rr.flags, "\n"
        #
        attr_accessor :flags
        #Returns the service field.
        #
        #    print "service = ", rr.service, "\n"
        #
        attr_accessor :service
        #Returns the regexp field.
        #
        #    print "regexp = ", rr.regexp, "\n"
        #
        attr_accessor :regexp
        #Returns the replacement field.
        #
        #    print "replacement = ", rr.replacement, "\n"
        #
        attr_accessor :replacement
        def init_rrsort_func 
          set_rrsort_func("order", Proc.new { |a,b| a.order <=> b.order || a.preference <=> b.preference } )                    
          set_rrsort_func("default_sort", get_rrsort_func("order"))
          set_rrsort_func("preference", Proc.new { |a,b| a.preference <=> b.preference || a.order <=> b.order } );
        end        
        
        def new_from_data(data, offset)
          if (@rdlength > 0)
            @order = data.unpack("\@#{offset} n")[0];
            offset += Net::DNS::INT16SZ;
            
            @preference = data.unpack("\@#{offset} n")[0];
            offset += Net::DNS::INT16SZ;
            
            len = data.unpack("\@#{offset} C")[0];
            offset+=1;
            @flags = data.unpack("\@#{offset} a#{len}")[0];
            offset += len;
            
            len = data.unpack("\@#{offset} C")[0];
            offset+=1;
            @service = data.unpack("\@#{offset} a#{len}")[0];
            offset += len;
            
            len = data.unpack("\@#{offset} C")[0];
            offset+=1;
            @regexp = data.unpack("\@#{offset} a#{len}")[0];
            offset += len;
            
            @replacement = Net::DNS::Packet::dn_expand(data, offset)[0];
          end
          
        end
        
        def new_from_string(string)
          if (string && string =~ /^(\d+)\s+(\d+)\s+['"] (.*?) ['"] \s+['"] (.*?) ['"] \s+['"] (.*?) ['"] \s+(\S+) $/x)
            
            @order       = $1;
            @preference  = $2;
            @flags       = $3;
            @service     = $4;
            @regexp      = $5;
            @replacement = $6;
            @replacement.sub!(/\.+$/,"");
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:order)
            @order = values[:order]
          end
          if values.has_key?(:preference)
            @preference = values[:preference]
          end
          if values.has_key?(:flags)
            @flags = values[:flags]
          end
          if values.has_key?(:service)
            @service = values[:service]
          end
          if values.has_key?(:regexp)
            @regexp = values[:regexp]
          end
          if values.has_key?(:replacement)
            @replacement = values[:replacement]
          end
        end
        
        def rdatastr
          rdatastr=""
          
          if (defined?@order)
            rdatastr = @order.to_s + ' ' +@preference.to_s + ' "'  +@flags.to_s + '" "' +@service.to_s + '" "' +@regexp.to_s + '" ' +@replacement.to_s + '.';
          else
            rdatastr = '';
          end
          
          return rdatastr;
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@order)
            
            rdata += [@order, @preference].pack("n2");
            
            rdata += [@flags.length].pack("C");
            rdata += @flags;
            
            rdata += [@service.length].pack("C");
            rdata += @service;
            
            rdata += [@regexp.length].pack("C");
            rdata += @regexp;
            
            rdata += packet.dn_comp(@replacement, offset + rdata.length);
          end
          
          return rdata;
        end
      end
    end
  end
end
