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
      #Net::DNS::RR::PTR - DNS PTR resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Pointer (PTR) resource records.
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
      #RFC 1035 Section 3.3.12
      class PTR < RR
        #Returns the domain name associated with this record.
        #
        #    print "ptrdname = ", rr.ptrdname, "\n"
        #
        attr_accessor :ptrdname
        def new_from_data(data, offset)
          if (@rdlength > 0)
            @ptrdname = Net::DNS::Packet::dn_expand(data, offset)[0];
          end
        end
        
        def new_from_string(s)
          if (s != nil)
            string = s.gsub(/\.+$/, "");
            @ptrdname = string;
          end
        end
        
        def new_from_hash(values)
          if (values.has_key?:ptrdname)
            @ptrdname = values[:ptrdname]
          end
        end
        
        def rdatastr
          return @ptrdname ? "#{@ptrdname}." : '';
          
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@ptrdname)
            rdata += packet.dn_comp(@ptrdname, offset);
          end
          
          return rdata;
        end
        
        def  _canonicalRdata(packet, offset)
          rdata = "";
          
          if (defined?@ptrdname)
            rdata += _name2wire(@ptrdname);
          end
          
          return rdata;
        end
      end
    end
  end
end
