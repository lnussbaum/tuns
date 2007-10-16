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
      #Net::DNS::RR::MR - DNS MR resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Mail Rename (MR) resource records.
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
      #RFC 1035 Section 3.3.8
      class MR < RR
        #Returns the RR's new name field.
        #
        #    print "newname = ", rr.newname, "\n"
        #
        attr_accessor :newname
        def new_from_data(data, offset)
          if (@rdlength > 0)
            @newname = Net::DNS::Packet::dn_expand(data, offset)[0];
          end
        end
        
        def new_from_string(s)
          if (s)
            string = s.sub(/\.+$/, "");
            @newname = string;
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:newname)
            @newname = values[:newname]
          end
        end
        
        def rdatastr
          return @newname ? "#{@newname}." : '';
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@newname)
            rdata += packet.dn_comp(@newname, offset);
          end
          
          return rdata;
        end
        
        def _canonicalRdata
          rdata = "";
          if (defined?@newname)
            rdata += _name2wire(@newname);
          end
          return rdata;
        end        
      end
    end
  end
end
