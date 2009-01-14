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
      #Net::DNS::RR::MG - DNS MG resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Mail Group (MG) resource records.
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
      #=head1 SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 1035 Section 3.3.6
      class MG < RR
        #Returns the RR's mailbox field.
        #
        #    print "mgmname = ", rr.mgmname, "\n"
        #
        attr_accessor :mgmname
        def new_from_data(data, offset)
          if (@rdlength > 0)
            @mgmname = Net::DNS::Packet::dn_expand(data, offset)[0];
          end
        end
        
        def new_from_string(s)
          if (s)
            string = s.sub(/\.+$/,"");
            @mgmname = string;
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:mgmname)
            @mgmname = values[:mgmname]
          end
        end
        
        def rdatastr
          if defined?@mgmname 
            return "#{@mgmname}."           
          else 
            return  ''
          end
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@mgmname)
            rdata += packet.dn_comp(@mgmname, offset);
          end
          
          return rdata;
        end
        
        
        def _canonicalRdata
          rdata = "";
          if (defined?@mgmname)
            rdata += _name2wire(@mgmname);
          end
          return rdata;
        end
      end
    end
  end
end
