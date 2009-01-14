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
      #Net::DNS::RR::DNAME - DNS DNAME resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Non-Terminal Name Redirection (DNAME) resource records.
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
      #RFC 2672
      class DNAME < RR
        #Returns the DNAME target.
        #
        #    print "dname = ", rr.dname, "\n"
        #
        attr_accessor :dname
        def new_from_data(packet, offset)
          if (@rdlength > 0)
            @dname = Net::DNS::Packet.dn_expand(packet, offset)[0];
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:dname)
            @dname = values[:dname]
          end
        end
        
        def new_from_string(s)
          if (s != nil)
            string = s.sub(/\.+$/o, "");
            @dname = string;
          end
        end
        
        def rdatastr
          return @dname ? "#{@dname}." : '';
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@dname)
            rdata = packet.dn_comp(@dname, offset);
          end
          
          return rdata;
        end
      end
    end
  end
end
