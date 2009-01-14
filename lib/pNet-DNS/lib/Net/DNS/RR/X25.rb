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
      #Net::DNS::RR::X25 - DNS X25 resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS X25 resource records.
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
      #RFC 1183 Section 3.1
      class X25 < RR
        #Returns the PSDN address.
        #
        #    print "psdn = ", rr.psdn, "\n"
        #
        attr_accessor :psdn
        def new_from_data(data, offset)
          if (@rdlength > 0)
            len = data.unpack("\@#{offset} C")[0]
            offset+=1
            @psdn = data[offset, len].to_i();
            offset += len;
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:psdn)
            @psdn = values[:psdn]
          end
        end
        
        def new_from_string(string)
          if (string && string =~ /^\s*["']?(.*?)["']?\s*$/)
            @psdn = $1.to_i();
          end
        end
        
        def rdatastr
          if defined?@psdn 
            return "'#{@psdn}'" 
          else
            return  ''
          end
        end
        
        def rr_rdata(*args)
          rdata = "";
          
          if (defined?@psdn)
            s = "%d" % @psdn
            rdata += [s.length].pack("C");
            rdata += s;
          end
          
          return rdata;
        end
      end
    end
  end
end
