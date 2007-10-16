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
      #Net::DNS::RR::ISDN - DNS ISDN resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS ISDN resource records.
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
      #RFC 1183 Section 3.2
      class ISDN < RR
        #Returns the RR's address field.
        #
        #    print "address = ", rr.address, "\n"
        #
        attr_accessor :address
        #Returns the RR's subaddress field.
        #
        #    print "subaddress = ", rr.sa, "\n"
        #
        attr_accessor :sa
        def new_from_data(data, offset)
          if (@rdlength > 0)
            len = data.unpack("\@#{offset} C")[0];
            offset+=1;
            address = data[offset, len];
            offset += len;
            
            if (len + 1 < @rdlength)
              len = data.unpack("\@#{offset} C")[0];
              offset+=1;
              sa = data[offset, len];
              offset += len;
            else
              sa = "";
            end
            @address = address;
            @sa  = sa;
          end
        end
        
        def new_from_string(string)
          if (string && string =~ /^['"](.*?)['"](.*)/s)
            @address = $1;
            rest = $2;
            
            if (rest =~ /^\s+['"](.*?)['"]$/)
              @sa = $1;
            else
              @sa = "";
            end
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:address)
            @address = values[:address]
          end
          if values.has_key?(:sa)
            @sa = values[:sa]
          end
        end
        
        def rdatastr
          return @address ? "'#{@address}' '#{@sa}'" : '';
        end
        
        def rr_rdata(*args)
          rdata = "";
          
          if (defined?@address)
            rdata += [@address.length].pack("C");
            rdata += @address;
            
            if (@sa)
              rdata += [@sa.length].pack("C");
              rdata += @sa;
            end
          end
          
          return rdata;
        end
      end
    end
  end
end
