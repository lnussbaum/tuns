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
      #Net::DNS::RR::A - DNS A resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Address (A) resource records.
      #
      #=head1 COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #=head1 SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 1035 Section 3.4.1
      class A < RR
        #Returns the RR's address field.
        #
        #    print "address = ", rr.address, "\n"
        #
        attr_accessor :address
        def inet_aton ip
          A.inet_aton ip
        end
        def A.inet_aton ip
          ret =          ip.split(/\./).map{|c| c.to_i}.pack("C*") # .unpack("N").first
          return ret
        end
        def inet_ntoa n
          A.inet_ntoa n
        end
        def A.inet_ntoa n
          ret=          n.unpack("C*").join "."
          return ret
        end
        def new_from_string(string)
          if (string && (string =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)\s*$/o))
            a = $1.to_i
            b = $2.to_i
            if (a >= 0) && (a <= 255) && (b >= 0) && (b <= 255)
              c = $3.to_i
              d = $4.to_i
              if (c >= 0) && (c <= 255) && (d >= 0) && (d <= 255) 
                
                @address = "#{a}.#{b}.#{c}.#{d}";
              end
            end
          end
        end
        def new_from_data(data, offset)
          if (@rdlength > 0)
            @address = inet_ntoa(data[offset, 4]);
            #              @address = IPAddr.new_ntoh(data[offset, 4])
            #              IPAddr.new(data[offset, 4], Socket::AF_INET).to_s
          end
        end
        def new_from_hash(values)
          if (values.has_key?(:address))
            @address=values[:address]
          end
        end
        
        def rdatastr
          return @address || '';
        end
        
        def rr_rdata(*args)
          if (defined?@address)
            return inet_aton(@address)
          else
            return ""
          end
        end
        
      end
    end
  end
end
