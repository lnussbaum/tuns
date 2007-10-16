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
      #Net::DNS::RR::AAAA - DNS AAAA resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS IPv6 Address (AAAA) resource records.
      #
      #= BUGS
      #
      #The inspect method returns only the preferred method of address
      #representation ("x:x:x:x:x:x:x:x", as documented in RFC 1884,
      #Section 2.2, Para 1).
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
      #RFC 1886 Section 2, RFC 1884 Sections 2.2 & 2.4.4
      class AAAA < RR
        #Returns the RR's address field.
        #
        #    print "address = ", rr.address, "\n"
        #
        attr_accessor :address
        def new_from_data(data, offset)
          if (@rdlength > 0)
            addr = data.unpack("\@#{offset} n8");
            #            @address = sprintf("%x:%x:%x:%x:%x:%x:%x:%x", addr);
            @address=""
            addr.each { |x| @address += sprintf("%x:", x) }
            @address = @address[0, @address.length-1]
          end
        end
        
        def new_from_string(string)
          if (string) 
            # I think this is correct, per RFC 1884 Sections 2.2 & 2.4.4.
            if (string =~ /^(.*):(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
              #			my ($front, $a, $b, $c, $d) = ($1, $2, $3, $4, $5);
              front = $1
              a = $2.to_1
              b = $3.to_i
              c = $4.to_i
              d = $5.to_i
              string = front + sprintf(":%x:%x",(a << 8 | b),(c << 8 | d));
            end
            
            if (string =~ /^(.*)::(.*)$/)
              #			my ($front, $back) = ($1, $2);
              front = $1
              back = $2
              front = front.split(/:/)
              back  = back.split(/:/)
              fill = 8 - (front ? front.length + 1 : 0)- (back  ? back.length  + 1 : 0);
              middle = []
              fill.times {middle.push("0")}
              addr = front + middle + back
            else
              addr = string.split(/:/);
              if (addr.length < 8)
               (8 - addr.length).times {addr.insert(0,"0")}
              end
            end
            
            @address = ""
            addr.each {|a| @address += sprintf("%x:", a.to_i(16))}
            # remove last ':'
            @address= @address[0, @address.length-1]
            
            # sprintf("%x:%x:%x:%x:%x:%x:%x:%x", addr.map { |a| a.to_i(16) });
            #		$self->{"address"} = sprintf("%x:%x:%x:%x:%x:%x:%x:%x", map { hex $_ } @addr);
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
          rdata = "";
          
          if (defined?@address)
            addr = @address.split(/:/)
            rdata += addr.map {|a| a.to_i(16) }.pack("n8");            
          end
          return rdata;
        end
        
        @@Regex = nil
        def AAAA.init_regex
          if (@@Regex == nil) 
            @@Regex_8Hex  	=  	/\A (?:[0-9A-Fa-f]{1,4}:){7} [0-9A-Fa-f]{1,4} \z/x  	   #	IPv6 address format a:b:c:d:e:f:g:h
            @@Regex_CompressedHex 	= 	/\A ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) :: ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) \z/x 	  #	Compressed IPv6 address format a::b
            @@Regex_6Hex4Dec 	= 	/\A ((?:[0-9A-Fa-f]{1,4}:){6,6}) (\d+)\.(\d+)\.(\d+)\.(\d+) \z/x 	  #	IPv4 mapped IPv6 address format a:b:c:d:e:f:w.x.y.z
            @@Regex_CompressedHex4Dec 	= 	/\A ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) :: ((?:[0-9A-Fa-f]{1,4}:)*) (\d+)\.(\d+)\.(\d+)\.(\d+) \z/x 	  #	Compressed IPv4 mapped IPv6 address format a::b:w.x.y.z
            @@Regex 	= 	/ (?:#{@@Regex_8Hex}) | (?:#{@@Regex_CompressedHex}) | (?:#{@@Regex_6Hex4Dec}) | (?:#{@@Regex_CompressedHex4Dec})/x 
          end
        end
        
        def AAAA.is_valid(a)
          init_regex
          if a =~ @@Regex
            return true
          else
            return false
          end
        end
      end
    end
  end
end
