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
      #Net::DNS::RR::TKEY - DNS TKEY resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS TKEY resource records.
      #
      #=head1 BUGS
      #
      #This code has not been extensively tested.  Use with caution on
      #production systems. See http://samba.org/ftp/samba/tsig-gss/ for an
      #example usage.
      #
      #=head1 COPYRIGHT
      #
      #Copyright (c) 2000 Andrew Tridgell.  All rights reserved.  This program
      #is free software; you can redistribute it and/or modify it under
      #the same terms as Perl itself.
      #
      #=head1 ACKNOWLEDGMENT
      #
      #The Net::DNS::RR::TKEY module is based on the TSIG module by Michael
      #Fuhr and Chris Turbeville.
      #
      #=head1 SEE ALSO
      #
      #L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
      #L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
      #RFC 2845
      class TKEY < RR
        attr_accessor :offset, :key
        #Gets or sets the domain name that specifies the name of the algorithm.
        #The default algorithm is gss.microsoft.com
        #
        #    rr.algorithm=(algorithm_name)
        #    print "algorithm = ", rr.algorithm, "\n"
        #
        attr_accessor :algorithm
        #Gets or sets the inception time as the number of seconds since 1 Jan 1970
        #00:00:00 UTC.
        #
        #The default inception time is the current time.
        #
        #    rr.inception=(time)
        #    print "inception = ", rr.inception, "\n"
        #
        attr_accessor :inception
        #Gets or sets the expiration time as the number of seconds since 1 Jan 1970
        #00:00:00 UTC.
        #
        #The default expiration time is the current time plus 1 day.
        #
        #    rr.expiration=(time)
        #    print "expiration = ", rr.expiration, "\n"
        #
        attr_accessor :expiration
        #Sets the key mode (see rfc2930). The default is 3 which corresponds to GSSAPI
        #
        #    rr.mode=(3)
        #    print "mode = ", rr.mode, "\n"
        #
        attr_accessor :mode
        #Returns the RCODE covering TKEY processing.  See RFC 2930 for details.
        #
        #    print "error = ", rr.error, "\n"
        #
        attr_accessor :error
        #Returns the length of the Other Data.  Should be zero.
        #
        #    print "other len = ", rr.other_len, "\n"
        #
        attr_accessor :other_len
        #Returns the Other Data.  This field should be empty.
        #
        #    print "other data = ", rr.other_data, "\n"
        #
        attr_accessor :other_data
        
        def new_from_data(data, offset)          
          # if we have some data then we are parsing an incoming TKEY packet
          # see RFC2930 for the packet format
          if (@rdlength > 0)
            @algorithm, @offset = Net::DNS::Packet::dn_expand(data, offset)
            
            @inception, @expiration = data.unpack("\@#{offset} NN")[0]
            offset += Net::DNS::INT32SZ() + Net::DNS::INT32SZ();
            
            @inception, @expiration = data.unpack("\@#{offset} nn")[0]
            offset += Net::DNS::INT16SZ + Net::DNS::INT16SZ
            
            key_len = data.unpack("\@#{offset} n")[0]
            offset += Net::DNS::INT16SZ
            @key = data[offset, key_len]
            offset += key_len
            
            other_len = data.unpack("\@#{offset} n")[0]
            offset += Net::DNS::INT16SZ
            @other_data = data[offset, other_len]
            offset += other_len
          end
        end
        
        def new_from_hash(values)
          init_defaults
          if (values.has_key?:key)
            @key = values[:key]
          end
          if (values.has_key?:offset)
            @offset = values[:offset]
          end
          if (values.has_key?:algorithm)
            @algorithm = values[:algorithm]
          end
          if (values.has_key?:expiration)
            @expiration = values[:expiration]
          end
          if (values.has_key?:inception)
            @inception = values[:inception]
          end
          if (values.has_key?:other_len)
            @other_len = values[:other_len]
          end
          if (values.has_key?:other_data)
            @other_data = values[:other_data]
          end
          if (values.has_key?:error)
            @error = values[:error]
          end
          if (values.has_key?:mode)
            @mode = values[:mode]
          end
        end
        
        def new_from_string(string)
          if (string != nil && (string =~ /^(.*)$/))
            @key     = $1;
          end
          
          init_defaults
        end
        
        def init_defaults
          @algorithm   = "gss.microsoft.com"
          @inception   = Time.now
          @expiration  = Time.now + 24*60*60
          @mode        = 3 # GSSAPI
          @error       = 0
          @other_len   = 0
          @other_data  = ""
        end
        
        def error
          rcode=0
          error = @error
          
          if (error!=nil)
            rcode = Net::DNS::rcodesbyval[error] || error
          end
          
          return rcode
        end
        
        def rdatastr
          error = @error
          error = "UNDEFINED" unless error!=nil
          
          rdatastr=""
          
          if (@algorithm!=nil)
            rdatastr = "#{@algorithm}. #{error}"
            if (@other_len != nil && @other_len >0 && @other_data!=nil)
              rdatastr += " #{@other_data}"
            end
          else
            rdatastr = ''
          end
          
          return rdatastr
        end
        
        def rr_rdata(packet, offset)
          rdata = ""
          
          packet.compnames = Hash.new()
          rdata += packet.dn_comp(@algorithm, 0)
          rdata += [@inception].pack("N")
          rdata += [@expiration].pack("N")
          rdata += [@mode].pack("n")
          rdata += [0].pack("n"); # error
          rdata += [@key.length].pack("n")
          rdata += @key
          rdata += [@other_data.length].pack("n")
          rdata += @other_data
          
          return rdata
        end
      end
    end
  end
end
