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
      #Net::DNS::RR::SSHFP - DNS SSHFP resource record
      #
      #= DESCRIPTION
      #
      #Class for Delegation signer (SSHFP) resource records.
      #
      #= ACKNOWLEDGEMENT
      #
      #Jakob Schlyter for code review and supplying patches.
      #
      #= COPYRIGHT
      #
      #Copyright (c) 2004 RIPE NCC, Olaf Kolkman.
      #
      #"All rights reserved, This program is free software; you may redistribute it
      #and/or modify it under the same terms as Perl itself.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #draft-ietf-dnssext-delegation-signer
      class SSHFP < RR
        #Returns the RR's algorithm field in decimal representation
        #
        #    1 = RSA
        #    2 = DSS
        #
        #    print "algoritm" = ", rr.algorithm, "\n"
        #
        attr_accessor :algorithm
        
        attr_accessor :fingerprint
        
        #Returns the SHA1 fingerprint over the label and key in hexadecimal
        #representation.
        #
        #
        #Returns the fingerprint as binary material.
        attr_accessor :fpbin
        
        #Returns the fingerprint type of the SSHFP RR.
        #
        #   print "fingerprint type  = " + rr.fptype  + "\n"
        #
        attr_accessor :fptype
        #=head2 babble
        #
        #   print $rr->babble;
        #
        #If Digest::BubbleBabble is available on the sytem this method returns the
        #'BabbleBubble' representation of the fingerprint. The 'BabbleBubble'
        #string may be handy for telephone confirmation.
        #
        #The 'BabbleBubble' string returned as a comment behind the RDATA when
        #the string method is called.
        #
        #The method returns an empty string if Digest::BubbleBable is not installed.
        #
        
        
        #        BEGIN {
        #          eval {
        #            require Digest::BubbleBabble; 
        #            Digest::BubbleBabble->import(qw(bubblebabble))
        #          };
        #          
        #          $HasBabble = $@ ? 0 : 1;
        #          
        #        }
        #        @TODO Use BubbleBabble!!
        HasBabble = false
        
        @@algtype = {
    'RSA' => 1,
	'DSA' => 2}
        
        @@fingerprinttype = {'SHA-1' => 1}
        
        @@fingerprinttypebyval = @@fingerprinttype.reverse 
        @@algtypebyval	       = @@algtype.reverse
        
        
        def new_from_data(data, offset)
          if (@rdlength > 0)
            offsettoalg    = offset
            offsettofptype = offset+1
            offsettofp     = offset+2
            fplength       = 20   # This will need to change if other fingerprint types
            # are being deployed.
            
            
            @algorithm = data[oggsettoalg, 1].unpack('C') # , substr($$data, $offsettoalg, 1))
            @fptype    = data[offsettofptype, 1].unpack('C') # , substr($$data, $offsettofptype, 1))
            
            raise NotImplementedError, "This fingerprint type #{@fptype} has not yet been implemented\n." +
			"Contact developer of Net::DNS::RR::SSHFP.\n"  unless fingerprinttypebyval[@fptype] != nil
            
            # All this is SHA-1 dependend
            @fpbin = data[offsettofp, fplength] # SHA1 digest 20 bytes long
            
            @fingerprint = @fpbin.unpack('H*').upcase!  # uc unpack('H*', $self->{:fpbin});
          end
        end
        
        
        def new_from_string(instring)
          if (string)
            instring = string.tr("()", "") # /()//d
            string.gsub!(/;.*$/, "") # /mg
            string.gsub!(/\n/, "")
            
            @algorithm, @fptype, @fingerprint = string.split(/\s+/, 3)
            
            # We allow spaces in the fingerprint.
            @fingerprint.gsub!(/\s/, "")
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:fingerprint)
            @fingerprint = values[:fingerprint]
          end
          if values.has_key?(:fptype)
            @fptype = values[:fptype]
          end
          if values.has_key?(:fpbin)
            @fpbin = values[:fpbin]
          end
          if values.has_key?(:algorithm)
            @algorithm = values[:algorithm]
          end
        end
        
        
        def rdatastr
          rdatastr = ''
          
          if (@algorithm!=nil)
            rdatastr = [@algorithm, @fptype, @fingerprint].join('  ') + ' ; ' + babble()
          end
          
          return rdatastr
        end
        
        def rr_rdata
          if (@algorithm != nil)
            return [@algorithm, @fptype].pack('C2') + fpbin()
          end
          
          return ''
        end
        
        
        def babble
          if (HasBabble)
            return bubblebabble(Digest => fpbin())
          else
            return ""
          end
        end
        
        
        def fpbin
          return @fpbin ||= [@fingerprint].pack('H*')
        end
      end
    end
  end
end	
