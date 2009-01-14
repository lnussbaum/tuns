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
      #Net::DNS::RR::OPT - DNS OPT
      #
      #= DESCRIPTION
      #
      #Class for EDNS pseudo resource record OPT.
      #
      #= Construction
      #
      #This object should only be used inside the Net::DNS classes itself.
      #
      #Since "OPT" is a pseudo record and should not be stored in
      #masterfiles; Therefore we have not implemented a method to create this
      #RR from string.
      #
      #One may create the object from a hash. See RFC 2671 for details for
      #the meaning of the hash keys.
      #
      # rr= Net::DNS::RR.new_from_hash({
      #    'name' => "",     # Ignored and set to ""
      #    'type' => "OPT",  
      #    'class' => 1024,    # sets UDP payload size
      #    :extendedrcode =>  0x00,    # sets the extended RCODE 1 octets
      #    :ednsflags     =>  0x0000,  # sets the ednsflags (2octets)  
      #    :optioncode   =>   0x0      # 2 octets
      #    :optiondata   =>   0x0      # optionlength octets
      # })
      #
      #The ednsversion is set to 0 for now. The ttl value is determined from 
      #the extendedrcode, the ednsversion and the ednsflag.
      #The rdata is constructed from the optioncode and optiondata 
      #see section 4.4 of RFC 2671
      #
      #If optioncode is left undefined then we do not expect any RDATA.
      #
      #The defaults are no rdata.   
      #
      #
      #= TODO
      #
      #- This class is tailored to use with dnssec. 
      #
      #- Do some range checking on the input.
      #
      #- This class probably needs subclasses once OPTION codes start to be defined.
      #
      #- look at use of extended labels
      #
      #= COPYRIGHT
      #
      #Copyright (c) 2001, 2002  RIPE NCC.  Author Olaf M. Kolkman
      #
      #Ruby version Copyright (c) 2006 AlexD (Nominet UK)
      #
      #All Rights Reserved
      #
      #Permission to use, copy, modify, and distribute this software and its
      #documentation for any purpose and without fee is hereby granted,
      #provided that the above copyright notice appear in all copies and that
      #both that copyright notice and this permission notice appear in
      #supporting documentation, and that the name of the author not be
      #used in advertising or publicity pertaining to distribution of the
      #software without specific, written prior permission.
      #
      #
      #THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
      #ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO EVENT SHALL
      #AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
      #DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
      #AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
      #OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
      #
      #Based on, and contains, code by Copyright (c) 1997-2002 Michael Fuhr.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 2435 Section 3
      class OPT < RR
        attr_accessor :optioncode, :optionlength, :optiondata, :extendedrcode, :ednsversion, :ednsflags
        @@EDNSVERSION = 0;
        
        @@extendedrcodesbyname = {
	"ONLY_RDATA" => 0,		# No name specified see 4.6 of 2671 
	"UNDEF1"     => 1,
	"UNDEF2"     => 2,
	"UNDEF3"     => 3,
	"UNDEF4"     => 4,
	"UNDEF5"     => 5,
	"UNDEF6"     => 6,
	"UNDEF7"     => 7,
	"UNDEF8"     => 8,
	"UNDEF9"     => 9,
	"UNDEF10"    => 10,
	"UNDEF11"    => 11,
	"UNDEF12"    => 12,
	"UNDEF13"    => 13,
	"UNDEF14"    => 14,
	"UNDEF15"    => 15,
	"BADVERS"    => 16,		# RFC 2671
        }
        @@extendedrcodesbyval = @@extendedrcodesbyname.invert
        
        
        
        def new_from_data(data, offset)
          @name = "" ;   # should allway be "root"
          
          if (@rdlength > 0)
            @optioncode   = data[offset, 2].unpack("n")[0];
            @optionlength = data[offset+2, 2].unpack("n")[0];
            @optiondata   = data[offset+4, @optionlength].unpack("n");
          end
          
          @_rcode_flags  = [@ttl].pack("N");
          
          @extendedrcode = @_rcode_flags[0, 1].unpack("C")[0];
          @ednsversion   = @_rcode_flags[1, 1].unpack("C")[0];
          @ednsflags     = @_rcode_flags[2, 2].unpack("n")[0];
        end          
        
        
        
        
        
        def new_from_string(*args)
          # There is no such thing as an OPT RR in a ZONE file. 
          # Not implemented!
          raise RuntimeError, "You should not try to create a OPT RR from a string\nNot implemented";
        end
        
        
        
        def new_from_hash(values)
          @name = "" ;   # should allway be "root"
          
          
          # Setting the MTU smaller then 512 does not make sense 
          # should we test for a maximum here?
          if (@rrclass == "IN" || @rrclass.to_s.to_i < 512) 
            @rrclass = 512;    # Default value...
          end
          
          @extendedrcode = 0
          if values.has_key?:extendedrcode
            @extendedrcode = values[:extendedrcode]
          end
          
          @ednsflags   = 0;
          if values.has_key?:ednsflags
            @ednsflags = values[:ednsflags]
          end
          
          @ednsversion = @@EDNSVERSION;
          if values.has_key?:ednsversion
            @ednsversion = values[:ednsversion]
          end
          
          @ttl= ([@extendedrcode].pack("C") + [@ednsversion].pack("C") + [@ednsflags].pack("n")).unpack("N")[0]
          
          if (values.has_key?:optioncode)
            @optiondata   = ""
            if values.has_key(:optiondata)
              @optiondata= values[:optiondata]
            end
            @optionlength = @optiondata.length 
          end
        end              
        
        
        
        
        def inpsect
          return "; EDNS Version "     + @ednsversion + \
	"\t UDP Packetsize: " +  @class  +  "\n; EDNS-RCODE:\t"   + @extendedrcode  + \
	" (" + @@extendedrcodesbyval[@extendedrcode] + ")" + \
	"\n; EDNS-FLAGS:\t"   + sprintf("0x%04x", @ednsflags) + "\n";
        end
        
        
        def rdatastr
          return '; Parsing of OPT rdata is not yet implemented';
        end              
        
        def rr_rdata(*args)
          rdata="";
          
          if (defined?@optioncode)
            rdata  = pack("n", @optioncode);
            rdata += pack("n", @optionlength); 
            rdata += @optiondata
          end	
          return rdata;
        end                                                
        
        #Reads the do flag. (first bit in the ednssflags);
        def do_flag
          return ( 0x8000 & @ednsflags );
        end
        
        #Sets the do flag. (first bit in the ednssflags);
        def set_do_flag
          return @ednsflags = ( 0x8000 | @ednsflags );
        end
        
        #Clears the do flag. (first bit in the ednssflags);
        def clear_do_flag
          return @ednsflags = ( ~0x8000 & @ednsflags );
        end                
        
        #Set the packet size.
        #
        #    opt.size(1498)
        def size=(s)
          if (s != nil)
            @rrclass=s;
          end
          return @rrclass;
        end
        
        #Get the packet size.
        #
        #    print "Packet size:". opt.size
        # 
        def size
          return @rrclass
        end        
      end
    end
  end
end
