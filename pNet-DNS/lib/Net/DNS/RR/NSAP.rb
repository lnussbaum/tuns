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
      #Net::DNS::RR::NSAP - DNS NSAP resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Network Service Access Point (NSAP) resource records.
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
      #it and/or modify it under the same terms as Perl itself.. 
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 1706.
      class NSAP < RR
        #Returns the RR's authority and format identifier.  Net::DNS
        #currently supports only AFI 47 (GOSIP Version 2).
        #
        #    print "afi = ", rr.afi, "\n"
        #
        attr_accessor :afi
        #Returns the RR's initial domain identifier.
        #
        #    print "idi = ", rr.idi, "\n"
        #
        attr_accessor :idi
        #Returns the RR's DSP format identifier.
        #
        #    print "dfi = ", rr.dfi, "\n"
        #
        attr_accessor :dfi
        #Returns the RR's administrative authority.
        #
        #    print "aa = ", rr.aa, "\n"
        #
        attr_accessor :aa
        #Returns the RR's routing domain identifier.
        #
        #    print "rd = ", rr.rd, "\n"
        #
        attr_accessor :rd
        #Returns the RR's area identifier.
        #
        #    print "area = ", rr.area, "\n"
        #
        attr_accessor :area
        #Returns the RR's system identifier.
        #
        #    print "id = ", rr.id, "\n"
        #
        attr_accessor :id
        #Returns the RR's NSAP selector.
        #
        #    print "sel = ", rr.sel, "\n"
        #
        attr_accessor :sel
        
        #Returns the RR's reserved field.
        #    print "rsvd = ", rr.rsvd, "\n"
        #
        attr_writer :rsvd
        def new_from_data(data, offset)
          if (@rdlength > 0)
            afi = data.unpack("\@#{offset} C")[0];
            @afi = sprintf("%02x", afi);
            offset+=1;
            
            if (@afi == "47")
              idi = data.unpack("\@#{offset} C2");
              offset += 2;
              
              dfi = data.unpack("\@#{offset} C")[0];
              offset += 1;
              
              aa = data.unpack("\@#{offset} C3");
              offset += 3;
              
              rsvd = data.unpack("\@#{offset} C2");
              offset += 2;
              
              rd = data.unpack("\@#{offset} C2");
              offset += 2;
              
              area = data.unpack("\@#{offset} C2");
              offset += 2;
              
              id = data.unpack("\@#{offset} C6");
              offset += 6;
              
              sel = data.unpack("\@#{offset} C")[0];
              offset += 1;
              
              @idi  = sprintf("%02x%02x", idi[0], idi[1]);
              @dfi  = sprintf("%02x", dfi);
              @aa   = sprintf("%02x%02x%02x", aa[0], aa[1], aa[2]);
              @rsvd = sprintf("%02x%02x", rsvd[0],rsvd[1]);
              @rd   = sprintf("%02x%02x", rd[0],rd[1]);
              @area = sprintf("%02x%02x", area[0],area[1]);
              @id   = sprintf("%02x%02x%02x%02x%02x%02x", id[0],id[1],id[2],id[3],id[4],id[5]);
              @sel  = sprintf("%02x", sel);
              
            else
              # What to do for unsupported versions?
            end
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:idi)
            @idi = values[:idi]
          end
          if values.has_key?(:dfi)
            @dfi = values[:dfi]
          end
          if values.has_key?(:afi)
            @afi = values[:afi]
          end
          if values.has_key?(:aa)
            @aa = values[:aa]
          end
          if values.has_key?(:sel)
            @sel = values[:sel]
          end
          if values.has_key?(:id)
            @id = values[:id]
          end
          if values.has_key?(:rsvd)
            @rsvd = values[:rsvd]
          end
          if values.has_key?(:rd)
            @rd = values[:rd]
          end
          if values.has_key?(:area)
            @area = values[:area]
          end
        end
        
        def new_from_string(s)
          if (s)
            string = s.gsub(/\./, "");  # remove all dots.
            string.gsub!(/^0x/,"");  # remove leading 0x
            
            if (string =~ /^[a-zA-Z0-9]{40}$/)
             (@afi, @idi, @dfi, @aa, @rsvd, @rd, @area, @id, @sel) = string.unpack("A2A4A2A6A4A4A4A12A2")
            end
          end
        end
        
        
        #Returns the RR's initial domain part (the AFI and IDI fields).
        #
        #    print "idp = ", rr.idp, "\n"
        #
        def idp
          ret = [@afi, @idi].join('')
          return ret
        end
        
        #Returns the RR's domain specific part (the DFI, AA, Rsvd, RD, Area,
        #ID, and SEL fields).
        #
        #    print "dsp = ", rr.dsp, "\n"
        #
        def dsp
          ret = [@dfi,@aa,rsvd,@rd,@area,@id,@sel].join('')
          return ret
        end
        
        def rsvd
          if (@rsvd==nil)
            return "0000"
          else
            return @rsvd
          end
        end
        
        def rdatastr
          rdatastr=""
          
          if (defined?@afi)
            if (@afi == "47")
              rdatastr = [idp, dsp].join('')
            else
              rdatastr = "; AFI #{@afi} not supported"
            end
          else
            rdatastr = ''
          end
          
          return rdatastr
        end
        
        def rr_rdata(*args)
          rdata = ""
          
          if (defined?@afi)
            #            rdata += [@afi.to_i().to_s(16).to_i()].pack("C");
            rdata += [@afi.to_i(16)].pack("C")
            
            if (@afi == "47")
              rdata += str2bcd(@idi,  2)
              rdata += str2bcd(@dfi,  1)
              rdata += str2bcd(@aa,   3)
              rdata += str2bcd(0,               2)	# rsvd
              rdata += str2bcd(@rd,   2)
              rdata += str2bcd(@area, 2)
              rdata += str2bcd(@id,   6)
              rdata += str2bcd(@sel,  1)
            end            
            # Checks for other versions would go here.
          end
          
          return rdata
        end
        
        #------------------------------------------------------------------------------
        # Usage:  str2bcd(STRING, NUM_BYTES)
        #
        # Takes a string representing a hex number of arbitrary length and
        # returns an equivalent BCD string of NUM_BYTES length (with
        # NUM_BYTES * 2 digits), adding leading zeros if necessary.
        #------------------------------------------------------------------------------
        
        # This can't be the best way....
        def str2bcd(s, bytes)
          retval = "";
          
          digits = bytes * 2;
          string = sprintf("%#{digits}s", s);
          string.tr!(" ","0");
          
          i=0;
          bytes.times do
            bcd = string[i*2, 2];
            retval += [bcd.to_i(16)].pack("C");
            i+=1
          end
          
          return retval;
        end
        
      end
    end
  end
end
