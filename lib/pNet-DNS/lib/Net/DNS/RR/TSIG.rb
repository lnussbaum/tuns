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
require 'base64'
require "digest/md5"
module Net
  module DNS
    class RR
      #= NAME
      #
      #Net::DNS::RR::TSIG - DNS TSIG resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Transaction Signature (TSIG) resource records.
      #
      #= BUGS
      #
      #This code is still under development.  Use with caution on production
      #systems.
      #
      #The time_signed and other_data fields should be 48-bit unsigned
      #integers (RFC 2845, Sections 2.3 and 4.5.2).  The current implementation
      #ignores the upper 16 bits; this will cause problems for times later
      #than 19 Jan 2038 03:14:07 UTC.
      #
      #The only builtin algorithm currently supported is
      #HMAC-MD5.SIG-ALG.REG.INT. You can use other algorithms by supplying an
      #appropriate sign_func.
      #
      #= COPYRIGHT
      #
      #Copyright (c) 2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #= ACKNOWLEDGMENT
      #
      #Most of the code in the Net::DNS::RR::TSIG module was contributed
      #by Chris Turbeville. 
      #
      #Support for external signing functions was added by Andrew Tridgell.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 2845
      class TSIG < RR
        DEFAULT_ALGORITHM = "HMAC-MD5.SIG-ALG.REG.INT"
        DEFAULT_FUDGE     = 300
        
        #Gets or sets the domain name that specifies the name of the algorithm.
        #The only algorithm currently supported is HMAC-MD5.SIG-ALG.REG.INT.
        #
        #    rr.algorithm=(algorithm_name)
        #    print "algorithm = ", rr.algorithm, "\n"
        #
        attr_accessor :algorithm
        
        #Gets or sets the signing time as the number of seconds since 1 Jan 1970
        #00:00:00 UTC.
        #
        #The default signing time is the current time.
        #
        #    rr.time_signed=(time)
        #    print "time signed = ", rr.time_signed, "\n"
        #
        attr_accessor :time_signed
        
        #Gets or sets the "fudge", i.e., the seconds of error permitted in the
        #signing time.
        #
        #The default fudge is 300 seconds.
        #
        #    rr.fudge=(60)
        #    print "fudge = ", rr.fudge, "\n"
        #
        attr_accessor :fudge
        
        #Returns the number of octets in the message authentication code (MAC).
        #The programmer must call a Net::DNS::Packet object's data method
        #before this will return anything meaningful.
        #
        #    print "MAC size = ", rr.mac_size, "\n"
        #
        attr_writer :mac_size
        
        #Returns the message authentication code (MAC) as a string of hex
        #characters.  The programmer must call a Net::DNS::Packet object's
        #data method before this will return anything meaningful.
        #
        #    print "MAC = ", rr.mac, "\n"
        #
        attr_writer :mac
        
        #Gets or sets the original message ID.
        #
        #    rr.original_id(12345)
        #    print "original ID = ", rr.original_id, "\n"
        #
        attr_accessor :fudge, :original_id
        
        #Returns the RCODE covering TSIG processing.  Common values are
        #NOERROR, BADSIG, BADKEY, and BADTIME.  See RFC 2845 for details.
        #
        #    print "error = ", rr.error, "\n"
        #
        attr_writer :error
        
        #Returns the length of the Other Data.  Should be zero unless the
        #error is BADTIME.
        #
        #    print "other len = ", rr.other_len, "\n"
        #
        attr_accessor :other_len
        
        #Returns the Other Data.  This field should be empty unless the
        #error is BADTIME, in which case it will contain the server's
        #time as the number of seconds since 1 Jan 1970 00:00:00 UTC.
        #
        #    print "other data = ", rr.other_data, "\n"
        #
        attr_accessor :other_data
        
        #This sets the signing function to be used for this TSIG record. 
        #
        #The default signing function is HMAC-MD5.
        #
        #     tsig.sign_func=(Proc.new {|key, data| return some_digest_algorithm(key, data)})
        #
        attr_accessor :sign_func
        attr_accessor :key
        
        def new_from_hash(values)
          init_defaults
          if (values.has_key?:key)
            @key = values[:key]
          end
          if (values.has_key?:fudge)
            @fudge = values[:fudge]
          end
          if (values.has_key?:algorithm)
            @algorithm = values[:algorithm]
          end
          if (values.has_key?:mac_size)
            @mac_size = values[:mac_size]
          end
          if (values.has_key?:mac)
            @mac = values[:mac]
          end
          if (values.has_key?:other_len)
            @other_len = values[:other_len]
          end
          if (values.has_key?:other_data)
            @other_data = values[:other_data]
          end
          if (values.has_key?:original_id)
            @original_id = values[:original_id]
          end
          if (values.has_key?:error)
            @error = values[:error]
          end
          if (values.has_key?:sign_func)
            @sign_func = values[:sign_func]
          end
          if (values.has_key?:time_signed)
            @time_signed = values[:time_signed]
          end
        end
        
        def new_from_data(data, offset)
          if (@rdlength > 0)
            @algorithm, offset = Net::DNS::Packet.dn_expand(data, offset)
            
            time_high, time_low = data.unpack("\@#{offset} nN")
            self.time_signed = time_low	# bug
            offset += Net::DNS::INT16SZ + Net::DNS::INT32SZ
            
            @fudge, @mac_size = data.unpack("\@$offset nn")
            offset += Net::DNS::INT16SZ + Net::DNS::INT16SZ
            
            @mac = data[offset, @mac_size]
            offset += @mac_size
            
            @original_id, @error, @other_len = data.unpack("\@#{offset} nnn")
            offset += Net::DNS::INT16SZ * 3
            
            odata = data[offset, @other_len]
            odata_high, odata_low = odata.unpack("nN")
            @other_data = odata_low
          end
        end
        
        def new_from_string(string)
          
          if (string!=nil && (string =~ /^(.*)$/))
            @key     = $1
          end
          
          init_defaults
        end
        
        def init_defaults
          @algorithm   = DEFAULT_ALGORITHM
          @time_signed = Time.now.to_i
          @fudge       = DEFAULT_FUDGE
          @mac_size    = 0
          @mac         = ""
          @original_id = 0
          @error       = 0
          @other_len   = 0
          @other_data  = nil
          @sign_func   = lambda { |key, data|
            # a signing function for the HMAC-MD5 algorithm. This can be overridden using
            # the sign_func element
            key.gsub!(/ /,"")
            key = Base64::decode64(key)
            
#            OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new("md5"), key, data) 
            OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new("md5"), key, data) 
            
            #            hmac = Digest::HMAC_MD5.new(key)
            #            hmac.add(data)
            
            #           hmac.digest
          }
          
          # RFC 2845 Section 2.3
          @rrclass = "ANY"
        end
        
        def error
          rcode=0
          error = @error
          
          if (error!=nil)
            rcode = Net::DNS::Rcodesbyval[error] || error
          end
          
          return rcode
        end
        
        def mac_size
          return (@mac!=nil ? @mac : "").length
        end
        
        def mac
          mac = @mac.unpack("H*") if @mac!=nil;
          return mac;
        end
        
        def rdatastr
          error = @error
          error = "UNDEFINED" unless error!=nil
          
          rdatastr=""
          
          if (@algorithm!=nil)
            rdatastr = "#{@algorithm}. #{error}";
            if (@other_len > 0 && @other_data!=nil)
              rdatastr += " #{@other_data}"
            end
          else
            rdatastr = ""
          end
          
          return rdatastr
        end
        
        #Returns the packet packed according to RFC2845 in a form for signing. This
        #is only needed if you want to supply an external signing function, such as is 
        #needed for TSIG-GSS. 
        #
        #     sigdata = tsig.sig_data(packet)
        #
        def sig_data(packet)
          # return the data that needs to be signed/verified. This is useful for
          # external TSIG verification routines
          newpacket = packet.clone
          sigdata = ""
          
          newpacket.additional = []
          newpacket.header = packet.header.clone
          newpacket.additional = packet.additional.map {|i| i}
          newpacket.additional.shift
          newpacket.header.arcount-=1
          newpacket.compnames = Hash.new
          
          # Add the request MAC if present (used to validate responses).
          sigdata += [@request_mac].pack("H*") if @request_mac
          
          sigdata += newpacket.data
          
          # Don't compress the record (key) name.
          tmppacket = Net::DNS::Packet.new
          sigdata += tmppacket.dn_comp(@name.downcase, 0)
          
          sigdata += [Net::DNS.classesbyname(@rrclass.upcase())].pack("n")
          sigdata += [@ttl].pack("N")
          
          # Don't compress the algorithm name.
          tmppacket.compnames = Hash.new
          sigdata += tmppacket.dn_comp(@algorithm.downcase, 0)
          
          sigdata += [0, @time_signed].pack("nN")	# bug
          sigdata += [@fudge].pack("n")
          sigdata += [@error, @other_len].pack("nn")
          
          sigdata += [0, @other_data].pack("nN") if @other_data!=nil
          
          return sigdata
        end
        
        def rr_rdata(packet, offset)
          rdata = ""
          
          if (@key != nil)
            # form the data to be signed
            sigdata = sig_data(packet)
            
            # and call the signing function
            @mac = @sign_func.call(@key, sigdata)
            @mac_size = @mac.length
            
            # construct the signed TSIG record
            packet.compnames = Hash.new
            rdata += packet.dn_comp(@algorithm, 0)
            
            rdata += [0, @time_signed].pack("nN")	# bug
            rdata += [@fudge, @mac_size].pack("nn")
            rdata += @mac
            
            rdata += [packet.header.id,@error,@other_len].pack("nnn")
            
            rdata += [0, @other_data].pack("nN") if @other_data!=nil
          end
          
          return rdata
        end
      end
    end
  end
end
