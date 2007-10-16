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
module Net
  module DNS
    class RR
#= NAME
#
#Net::DNS::RR::CERT - DNS CERT resource record
#
#= DESCRIPTION
#
#Class for DNS Certificate (CERT) resource records. (see RFC 2538)
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
#RFC 2782
      class CERT < RR
#Returns the format code for the certificate (in numeric form)
#
#    print "format = ", rr.format, "\n"
#
        attr_accessor :format
#Returns the key tag for the public key in the certificate
#
#    print "tag = ", rr.tag, "\n"
#
        attr_accessor :tag
#Returns the algorithm used by the certificate (in numeric form)
#
#    print "algorithm = ", rr.algorithm, "\n"
#
        attr_accessor :algorithm
#Returns the data comprising the certificate itself (in raw binary form)
#
#    print "certificate = ", rr.certificate, "\n"
#
        attr_accessor :certificate
        FORMATS = {
        'PKIX' => 1,
        'SPKI' => 2,
        'PGP'  => 3,
        'URI'  => 253,
        'OID'  => 254,
        }
        
        R_FORMATS = FORMATS.invert
        
        ALGORITHMS = {
        'RSAMD5'     => 1,
        'DH'         => 2,
        'DSA'        => 3,
        'ECC'        => 4,
        'INDIRECT'   => 252,
        'PRIVATEDNS' => 253,
        'PRIVATEOID' => 254,
        }
        
        R_ALGORITHMS = ALGORITHMS.invert;
        
        def new_from_data(data, offset)
          if (@rdlength > 0)
            format, tag, algorithm = data.unpack("\@#{offset} n2C");
            
            offset        += 2 * Net::DNS::INT16SZ + 1;
            
            length      = @rdlength - (2 * Net::DNS::INT16SZ + 1);
            certificate = data[offset, length];
            
            @format      = format;
            @tag         = tag;
            @algorithm   = algorithm;
            @certificate = certificate;
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:format)
            @format = values[:format]
          end
          if values.has_key?(:tag)
            @tag = values[:tag]
          end
          if values.has_key?(:algorithm)
            @algorithm = values[:algorithm]
          end
          if values.has_key?(:certificate)
            @certificate = values[:certificate]
          end
        end
        
        def new_from_string(string)
          if (string==nil)
            return
          end
          
          format, tag, algorithm, rest = string.split(" ")
          if (rest == nil) 
            return
          end
          
          # look up mnemonics
          # the "die"s may be rash, but proceeding would be dangerous
          if (algorithm =~ /\D/)
            if defined?ALGORITHMS[algorithm]
              algorithm = ALGORITHMS[algorithm]
            else
              raise RuntimeError,	"Unknown algorithm mnemonic: '#{algorithm}'"
            end
          end
          
          if (format =~ /\D/)
            if defined?FORMATS[format]
              format = FORMATS[format]
            else
              die "Unknown format mnemonic: '#{format}'"
            end
          end
          
          @format      = format;
          @tag        = tag;
          @algorithm   = algorithm;
          @certificate = Base64::decode64([rest].join(''));
        end
        
        def rdatastr
          rdatastr=""
          
          if (defined?@format)
            cert = Base64::encode64 @certificate;
            cert.gsub!(/\n/,"");
            
            format = @format
            if defined?R_FORMATS[@format] 
              format = R_FORMATS[@format]
            end
            
            algorithm = @algorithm;
            if  defined?R_ALGORITHMS[@algorithm]  
              algorithm = R_ALGORITHMS[@algorithm] 
            end
            
            rdatastr = "#{format} #{@tag} #{algorithm} #{cert}";
          else
            rdatastr = '';
          end
          
          return rdatastr;
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          if (defined?@format)
            rdata += [@format, @tag].pack("n2")
            rdata += [@algorithm].pack("C")
            rdata += @certificate
          end
          
          return rdata;
        end
      end
    end
  end
end
