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
#Net::DNS::RR::HINFO - DNS HINFO resource record
#
#= DESCRIPTION
#
#Class for DNS Host Information (HINFO) resource records.
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
#RFC 1035 Section 3.3.2
      class HINFO < RR
#Returns the CPU type for this RR.
#
#    print "cpu = ", rr.cpu, "\n"
#
        attr_accessor :cpu

#Returns the operating system type for this RR.
#
#    print "os = ", rr.os, "\n"
#
        attr_accessor :os
        def new_from_data(data, offset)
          if (@rdlength > 0)
            len = data.unpack("\@#{offset} C")[0];
            offset+=1;
            cpu = data[offset, len];
            offset += len;
            
            len = data.unpack("\@#{offset} C")[0];
            offset+=1;
            os = data[offset, len];
            offset += len;
            
            @cpu = cpu;
            @os  = os;
          end
        end
        
        def new_from_string(string)
          if (string && string =~ /^["'](.*?)["']\s+["'](.*?)["']$/)
            @cpu = $1;
            @os  = $2;
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:cpu)
            @cpu = values[:cpu]
          end
          if values.has_key?(:os)
            @os = values[:os]
          end
        end
        
        def rdatastr
          return @cpu ? "'#{@cpu}' '#{@os}'" : '';
        end
        
        def rr_rdata(*args)
          rdata = "";
          
          if (defined?@cpu)
            rdata += [@cpu.length].pack("C");
            rdata += @cpu;
            
            rdata += [@os.length].pack("C");
            rdata += @os;
          end
          
          return rdata;
        end
      end
    end
  end
end
