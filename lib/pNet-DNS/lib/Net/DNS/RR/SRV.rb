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
      #Net::DNS::RR::SRV - DNS SRV resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Service (SRV) resource records.
      #
      #= COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #
      #Ruby version Copyright (c) 2006 AlexD, Nominet UK.
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 2782
      class SRV < RR
        #Returns the priority for this target host.
        #
        #    print "priority = ", rr.priority, "\n"
        #
        attr_accessor :priority
        #Returns the weight for this target host.
        #
        #    print "weight = ", rr.weight, "\n"
        #
        attr_accessor :weight
        #Returns the port on this target host for the service.
        #
        #    print "port = ", rr.port, "\n"
        #
        attr_accessor :port
        #Returns the target host.
        #
        #    print "target = ", rr.target, "\n"
        #
        attr_accessor :target
        def init_rrsort_func
          set_rrsort_func("priority", Proc.new { |a,b|
            a.priority <=> b.priority || b.weight <=> a.weight
          })
          
          
          set_rrsort_func("default_sort", get_rrsort_func("priority"));
          
          set_rrsort_func("weight", Proc.new { |a,b| 
            b.weight <=> a.weight || a.priority <=> b.priority
          })
        end
        
        
        
        def new_from_data(data, offset) 
          if (@rdlength > 0)
            ret = data.unpack("\@#{offset} n3");
            @priority = ret[0]
            @weight = ret[1]
            @port = ret[2]
            offset += 3 * Net::DNS::INT16SZ;
            
            @target = Net::DNS::Packet.dn_expand(data, offset)[0];
          end
        end
        
        def new_from_hash(values)
          if (values.has_key?:priority)
            @priority = values[:priority]
          end
          if (values.has_key?:weight)
            @weight = values[:weight]
          end
          if (values.has_key?:port)
            @port = values[:port]
          end
          if (values.has_key?:target)
            @target = values[:target]
          end
        end
        
        def new_from_string(string)
          if (string && (string =~ /^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)$/))
            @priority = $1.to_i
            @weight = $2.to_i
            @port = $3.to_i
            @target = $4
            
            @target.sub!(/\.+$/, "");
          end
        end
        
        def rdatastr
          if (defined?@priority)
            rdatastr = [@priority, @weight, @port, @target].join(' ');
            rdatastr.sub!(/(.*[^\.])$/) { |s| s+"." };
          else
            rdatastr = '';
          end
          
          return rdatastr;
        end
        
        def rr_rdata(packet, offset)
          rdata = '';
          
          if (defined?priority)
            rdata += [@priority, @weight, @port].pack('n3');
            rdata += packet.dn_comp(@target, offset + rdata.length );
          end
          
          return rdata;
        end
        
        
        def _canonicalRdata
          rdata = '';
          
          if (defined?priority)
            rdata += [@priority.to_i, @weight.to_i, @port.to_i].pack('n3');
            rdata += _name2wire(@target);
          end
          
          return rdata;
        end
      end
    end
  end
end
