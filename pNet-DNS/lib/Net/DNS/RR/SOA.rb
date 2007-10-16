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
      #Net::DNS::RR::SOA - DNS SOA resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Start of Authority (SOA) resource records.
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
      #RFC 1035 Section 3.3.13
      class SOA < RR
        #Returns the domain name of the original or primary nameserver for
        #this zone.
        #
        #    print "mname = ", rr.mname, "\n"
        #
        attr_accessor :mname
        #Returns a domain name that specifies the mailbox for the person
        #responsible for this zone.
        #
        #    print "rname = ", rr.rname, "\n"
        #
        attr_accessor :rname
        #Returns the zone's serial number.
        #
        #    print "serial = ", rr.serial, "\n"
        #
        attr_accessor :serial
        #Returns the zone's refresh interval.
        #
        #    print "refresh = ", rr.refresh, "\n"
        #
        attr_accessor :refresh
        #Returns the zone's retry interval.
        #
        #    print "retry = ", rr.retry, "\n"
        #
        attr_accessor :retry
        #Returns the zone's expire interval.
        #
        #    print "expire = ", rr.expire, "\n"
        #
        attr_accessor :expire
        #Returns the minimum (default) TTL for records in this zone.
        #
        #    print "minimum = ", rr.minimum, "\n"
        #
        attr_accessor :minimum
        def new_from_data(data, offset)
          if (@rdlength > 0)
           (@mname, offset) = Net::DNS::Packet::dn_expand(data, offset);
           (@rname, offset) = Net::DNS::Packet::dn_expand(data, offset);
            
             (@serial, @refresh, @retry, @expire, @minimum) = data.unpack("\@#{offset} N5");
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:mname)
            @mname = values[:mname]
          end
          if values.has_key?(:rname)
            @rname = values[:rname]
          end
          if values.has_key?(:serial)
            @serial = values[:serial]
          end
          if values.has_key?(:refresh)
            @refresh = values[:refresh]
          end
          if values.has_key?(:retry)
            @retry = values[:retry]
          end
          if values.has_key?(:expire)
            @expire = values[:expire]
          end
          if values.has_key?(:minimum)
            @minimum = values[:minimum]
          end
        end
        
        def new_from_string(s)
          if (s!= nil)
            #            string =~ tr/()//d;
            string = s.tr("()", "")
            
            # XXX do we need to strip out comments here now that RR.pm does it?
            string.gsub!(/;.*$/, "");
            
            @mname, string = get_next_param(string)
            @rname, string = get_next_param(string)
            @serial, string = get_next_param(string)
            @refresh, string = get_next_param(string)
            @retry, string = get_next_param(string)
            @expire, string = get_next_param(string)
            @minimum, string = get_next_param(string)
            
            @mname.sub!(/\.+$/, "");
            @rname.sub!(/\.+$/, "");
          end
        end
        
        def get_next_param(s) 
          s =~ /(\S+)/
          param = $1
          string = s[param.length, s.length-param.length]
          string.sub!(/\s*/, "")
          return param, string
        end
        
        def rdatastr
          rdatastr="";
          
          if (defined?@mname)
            rdatastr  = "#{@mname}. #{@rname}. (\n";
            rdatastr += "\t\t\t\t\t" + "#{@serial}\t; Serial\n";
            rdatastr += "\t\t\t\t\t" + "#{@refresh}\t; Refresh\n";
            rdatastr += "\t\t\t\t\t" + "#{@retry}\t; Retry\n";
            rdatastr += "\t\t\t\t\t" + "#{@expire}\t; Expire\n";
            rdatastr += "\t\t\t\t\t" + "#{@minimum} )\t; Minimum TTL";
          else
            rdatastr = '';
          end
          
          return rdatastr;
        end
        
        def rr_rdata(packet, offset)
          rdata = "";
          
          # Assume that if one field exists, they all exist.  Script will
          # print a warning otherwise.
          
          if (defined?@mname)
            rdata += packet.dn_comp(@mname, offset);
            rdata += packet.dn_comp(@rname,  offset + rdata.length);
            
            rdata += [@serial, @refresh, @retry, @expire, @minimum].pack("N5");
          end
          
          return rdata;
        end
        
        
        
        def _canonicalRdata
          rdata = "";
          
          # Assume that if one field exists, they all exist.  Script will
          # print a warning otherwise.
          
          if (defined?@mname)
            rdata += _name2wire(@mname);		
            rdata += _name2wire(@rname);
            rdata += [@serial, @refresh, @retry, @expire, @minimum].pack("N5");
          end
          
          return rdata;
        end
      end
    end
  end
end
