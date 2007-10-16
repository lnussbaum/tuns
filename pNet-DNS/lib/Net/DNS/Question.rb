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
    #= NAME
    #
    #Net::DNS::Question - DNS question class
    #
    #= SYNOPSIS
    #
    #use Net::DNS::Question
    #
    #= DESCRIPTION
    #
    #A Net::DNS::Question object represents a record in the
    #question section of a DNS packet.
    #
    #
    #= COPYRIGHT
    #
    #Copyright (c) 1997-2002 Michael Fuhr. 
    #
    #Portions Copyright (c) 2002-2004 Chris Reinhardt.
    #
    #All rights reserved.  This program is free software; you may redistribute
    #it and/or modify it under the same terms as Perl itself.
    #
    #= SEE ALSO
    #
    #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
    #Net::DNS::Update, Net::DNS::Header, Net::DNS::RR,
    #RFC 1035 Section 4.1.2
    class Question < RR
      attr_accessor :qname, :qtype, :qclass
      
      #Creates a question object from the domain, type, and class passed
      #as arguments.
      #
      #    question = Net::DNS::Question.new("example.com", "MX", "IN")
      def initialize(qname, qtypein="ANY", qclassin="ANY")
        qname  = "" if (qname==nil);
        
        qtype = qtypein.upcase
        qclass = qclassin.upcase
        
        # Check if the caller has the type and class reversed.
        # We are not that kind for unknown types.... :-)
        if ((Net::DNS::typesbyname(qtype)==nil ||  \
          Net::DNS::classesbyname(qclass)==nil)   \
          && Net::DNS::classesbyname(qtype)!=nil   \
          && Net::DNS::typesbyname(qclass)!=nil)
          
          temp = qtype
          qtype = qclass
          qclass = temp
        end
        
        #	$qname =~ s/^\.+//o;
        #	$qname =~ s/\.+$//o;
        qname.gsub!("^\.+", "");
        qname.gsub!("\.+$", "");
        
        @qname  = qname;
        @qtype  = qtype;
        @qclass = qclass;
      end
      
      #Returns a string representation of the question record.
      #
      #    print qr.inspect, "\n"
      def inspect
        return "#{@qname}.\t#{@qclass}\t#{@qtype}";
      end
      
      #Returns the question record in binary format suitable for inclusion
      #in a DNS packet.
      #
      #Arguments are a Net::DNS::Packet object and the offset within
      #that packet's data where the Net::DNS::Question record is to
      #be stored.  This information is necessary for using compressed
      #domain names.
      #
      #    qdata = question.data(packet, offset)
      def data(packet, offset) 
        data, offset = packet.dn_comp(@qname, offset);
        
        data+=[Net::DNS::typesbyname(@qtype.upcase)].pack("n")
        data+=[Net::DNS::classesbyname(@qclass.upcase)].pack("n")
        
        return data;
      end
      
      def zname
        return qname
      end
      def ztype
        return qtype
      end
      def zclass
        return qclass
      end
    end
  end
end
