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
    #Net::DNS::Header - DNS packet header class
    #
    #= DESCRIPTION
    #
    #A Net::DNS::Header object represents the header portion of a DNS
    #packet.
    #
    #= COPYRIGHT
    #
    #Copyright (c) 1997-2002 Michael Fuhr. 
    #
    #Portions Copyright (c) 2002-2004 Chris Reinhardt.
    #
    #Portions Copyright (c) 2006 AlexD (Nominet UK)
    #
    #All rights reserved.  This program is free software; you may redistribute
    #it and/or modify it under the same terms as Perl itself.
    #
    #= SEE ALSO
    #
    #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
    #Net::DNS::Update, Net::DNS::Question, Net::DNS::RR,
    #RFC 1035 Section 4.1.1
    class Header
      
      #The query identification number.
      attr_accessor :id
      
      #Gets or sets the query response flag.
      attr_accessor :qr
      
      #    print "query opcode = ", header.opcode, "\n"
      #    header.opcode("UPDATE")
      #
      #Gets or sets the query opcode (the purpose of the query).
      attr_accessor :opcode
      
      #    print "answer is ", (header.aa!=0) ? "" : "non-", "authoritative\n"
      #    header.aa=(0)
      #
      #Gets or sets the authoritative answer flag.
      attr_accessor :aa
      
      #    print "packet is ", header.tc!=0 ? "" : "not ", "truncated\n"
      #    header.tc=(0)
      #
      #Gets or sets the truncated packet flag.
      attr_accessor :tc
      
      #    print "recursion was ", header.rd!=0 ? "" : "not ", "desired\n"
      #    header.rd=(0)
      #
      #Gets or sets the recursion desired flag.
      attr_accessor :rd
      
      #    print "checking was ", header.cd!=0 ? "not" : "", "desired\n"
      #    header.cd=(0)
      #
      #Gets or sets the checking disabled flag.
      attr_accessor :cd
      
      #    print "recursion is ", header.ra!=0 ? "" : "not ", "available\n"
      #    header.ra=(0)
      #
      #Gets or sets the recursion available flag.
      attr_accessor :ra
      
      #    print "The result has ", header.ad!=0 ? "" : "not", "been verified\n"
      #
      #Relevant in DNSSEC context.
      #
      #(The AD bit is only set on answers where signatures have been
      #cryptographically verified or the server is authoritative for the data
      #and is allowed to set the bit by policy.)
      attr_accessor :ad
      
      #    print "query response code = ", header.rcode, "\n"
      #    header.rcode=("SERVFAIL")
      #
      #Gets or sets the query response code (the status of the query).
      attr_accessor :rcode
      
      #    print "# of question records: ", header.qdcount, "\n"
      #    header.qdcount=(2)
      #
      #Gets or sets the number of records in the question section of the packet.
      #In dynamic update packets, this field is known as zocount and refers
      #to the number of RRs in the zone section.
      attr_accessor :qdcount
      
      #    print "# of answer records: ", header.ancount, "\n"
      #    header.ancount=(5)
      #
      #Gets or sets the number of records in the answer section of the packet.
      #In dynamic update packets, this field is known as prcount and refers
      #to the number of RRs in the prerequisite section.
      attr_accessor :ancount
      
      #    print "# of authority records: ", header.nscount, "\n"
      #    header.nscount=(2)
      #
      #Gets or sets the number of records in the authority section of the packet.
      #In dynamic update packets, this field is known as upcount and refers
      #to the number of RRs in the update section.
      attr_accessor :nscount
      
      #    print "# of additional records: ", header.arcount, "\n"
      #    header.arcount=(3)
      #
      #Gets or sets the number of records in the additional section of the packet.
      #In dynamic update packets, this field is known as adcount.
      attr_accessor :arcount
      
      alias zocount qdcount
      alias zocount= qdcount=
      
      alias prcount ancount
      alias prcount= ancount=
      
      alias upcount nscount
      alias upcount= nscount=
      
      alias adcount arcount
      alias adcount= arcount=
      
      MAX_ID = 65535
      @@next_id = rand(MAX_ID)
      
      # Get the next Header ID
      def nextid()
        @@next_id += 1
        if (@@next_id > MAX_ID)
          @@next_id = 0
        end
        return @@next_id
      end
      
      #    header = Net::DNS::Header.new
      #    header = Net::DNS::Header.new(data)
      #
      #Without an argument, new creates a header object appropriate
      #for making a DNS query.
      #
      #If new is passed a reference to a scalar containing DNS packet
      #data, it creates a header object from that data.
      #
      #Returns *nil* if unable to create a header object (e.g., if
      #the data is incomplete).
      def initialize(*args)
        
        @qr		= 0
        @opcode	= 0
        @aa		= 0
        @tc		= 0
        @rd		= 1
        @ra		= 0
        @ad		= 0
        @cd		= 0  
        @rcode		= 0
        @qdcount	= 0
        @ancount	= 0
        @nscount	= 0
        @arcount	= 0
        
        if (args != nil && args.length > 0)
          data = args[0];
          
          if (data) 
            
            if (data.length < Net::DNS::HFIXEDSZ )
              return nil;
            end
            
            a = data.unpack("n C2 n4");
            @id		= a[0]
            @qr		= (a[1] >> 7) & 0x1
            @opcode	= (a[1] >> 3) & 0xf
            @aa		= (a[1] >> 2) & 0x1
            @tc		= (a[1] >> 1) & 0x1
            @rd		= a[1] & 0x1
            @ra		= (a[2] >> 7) & 0x1
            @ad		= (a[2] >> 5) & 0x1
            @cd		= (a[2] >> 4) & 0x1
            @rcode		= a[2] & 0xf
            @qdcount	= a[3]
            @ancount	= a[4]
            @nscount	= a[5]
            @arcount	= a[6]
          else
            @id		= nextid()            
          end
        else
          @id		= nextid()
        end
        
        hasKey = Net::DNS::Opcodesbyval.has_key?@opcode
        temp = Net::DNS::Opcodesbyval[@opcode]
        temp2 = Net::DNS::Opcodesbyval
        if (Net::DNS::Opcodesbyval[@opcode] != nil)
          @opcode = Net::DNS::Opcodesbyval[@opcode]
        end
        if (Net::DNS::Rcodesbyval[@rcode]!=nil)
          @rcode = Net::DNS::Rcodesbyval[@rcode]
        end
      end
      
      #Returns a string representation of the header object.
      #
      #    print header.inspect
      def inspect
        retval = ";; id = #{@id}\n";
        
        if (@opcode == "UPDATE")
          retval += ";; qr = #{@qr}    " +\
		           "opcode = #{@opcode}    "+\
		           "rcode = #{@rcode}\n";
          
          retval += ";; zocount = #{@qdcount}  "+\
		           "prcount = #{@ancount}  " +\
		           "upcount = #{@nscount}  "  +\
		           "adcount = #{@arcount}\n";
        else
          retval += ";; qr = #{@qr}    "  +\
		           "opcode = #{@opcode}    " +\
		           "aa = #{@aa}    "  +\
		           "tc = #{@tc}    " +\
		           "rd = #{@rd}\n";
          
          retval += ";; ra = #{@ra}    " +\
		           "ad = #{@ad}    "  +\
		           "cd = #{@cd}    "  +\
		           "rcode  = #{@rcode}\n";
          
          retval += ";; qdcount = #{@qdcount}  " +\
		           "ancount = #{@ancount}  " +\
		           "nscount = #{@nscount}  " +\
		           "arcount = #{@arcount}\n";
        end
        
        return retval;
      end
      
      
      #Returns the header data in binary format, appropriate for use in a
      #DNS query packet.
      #
      #    hdata = header.data
      def data
        opcode = Net::DNS::Opcodesbyname[@opcode];
        rcode  = Net::DNS::Rcodesbyname[@rcode];
        
        byte2 = (@qr << 7) | (opcode << 3) | (@aa << 2) | (@tc << 1) | @rd;
        
        byte3 = (@ra << 7) | (@ad << 5) | (@cd << 4) | rcode;
        
        return [@id, byte2, byte3, @qdcount, @ancount, @nscount, @arcount].pack("n C2 n4");
      end
      
      def ==(other)
        if (other != nil) && (other.is_a?(Header))
          return false if @qr!=other.qr;
          return false if @opcode!=other.opcode;
          return false if @aa!=other.aa;
          return false if @tc!=other.tc;
          return false if @rd!=other.rd;
          return false if @ra!=other.ra;
          return false if @ad!=other.ad;
          return false if @cd!=other.cd;
          return false if @rcode!=other.rcode;
          return false if @ancount!=other.ancount;
          return false if @nscount!=other.nscount;
          return false if @qdcount!=other.qdcount;
          return false if @id!=other.id;
          return false if @arcount!=other.arcount;
          
          return true;
        else
          return false
        end
      end
      
    end
  end
end
