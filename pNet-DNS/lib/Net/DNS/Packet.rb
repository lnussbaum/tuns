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
    #Net::DNS::Packet - DNS packet object class
    #
    #= DESCRIPTION
    #
    #A Net::DNS::Packet object represents a DNS packet.
    #
    #= COPYRIGHT
    #
    #Copyright (c) 1997-2002 Michael Fuhr. 
    #
    #Portions Copyright (c) 2002-2004 Chris Reinhardt.
    #
    #Portions Copyright (c) 2002-2005 Olaf Kolkman
    #
    #Ruby version Copyright (c) 2006 AlexD (Nominet UK)
    #
    #All rights reserved.  This program is free software; you may redistribute
    #it and/or modify it under the same terms as Perl itself.
    #
    #= SEE ALSO
    #
    #Net::DNS, Net::DNS::Resolver, Net::DNS::Update,
    #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
    #RFC 1035 Section 4.1, RFC 2136 Section 2, RFC 2845
    class Packet
      #    header = packet.header
      #
      #Returns a Net::DNS::Header object representing the header section
      #of the packet.
      attr_accessor :header
      
      #    question = packet.question
      #
      #Returns a list of Net::DNS::Question objects representing the
      #question section of the packet.
      #
      #In dynamic update packets, this section is known as zone and
      #specifies the zone to be updated.
      attr_accessor :question
      
      #    answer = packet.answer
      #
      #Returns a list of Net::DNS::RR objects representing the answer
      #section of the packet.
      #
      #In dynamic update packets, this section is known as pre or
      #prerequisite and specifies the RRs or RRsets which must or
      #must not preexist.
      attr_accessor :answer
      
      #    authority = packet.authority
      #
      #Returns a list of Net::DNS::RR objects representing the authority
      #section of the packet.
      #
      #In dynamic update packets, this section is known as update and
      #specifies the RRs or RRsets to be added or delted.
      attr_accessor :authority
      
      #    additional = packet.additional
      #
      #Returns a list of Net::DNS::RR objects representing the additional
      #section of the packet.
      attr_accessor :additional
      
      #    print "packet received from ", packet.answerfrom, "\n"
      #
      #Returns the IP address from which we received this packet.  User-created
      #packets will return nil for this method.
      attr_accessor :answerfrom
      
      #    print "packet size: ", packet.answersize, " bytes\n"
      #
      #Returns the size of the packet in bytes as it was received from a
      #nameserver.  User-created packets will return nil for this method
      #(use packet.data.length instead).
      attr_accessor :answersize
      
      
      attr_accessor :compnames
      
      alias zone question
      alias pre answer
      alias prerequisite answer
      alias update authority
      
      # Do not use new with arguments! Use either Packet.new_from_binary or Packet.new_from_values to create a packet from data
      def initialize(*args)
        if (args.length > 0)
          raise ArgumentError, "Do not use new with arguments! Use either Packet.new_from_binary or Packet.new_from_values to create a packet from data"
        end
        @compnames = Hash.new()
        @seen=Hash.new()
        @header = Net::DNS::Header.new
        @answer=[]
        @question=[]
        @authority=[]
        @additional=[]
      end
      
      #    packet = Net::DNS::Packet.new_from_binary(data)
      #    packet = Net::DNS::Packet.new_from_binary(data, 1)  # set debugging
      #
      #    (packet, err) = Net::DNS::Packet.new_from_binary(data)
      #
      #If passed a reference to a scalar containing DNS packet data,
      #*new* creates a packet object from that data.  A second argument
      #can be passed to turn on debugging output for packet parsing.
      #
      #If called in array context, returns a packet object and an
      #error string.  The error string will only be defined if the
      #packet object is undefined (i.e., couldn't be created).
      #
      #Returns *nil* if unable to create a packet object (e.g., if
      #the packet data is truncated).
      def Packet.new_from_binary(*args)
        packet = Packet.new
        #        if args[0].is_a? String
        data  = args[0]
        debug = args[1]
        debug = false if debug == nil
        
        #--------------------------------------------------------------
        # Parse the header section.
        #--------------------------------------------------------------
        
        print ";; HEADER SECTION\n" if debug
        
        
        packet.header= Net::DNS::Header.new(data)
        
        raise ArgumentError, "header section incomplete" if packet.header == nil		
        
        print packet.header.inspect if debug
        
        offset = Net::DNS::HFIXEDSZ
        
        #--------------------------------------------------------------
        # Parse the question/zone section.
        #--------------------------------------------------------------
        
        if debug then
          print "\n"
          section = (packet.header.opcode == "UPDATE") ? "ZONE" : "QUESTION"
          print ";; #{section} SECTION (#{packet.header.qdcount}  record #{packet.header.qdcount == 1 ? '' : 's'})\n"
        end
        
        packet.question = []
        packet.header.qdcount.times {
         (qobj, offset) = parse_question(data, offset)
          
          #          raise ArgumentError, "question section incomplete" if qobj == nil		
          if (qobj==nil)
            if (packet.header.tc==1) 
              return packet
            else
              return nil
            end
          end
          #			unless (defined $qobj) {
          #				last PARSE if $self{"header"}->tc;
          #				return wantarray
          #				       ? (nil, "question section incomplete")
          #				       : nil;
          #			}
          
          packet.push("question", qobj)
          if debug then
            print ";; "
            print qobj.inspect
          end
        }
        
        #--------------------------------------------------------------
        # Parse the answer/prerequisite section.
        #--------------------------------------------------------------
        
        if debug then
          print "\n"
          section = (packet.header.opcode == "UPDATE") ? "PREREQUISITE" : "ANSWER"
          print ";; #{section} SECTION (#{packet.header.ancount} record #{packet.header.ancount == 1 ? '' : 's'})\n"
        end
        
        packet.answer = []
        packet.header.ancount.times {
         (rrobj, offset) = parse_rr(data, offset)
          
          #          raise ArgumentError, "answer section incomplete" if rrobj == nil		
          if (rrobj==nil)
            if (packet.header.tc==1) 
              return packet
            else
              return nil
            end
          end
          
          packet.push("answer", rrobj)
          print rrobj.inspect + "\n" if debug
        }
        
        #--------------------------------------------------------------
        # Parse the authority/update section.
        #--------------------------------------------------------------
        
        if debug then
          print "\n"
          section = (packet.header.opcode == "UPDATE") ? "UPDATE" : "AUTHORITY"
          print ";; #{section} SECTION (#{packet.header.nscount} record#{packet.header.nscount == 1 ? '' : 's'})\n"
        end
        
        packet.authority = []
        packet.header.nscount.times {
          rrobj = nil
           (rrobj, offset) = parse_rr(data, offset)
          
          #          raise ArgumentError, "authority section incomplete" if rrobj == nil		
          if (rrobj==nil)
            if (packet.header.tc==1) 
              return packet
            else
              return nil
            end
          end
          
          packet.push("authority", rrobj)
          print rrobj.inspect + "\n" if debug
        }
        
        #--------------------------------------------------------------
        # Parse the additional section.
        #--------------------------------------------------------------
        
        if debug then
          print "\n";
          print ";; ADDITIONAL SECTION (#{packet.header.adcount} record#{packet.header.adcount == 1 ? '' : 's'})\n";
        end
        
        packet.additional = [];
        packet.header.arcount.times {
          rrobj=nil
           (rrobj, offset) = parse_rr(data, offset)
          
          raise ArgumentError, "additional section incomplete" if rrobj == nil		
          if (rrobj==nil)
            if (packet.header.tc==1) 
              return packet
            else
              return nil
            end
          end
          
          
          packet.push("additional", rrobj);
          print rrobj.inspect + "\n" if debug
        }
        packet.header= Net::DNS::Header.new(data)
        return packet
      end
      
      #    packet = Net::DNS::Packet.new_from_values("example.com")
      #    packet = Net::DNS::Packet.new_from_values("example.com", "MX", "IN")
      #
      #If passed a domain, type, and class, *new* creates a packet
      #object appropriate for making a DNS query for the requested
      #information.  The type and class can be omitted; they default
      #to A and IN.
      def Packet.new_from_values(qName, qType="A", qClass="IN")
        packet = Packet.new        
        packet.header.qdcount=(1)
        packet.question = [ Net::DNS::Question.new(qName, qType, qClass) ]
        return packet
      end
      
      #= data
      #
      #    data = packet.data
      #
      #Returns the packet data in binary format, suitable for sending to
      #a nameserver.
      def data 
        #----------------------------------------------------------------------
        # Flush the cache of already-compressed names.  This should fix the bug
        # that caused this method to work only the first time it was called.
        #----------------------------------------------------------------------
        
        @compnames = Hash.new()
        
        #----------------------------------------------------------------------
        # Get the data for each section in the packet.
        #----------------------------------------------------------------------
        # Note that EDNS OPT RR data should inly be appended to the additional
        # section of the packet. TODO: Packet is dropped silently if is tried to
        # have it appended to one of the other section
        
        # Collect the data first, and count the number of records along
        # the way. ( see rt.cpan.org: Ticket #8608 )
        qdcount = 0
        ancount = 0
        nscount = 0
        arcount = 0
        # Note that the only pieces we;ll fill in later have predefined
        # length.
        
        headerlength=@header.data.length
        
        data = @header.data
        
        #	foreach my $question (@{$self->{"question"}}) {
        @question.each { |question| 
          offset = data.length
          data = data + question.data(self, offset)
          qdcount = qdcount + 1
        }
        
        #	foreach my $rr (@{$self->{"answer"}}) {
        @answer.each { |rr| 
          offset = data.length
          data = data + rr.data(self, offset)
          ancount = ancount + 1
        }
        
        
        #	foreach my $rr (@{$self->{"authority"}}) {
        @authority.each { |rr| 
          offset = data.length
          data = data + rr.data(self, offset)
          nscount =  nscount + 1
        }
        
        
        #	foreach my $rr (@{$self->{"additional"}}) {
        @additional.each { |rr| 
          offset = data.length
          data = data + rr.data(self, offset);
          arcount = arcount + 1;
        }
        
        
        # Fix up the header so the counts are correct.  This overwrites
        # the user's settings, but the user should know what they are doing.
        @header.qdcount=( qdcount );
        @header.ancount=( ancount );
        @header.nscount=( nscount );
        @header.arcount=( arcount );
        
        # Replace the orginal header with corrected counts.
        
        return @header.data + data[headerlength, data.length-headerlength];
      end
      
      #    print packet.inspect
      #
      #Returns a string representation of the packet.
      def inspect
        retval = "";
        
        if (@answerfrom != nil && @answerfrom != "")
          retval = retval + ";; Answer received from #{@answerfrom} (#{@answersize} bytes)\n;;\n";
        end
        
        retval = retval + ";; HEADER SECTION\n";
        retval = retval + @header.inspect;
        
        retval = retval + "\n";
        section = (@header.opcode == "UPDATE") ? "ZONE" : "QUESTION";
        retval = retval +  ";; #{section} SECTION (#{@header.qdcount}  record#{@header.qdcount == 1 ? '' : 's'})\n";
        question.each { |qr|
          retval = retval + ";; #{qr.inspect}\n";
        }
        
        retval = retval + "\n";
        section = (@header.opcode == "UPDATE") ? "PREREQUISITE" : "ANSWER";
        retval = retval + ";; #{section} SECTION (#{@header.ancount}  record#{@header.ancount == 1 ? '' : 's'})\n";
        @answer.each { |rr|
          retval = retval + rr.inspect + "\n";
        }
        
        retval = retval + "\n";
        section = (@header.opcode == "UPDATE") ? "UPDATE" : "AUTHORITY";
        retval = retval + ";; #{section} SECTION (#{@header.nscount}  record#{@header.nscount == 1 ? '' : 's'})\n";
        @authority.each { |rr|
          retval = retval + rr.inspect + "\n";
        }
        
        retval = retval + "\n";
        retval = retval + ";; ADDITIONAL SECTION (#{@header.arcount}  record#{@header.arcount == 1 ? '' : 's'})\n";
        @additional.each { |rr|
          retval = retval + rr.inspect + "\n";
        }
        
        return retval;
      end
      
      #    packet.push("pre", rr)
      #    packet.push("update", rr)
      #    packet.push("additional", rr)
      #
      #    packet.push("update", rr1, rr2, rr3)
      #    packet.push("update", rr)
      #
      #Adds RRs to the specified section of the packet.
      def push(insection, rr)
        return if (insection == nil)
        
        section = insection.to_s.downcase
        if ((section == "prerequisite") || (section == "prereq"))
          section = "pre";
        end
        if !rr.instance_of?Array
          rr = [rr]
        end
        
        if ((@header.opcode == "UPDATE") && ((section == "pre") || (section == "update")) )
          zone_class = zone()[0].zclass
          rr.each { |r_rec|
            r_rec.rrclass=(zone_class) unless (r_rec.rrclass == "NONE" || r_rec.rrclass == "ANY")
          }
        end
        
        if (section == "answer" || section == "pre")
          #          @answer.push(rr);
          @answer += rr 
          ancount = @header.ancount;
          @header.ancount=(ancount + 1); # rr);
        elsif (section == "authority" || section == "update")
          #          @authority.push(rr);
          @authority += rr
          nscount = @header.nscount;
          @header.nscount=(nscount + 1); # rr);
        elsif (section == "additional")
          #          @additional.push(rr);
          @additional+=rr
          adcount = @header.adcount;
          @header.adcount=(adcount + 1); # rr);
        elsif (section == "question")
          #          @question.push(rr);
          @question += rr
          qdcount = @header.qdcount;
          @header.qdcount=(qdcount + 1); # rr);
        else
          #		Carp::carp(qq(invalid section "$section"\n));
          return;
        end
      end
      
      #    packet.unique_push("pre"        => rr)
      #    packet.unique_push("update"     => rr)
      #    packet.unique_push("additional" => rr)
      #
      #    packet.unique_push("update" => rr1, rr2, rr3)
      #    packet.unique_push("update" => rr)
      #
      #Adds RRs to the specified section of the packet provided that 
      #the RRs do not already exist in the packet.
      def unique_push(section, rrs)	
        rrs.each { |rr|
          #		next if $self->{'seen'}->{rr.string}++;
          if @seen[rr.inspect] != nil
            @seen[rr.inspect] = @seen[rr.inspect] + 1
          else
            push(section, rr);
            @seen[rr.inspect] = 1
          end
        }
      end
      
      #    rr = packet.pop("pre")
      #    rr = packet.pop("update")
      #    rr = packet.pop("additional")
      #    rr = packet.pop("question")
      #
      #Removes RRs from the specified section of the packet.
      def pop(section) 
        return unless section
        section = section.to_s.downcase
        
        if ((section == "prerequisite") || (section == "prereq"))
          section = "pre";
        end
        
        if (section == "answer" || section == "pre")
          ancount = @header.ancount;
          if (ancount)
            rr = @answer.pop;
            @header.ancount=(ancount - 1);
          end
        elsif (section == "authority" || section == "update")
          nscount = @header.nscount;
          if (nscount) 
            rr = @authority.pop;
            @header.nscount=(nscount - 1);
          end
        elsif (section == "additional")
          adcount = @header.adcount;
          if (adcount)
            rr = @additional.pop;
            @header.adcount=(adcount - 1);
          end
        elsif (section == "question")
          qdcount = @header.qdcount;
          if (qdcount)
            rr = @question.pop;
            @header.qdcount=(qdcount - 1);
          end
        else
          raise ArgumentError, "Invalid section #{section}"
        end
        
        return rr;
      end
      
      #    compname = packet.dn_comp("foo.example.com", $offset)
      #
      #Returns a domain name compressed for a particular packet object, to
      #be stored beginning at the given offset within the packet data.  The
      #name will be added to a running list of compressed domain names for
      #future use.
      def dn_comp(name, offset)
        # should keep track of compressed names FOR THIS PACKET
        # If we see one already used, then we can add in the offset for that name
        # So, we need to store the offset in compnames
        name="" if name==nil
        compname="";
        names=Net::DNS::name2labels(name);
        
        if ((names.length == 1 && names[0]==""))
          names=[]
        else
          while (!names.empty?)
            dname = names.join(".");
            
            if (@compnames.has_key?(dname))
              pointer = @compnames[dname];
              #			$compname .= pack("n", 0xc000 | $pointer);
              compname = compname +  [(0xc000 | pointer)].pack("n");
              break;
            end
            
            @compnames[dname] = offset;
            first = names.shift
            length = first.length;
            #		croak "length of $first is larger than 63 octets" if $length>63;
            raise RuntimeError, "length of #{first} is larger than 63 octets" if length > 63
            compname = compname + [length, first].pack("C a*");
            offset = offset + length + 1;
          end
        end
        
        if names.empty?
          compname = compname + [0].pack("C") 
        end
        return compname;
      end
      
      #    name, nextoffset = dn_expand(data, offset)
      #
      #    name, nextoffset = Net::DNS::Packet::dn_expand(data, offset)
      #
      #Expands the domain name stored at a particular location in a DNS
      #packet.  The first argument is a reference to a scalar containing
      #the packet data.  The second argument is the offset within the
      #packet where the (possibly compressed) domain name is stored.
      #
      #Returns the domain name and the offset of the next location in the
      #packet.
      #
      #Returns nil, nil if the domain name couldn't be expanded.
      def Packet.dn_expand(packet, offset)
        if (Net::DNS::HAVE_XS)
         (name, roffset)=dn_expand_XS(packet, offset);
        else
         (name, roffset)=dn_expand_PP(packet, offset);
        end
        
        return name, roffset
      end
      
      def Packet.dn_expand_PP(packet, offset)
        name = "";
        packetlen = packet.length;
        int16sz = Net::DNS::INT16SZ;
        
        while (true)
          return nil, nil if packetlen < (offset + 1);
          
          len = packet.unpack("\@#{offset} C") [0];
          
          if (len == 0)
            offset+=1;
            break
          elsif ((len & 0xc0) == 0xc0)
            return nil, nil if packetlen < (offset + int16sz);
            
            ptr = packet.unpack("\@#{offset} n") [0];
            ptr = ptr&(0x3fff);
            name2 = dn_expand_PP(packet, ptr) [0]; # pass $seen for debugging
            
            return nil, nil unless name2!=nil;
            
            name += name2;
            offset += int16sz;
            break
          else 
            offset+=1;
            
            return nil, nil if packetlen < (offset + len);
            
            elem = packet[offset, len]
            
            name += Net::DNS::wire2presentation(elem)+".";
            
            offset += len;
          end
        end
        
        name.gsub!(/\.$/o, "")
        return name, offset
      end
      
      #    key_name = "tsig-key"
      #    key      = "awwLOtRfpGE+rRKF2+DEiw=="
      #
      #    update = Net::DNS::Update.new("example.com")
      #    update.push("update", rr_add("foo.example.com A 10.1.2.3"))
      #
      #    update.sign_tsig(key_name, key)
      #
      #    response = res.send(update)
      #
      #Signs a packet with a TSIG resource record (see RFC 2845).  Uses the
      #following defaults:
      #
      #    algorithm   = HMAC-MD5.SIG-ALG.REG.INT
      #    time_signed = current time
      #    fudge       = 300 seconds
      #
      #If you wish to customize the TSIG record, you'll have to create it
      #yourself and call the appropriate Net::DNS::RR::TSIG methods.  The
      #following example creates a TSIG record and sets the fudge to 60
      #seconds:
      #
      #    key_name = "tsig-key"
      #    key      = "awwLOtRfpGE+rRKF2+DEiw=="
      #
      #    tsig = Net::DNS::RR.new("#{key_name} TSIG #{key}")
      #    tsig.fudge(60)
      #
      #    query = Net::DNS::Packet.new("www.example.com")
      #    query.sign_tsig(tsig)
      #
      #    response = res.send(query)
      #
      #You shouldn't modify a packet after signing it; otherwise authentication
      #will probably fail.
      def sign_tsig(*args)
        #	if (@_ == 1 && ref($_[0])) {
        if (args.length == 1) 
          tsig = args[0];
          #	elsif (@_ == 2) {
        else
          key_name, key = args;
          if ((key_name!=nil) && (key!=nil))
            tsig = Net::DNS::RR.new_from_string("#{key_name} TSIG #{key}")
          end
        end
        
        push("additional", tsig) if tsig;
        return tsig;
      end
      
      #SIG0 support is provided through the Net::DNS::RR::SIG class. This class is not part
      #of the default Net::DNS distribution but resides in the Net::DNS::SEC distribution.
      #
      #    update = Net::DNS::Update.new("example.com")
      #    update.push("update", rr_add("foo.example.com A 10.1.2.3"))
      #    update.sign_sig0("Kexample.com+003+25317.private")
      #
      #
      #SIG0 support is experimental see Net::DNS::RR::SIG for details.
      #
      #The method will raise a RuntimeError if Net::DNS::RR::SIG cannot be found.
      def Packet.sign_sig0(*args)
        raise RuntimeError, 'The sign_sig0() method is only available when the Net::DNS::SEC package is installed.' unless Net::DNS::DNSSEC;
        
        # @TODO implement this!!!	
        #	if (@_ == 1 && ref($_[0])) {
        #		if (UNIVERSAL::isa($_[0],"Net::DNS::RR::SIG::Private")) {
        #			Carp::carp('Net::DNS::RR::SIG::Private is deprecated use Net::DNS::SEC::Private instead');
        #			$sig0 = Net::DNS::RR::SIG->create('', $_[0]) if $_[0];
        #		
        #		} elsif (UNIVERSAL::isa($_[0],"Net::DNS::SEC::Private")) {
        #			$sig0 = Net::DNS::RR::SIG->create('', $_[0]) if $_[0];
        #		
        #		} elsif (UNIVERSAL::isa($_[0],"Net::DNS::RR::SIG")) {
        #			$sig0 = $_[0];
        #		} else {
        #		  Carp::croak('You are passing an incompatible class as argument to sign_sig0: ' . ref($_[0]));
        #		}
        #	elsif (@_ == 1 && ! ref($_[0]))
        #		my $key_name = $_[0];
        #		$sig0 = Net::DNS::RR::SIG->create('', $key_name) if $key_name
        #	end
        #	
        #	$self->push('additional', $sig0) if $sig0;
        #	return $sig0;
      end
      
      #--      
      #------------------------------------------------------------------------------
      # parse_question
      #
      #     queryobj, newoffset = parse_question(data, offset)
      #
      # Parses a question section record contained at a particular location within
      # a DNS packet.  The first argument is a reference to the packet data.  The
      # second argument is the offset within the packet where the question record
      # begins.
      #
      # Returns a Net::DNS::Question object and the offset of the next location
      # in the packet.
      #
      # Returns nil, nil if the question object couldn't be created (e.g.,
      # if there isn't enough data).
      #------------------------------------------------------------------------------
      def Packet.parse_question(data, offset)
        qname, offset = dn_expand(data, offset);
        return nil, nil unless qname!=nil;
        
        if data.length < (offset + 2 * Net::DNS::INT16SZ)
          return nil, nil 
        end
        
        qtype, qclass = data.unpack("\@#{offset} n2");
        offset += 2 * Net::DNS::INT16SZ;
        
        qtype  = Net::DNS::typesbyval(qtype);
        qclass = Net::DNS::classesbyval(qclass);
        
        return Net::DNS::Question.new(qname, qtype, qclass), offset;
      end
      
      #--      
      #------------------------------------------------------------------------------
      # parse_rr
      #
      #    rrobj, newoffset = parse_rr(data, offset)
      #
      # Parses a DNS resource record (RR) contained at a particular location
      # within a DNS packet.  The first argument is a reference to a scalar
      # containing the packet data.  The second argument is the offset within
      # the data where the RR is located.
      #
      # Returns a Net::DNS::RR object and the offset of the next location
      # in the packet.
      #------------------------------------------------------------------------------
      def Packet.parse_rr(data, offset)
        name, offset = dn_expand(data, offset);
        return nil, nil unless name!=nil;
        
        if data.length < (offset + Net::DNS::RRFIXEDSZ)
          return nil, nil
        end
        
        type, klass, ttl, rdlength = data.unpack("\@#{offset} n2 N n");
        
        type  = Net::DNS::typesbyval(type)    || type;
        
        # Special case for OPT RR where CLASS should be interperted as 16 bit 
        # unsigned 2671 sec 4.3
        if (type != "OPT") 
          klass = Net::DNS::classesbyval(klass) || klass;
        end
        # else just keep at its numerical value
        
        offset += Net::DNS::RRFIXEDSZ;
        
        if data.length < (offset + rdlength)
          return nil, nil 
        end
        
        rrobj = Net::DNS::RR.create(name, type, klass, ttl, rdlength, data, offset)
        
        return nil, nil unless rrobj!=nil;
        
        offset += rdlength;
        return rrobj, offset;
      end
      
      # Iterators
      def each_address
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::A
          yield elem.address
        end
      end
      def each_nameserver
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::NS
          yield elem.nsdname
        end
      end
      def each_mx
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::MX
          yield elem.preference,elem.exchange
        end
      end
      def each_cname
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::CNAME
          yield elem.cname
        end
      end
      def each_ptr
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::PTR
          yield elem.ptrdname
        end
      end
      
    end
  end
end
