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
    #Net::DNS::RR - DNS Resource Record class
    #
    #= DESCRIPTION
    #
    #Net::DNS::RR is the base class for DNS Resource Record (RR) objects.
    #See also the manual pages for each RR type.
    #
    #*WARNING!!!*  Don't assume the RR objects you receive from a query
    #are of a particular type -- always check an object's type before calling
    #any of its methods.  If you call an unknown method, you'll get a nasty
    #warning message and Net::DNS::RR will return *nil* to the caller.
    #
    #= Sorting of RR arrays
    #
    #As of version 0.55 there is functionality to help you sort RR
    #arrays. The sorting is done by Net::DNS::rrsort(), see the
    #Net::DNS documentation. This package provides class methods to set
    #the sorting functions used for a particular RR based on a particular
    #attribute.
    #
    #= BUGS
    #
    #This version of Net::DNS::RR does little sanity checking on user-created
    #RR objects.
    #
    #= COPYRIGHT
    #
    #Copyright (c) 1997-2002 Michael Fuhr. 
    #
    #Portions Copyright (c) 2002-2004 Chris Reinhardt.
    #
    #Portions Copyright (c) 2005 Olaf Kolkman 
    #
    #Ruby version Copyright (c) 2006 AlexD (Nominet UK)
    #
    #All rights reserved.  This program is free software; you may redistribute
    #it and/or modify it under the same terms as Perl itself.
    #
    #EDNS0 extensions by Olaf Kolkman.
    #
    #= SEE ALSO
    #
    #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
    #Net::DNS::Update, Net::DNS::Header, Net::DNS::Question,
    #RFC 1035 Section 4.1.3
    class RR
      RRS = [
		"A",
		"AAAA",
		"AFSDB",
		"CNAME",
		"CERT",
		"DNAME",
		"EID",
		"HINFO",
		"ISDN",
		"LOC",
		"MB",
		"MG",
		"MINFO",
		"MR",
		"MX",
		"NAPTR",
		"NIMLOC",
		"NS",
		"NSAP",
		"NULL",
		"PTR",
		"PX",
		"RP",
		"RT",
		"SOA",
		"SRV",
		"TKEY",
		"TSIG",
		"TXT",
		"X25",
		"OPT",
		"SSHFP",
		"SPF"]
      
      #The record's domain name.
      attr_accessor :name
      
      #The record's type.
      attr_accessor :type
      
      #The record's class.
      attr_accessor :rrclass
      
      #Returns the record's time-to-live (TTL).
      attr_accessor :ttl
      
      #Returns the length of the record's data section.
      attr_accessor :rdlength
      
      #Returns the record's data section as binary data.
      attr_writer :rdata
      
      
      #  @TODO Only load DNSSEC if available
      #  
      
      @@rr_regex = nil
      def RR.build_regex
        if (@@rr_regex!=nil)
          return @@rr_regex
        end
        #   Types = join('|', sort { length $b <=> length $a } keys Net::DNS::TypesByName)
        # Longest ones go first, so the regex engine will match AAAA before A.
        types = (Net::DNS::Typesbyname.keys.sort { |a, b| b.length <=> a.length }).join('|')
        types += '|TYPE\\d+';
        
        #	my $classes = join('|', keys %Net::DNS::classesbyname, 'CLASS\\d+');
        classes = Net::DNS::Classesbyname.keys.join('|') + "|CLASS\\d+"
        
        #        #        @rr_regex = Regexp.new("^\s*(\S+)\s*(\d+)?\s*(#{classes})?\s*(#{types})?\s*(.*)$")
        #        @rr_regex = Regexp.new("^\\s*(\\S+)\\s*(\\d+)?\\s*(#{classes})?\\s*(#{types})?\\s*(.*)\$"); 
        @@rr_regex = Regexp.new("^\\s*(\\S+)\\s*(\\d+)?\\s*(#{classes})?\\s*(#{types})?\\s*([\\s\\S]*)\$"); 
        return @@rr_regex
      end
      
      def init(*args)
        if (args.length == 2)
          #          @rdata = args[0]
          #          @rdlength = @rdata.length
          new_from_data(args[0], args[1])
        elsif (args.length == 1)
          if (args[0].class == String)
            @rdatastr = args[0]
            new_from_string(args[0])
          elsif (args[0].class == Hash)
            new_from_hash(args[0])
          end
        end
      end
      
      #String version
      #       
      # a     = Net::DNS::RR.create("foo.example.com. 86400 A 10.1.2.3")
      # mx    = Net::DNS::RR.create("example.com. 7200 MX 10 mailhost.example.com.")
      # cname = Net::DNS::RR.create("www.example.com 300 IN CNAME www1.example.com")
      # txt   = Net::DNS::RR.create('baz.example.com 3600 HS TXT "text record"')
      #
      #Returns a Net::DNS::RR object of the appropriate type and
      #initialized from the string passed by the user.  The format of the
      #string is that used in zone files, and is compatible with the string
      #returned by Net::DNS::RR.inspect
      #
      #The name and RR type are required; all other information is optional.
      #If omitted, the TTL defaults to 0 and the RR class defaults to IN.
      #Omitting the optional fields is useful for creating the empty RDATA
      #sections required for certain dynamic update operations.  See the
      #Net::DNS::Update manual page for additional examples.
      #
      #All names must be fully qualified.  The trailing dot (.) is optional.
      #
      #
      #
      #Hash version
      #
      # rr = Net::DNS::RR.create({
      #	 "name"    => "foo.example.com",
      #	 "ttl"     => 86400,
      #	 "rrclass"   => "IN",
      #	 "type"    => "A",
      #	 "address" => "10.1.2.3"
      #  })
      # 
      # rr = Net::DNS::RR.create({
      #	 "name" => "foo.example.com",
      #	 "type" => "A"
      # })
      #
      #Returns an RR object of the appropriate type, or a Net::DNS::RR
      #object if the type isn't implemented.  See the manual pages for
      #each RR type to see what fields the type requires.
      #
      #The name and type fields are required; all others are optional.
      #If omitted, ttl defaults to 0 and rrclass defaults to IN.  Omitting
      #the optional fields is useful for creating the empty RDATA sections
      #required for certain dynamic update operations.
      #
      #The fields are case-insensitive, but starting each with uppercase
      #is recommended.
      def RR.create(*args)
        if (args.length == 1) && (args[0].class == String) 
          return new_from_string(args[0])
        elsif (args.length == 1) && (args[0].class == Hash) 
          return new_from_hash(args[0])
        else 
          return new_from_data(args)
        end
      end
      
      def RR.new_from_data(args)
        name = args[0]
        rrtype = args[1]
        rrclass = args[2]
        ttl = args[3]
        rdlength = args[4]
        data = args[5]
        offset = args[6];
        rdata = data[offset, rdlength]
        if (RRS.include?(rrtype))
          subclass = _get_subclass(name, rrtype, rrclass, ttl, rdlength);          
        else
          subclass = _get_subclass(name, rrtype, rrclass, ttl, rdlength);          
        end
        subclass.init(data, offset);
        return subclass
      end
      
      def RR.new_from_hash(values)
        raise ArgumentError, 'RR name not specified' if !(values.has_key?(:name))
        raise ArgumentError, 'RR type not specified' if !(values.has_key?(:type))
        name = values[:name]
        rrtype = values[:type]
        rrclass = 'IN' 
        if (values.has_key?:class)
          rrclass = values[:class] 
        end
        ttl = 0
        if (values.has_key?:ttl)
          ttl = values[:ttl] 
        end
        rdata = ""
        if (values.has_key?:data)
          rdata = values[:data] 
        end
        rdlength = rdata.length
        
        subclass = _get_subclass(name, rrtype, rrclass, ttl, rdlength);          
        
        subclass.init(values)          
        return subclass
      end
      
      def RR.new_from_string(rrstring, update_type=nil)        
        build_regex()
        
        # strip out comments
        # Test for non escaped ";" by means of the look-behind assertion
        # (the backslash is escaped)
        rrstring.gsub!(/(\?<!\\);.*/o, "");
        
        #        if ((rrstring =~/#{@rr_regex}/xso) == nil)
        if ((rrstring =~@@rr_regex) == nil)
          raise Exception, "#{rrstring} did not match RR pat.\nPlease report this to the author!\n";
        end
        
        name    = $1;
        ttl     = $2.to_i || 0;
        rrclass = $3 || '';
        
        
        rrtype  = $4 || '';
        rdata   = $5 || '';
        
        if rdata 
          rdata.gsub!(/\s+$/o, "")
        end
        if name 
          name.gsub!(/\.$/o, "");
        end
        
        
        # RFC3597 tweaks
        # This converts to known class and type if specified as TYPE###
        if rrtype  =~/^TYPE\d+/o
          rrtype  = Net::DNS::typesbyval(Net::DNS::typesbyname(rrtype))
        end
        if rrclass =~/^CLASS\d+/o
          rrclass = Net::DNS::classesbyval(Net::DNS::classesbyname(rrclass))
        end
        
        
        if (rrtype=='' && rrclass && rrclass == 'ANY')
          rrtype  = 'ANY';
          rrclass = 'IN';
        elsif (rrclass=='')
          rrclass = 'IN';
        end
        
        if (rrtype == '')
          rrtype = 'ANY';
        end
        
        if (update_type)
          update_type.downcase!;
          
          if (update_type == 'yxrrset')
            ttl     = 0;
            rrclass = 'ANY' unless rdata!=nil && rdata.length > 0
          elsif (update_type == 'nxrrset')
            ttl     = 0;
            rrclass = 'NONE';
            rdata   = '';
          elsif (update_type == 'yxdomain')
            ttl     = 0;
            rrclass = 'ANY';
            rrtype  = 'ANY';
            rdata   = '';
          elsif (update_type == 'nxdomain')
            ttl     = 0;
            rrclass = 'NONE';
            rrtype  = 'ANY';
            rdata   = '';
          elsif (update_type =~/^(rr_)?add$/o)
            ttl = 86400 unless ttl!=nil
          elsif (update_type =~/^(rr_)?del(ete)?$/o)
            ttl     = 0;
            rrclass = (rdata != nil && rdata.length > 0) ? 'NONE' : 'ANY';
          end
        end
        
        
        if (RRS.include?(rrtype) && rdata !~/^\s*\\#/o )
          #          subclass = _get_subclass(rrtype);
          subclass = _get_subclass(name, rrtype, rrclass, ttl);          
          
          subclass.init(rdata);
          return subclass
        elsif (RRS.include?(rrtype))   # A RR type known to Net::DNS starting with \#
          rdata =~ /\\\#\s+(\d+)\s+(.*)$/o;
          
          rdlength = $1.to_i;
          hexdump  = $2;		
          hexdump.gsub!(/\s*/, "");
          
          if hexdump.length() != rdlength*2
            raise Exception, "#{rdata} is inconsistent; length does not match content"
          end
          
          rdata = [hexdump].pack('H*');
          
          return new_from_data([name, rrtype, rrclass, ttl, rdlength, rdata, 0]) # rdata.length() - rdlength]);
        elsif (rdata=~/\s*\\\#\s+\d+\s+/o)
          #We are now dealing with the truly unknown.
          raise Exception, 'Expected RFC3597 representation of RDATA' unless rdata =~/\\\#\s+(\d+)\s+(.*)$/o;
          
          rdlength = $1.to_i;
          hexdump  = $2;		
          hexdump.gsub!(/\s*/o, "");
          
          if hexdump.length() != rdlength*2
            raise Exception, "#{rdata} is inconsistent; length does not match content" ;
          end
          
          rdata = [hexdump].pack('H*');
          
          return new_from_data([name,rrtype,rrclass,ttl,rdlength,rdata,0]) # rdata.length() - rdlength);
        else
          #God knows how to handle these... bless them in the RR class.
          subclass = _get_subclass(name, rrtype, rrclass, ttl);          
          return subclass
        end
      end
      
      #Returns a string representation of the RR.  Calls the
      #rdatastr method to get the RR-specific data.
      #
      #    print rr.inspect, "\n"
      def inspect 
        return @name + ".\t" +@ttl.to_s + "\t" + @rrclass.to_s + "\t" + @type + "\t" + ((rdatastr()!=nil && rdatastr().length>0) ? rdatastr() : '; no data')
      end
      
      #Returns a string containing RR-specific data.
      #
      #    s = rr.rdatastr
      def rdatastr 
        # For subclasses to implement themselves
        @rdlength!=nil ? "; rdlength = #{@rdlength}" : '';
      end
      
      def rdata(*args)
        if (args.length == 2)
          packet, offset = args;
          ret = rr_rdata(packet, offset);
          return ret
          # rr_rdata
        elsif (@rdata != nil)
          return @rdata;
        end
        return nil;
      end
      
      def rr_rdata(*args)
        return (@rdata!=nil ? @rdata : '');
      end
      
      
      #--      
      #------------------------------------------------------------------------------
      # sub data
      #
      # This method is called by Net::DNS::Packet->data to get the binary
      # representation of an RR.
      #------------------------------------------------------------------------------
      def data(packet, offset)
        # Don't compress TSIG or TKEY names and don't mess with EDNS0 packets
        if (@type.upcase == 'TSIG' || @type.upcase == 'TKEY')
          tmp_packet = Net::DNS::Packet.new_from_binary()
          data = tmp_packet.dn_comp(@name, 0)
        elsif (@type.upcase == 'OPT')
          tmp_packet = Net::DNS::Packet.new_from_binary()
          data = tmp_packet.dn_comp('', 0)
        else
          data = packet.dn_comp(@name, offset)
        end
        qtype     = @type.upcase;
        ret = (qtype =~ /^\d+$/o)
        qtype_val = (ret != nil) ? qtype : Net::DNS::typesbyname(qtype)
        qtype_val    = 0 if (qtype_val==nil)
        
        qclass_val = 0
        if (@rrclass != nil) 
          qclass     = @rrclass.to_s.upcase
          ret = qclass =~ /^\d+$/o
          qclass_val = (ret != nil) ? qclass : Net::DNS::classesbyname(qclass)
          qclass_val    = 0 if (qclass_val==nil)
        end        
        data += [qtype_val].pack('n')
        
        # If the type is OPT then class will need to contain a decimal number
        # containing the UDP payload size. (RFC2671 section 4.3)
        if (@type != 'OPT') 
          data += [qclass_val].pack('n')
        else
          data += [@rrclass].pack('n')
        end
        
        data += [@ttl].pack('N')
        
        offset += data.length + Net::DNS::INT16SZ	# allow for rdlength
        
        rd = rdata(packet, offset)
        
        data += [rd.length].pack('n')
        data+=rd
        
        return data
      end
      
      #--      
      #------------------------------------------------------------------------------
      #  This method is called by SIG objects verify method. 
      #  It is almost the same as data but needed to get an representation of the
      #  packets in wire format withoud domain name compression.
      #  It is essential to DNSSEC RFC 2535 section 8
      #------------------------------------------------------------------------------
      def _canonicaldata
        data=''
        dname=Net::DNS::name2labels(@name)
        #	    for (my $i=0;$i<dname;$i++){
        i = 0
        dname.length.times do 
          data += [dname[i].length].pack('C')
          data += dname[i].downcase
          i += 1
        end
        data += [0].pack('C')
        data += [Net::DNS::typesbyname(@type.upcase)].pack('n')
        data += [Net::DNS::classesbyname(@rrclass.upcase)].pack('n')
        data += [@ttl].pack('N')
        
        rdata = _canonicalRdata
        
        data += [rdata.length].pack('n')
        data += rdata
        return data
      end
      
      #--      
      # These are methods that are used in the DNSSEC context...  Some RR
      # have domain names in them. Verification works only on RRs with
      # uncompressed domain names. (Canonical format as in sect 8 of
      # RFC2535) _canonicalRdata is overwritten in those RR objects that
      # have domain names in the RDATA and _name2wire is used to convert a
      # domain name to "wire format"
      
      def _canonicalRdata
        packet=Net::DNS::Packet.new()
        rdata = rr_rdata(packet,0)
        return rdata
      end
      
      def _name2wire(name)
        return RR._name2wire(name)
      end
      
      def RR._name2wire(name)
        rdata="";
        compname = "";
        dname = Net::DNS::name2labels(name);
        
        dname.each { |i|
          rdata += [i.length].pack('C');
          rdata += i ;
        }    
        rdata += [0].pack('C');
        return rdata;
      end
      
      def RR._get_subclass(name, type, rrclass, ttl, rdlength=0)
        return unless (type!=nil)
        if RRS.include?(type)
          klass = Net::DNS::RR.const_get(type)
        else
          klass = Net::DNS::RR::UNKNOWN
        end
        ret = klass.new
        ret.name=(name)
        ret.type=(type)
        ret.rrclass=(rrclass)
        ret.rdlength=(rdlength)
        ret.ttl=(ttl)
        ret.create_rrsort_func
        return ret
      end	
      
      def create_rrsort_func
        @rrsortfunc=Hash.new()
        init_rrsort_func
      end
      
      def init_rrsort_func
        # empty implementation for interested subclasses to fill out
      end
      
      #set_rrsort_func needs to be called as a class method. The first
      #argument is the attribute name on which the sorting will need to take
      #place. If you specify "default_sort" than that is the sort algorithm
      #that will be used in the case that rrsort() is called without an RR
      #attribute as argument. The second argument is a Proc to do the sort.
      #
      #The following example is the sorting function that actually is implemented in 
      #SRV.
      #
      #    Net::DNS::RR::SRV.set_rrsort_func("priority", Proc.new {  |a,b|
      #				   a.priority <=> b.priority
      #				   ||
      #				   b.weight <=> a.weight})
      #
      #    Net::DNS::RR::SRV.set_rrsort_func("default_sort", Proc.new { |a,b|
      #				   a.priority <=> b.priority
      #				   ||
      #				   b.weight <=> a.weight})
      def set_rrsort_func(attribute, func)
        @rrsortfunc[attribute]=func;
      end
      
      def get_rrsort_func(attribute=nil)
        if (@rrsortfunc != nil)
          if (attribute!=nil &&  @rrsortfunc[attribute]!=nil)
            #  The default overwritten by the class variable in Net::DNS
            return @rrsortfunc[attribute];
          elsif((attribute==nil) &&  (@rrsortfunc[:default_sort]!=nil))
            #  The default overwritten by the class variable in Net::DNS
            return @rrsortfunc[:default_sort];
          end    
        end
        if( attribute!=nil && attribute != "")           
          ret = Proc.new { |a,b| (a.respond_to?(attribute) ? (a.send(attribute) <=> b.send(attribute)) : (a._canonicaldata() <=> b._canonicaldata())) }
          return ret
        else
          ret = Proc.new { |a,b| a._canonicaldata() <=> b._canonicaldata() }
          return ret           
        end
        
        return sortsub;
      end
      
      
    end
  end
end

require 'Net/DNS/RR/A'
require 'Net/DNS/RR/AAAA'
require 'Net/DNS/RR/MX'
require 'Net/DNS/RR/TXT'
require 'Net/DNS/RR/SRV'
require 'Net/DNS/RR/NS'
require 'Net/DNS/RR/SOA'
require 'Net/DNS/RR/OPT'
require 'Net/DNS/RR/AFSDB'
require 'Net/DNS/RR/CNAME'
require 'Net/DNS/RR/DNAME'
require 'Net/DNS/RR/HINFO'
require 'Net/DNS/RR/ISDN'
require 'Net/DNS/RR/MB'
require 'Net/DNS/RR/MG'
require 'Net/DNS/RR/MINFO'
require 'Net/DNS/RR/MR'
require 'Net/DNS/RR/NAPTR'
require 'Net/DNS/RR/PTR'
require 'Net/DNS/RR/NSAP'
require 'Net/DNS/RR/PX'
require 'Net/DNS/RR/RP'
require 'Net/DNS/RR/RT'
require 'Net/DNS/RR/X25'
require 'Net/DNS/RR/LOC'
#require 'Net/DNS/RR/CERT'
require 'Net/DNS/RR/SPF'
require 'Net/DNS/RR/TKEY'
#require 'Net/DNS/RR/TSIG'
require 'Net/DNS/RR/EID'
require 'Net/DNS/RR/NIMLOC'
require 'Net/DNS/RR/NULL'
require 'Net/DNS/RR/UNKNOWN'
