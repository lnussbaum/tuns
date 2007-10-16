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
require 'Net/DNS/Resolver'
require 'Net/DNS/Nameserver'


module Net
  #= NAME
  #
  #Net::DNS - Perl interface to the DNS resolver
  #
  #= SYNOPSIS
  #
  #<tt>use Net::DNS;</tt>
  #
  #= DESCRIPTION
  #
  #Net::DNS is a collection of modules that act as a Domain
  #Name System (DNS) resolver. It is a port of the perl
  #Net::DNS package.
  #
  #The programmer should be somewhat familiar with the format of
  #a DNS packet and its various sections.  See RFC 1035 or
  #<em>DNS and BIND</em> (Albitz & Liu) for details.
  #
  #= Resolver Objects
  #
  #A resolver object is an instance of the
  #Net::DNS::Resolver class. A program can have
  #multiple resolver objects, each maintaining its own state information
  #such as the nameservers to be queried, whether recursion is desired,
  #etc.
  #
  #== Packet Objects
  #
  #Net::DNS::Resolver queries return
  #Net::DNS::Packet objects.  Packet objects have five
  #sections:
  #
  # * The header section, a Net::DNS::Header object.
  #
  # * The question section, a list of Net::DNS::Question objects.
  #
  # * The answer section, a list of Net::DNS::RR objects.
  #
  # * The authority section, a list of Net::DNS::RR objects.
  #
  # * The additional section, a list of Net::DNS::RR objects.
  #
  #== Update Objects
  #
  #The Net::DNS::Update package is a subclass of
  #Net::DNS::Packet for creating packet objects to be
  #used in dynamic updates.  
  #
  #== Header Objects
  #
  #Net::DNS::Header objects represent the header
  #section of a DNS packet.
  #
  #== Question Objects
  #
  #Net::DNS::Question objects represent the question
  #section of a DNS packet.
  #
  #== RR Objects
  #
  #Net::DNS::RR is the base class for DNS resource record
  #(RR) objects in the answer, authority, and additional sections of a DNS
  #packet.
  #
  #Don't assume that RR objects will be of the type you requested -- always
  #check an RR object's type before calling any of its methods.
  #
  #== Sorting of RR arrays
  #
  #As of version 0.55 there is functionality to help you sort RR
  #arrays. 'rrsort()' is the function that is available to do the
  #sorting. In most cases rrsort will give you the answer that you
  #want but you can specify your own sorting method by using the 
  #Net::DNS::RR::FOO.set_rrsort_func() class method. See Net::DNS::RR
  #for details.
  #
  #= EXAMPLES
  #
  #The following examples show how to use the <tt>Net::DNS</tt> modules.
  #See the other manual pages and the demo scripts included with the
  #source code for additional examples.
  #
  #See the <tt>Net::DNS::Update</tt> manual page for an example of performing
  #dynamic updates.
  #
  #== Look up a host's addresses.
  #  
  #  require 'Net/DNS'
  #  res   = Net::DNS::Resolver.new
  #  query = res.search("host.example.com")
  #  
  #  if (query)
  #      query.answer.each do |rr|
  #          next unless rr.class == Net::DNS::RR::A
  #          print rr.address + "\n"
  #      end
  #  else
  #      print "query failed: " + res.errorstring + "\n"
  #  end
  #  
  #
  #== Find the nameservers for a domain.
  #  
  #  require 'Net/DNS'
  #  res   = Net::DNS::Resolver.new
  #  query = res.query("example.com", "NS")
  #  
  #  if (query)
  #      (query.answer.select { |i| i.class == Net::DNS::RR::NS}).each do |rr|
  #          print rr.nsdname + "\n"
  #      end
  #  else
  #      print "query failed: " + res.errorstring + "\n"
  #  end
  #  
  #== Find the MX records for a domain.
  #  
  #  require 'Net/DNS'
  #  name='ENTER_NAME_HERE'
  #  res = Net::DNS::Resolver.new
  #  mx   = Net::DNS.mx(name, res, 'IN')
  #  
  #  if (mx)
  #      mx.each do |rr|
  #          print rr.preference, " ", rr.exchange, "\n"
  #      end
  #  else
  #      print "Can't find MX records for #{name}: " + res.errorstring + "\n"
  #  end
  #
  #== Print a domain's SOA record in zone file format.
  #  
  #  require 'Net/DNS'
  #  res   = Net::DNS::Resolver.new
  #  query = res.query("example.com", "SOA")
  #  
  #  if (query)
  #      (query.answer)[0].print
  #  else
  #      print "query failed: ", res.errorstring, "\n"
  #  end
  #
  #== Perform a zone transfer and print all the records.
  #
  #  require 'Net/DNS'
  #  res   = Net::DNS::Resolver.new
  #  res.nameservers("ns.example.com")
  #  
  #  zone = res.axfr("example.com")
  #  
  #  zone.each do |rr|
  #      rr.print
  #  end
  #
  #--
  #== Perform a background query and do some other work while waiting
  #for the answer.
  #
  #  require 'Net/DNS'
  #  res   = Net::DNS::Resolver.new
  #  socket = res.bgsend("host.example.com")
  #
  #  until (res.bgisready(socket))
  #      # do some work here while waiting for the answer
  #      # ...and some more here
  #  end
  #
  #  packet = res.bgread(socket)
  #  packet.print
  #
  #
  #== Send a background query and use select to determine when the answer
  #has arrived.
  #
  #  require 'Net/DNS'
  #  
  #  timeout = 5
  #  res     = Net::DNS::Resolver.new
  #  sockets  = [res.bgsend("host.example.com")]
  #  
  #  # Add more sockets to sockets if desired.
  # ready = IO::select(sockets, nil, nil, timeout)[0]
  #  if (ready != nil)
  #      ready.each do { |sock|
  #          if (sock == bgsock)
  #              packet = res.bgread(bgsock)
  #              packet.print
  #              bgsock = nil
  #          end
  #          # Check for the other sockets.
  #          sockets.remove(sock)
  #       end
  #  else
  #      warn "timed out after #{timeout} seconds\n"
  #  end
  #
  #++
  #
  #= BUGS
  #
  #Net::DNS is slow.
  #
  #For other items to be fixed, please see the "TODO" file included with
  #the source distribution.
  #
  #= COPYRIGHT
  #
  #Copyright (c) 1997-2002 Michael Fuhr. 
  #
  #Portions Copyright (c) 2002-2004 Chris Reinhardt.
  #
  #Portions Copyright (c) 2005 Olaf Kolkman (RIPE NCC)
  #
  #Portions Copyright (c) 2006 Olaf Kolkman (NLnet Labs)
  #
  #Portions Copyright (c) 2006 AlexD (Nominet UK)
  #
  #All rights reserved.
  #
  #= AUTHOR INFORMATION
  #
  #Ruby port (2006) from Nominet UK by :
  #        Alex D
  #   alexd@nominet.org.uk
  #
  #Port from perl Net::DNS (version 0.57) maintained at NLnet Labs (www.nlnetlabs.nl) by:
  #        Olaf Kolkman
  #	olaf@net-dns.org
  #
  #Between 2002 and 2004 Net::DNS was maintained by:
  #       Chris Reinhardt
  #
  #
  #Net::DNS was created by:
  #	Michael Fuhr
  #	mike@fuhr.org 
  #
  #
  #
  #For more information see:
  #    http://www.net-dns.org/
  #
  #Stay tuned and syncicate:
  #    http://www.net-dns.org/blog/
  #
  #= SEE ALSO
  # 
  # Net::DNS::Resolver, Net::DNS::Packet, Net::DNS::Update,
  #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR, RFC 1035,
  #<em>DNS and BIND</em> by Paul Albitz & Cricket Liu
  module DNS
    
    
    #Returns the version of Net::DNS.
    VERSION = '0.0.1'
    #Returns the default packet size
    PACKETSZ = 512
    #Header size
    HFIXEDSZ = 12
    QFIXEDSZ = 4
    RRFIXEDSZ = 10
    INT32SZ = 4
    INT16SZ = 2
    
    HAVE_XS = false # @TODO
    DNSSEC = false # @TODO
    DN_EXPAND_ESCAPES = false # @TODO
    
    
    #--
    # If you implement an RR record make sure you also add it to 
    # Net::DNS::RR::RR hash otherwise it will be treated as unknown type.
    # 
    
    # Do not use these tybesby hashes directly. Use the interface
    # functions, see below.
    # 
    Typesbyname = {
      'SIGZERO'   => 0,       # RFC2931 consider this a pseudo type
      'A'         => 1,       # RFC 1035, Section 3.4.1
      'NS'        => 2,       # RFC 1035, Section 3.3.11
      'MD'        => 3,       # RFC 1035, Section 3.3.4 (obsolete)
      'MF'        => 4,       # RFC 1035, Section 3.3.5 (obsolete)
      'CNAME'     => 5,       # RFC 1035, Section 3.3.1
      'SOA'       => 6,       # RFC 1035, Section 3.3.13
      'MB'        => 7,       # RFC 1035, Section 3.3.3
      'MG'        => 8,       # RFC 1035, Section 3.3.6
      'MR'        => 9,       # RFC 1035, Section 3.3.8
      'NULL'      => 10,      # RFC 1035, Section 3.3.10
      'WKS'       => 11,      # RFC 1035, Section 3.4.2 (deprecated)
      'PTR'       => 12,      # RFC 1035, Section 3.3.12
      'HINFO'     => 13,      # RFC 1035, Section 3.3.2
      'MINFO'     => 14,      # RFC 1035, Section 3.3.7
      'MX'        => 15,      # RFC 1035, Section 3.3.9
      'TXT'       => 16,      # RFC 1035, Section 3.3.14
      'RP'        => 17,      # RFC 1183, Section 2.2
      'AFSDB'     => 18,      # RFC 1183, Section 1
      'X25'       => 19,      # RFC 1183, Section 3.1
      'ISDN'      => 20,      # RFC 1183, Section 3.2
      'RT'        => 21,      # RFC 1183, Section 3.3
      'NSAP'      => 22,      # RFC 1706, Section 5
      'NSAP_PTR'  => 23,      # RFC 1348 (obsolete)
      # The following 2 RRs are impemented in Net::DNS::SEC
      'SIG'       => 24,      # RFC 2535, Section 4.1
      'KEY'       => 25,      # RFC 2535, Section 3.1
      'PX'        => 26,      # RFC 2163,
      'GPOS'      => 27,      # RFC 1712 (obsolete)
      'AAAA'      => 28,      # RFC 1886, Section 2.1
      'LOC'       => 29,      # RFC 1876
      # The following RR is impemented in Net::DNS::SEC
      'NXT'       => 30,      # RFC 2535, Section 5.2 obsoleted by RFC3755
      'EID'       => 31,      # draft-ietf-nimrod-dns-xx.txt
      'NIMLOC'    => 32,      # draft-ietf-nimrod-dns-xx.txt
      'SRV'       => 33,      # RFC 2052
      'ATMA'      => 34,      # ???
      'NAPTR'     => 35,      # RFC 2168
      'KX'        => 36,      # RFC 2230
      'CERT'      => 37,      # RFC 2538
      'DNAME'     => 39,      # RFC 2672
      'OPT'       => 41,      # RFC 2671
      # The following 4 RRs are impemented in Net::DNS::SEC
      'DS'        => 43,      # RFC 4034
      'SSHFP'     => 44,      # draft-ietf-secsh-dns (No RFC # yet at time of coding)
      #    'IPSECKEY'  => 45,      # RFC 4025
      'RRSIG'     => 46,      # RFC 4034
      'NSEC'      => 47,      # RFC 4034
      'DNSKEY'    => 48,      # RFC 4034
      'SPF'       => 99,      # rfc-schlitt-spf-classic-o2 (No RFC # yet at time of coding)
      'UINFO'     => 100,     # non-standard
      'UID'       => 101,     # non-standard
      'GID'       => 102,     # non-standard
      'UNSPEC'    => 103,     # non-standard
      'TKEY'      => 249,     # RFC 2930
      'TSIG'      => 250,     # RFC 2931
      'IXFR'      => 251,     # RFC 1995
      'AXFR'      => 252,     # RFC 1035
      'MAILB'     => 253,     # RFC 1035 (MB, MG, MR)
      'MAILA'     => 254,     # RFC 1035 (obsolete - see MX)
      'ANY'       => 255,     # RFC 1035
    }
    Typesbyval = Typesbyname.invert;
    
    #
    # Do not use these classesby hashes directly. See below. 
    #
    
    Classesbyname = {
      'IN'        => 1,       # RFC 1035
      'CH'        => 3,       # RFC 1035
      'CHAOS'        => 3,       # RFC 1035
      'HS'        => 4,       # RFC 1035
      'HESIOD'        => 4,       # RFC 1035
      'NONE'      => 254,     # RFC 2136
      'ANY'       => 255,     # RFC 1035
    }
    Classesbyval = {
      1 => 'IN',       # RFC 1035
      3 => 'CH',       # RFC 1035
      4 => 'HS',       # RFC 1035
      254 => 'NONE',     # RFC 2136
      255 => 'ANY',     # RFC 1035
    }
    
    
    # The qtypesbyval and metatypesbyval specify special typecodes
    # See rfc2929 and the relevant IANA registry
    # http://www.iana.org/assignments/dns-parameters
    
    
    Qtypesbyname = {
      'IXFR'   => 251,  # incremental transfer                [RFC1995]
      'AXFR'   => 252,  # transfer of an entire zone          [RFC1035]
      'MAILB'  => 253,  # mailbox-related RRs (MB, MG or MR)   [RFC1035]
      'MAILA'  => 254,  # mail agent RRs (Obsolete - see MX)   [RFC1035]
      'ANY'    => 255,  # all records                      [RFC1035]
    }
    Qtypesbyval = Qtypesbyname.invert;
    
    
    Metatypesbyname = {
      'TKEY'        => 249,    # Transaction Key   [RFC2930]
      'TSIG'        => 250,    # Transaction Signature  [RFC2845]
      'OPT'         => 41,     # RFC 2671
    }
    Metatypesbyval = Metatypesbyname.invert;
    
    
    Opcodesbyname = {
      'QUERY'        => 0,        # RFC 1035
      'IQUERY'       => 1,        # RFC 1035
      'STATUS'       => 2,        # RFC 1035
      'NS_NOTIFY_OP' => 4,        # RFC 1996
      'UPDATE'       => 5,        # RFC 2136
    }
    Opcodesbyval = Opcodesbyname.invert;
    
    
    Rcodesbyname = {
      'NOERROR'   => 0,       # RFC 1035
      'FORMERR'   => 1,       # RFC 1035
      'SERVFAIL'  => 2,       # RFC 1035
      'NXDOMAIN'  => 3,       # RFC 1035
      'NOTIMP'    => 4,       # RFC 1035
      'REFUSED'   => 5,       # RFC 1035
      'YXDOMAIN'  => 6,       # RFC 2136
      'YXRRSET'   => 7,       # RFC 2136
      'NXRRSET'   => 8,       # RFC 2136
      'NOTAUTH'   => 9,       # RFC 2136
      'NOTZONE'   => 10,      # RFC 2136
    }
    Rcodesbyval = Rcodesbyname.invert;
    
    #--
    # typesbyval and typesbyname functions are wrappers around the similarly named
    # hashes. They are used for 'unknown' DNS RR types (RFC3597)    
    # typesbyname returns they TYPEcode as a function of the TYPE
    # mnemonic. If the TYPE mapping is not specified the generic mnemonic
    # TYPE### is returned.
    def DNS.typesbyname(name) 
      name.upcase!
      
      if Typesbyname[name]
        return Typesbyname[name]
      end
      
      
      if ((name =~/^\s*TYPE(\d+)\s*$/o)==nil)
        raise ArgumentError, "Net::DNS::typesbyname() argument (#{name}) is not TYPE###"
      end
      
      val = $1.to_i
      if val > 0xffff
        raise ArgumentError, 'Net::DNS::typesbyname() argument larger than ' + 0xffff
      end
      
      return val;
    end
    
    
    # typesbyval returns they TYPE mnemonic as a function of the TYPE
    # code. If the TYPE mapping is not specified the generic mnemonic
    # TYPE### is returned.
    def DNS.typesbyval(val)
      if (!defined?val)
        raise ArgumentError,  "Net::DNS::typesbyval() argument is not defined"
      end
      
      if val.class == String
        #      if val.gsub!("^\s*0*(\d+)\s*$", "$1")
        if ((val =~ /^\s*0*(\d+)\s*$", "$1/o) == nil)
          raise ArgumentError,  "Net::DNS::typesbyval() argument (#{val}) is not numeric" 
          #          val =~s/^\s*0*(\d+)\s*$/$1/o;
        end
        
        val = $1.to_i
      end
      
      
      if Typesbyval[val]
        return Typesbyval[val] 
      end
      
      raise ArgumentError,  'Net::DNS::typesbyval() argument larger than ' + 0xffff if 
      val > 0xffff;
      
      return "TYPE#{val}";
    end
    
    
    
    # classesbyval and classesbyname functions are wrappers around the
    # similarly named hashes. They are used for 'unknown' DNS RR classess
    # (RFC3597)    
    # See typesbyval and typesbyname, these beasts have the same functionality    
    def DNS.classesbyname(name)
      name.upcase!;
      if Classesbyname[name]
        return Classesbyname[name]
      end
      
      if ((name =~/^\s*CLASS(\d+)\s*$/o) == nil)
        raise ArgumentError, "Net::DNS::classesbyval() argument is not CLASS### (#{name})"
      end
      
      val = $1.to_i
      if val > 0xffff
        raise ArgumentError, 'Net::DNS::classesbyval() argument larger than ' + 0xffff
      end
      
      return val;
    end
    
    
    
    def DNS.classesbyval(val)          
      if (val.class == String)
        if ((val =~ /^\s*0*([0-9]+)\s*$/) == nil)
          raise ArgumentError,  "Net::DNS::classesbybal() argument is not numeric (#{val})" # unless  val.gsub!("^\s*0*([0-9]+)\s*$", "$1")
          #          val =~ s/^\s*0*([0-9]+)\s*$/$1/o;#
        end
        val = $1.to_i
      end
      
      return Classesbyval[val] if Classesbyval[val];
      
      raise ArgumentError,  'Net::DNS::classesbyval() argument larger than ' + 0xffff if val > 0xffff;
      
      return "CLASS#{val}";
    end            
    
    # Usage:
    #    mxes = mx('example.com', 'IN')
    #
    #    # Use a default resolver -- can't get an error string this way.
    #    require 'Net/DNS'
    #    mx = Net::DNS.mx("example.com")
    #
    #    # Use your own resolver object.
    #    require 'Net/DNS'
    #    res = Net::DNS::Resolver.new
    #    mx = Net::DNS.mx("example.com", res)
    #
    #Returns a list of Net::DNS::RR::MX objects
    #representing the MX records for the specified name; the list will be
    #sorted by preference. Returns an empty list if the query failed or no MX
    #records were found.
    #
    #This method does not look up A records -- it only performs MX queries.
    #
    #See EXAMPLES for a more complete example.
    #
    def DNS.mx(name, resolver=nil, klass='IN')
      if resolver == nil 
        resolver = Net::DNS::Resolver.new
      end
      
      ans = resolver.query(name, 'MX', klass) || return;
      
      # This construct is best read backwords.
      #
      # First we take the answer secion of the packet.
      # Then we take just the MX records from that list
      # Then we sort the list by preference
      # Then we return it.
      # We do this into an array to force list context.
      ret = []
      ans.answer.each do |rec|
        if (rec.type == 'MX') 
          ret.push(rec)
        end
      end
      ret.sort! { |a,b| a.preference <=> b.preference }
      
      return ret;
    end
    
    #Use this method to add an "RRset exists" prerequisite to a dynamic
    #update packet.  There are two forms, value-independent and
    #value-dependent:
    #
    #    # RRset exists (value-independent)
    #    update.push('pre' => yxrrset("host.example.com A"))
    #
    #Meaning:  At least one RR with the specified name and type must
    #exist.
    #
    #    # RRset exists (value-dependent)
    #    packet.push('pre' => yxrrset("host.example.com A 10.1.2.3"))
    #
    #Meaning:  At least one RR with the specified name and type must
    #exist and must have matching data.
    #
    #Returns a Net::DNS::RR object or nil if the object couldn't
    #be created.
    def DNS.yxrrset(arg)
      return Net::DNS::RR.new_from_string(arg, 'yxrrset');
    end
    
    #Use this method to add an "RRset does not exist" prerequisite to
    #a dynamic update packet.
    #
    #    packet.push('pre' => nxrrset("host.example.com A"))
    #
    #Meaning:  No RRs with the specified name and type can exist.
    #
    #Returns a Net::DNS::RR object or nil if the object couldn't
    #be created.
    #
    def DNS.nxrrset(arg)
      return Net::DNS::RR.new_from_string(arg, 'nxrrset');
    end
    
    #Use this method to add a "name is in use" prerequisite to a dynamic
    #update packet.
    #
    #    packet.push('pre' => yxdomain("host.example.com"))
    #
    #Meaning:  At least one RR with the specified name must exist.
    #
    #Returns a Net::DNS::RR object or nil if the object couldn't
    #be created.
    def DNS.yxdomain(arg)
      return Net::DNS::RR.new_from_string(arg, 'yxdomain')
    end
    
    #Use this method to add a "name is not in use" prerequisite to a
    #dynamic update packet.
    #
    #    packet.push('pre' => nxdomain("host.example.com"))
    #
    #Meaning:  No RR with the specified name can exist.
    #
    #Returns a Net::DNS::RR object or nil if the object couldn't
    #be created.
    #
    def DNS.nxdomain(arg)
      return Net::DNS::RR.new_from_string(arg, 'nxdomain')
    end
    
    #Use this method to add RRs to a zone.
    #
    #    packet.push('update' => rr_add("host.example.com A 10.1.2.3"))
    #
    #Meaning:  Add this RR to the zone.
    #
    #RR objects created by this method should be added to the "update"
    #section of a dynamic update packet.  The TTL defaults to 86400
    #seconds (24 hours) if not specified.
    #
    #Returns a C<Net::DNS::RR object or nil if the object couldn't
    #be created.
    #
    def DNS.rr_add(arg)
      return Net::DNS::RR.new_from_string(arg, 'rr_add');
    end
    
    #Use this method to delete RRs from a zone.  There are three forms:
    #delete an RRset, delete all RRsets, and delete an RR.
    #
    #    # Delete an RRset.
    #    packet.push(:update => rr_del("host.example.com A"))
    #
    #Meaning:  Delete all RRs having the specified name and type.
    #
    #    # Delete all RRsets.
    #    packet.push(:update => rr_del("host.example.com"))
    #
    #Meaning:  Delete all RRs having the specified name.
    #
    #    # Delete an RR.
    #    packet.push(:update => rr_del("host.example.com A 10.1.2.3"))
    #
    #Meaning:  Delete all RRs having the specified name, type, and data.
    #
    #RR objects created by this method should be added to the "update"
    #section of a dynamic update packet.
    #
    #Returns a Net::DNS::RR object or nil if the object couldn't
    #be created.
    #
    def DNS.rr_del(arg)
      return Net::DNS::RR.new_from_string(arg, 'rr_del')
    end
    
    
    # Utility function
    #
    # name2labels to translate names from presentation format into an
    # array of "wire-format" labels.        
    # in: dName a string with a domain name in presentation format (1035
    # sect 5.1)
    # out: an array of labels in wire format.        
    def DNS.name2labels (dName)
      names=[]
      j=0;
      while (dName && dName.length > 0)
        names[j],dName = presentation2wire(dName)
        j+=1
      end
      
      return names
    end
    
    
    def DNS.wire2presentation(wire)
      presentation=""
      length=wire.length
      # There must be a nice regexp to do this.. but since I failed to
      # find one I scan the name string until I find a '\', at that time
      # I start looking forward and do the magic.
      
      i=0;
      
      while (i < length )
        c=wire.unpack("x#{i}C1") [0]
        if ( c < 33 || c > 126 )
          presentation=presentation + sprintf("\\%03u" ,c)
        elsif ( c.chr ==  "\"" )
          presentation=presentation +  "\\\""
        elsif ( c.chr ==  "\$")
          presentation=presentation +  "\\\$"
        elsif ( c.chr == "(" )
          presentation=presentation + "\\("
        elsif ( c.chr == ")" )
          presentation=presentation +  "\\)"
        elsif ( c.chr == ";" )
          presentation=presentation +  "\\;"
        elsif ( c.chr == "@" )
          presentation=presentation +  "\\@"
        elsif ( c.chr == "\\" )
          presentation=presentation + "\\\\" 
        elsif ( c.chr == ".")
          presentation=presentation +  "\\."
        else
          presentation=presentation + c.chr()
        end
        i=i+1
      end
      
      return presentation
    end
    
    
    
    # wire,leftover=presentation2wire(leftover)    
    # Will parse the input presentation format and return everything before
    # the first non-escaped "." in the first element of the return array and
    # all that has not been parsed yet in the 2nd argument.        
    def DNS.presentation2wire(presentation)
      wire="";
      length=presentation.length;
      
      i=0;
      
      while (i < length )
        c=presentation.unpack("x#{i}C1") [0]
        if (c == 46) # ord('.')
          #    	    return (wire,substr(presentation,i+1));
          #          return wire,presentation[i+1, length-(i+1)]
          endstring = presentation[i+1, presentation.length-(i+1)]
          return wire,endstring
        end
        if (c == 92) # ord'\\'
          #backslash found
          #    	    pos(presentation)=i+1;
          pos = i+1
          # pos sets where next pattern matching should start
          #    	    if (presentation=~/\G(\d\d\d)/)
          if (presentation.index(/\G(\d\d\d)/o, pos))
            wire=wire+[$1.to_i].pack("C")
            i=i+3
            #    	    elsif(presentation=~/\Gx([0..9a..fA..F][0..9a..fA..F])/)
          elsif(presentation.index(/\Gx([0..9a..fA..F][0..9a..fA..F])/o, pos))
            wire=wire+[$1].pack("H*")
            i=i+3
            #    	    elsif(presentation=~/\G\./)
          elsif(presentation.index(/\G\./o, pos))
            wire=wire+"\."
            i=i+1
            #    	    elsif(presentation=~/\G@/)
          elsif(presentation.index(/\G@/o,pos))
            wire=wire+"@"
            i=i+1
            #    	    elsif(presentation=~/\G\(/)
          elsif(presentation.index(/\G\(/o, pos))
            wire=wire+"("
            i=i+1
            #    	    elsif(presentation=~/\G\)/)
          elsif(presentation.index(/\G\)/o, pos))
            wire=wire+")"
            i=i+1
            #            elsif(presentation=~/\G\\/)
          elsif(presentation.index(/\G\\/o, pos))
            wire=wire+"\\"
            i+=1
          end
        else
          wire = wire + [c].pack("C")
        end
        i=i+1
      end
      
      return wire
    end
    
    #   require 'Net::DNS'
    #
    #   prioritysorted=rrsort("SRV","priority",rr_array)
    #
    #
    #rrsort() selects all RRs from the input array that are of the type
    #that are defined in the first argument. Those RRs are sorted based on
    #the attribute that is specified as second argument.
    #
    #There are a number of RRs for which the sorting function is
    #specifically defined for certain attributes.  If such sorting function
    #is defined in the code (it can be set or overwritten using the
    #set_rrsort_func() class method) that function is used. 
    #
    #For instance:
    #   prioritysorted=rrsort("SRV","priority",rr_array)
    #returns the SRV records sorted from lowest to heighest priority and
    #for equal priorities from heighes to lowes weight.
    #
    #If the function does not exist then a numerical sort on the attribute
    #value is performed. 
    #   portsorted=rrsort("SRV","port",rr_array)
    #
    #If the attribute does not exist for a certain RR than the RRs are
    #sorted on string comparrisson of the rdata.
    #
    #If the attribute is not defined than either the default_sort function
    #will be defined or "Canonical sorting" (as defined by DNSSEC) will be
    #used.
    #
    #rrsort() returns a sorted array with only elements of the specified
    #RR type or undef.
    #
    #rrsort() returns undef when arguments are incorrect.
    #--
    def DNS.rrsort(*args)
      rrtype = args[0]
      attribute = args[1]
      rr_array = args[2]
      if (args.length < 2)
        return nil
      elsif (args.length == 2)
        rr_array = attribute
        attribute = nil
      end
      # invalid error type
      return unless (Net::DNS::typesbyname(rrtype.upcase()))
      if (rr_array == nil)
        rr_array = Array.new
      end
      
      # attribute is empty or not specified.    
      if( attribute=~/^Net::DNS::RR::.*/)
        # push the attribute back on the array.
        rr_array.push(attribute)
        attribute=nil
      end
      
      extracted_rr=[]
      rr_array.each do |rr|
        extracted_rr.push(rr) if ((rr.type.upcase) == rrtype.upcase)
      end
      return () unless  extracted_rr.size() > 0
      
      proc = ((Net::DNS::RR.const_get(rrtype)).new).get_rrsort_func(attribute)
      sorted = extracted_rr.sort{ |a,b| proc.call(a,b)}
      
      return sorted; 
      
    end
    
  end
end
