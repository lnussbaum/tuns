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

require 'Net/DNS/Packet'
require 'Net/DNS/Update'
require 'Net/DNS/Header'
require 'Net/DNS/RR'
require 'Net/DNS/Question'
require 'socket'
require 'timeout'
require 'rbconfig'

module Net
  module DNS
    #= NAME
    #
    #Net::DNS::Resolver - DNS resolver class
    #
    #= SYNOPSIS
    #
    #  require 'Net\DNS'
    #  
    #  res = Net::DNS::Resolver.new
    #  
    #  # Perform a lookup, using the searchlist if appropriate.
    #  answer = res.search('example.com')
    #  
    #  # Perform a lookup, without the searchlist
    #  answer = res.query('example.com', 'MX')
    #  
    #  # Perform a lookup, without pre or post-processing
    #  answer = res.send('example.com', 'MX', 'CH')
    #  
    #  # Send a prebuilt packet
    #  answer = res.send(packet)
    #  
    #= DESCRIPTION
    #
    #Instances of the Net::DNS::Resolver class represent resolver objects.
    #A program can have multiple resolver objects, each maintaining its
    #own state information such as the nameservers to be queried, whether
    #recursion is desired, etc.
    #
    #
    #=head1 IPv6 transport
    #
    #The Net::DNS::Resolver library will use IPv6 transport if the
    #transport is available
    #and the address the server tries to connect to is an IPv6 address.
    #
    #The print() will method will report if IPv6 transport is available.
    #
    #You can use the force_v4() method with a non-zero argument
    #to force IPv4 transport.
    #
    #The nameserver() method has IPv6 dependend behavior. If IPv6 is not
    #available or IPv4 transport has been forced the nameserver() method
    #will only return IPv4 addresses.
    #
    #For example
    #
    #    res.nameservers=('192.168.1.1', '192.168.2.2', '2001:610:240:0:53:0:0:3')
    #    res.force_v4=(true)
    #    print res.nameservers.join(" "))
    #
    #Will print: 192.168.1.1 192.168.2.2
    #
    #= ENVIRONMENT
    #
    #The following environment variables can also be used to configure
    #the resolver:
    #
    #= RES_NAMESERVERS
    #
    #    # Bourne Shell
    #    RES_NAMESERVERS="192.168.1.1 192.168.2.2 192.168.3.3"
    #    export RES_NAMESERVERS
    #
    #    # C Shell
    #    setenv RES_NAMESERVERS "192.168.1.1 192.168.2.2 192.168.3.3"
    #
    #A space-separated list of nameservers to query.
    #
    #= RES_SEARCHLIST
    #
    #    # Bourne Shell
    #    RES_SEARCHLIST="example.com sub1.example.com sub2.example.com"
    #    export RES_SEARCHLIST
    #
    #    # C Shell
    #    setenv RES_SEARCHLIST "example.com sub1.example.com sub2.example.com"
    #
    #A space-separated list of domains to put in the search list.
    #
    #= LOCALDOMAIN
    #
    #    # Bourne Shell
    #    LOCALDOMAIN=example.com
    #    export LOCALDOMAIN
    #
    #    # C Shell
    #    setenv LOCALDOMAIN example.com
    #
    #The default domain.
    #
    #= RES_OPTIONS
    #
    #    # Bourne Shell
    #    RES_OPTIONS="retrans:3 retry:2 debug"
    #    export RES_OPTIONS
    #
    #    # C Shell
    #    setenv RES_OPTIONS "retrans:3 retry:2 debug"
    #
    #A space-separated list of resolver options to set.  Options that
    #take values are specified as *option*:*value*.
    #
    #= BUGS
    #
    #Error reporting and handling needs to be improved.
    #
    #The current implementation supports TSIG only on outgoing packets.
    #No validation of server replies is performed.
    #
    #Asynchronous send not implemented.
    #
    #Non-blocking version?
    #
    #Windows configuration not implemented
    #
    #= COPYRIGHT
    #
    #Copyright (c) 1997-2002 Michael Fuhr. 
    #
    #Portions Copyright (c) 2002-2004 Chris Reinhardt.
    #
    #Portions Copyright (c) 2005 Olaf M. Kolkman, NLnet Labs.
    #
    #Ruby version Copyright (c) 2006 AlexD, Nominet UK
    #
    #All rights reserved.  This program is free software; you may redistribute
    #it and/or modify it under the same terms as Perl itself.
    #
    #= SEE ALSO
    #
    #Net::DNS, Net::DNS::Packet, Net::DNS::Update,
    #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
    #RFC 1035, RFC 1034 Section 4.3.5
    class Resolver
      
      # @TODO@ should get config working on Windows
      os = Config::CONFIG['host_os'] # e.g. "mswin32"
      if (os=='mswin32')
        # Should we print a warning here? We don't *really* need the file...
        #        print "WARNING: You must have \\etc\\resolv.conf for Net::DNS to work correctly\n"
      end
      # /etc/resolv.conf required
      
      #The nameservers to be queried.
      #
      #    nameservers = res.nameservers
      #    res.nameservers=('192.168.1.1', '192.168.2.2', '192.168.3.3')
      attr_reader :nameservers
      
      #Returns the size in bytes of the last answer we received in
      #response to a query.
      #
      #
      #    print 'size of last answer: ', res.answersize, "\n"
      #
      attr_reader :answersize
      
      #The IP address from which we received the last answer in
      #response to a query.
      #
      #
      #    print 'last answer was from: ', res.answerfrom, "\n"
      #
      attr_reader :answerfrom
      
      #Returns a string containing the status of the most recent query.
      #
      #
      #    print 'query status: ', res.errorstring, "\n"
      #
      attr_reader :errorstring
      
      attr_reader :tsig_rr, :querytime, :axfr_sel,
      :set, :axfr_rr, :axfr_soa_count, :sockets
      
      #Enabled DNSSEC this will set the checking disabled flag in the query header
      #and add EDNS0 data as in RFC2671 and RFC3225
      #
      #When set to true the answer and additional section of queries from
      #secured zones will contain DNSKEY, NSEC and RRSIG records.
      #
      #Setting calling the dnssec method with a non-zero value will set the
      #UDP packet size to the default value of 2048. If that is to small or
      #to big for your environement you should call the udppacketsize=()
      #method immeditatly after.
      #
      #   res.dnssec=(1)    # turns on DNSSEC and sets udp packetsize to 2048
      #   res.udppacketsize=(1028)   # lowers the UDP pakcet size
      #
      #The method will Croak::croak with the message "You called the
      #Net::DNS::Resolver::dnssec() method but do not have Net::DNS::SEC
      #installed at ..." if you call it without Net::DNS::SEC being in your
      #@INC path.
      #
      #
      #    print "dnssec flag: ", res.dnssec, "\n"
      #    res.dnssec=(0)
      #
      attr_reader :dnssec
      
      #The CD bit for a dnssec query.  This bit is always zero
      #for non dnssec queries. When the dnssec is enabled the flag can be set
      #to 1.
      #
      #
      #    print "checking disabled flag: ", res.dnssec, "\n"
      #    res.dnssec=(1)
      #    res.cdflag=(1)
      #
      attr_reader :cdflag
      
      
      #udppacketsize will set or get the packet size. If set to a value greater than 
      #Net::DNS::PACKETSZ an EDNS extension will be added indicating suppport for MTU path 
      #recovery.
      #
      #Default udppacketsize is Net::DNS::PACKETSZ (512)
      #
      #    print "udppacketsize: ", res.udppacketsize, "\n"
      #    res.udppacketsize=(2048)
      #
      attr_reader :udppacketsize
      
      #Gets or sets the resolver search list.
      #
      #    searchlist = res.searchlist
      #    res.searchlist=('example.com', 'a.example.com', 'b.example.com')
      attr_accessor :searchlist
      
      
      #The port to which we send queries.  This can be useful
      #for testing a nameserver running on a non-standard port.  The
      #default is port 53.
      #
      #
      #    print 'sending queries to port ', res.port, "\n"
      #    res.port=(9732)
      attr_accessor :port
      
      #The port from which we send queries.  The default is 0,
      #meaning any port.
      #
      #
      #    print 'sending queries from port ', res.srcport, "\n"
      #    res.srcport=(5353)
      #
      attr_accessor :srcport 
      
      #The source address from which we send queries.  Convenient
      #for forcing queries out a specific interfaces on a multi-homed host.
      #The default is 0.0.0.0, meaning any local address.
      #
      #
      #    print 'sending queries from address ', res.srcaddr, "\n"
      #    res.srcaddr=('192.168.1.1')
      #
      attr_accessor :srcaddr
      
      #The persistent TCP setting.  If set to true, Net::DNS
      #will keep a TCP socket open for each host:port to which it connects.
      #This is useful if you're using TCP and need to make a lot of queries
      #or updates to the same nameserver.
      #
      #This option defaults to false unless you're running under a
      #SOCKSified Perl, in which case it defaults to true.
      #
      #
      #    print 'Persistent TCP flag: ', res.persistent_tcp, "\n"
      #    res.persistent_tcp=(1)
      #
      attr_accessor :persistent_tcp
      
      #The persistent UDP setting.  If set to true, Net::DNS
      #will keep a single UDP socket open for all queries.
      #This is useful if you're using UDP and need to make a lot of queries
      #or updates.
      #
      #
      #    print 'Persistent UDP flag: ', res.persistent_udp, "\n"
      #    res.persistent_udp=(1);
      #
      attr_accessor :persistent_udp
      
      #The TCP timeout in seconds.  A timeout of nil means
      #indefinite.  The default is 120 seconds (2 minutes).
      #
      #
      #    print 'TCP timeout: ', res.tcp_timeout, "\n"
      #    res.tcp_timeout=(10)
      #
      attr_accessor :tcp_timeout
      
      #The UDP timeout in seconds.  A timeout of nil means
      #the retry and retrans settings will be just utilized to perform the
      #retries until they are exhausted.  The default is nil.
      #
      #
      #    print 'UDP timeout: ', res.udp_timeout, "\n"
      #    res.udp_timeout=(10)
      #
      attr_accessor :udp_timeout
      
      #The recursion flag.  If this is true, nameservers will
      #be requested to perform a recursive query.  The default is true.
      #
      #
      #    print 'recursion flag: ', res.recurse, "\n"
      #    res.recurse=(0)
      #
      attr_accessor :recurse
      
      #The defnames flag.  If this is true, calls to query() will
      #append the default domain to names that contain no dots.  The default
      #is true.
      #
      #
      #    print 'defnames flag: ', res.defnames, "\n"
      #    res.defnames=(0)
      #
      attr_accessor :defnames
      
      #Get or set the usevc flag.  If true, then queries will be performed
      #using virtual circuits (TCP) instead of datagrams (UDP).  The default
      #is false.
      #
      #    print 'usevc flag: ', res.usevc, "\n"
      #    res.usevc=(1)
      #
      attr_accessor :usevc
      
      #The igntc flag.  If true, truncated packets will be
      #ignored.  If false, truncated packets will cause the query to
      #be retried using TCP.  The default is false.
      #
      #
      #    print 'igntc flag: ', res.igntc, "\n"
      #    res.igntc=(1)
      #
      attr_accessor :igntc
      
      #The retransmission interval.  The default is 5.
      #
      #    print 'retrans interval: ', res.retrans, "\n"
      #    res.retrans=(3)
      #
      attr_accessor :retrans
      
      #The dnsrch flag.  If this is true, calls to search will
      #apply the search list.  The default is true.
      #
      #    print 'dnsrch flag: ', res.dnsrch, "\n"
      #    res.dnsrch=(0)
      #
      attr_accessor :dnsrch
      
      #Get or set the debug flag.  If set, calls to search, query,
      #and send will print debugging information on the standard output.
      #The default is false.
      #
      #
      #    print 'debug flag: ', res.debug, "\n"
      #    res.debug=(1)
      #
      attr_accessor :debug
      
      #The number of times to try the query.  The default is 4.
      #
      #
      #    print 'number of tries: ', res.retry, "\n"
      #    res.retry=(2)
      #
      attr_accessor :retry
      
      #Set force_v4 to true to use IPv4 only
      attr_accessor :force_v4
      
      attr_accessor :domain, :stayopen, :ignqrid
      
      DEFAULT_ERROR_STRING = 'unknown error or no error'
      RESOLV_CONF = '/etc/resolv.conf'
      DOTFILE     = '.resolv.conf'
      
      alias_method :send_method,  :send
      
      def set_defaults
        # class defaults
        @nameservers	   = ['127.0.0.1']
        @port		   = 53
        @srcaddr        = '0.0.0.0'
        @srcport        = 0
        @domain	       = ''
        @searchlist	   = []
        @retrans	       = 5
        @retry		   = 4
        @usevc		   = false
        @stayopen       = false
        @igntc          = false
        @recurse        = true
        @defnames       = true
        @dnsrch         = true
        @debug          = false
        @errorstring	   = DEFAULT_ERROR_STRING
        @tsig_rr        = nil
        @answerfrom     = ''
        @answersize     = 0
        @querytime      = nil
        @tcp_timeout    = 120
        @udp_timeout    = nil
        @axfr_sel       = nil
        @axfr_rr        = []
        @axfr_soa_count = 0
        @persistent_tcp = false
        @persistent_udp = false
        @dnssec         = false
        @udppacketsize  = 0  # The actual default is lower bound by Net::DNS::PACKETSZ
        @force_v4       = false # force_v4 is only relevant when we have
        # v6 support available
        @cdflag         = 1  # this is only used when {dnssec} == 1
        @ignqrid        = false  # normally packets with non-matching ID 
        # or with the qr bit of are thrown away
        # in 'ignqrid' these packets are 
        # are accepted.
        # USE WITH CARE, YOU ARE VULNARABLE TO
        # SPOOFING IF SET.
        # This is may be a temporary feature
        
        
        #	# If we're running under a SOCKSified Perl, use TCP instead of UDP
        #	# and keep the sockets open.
        if (@usesocks)
          @usevc = true
          @persistent_tcp = true
        end
      end
      
      #  # Use the system defaults
      #  res = Net::DNS::Resolver.new
      #  
      #  # Use my own configuration file
      #  res = Net::DNS::Resolver.new('config_file' => '/my/dns.conf')
      #  
      #  # Set options in the constructor
      #  res = Net::DNS::Resolver.new(
      #  	nameservers => ['10.1.1.128', '10.1.2.128'],
      #  	recurse     => 0,
      #  	debug       => 1)
      #
      #Returns a resolver object.  If given no arguments, new() returns an
      #object configured to your system's defaults.  On UNIX systems the 
      #defaults are read from the following files, in the order indicated:
      #
      #    /etc/resolv.conf
      #    $HOME/.resolv.conf
      #    ./.resolv.conf
      #
      #The following keywords are recognized in resolver configuration files:
      #
      #* domain - The default domain.
      #
      #* search - A space-separated list of domains to put in the search list.
      #
      #* nameserver - A space-separated list of nameservers to query.
      #
      #Files except for /etc/resolv.conf must be owned by the effective
      #userid running the program or they won't be read.  In addition, several
      #environment variables can also contain configuration information; see
      #ENVIRONMENT.
      #
      #On Windows systems, an attempt is made to determine the system defaults
      #using the registry.  This is still a work in progress; systems with many
      #dynamically configured network interfaces may confuse Net::DNS.
      #
      #You can include a configuration file of your own when creating a
      #resolver object:
      #
      # # Use my own configuration file 
      # res = Net::DNS::Resolver.new("config_file" => '/my/dns.conf')
      #
      #This is supported on both UNIX and Windows.  Values pulled from a custom
      #configuration file override the the system's defaults, but can still be
      #overridden by the other arguments to new().
      #
      #Explicit arguments to new override both the system's defaults and the
      #values of the custom configuration file, if any.  The following
      #arguments to new() are supported:
      #
      #* nameservers - An array reference of nameservers to query.  
      #
      #* searchlist - An array reference of domains.
      #
      #* recurse
      #
      #* debug
      #
      #* domain
      #
      #* port
      #
      #* srcaddr
      #
      #* srcport
      #
      #* tcp_timeout
      #
      #* udp_timeout
      #
      #* retrans
      #
      #* retry
      #
      #* usevc
      #
      #* stayopen
      #
      #* igntc
      #
      #* defnames
      #
      #* dnsrch
      #
      #* persistent_tcp
      #
      #* persistent_udp
      #
      #* dnssec
      def initialize(*input_args)       
        @sockets=Hash.new
        @sockets['AF_INET']=Hash.new
        @sockets['AF_INET6']= Hash.new
        @sockets['AF_UNSPEC']=Hash.new
        
        set_defaults  
        
        config_path=[]
        config_path.push(ENV['HOME']) if ENV['HOME']
        config_path.push('.')
        
        begin
          read_config_file(RESOLV_CONF) # if -f Resolv_conf && -r _
          
          #	foreach my $dir (@config_path)
          config_path.each do |dir|
            file = "#{dir}/#{DOTFILE}"
            read_config_file(file) # if -f file && -r _ && -o _
          end
        rescue Exception
          # Don't worry if we couldn't find one of these files
        end
        
        read_env
        
        if (input_args.size > 0)
          if (!(input_args[0].instance_of?(Hash)))	
            raise ArgumentError, "Expecting input Hash"
          end
          args=Hash.new
          input_args[0].keys.each do |key|
            args[key] = input_args[0][key]
          end
          if (args[:config_file])
            read_config_file(args[:config_file])
          end
          
          args.keys.each do |attr|
            
            if (attr == :nameservers || attr == :searchlist)
              if (args[attr]==nil ||  !(args[attr].instance_of?(Array)))
                raise ArgumentError, "Net::DNS::Resolver.new(): #{attr} must be an Array\n"			  
              end
            end
            
            if (attr == :nameservers)
              @nameservers=(args[attr])
            else
              begin
                send_method(attr.to_s+"=", args[attr])
              rescue Exception
                print "Argument #{attr} not valid\n" 
              end
            end
          end
        end
      end
      
      def read_env
        if ENV['RES_NAMESERVERS']
          @nameservers = ENV['RES_NAMESERVERS'].split(" ")
        end
        
        if ENV['RES_SEARCHLIST']
          @searchlist = ENV['RES_SEARCHLIST'].split(" ")
        end
        
        if ENV['LOCALDOMAIN']
          @domain = ENV['LOCALDOMAIN']
        end
        
        if ENV['RES_OPTIONS']
          ENV['RES_OPTIONS'].split(" ").each do |opt|
            name,val = opt.split(":")
            if (val != nil && val.length == 1)
              if val[0]>=48 && val[0]<=57
                val = val[0]-48
              end
            end
            val = 1 if val == nil
            #            if (name == "retry")
            #              name = "retrytime"
            #            end
            begin
              send_method(name+"=", val)
            rescue Exception
              print "Argument #{name} not valid\n"
            end
          end
        end
      end      
      
      def read_config_file(conf_file)
        ns=[]
        searchlist=[]
        if !(File.exist? conf_file)
          if (/java/ =~ RUBY_PLATFORM && !(conf_file=~/:/))
            # Problem with paths and Windows on JRuby - see if we can munge the drive...
            wd = Dir.getwd
            drive = wd.split(':')[0]
            if (drive.length==1)
              conf_file = drive << ":" << conf_file
            end
          end
        end
        IO.foreach(conf_file) do |line|
          line.gsub!(/\s*[;#].*/,"")
          next unless line =~ /\S/
          case line
          when /^\s*domain\s+(\S+)/
            @domain = $1
          when /^\s*search\s+(.*)/
            @searchlist = $1.split(" ")
          when /^\s*nameserver\s+(.*)/
            @nameservers = []
            #              if @nameservers.length == 1 && @nameservers[0]=='127.0.0.1'
            #                @nameservers=[]
            #              end
            $1.split(" ").each do |ns|
              ns = "0.0.0.0" if ns == "0"
              next if ns =~ /:/ # skip IPv6 addresses
              @nameservers.push(ns)
            end
          end
        end
      end
      
      #Returns a string representation of the resolver state.
      def inspect
        timeout = defined?@tcp_timeout ? @tcp_timeout : 'indefinite';
        hasINET6line= " (IPv6 Transport is available)"
        ignqrid=@ignqrid ? "\n;; ACCEPTING ALL PACKETS (IGNQRID)" : "";
        return ";\
;; RESOLVER state:\
;;  domain       = #{@domain}\
;;  searchlist   = #{@searchlist}}\
;;  nameservers  = #{@nameservers}\
;;  port         = #{@port}\
;;  srcport      = #{@srcport}\
;;  srcaddr      = #{@srcaddr}\
;;  tcp_timeout  = #{timeout}\
;;  retrans  = #{@retrans}  retry    = #{@retry}\
;;  usevc    = #{@usevc}  stayopen = #{@stayopen}    igntc = #{@igntc}\
;;  defnames = #{@defnames}  dnsrch   = #{dnsrch}\
;;  recurse  = #{@recurse}  debug    = #{debug}\
;;  force_v4 = #{@force_v4} #{hasINET6line} #{ignqrid}
"
      end
      
      #      def nameservers=(*args)
      #        if (args)
      #          a = []
      #          args.each do |ns|
      #            if (ns =~ /^(\d+(:?\.\d+){0,3})$/)
      #              #              if ( ip_is_ipv4(ns) )
      #              #                push @a, ($1 == '0') ? '0.0.0.0' : $1;
      #              a.push(($1 == '0') ? '0.0.0.0' : $1) 
      #              #              end
      #              #            elsif ( ip_is_ipv6(ns) )
      #              #              a.push( (ns == '0') ? '::0' : ns)
      #              #            end              
      
      
      def nameservers=(arg)
        if arg.is_a?String
          arr = arg.split(" ")
        elsif arg.is_a?Array
          arr = arg
        else
          raise ArgumentError, "Argument must be String or Array"
        end
        
        a = []
        arr.each do |ns|
          if ns =~ /^(\d+(:?\.\d+){0,3})$/ # Dotted decimal or IPv6 format
            if $1 == 0
              a.push("0.0.0.0")
            else
              a.push($1)
            end
          else
            not_ip = false
            begin
              if IPAddr.new(ns).ipv6?
                a.push((ns == '0') ? '::0' : ns)
              end
            rescue ArgumentError
              not_ip = true
            end
            if (not_ip)
              
              defres = Net::DNS::Resolver.new;
              names=[]
              
              if (ns !~ /\./)
                if (defres.searchlist.size > 0)
                  #                  names = map { ns + '.' + $_ }
                  names = defres.searchlist.map( ns + '.' + $_)
                elsif (defres.domain!="")
                  names = [(ns + '.' + defres.domain)]
                end
              else
                names = [ns]
              end
              
              packet = defres.search(ns);
              @errorstring=(defres.errorstring);
              if (packet!=nil)
                a+=(cname_addr(names, packet))
              end
            end
          end
        end
        
        @nameservers = a
        #        end
      end
      
      def nameservers
        returnval=[]
        @nameservers.each do |ns|
          begin
            next if IPAddr.new(ns).ipv6? && (@force_v4)
          rescue ArgumentError
          end
          returnval.push(ns)
        end
        return returnval
      end
      
      alias :nameserver :nameservers
      alias :nameserver= :nameservers=
      
      def cname_addr(names, packet)
        addr=[]
        
        oct2 = '(?:2[0-4]\d|25[0-5]|[0-1]?\d\d|\d)';
        
        packet.answer.each do |rr|
          if (names.index(rr.name) != nil)
            if (rr.type == 'CNAME')
              names.push(rr.cname)
            elsif (rr.type == 'A')
              if (rr.address =~ /^(#{oct2}\.#{oct2}\.#{oct2}\.#{oct2})$/o)
                addr.push($1)
              end
            end
          end
        end            
        return addr;
      end
      
      # if (@udppacketsize  > Net::DNS::PACKETSZ() 
      # then we use EDNS and @udppacketsize
      # should be taken as the maximum packet_data length
      def _packetsz
        ret = (@udppacketsize > Net::DNS::PACKETSZ ? @udppacketsize : Net::DNS::PACKETSZ) 
        return ret
      end
      
      def _reset_errorstring
        @errorstring = DEFAULT_ERROR_STRING;
      end
      
      #Performs a DNS query for the given name, applying the searchlist
      #if appropriate.  The search algorithm is as follows:
      #
      #* If the name contains at least one dot, try it as is.
      #
      #* If the name doesn't end in a dot then append each item in
      #  the search list to the name.  This is only done if dnsrch
      #  is true.
      #
      #* If the name doesn't contain any dots, try it as is.
      #
      #The record type and class can be omitted; they default to A and
      #IN.  If the name looks like an IP address (4 dot-separated numbers),
      #then an appropriate PTR query will be performed.
      #
      #Returns a Net::DNS::Packet object, or nil if no answers were
      #found.  If you need to examine the response packet whether it contains
      #any answers or not, use the send() method instead.
      #
      #    packet = res.search('mailhost')
      #    packet = res.search('mailhost.example.com')
      #    packet = res.search('192.168.1.1')
      #    packet = res.search('example.com', 'MX')
      #    packet = res.search('user.passwd.example.com', 'TXT', 'HS')
      def search(*args)
        name = args[0]
        type = 'A'
        klass = "IN"
        if args.length >1
          type = args[1]
          if args.length > 2
            klass = args[2]
          end
        end
        ans=""
        
        # If the name looks like an IP address then do an appropriate
        # PTR query.
        if (name =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
          name = "#{$4}.#{$3}.#{$2}.#{$1}.in-addr.arpa.";
          type = 'PTR';
        end
        
        # pass IPv6 addresses right to query()
        if (name.index(':')!=nil and name.index('.')==nil)
          return query(name);
        end
        
        # If the name contains at least one dot then try it as is first.
        if (name.index('.') != nil)
          print ";; search(#{name}, #{type}, #{klass})\n" if @debug
          ans = query(name, type, klass)
          return ans if ans!=nil and ans.header.ancount > 0
        end
        
        # If the name doesn't end in a dot then apply the search list.
        if ((name !~ /\.$/) && @dnsrch)
          #		foreach my $domain (@{$self->{'searchlist'}}) {
          @searchlist.each do |domain|
            newname = "#{name}.#{domain}"
            print ";; search(#{newname}, #{type}, #{klass})\n" if @debug
            ans = query(newname, type, klass)
            return ans if ans!=nil and ans.header.ancount > 0
          end
        end
        
        # Finally, if the name has no dots then try it as is.
        if (name.index('.')==nil)
          print ";; search(#{name}, #{type}, #{klass})\n" if @debug
          ans = query("#{name}.", type, klass)
          return ans if ans!=nil and ans.header.ancount > 0
        end
        
        # No answer was found.
        return nil;
      end
      
      #Performs a DNS query for the given name; the search list is not
      #applied.  If the name doesn't contain any dots and defnames
      #is true then the default domain will be appended.
      #
      #The record type and class can be omitted; they default to A and
      #IN.  If the name looks like an IP address (IPv4 or IPv6),
      #then an appropriate PTR query will be performed.
      #
      #Returns a Net::DNS::Packet object, or nil if no answers were
      #found.  If you need to examine the response packet whether it contains
      #any answers or not, use the send() method instead.
      #
      #    packet = res.query('mailhost')
      #    packet = res.query('mailhost.example.com')
      #    packet = res.query('192.168.1.1')
      #    packet = res.query('example.com', 'MX')
      #    packet = res.query('user.passwd.example.com', 'TXT', 'HS')
      def query(*args)
        name = args[0]
        type  = 'A';
        klass = 'IN';
        if (args.length > 1) 
          type = args[1]
          if (args.length > 2)
            klass = args[2]
          end
        end
        
        # If the name doesn't contain any dots then append the default domain.
        if ((name.index('.')==nil) && (name.index(':')==nil) && @defnames!=nil)
          name += ".#{@domain}";
        end
        
        # If the name looks like an IP address then do an appropriate
        # PTR query.
        if (name =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
          name = "#{$4}.#{$3}.#{$2}.#{$1}.in-addr.arpa";
          type = 'PTR';
        end
        
        # IPv4 address in IPv6 format (very lax regex)
        if (name =~ /^[0:]*:ffff:(\d+)\.(\d+)\.(\d+)\.(\d+)$/i)
          name = "#{$4}.#{$3}.#{$2}.#{$1}.in-addr.arpa";
          type = 'PTR';
        end
        
        # if the name looks like an IPv6 0-compressed IP address then expand
        # PTR query. (eg 2001:5c0:0:1::2)
        if (name =~ /::/)
          # avoid stupid "Use of implicit split to @_ is deprecated" warning
          while ((parts = name.split(/:/)).length < 8) do
            name.sub!(/::/, ":0::")
          end
          name.sub!(/::/, ":0:")
        end
        
        # if the name looks like an IPv6 address then do appropriate
        # PTR query. (eg 2001:5c0:0:1:0:0:0:2)
        if (name =~ /:/)
          stuff = name.split(/:/)
          if (stuff.length == 8)
            name = 'ip6.arpa.'
            type = 'PTR'
            stuff.each do |segment|
              segment = sprintf("%04s", segment)
              segment.gsub!(/ /, "0")
              segment =~ /(.)(.)(.)(.)/
              name = "#{$4}.#{$3}.#{$2}.#{$1}.#{name}"
            end
          else
            # no idea what this is
          end
        end
        
        print ";; query(#{name}, #{type}, #{klass})\n" if @debug;
        packet = Net::DNS::Packet.new_from_values(name, type, klass);
        
        ans = send(packet);
        
        #        return (ans && ans.header.ancount)   ? ans : nil;
        return ans
      end
      
      #Performs a DNS query for the given name.  Neither the searchlist
      #nor the default domain will be appended.  
      #
      #The argument list can be either a Net::DNS::Packet object or a list
      #of strings.  The record type and class can be omitted; they default to
      #A and IN.  If the name looks like an IP address (Ipv4 or IPv6),
      #then an appropriate PTR query will be performed.
      #
      #Returns a Net::DNS::Packet object whether there were any answers or not.
      #Use packet.header.ancount or packet.answer to find out
      #if there were any records in the answer section.  Returns nil if there
      #was an error.
      #
      #    packet = res.send(packet_object)
      #    packet = res.send('mailhost.example.com')
      #    packet = res.send('example.com', 'MX')
      #    packet = res.send('user.passwd.example.com', 'TXT', 'HS')
      def send(*args)
        packet = make_query_packet(args);
        packet_data = packet.data;
        
        
        ans = ""
        
        if (@usevc || packet_data.length > _packetsz)
          
          ans = send_tcp(packet, packet_data);
          
        else
          ans = send_udp(packet, packet_data);
          if (ans!=nil && !(!ans.header.tc || ans.header.tc == 0) && !@igntc)
            print ";;\n;; packet truncated: retrying using TCP\n" if @debug;
            ans = send_tcp(packet, packet_data);
          end
        end
        
        return ans;
      end
      
      def send_tcp(packet, packet_data)
        lastanswer=""
        
        srcport = @srcport
        srcaddr = @srcaddr
        dstport = @port
        
        if ( @nameservers==nil)
          @errorstring=('no nameservers')
          print ";; ERROR: send_tcp: no nameservers\n" if @debug
          return;
        end
        
        _reset_errorstring
        
        
        #      NAMESERVER: foreach my $ns ($self->nameservers()) {
        @nameservers.each do |ns|	      
          print ";; attempt to send_tcp(#{ns}:#{dstport}) (src port = #{srcport})\n" if @debug
          
          sock=""
          sock_key = "#{ns}:#{dstport}";
          host,port=""
          if (@persistent_tcp && @sockets['AF_UNSPEC'][sock_key])
            sock = @sockets['AF_UNSPEC'][sock_key];
            print ";; using persistent socket\n" if @debug
          else
            sock= _create_tcp_socket(ns)
            next unless sock!=nil
            
            @sockets['AF_UNSPEC'][sock_key] = sock if @persistent_tcp
          end
          
          
          lenmsg = [packet_data.length].pack('n')
          print ';; sending ' + packet_data.length.to_s + " bytes\n" if @debug
          
          # note that we send the length and packet data in a single call
          # as this produces a single TCP packet rather than two. This
          # is more efficient and also makes things much nicer for sniffers.
          # (ethereal doesn't seem to reassemble DNS over TCP correctly)
          
          
          if (!sock.send( lenmsg + packet_data,0))
            @errorstring=($!)
            print ";; ERROR: send_tcp: data send failed: #{@errorstring}\n" if @debug
            next
          end
          
          begin
            Timeout::timeout(@tcp_timeout) {
              buf, from = read_tcp(sock, Net::DNS::INT16SZ, @debug)
              
              next unless buf.length # Failure to get anything
              len = buf.unpack('n')[0]
              next unless len         # Cannot determine size
              
              buf, from = read_tcp(sock, len, @debug)
              
              @answerfrom=(from[2])
              @answersize=(buf.length)
              
              print ';; received ' + buf.length.to_s + " bytes\n" if @debug
              
              unless (buf.length == len)
                @errorstring=("expected #{len} bytes, received " + buf.length)
                next
              end
              
              ans, err = Net::DNS::Packet.new_from_binary(buf, @debug)
              if (ans!=nil)
                @errorstring=(ans.header.rcode)
                ans.answerfrom=(@answerfrom)
                ans.answersize=(@answersize)
                
                if (ans.header.rcode != "NOERROR" && ans.header.rcode != "NXDOMAIN")
                  # Remove this one from the stack
                  print "RCODE: " + ans.header.rcode + "; trying next nameserver\n" if @debug
                  lastanswer=ans
                  next
                end
              elsif (err!=nil)
                @errorstring=(err)
              end
              return ans
            }
          rescue Timeout::Error => e
            @errorstring=('Timeout: #{e.message}')
            next
          ensure
            if (!@persistent_tcp)
              sock.close()
            end
          end
        end
        
        #          sel = IO::Select.new(sock)
        #          timeout=@tcp_timeout
        #          if (sel.can_read(timeout))
        #            buf = read_tcp(sock, Net::DNS::INT16SZ, @debug)
        #            next unless buf.length # Failure to get anything
        #            len = buf.unpack('n')[0]
        #            next unless len         # Cannot determine size
        #            
        #            unless (sel.can_read(timeout))
        #              @errorstring=('timeout')
        #              print ";; TIMEOUT\n" if @debug
        #              next
        #            end
        #            
        #            buf = read_tcp(sock, len, @debug)
        #            
        #            answerfrom(sock.peerhost)
        #            answersize(buf.length)
        #            
        #            print ';; received ' + buf.length + " bytes\n" if @debug
        #            
        #            unless (buf.length == len)
        #              @errorstring=("expected #{len} bytes, received " + buf.length)
        #              next
        #            end
        #            
        #            ans, err = Net::DNS::Packet.new_from_data(buf, @debug)
        #            if (ans!=nil)
        #              @errorstring=(ans.header.rcode)
        #              ans.answerfrom=(@answerfrom)
        #              ans.answersize=(@answersize)
        #              
        #              if (ans.header.rcode != "NOERROR" && ans.header.rcode != "NXDOMAIN")
        #                # Remove this one from the stack
        #                print "RCODE: " + ans.header.rcode + "; trying next nameserver\n" if @debug
        #                lastanswer=ans
        #                next
        #              end
        #            elsif (err!=nil)
        #              @errorstring=(err)
        #            end
        #            return ans
        #          else
        #            @errorstring=('timeout')
        #            next
        #          end
        #        end
        
        if (lastanswer!="")
          @errorstring=(lastanswer.header.rcode)
          return lastanswer
        end
        
        return
      end
      
      def send_udp(packet, packet_data)
        retrans = @retrans
        timeout = retrans
        
        lastanswer=""
        
        stop_time = Time.now + @udp_timeout if (@udp_timeout && @udp_timeout > 0)
        
        _reset_errorstring;
        
        ns=[]
        dstport = @port
        srcport = @srcport
        srcaddr = @srcaddr
        
        sock=Hash.new
        
        if (@persistent_udp)
          if ( (@sockets['AF_INET6']['UDP'])!=nil)
            sock[AF_INET6] = @sockets['AF_INET6']['UDP']
            print ";; using persistent AF_INET6 family type socket\n" if @debug
          end
          if ( (@sockets['AF_INET']['UDP'])!=nil)
            sock['AF_INET'] = @sockets['AF_INET']['UDP'];
            print ";; using persistent AF_INET() family type socket\n" if @debug
          end
        end
        
        if (! @force_v4 && @sockets['AF_INET6']==nil )
          
          
          # '::' Otherwise the INET6 socket will fail.
          
          srcaddr6 = srcaddr == '0.0.0.0' ? '::' : srcaddr
          
          print ";; Trying to set up a AF_INET6 family type UDP socket with srcaddr: #{srcaddr} ... " if @debug
          
          
          # IO::Socket carps on errors if Perl's -w flag is turned on.
          # Uncomment the next two lines and the line following the "new"
          # call to turn off these messages.
          
          #my $old_wflag = $^W;
          #$^W = 0;
          
          sock['AF_INET6'] = UDPSocket.new
          sock['AF_INET6'].bind(srcaddr6, srcport)
          print(sock['AF_INET6']!=nil ? "done\n":"failed\n") if @debug
        end
        
        # Always set up an AF_INET socket. 
        # It will be used if the address familly of for the endpoint is V4.
        
        if (sock['AF_INET']==nil)
          print ";; setting up an AF_INET() family type UDP socket\n" if @debug
          
          sock['AF_INET'] = UDPSocket.new()
          sock['AF_INET'].bind(srcaddr, srcport)
        end
        
        
        
        unless (sock['AF_INET']!=nil || sock['AF_INET6']!=nil)
          
          @errorstring=("could not get socket")
          return;
        end
        
        @sockets['AF_INET']['UDP'] = sock['AF_INET'] if (@persistent_udp) && sock != nil
        @sockets['AF_INET6']['UDP'] = sock['AF_INET6'] if persistent_udp && (sock['AF_INET6']!=nil) && ! @force_v4
        
        # Constructing an array of arrays that contain 3 elements: The
        # nameserver IP address, its sockaddr and the sockfamily for
        # which the sockaddr structure is constructed.
        
        nmbrnsfailed=0;
        #        #        NSADDRESS: foreach my $ns_address ($self->nameservers()){
        #        #      NSADDRESS: @nameservers.each do |ns_address|
        @nameservers.each do |ns_address|
          # The logic below determines the $dst_sockaddr.
          # If getaddrinfo is available that is used for both INET4 and INET6
          # If getaddrinfo is not avialable (Socket6 failed to load) we revert
          # to the 'classic mechanism
          
          # we can use getaddrinfo
          #              no strict 'subs';   # Because of the eval statement in the BEGIN
          # AI_NUMERICHOST is not available at compile time.
          # The AI_NUMERICHOST surpresses lookups.
          
          if (IPAddr.new(ns_address).ipv6? && @force_v4)
            next
          end
          begin
            res = Socket::getaddrinfo(ns_address, dstport)[0] # , Socket::AF_UNSPEC, Socket::SOCK_DGRAM, 
            # 0, Socket::AI_NUMERICHOST)[0]
            
            
            sockfamily = res[0]
            socktype_tmp = res[1]
            proto_tmp = res[2]
            dst_sockaddr = res[3]
            canonname_tmp = res[4]
            
          rescue SocketError
            #            if (res.length < 5)
            raise RuntimeError, ('can\'t resolve ' + ns_address + ' to address')
          end
          
          ns.push([ns_address,dst_sockaddr,sockfamily])
        end   
        
        if (nameservers.length == 0)
          print "No nameservers" if @debug;
          @errorstring=('no nameservers');
          return;
        end
        
        
        select = []
        # We allready tested that one of the two socket exists
        
        select.push(sock['AF_INET']) if (sock['AF_INET'] != nil)
        select.push(sock['AF_INET6']) if ((sock['AF_INET6'] != nil) && !@force_v4)
        
        
        # Perform each round of retries.
        #      for (i = 0
        #           i < @retry;
        #        ++i, retrans *= 2, timeout = int(retrans / (ns.length || 1)))
        @retry.times do |i|
          
          if (i>0)         
            retrans *= 2
          end
          i += 1
          timeout = (retrans / (ns.length || 1)).to_int
          
          timeout = 1 if (timeout < 1)
          
          # Try each nameserver.
          #                  NAMESERVER: foreach my $ns (@ns) {
          #          NAMESERVER: ns.each do |nstemp|
          ns.each do |nstemp|
            next if nstemp[3]!=nil
            if (stop_time)
              now = Time.now
              if (stop_time < now)
                @errorstring=('query timed out')
                return;
              end
              if (timeout > 1 && timeout > (stop_time-now))
                timeout = stop_time-now;
              end
            end
            nsname = nstemp[0]
            nsaddr = nstemp[1]
            nssockfamily = nstemp[2]
            
            # If we do not have a socket for the transport
            # we are supposed to reach the namserver on we
            # should skip it.
            unless ((sock[ nssockfamily ])!=nil)
              print "Send error: cannot reach #{nsname} (" +                
               ( (nssockfamily == 'AF_INET6') ? "IPv6" : "" ) +
               ( (nssockfamily == 'AF_INET') ? "IPv4" : "" ) +
        				") not available" if @debug
              
              
              @errorstring=("Send error: cannot reach #{nsname} (" +
               ( (nssockfamily == 'AF_INET6') ? "IPv6" : "" ) +
               ( (nssockfamily == 'AF_INET') ? "IPv4" : "" ) +
        					       ") not available")
              next
            end
            
            print ";; send_udp(#{nsname}:#{dstport})\n" if @debug
            
            unless (sock[nssockfamily].send(packet_data, 0, nsaddr, @port))
              print ";; send error: #{$!}\n" if @debug
              @errorstring=("Send error: #{$!}")
              nmbrnsfailed+=1
              nstemp[3]="Send error" + @errorstring
              next
            end
            
            # See ticket 11931 but this works not quite yet
            oldpacket_timeout=Time.now+timeout
            while ( oldpacket_timeout > Time.now)
              #                      ready = sel.can_read(timeout)
              ready = IO.select(select, nil, nil, timeout)
              if (ready != nil)
                ready = ready[0]
                ready.each do |readytemp|
                  buf = ''
                  
                  if (ret = readytemp.recvfrom(_packetsz))
                    
                    buf = ret[0]
                    from = ret[1]
                    @answerfrom=(from[2])
                    @answersize=(buf.length)
                    
                    print ';; answer from ' + \
                    from[2].inspect +  ':' + \
                    from[3].inspect + ' : ' + \
                    buf.length.inspect + " bytes\n" if @debug
                    
                    ans, err = Net::DNS::Packet.new_from_binary(buf, @debug)
                    
                    if (ans!= nil)
                      next unless ( ans.header.qr || @ignqrid)
                      next unless  ( (ans.header.id == packet.header.id) || @ignqrid )
                      @errorstring=(ans.header.rcode)
                      ans.answerfrom=(@answerfrom)
                      ans.answersize=(@answersize)
                      if (ans.header.rcode != "NOERROR" && ans.header.rcode != "NXDOMAIN")
                        #                      # Remove this one from the stack
                        
                        print "RCODE: " + ans.header.rcode + "; trying next nameserver\n" if @debug
                        nmbrnsfailed+=1
                        nstemp[3]="RCODE: " + ans.header.rcode()
                        lastanswer=ans
                        #                          throw :nameserver
                        break
                      end
                    elsif (err != nil)
                      @errorstring=(err)
                    end
                    
                    return ans
                  else
                    @errorstring=($!)
                    print ';; recv ERROR(' + \
                    readytemp.peerhost + ':' + \
                    readytemp.peerport + '): ' + \
                    @errorstring + "\n" if @debug
                    nstemp[3]="Recv error " + @errorstring
                    nmbrnsfailed+=1
                    # We want to remain in the SELECTOR LOOP...
                    # unless there are no more nameservers
                    return unless (nmbrnsfailed < ns.length)
                    print ';; Number of failed nameservers: #{nmbrnsfailed} out of ' + ns.length + "\n" if @debug
                    
                  end
                end # not ready
              end #SELECTOR LOOP
            end # until stop_time loop
            #           end # :nameserver
          end #NAMESERVER LOOP
        end # retry times
        
        if (lastanswer!="")
          @errorstring=(lastanswer.header.rcode )
          return lastanswer
        end
        if (select.length > 0)
          # If there are valid handles then we have either a timeout or 
          # a send error.
          @errorstring=('query timed out') unless (@errorstring =~ /Send error:/)
        else
          if (nmbrnsfailed < ns.length)
            @errorstring=('Unexpected Error') ;
          else
            @errorstring=('all nameservers failed');
          end
        end
        return
      end
      
      
      #Performs a background DNS query for the given name, i.e., sends a
      #query packet to the first nameserver listed in res.nameservers
      #and returns immediately without waiting for a response.  The program
      #can then perform other tasks while waiting for a response from the 
      #nameserver.
      #
      #The argument list can be either a Net::DNS::Packet object or a list
      #of strings.  The record type and class can be omitted; they default to
      #A and IN.  If the name looks like an IP address (4 dot-separated numbers),
      #then an appropriate PTR query will be performed.
      #
      #Returns an IO::Socket::INET object or nil on error in which
      #case the reason for failure can be found through a call to the
      #errorstring method.
      #
      #The program must determine when the socket is ready for reading and
      #call res.bgread to get the response packet.  You can use 
      #res.bgisready or IO::Select to find out if the socket is ready
      #before reading it.
      #
      #
      #    socket = res.bgsend(packet_object) || die " #{res.errorstring}"
      #
      #    socket = res.bgsend('mailhost.example.com')
      #    socket = res.bgsend('example.com', 'MX')
      #    socket = res.bgsend('user.passwd.example.com', 'TXT', 'HS')
      #
      def bgsend(*args)
        if (@nameservers == nil || @nameservers.length == 0)
          @errorstring=('no nameservers')
          return
        end
        
        _reset_errorstring;
        
        packet = make_query_packet(args);
        packet_data = packet.data;
        
        srcaddr = @srcaddr
        srcport = @srcport
        
        res = []
        dst_sockaddr=""
        ns_address = (@nameservers)[0]
        dstport = @port
        sockfamily=""
        
        # The logic below determines ther $dst_sockaddr.
        # If getaddrinfo is available that is used for both INET4 and INET6
        # If getaddrinfo is not avialable (Socket6 failed to load) we revert
        # to the 'classic mechanism
        
        socktype_tmp=""
        proto_tmp=""
        canonname_tmp=""
        
        begin
          # The AI_NUMERICHOST surpresses lookups.
          res = Socket::getaddrinfo(ns_address, dstport)[0] # , Socket::AF_UNSPEC, 
          # Socket::SOCK_DGRAM, 0 , Socket::AI_NUMERICHOST)[0]
          
          sockfamily = res[0]
          socktype_tmp = res[1]
          proto_tmp = res[2]
          dst_sockaddr = res[3]
          canonname_tmp = res[4]
          
          #          if (res.length < 5)
        rescue SocketError
          raise RuntimeError, "can't resolve \"#{ns_address}\" to address (it could have been an IP address)"
        end
        sock=nil
        
        if (sockfamily == 'AF_INET')
          sock = UDPSocket.new()
          sock.bind(srcaddr, srcport)
          #          socket[sockfamily] = IO::Socket::INET.new({
          #            Proto => 'udp',
          #            Type => Socket::SOCK_DGRAM,
          #            LocalAddr => srcaddr,
          #            LocalPort => (srcport || nil),
          #          })
          #        elsif (sockfamily == AF_INET6 )
          #          # Otherwise the INET6 socket will just fail
          #          srcaddr6 = srcaddr == "0.0.0.0" ? '::' : srcaddr
          #          socket[sockfamily] = IO::Socket::INET6.new({
          #            Proto => 'udp',
          #            Type => SOCK_DGRAM,
          #            LocalAddr => srcaddr6,
          #            LocalPort => (srcport || nil),
          #          })
        else
          raise RuntimeError, " bgsend:Unsupported Socket Family: #{sockfamily}"
        end
        
        unless (sock != nil)
          @errorstring=("could not get socket")
          return;
        end
        
        print ";; bgsend(#{ns_address} : #{dstport})\n" if @debug
        
        unless (sock.send(packet_data,0,dst_sockaddr, dstport))
          err = $!
          print ";; send ERROR(#{ns_address}): #{err}\n" if @debug
          
          @errorstring=("Send: " + err)
          return
        end
        return sock
        
      end
      
      #Reads the answer from a background query (see bgsend).  The argument
      #is an IO::Socket object returned by bgsend.
      #
      #Returns a Net::DNS::Packet object or nil on error.
      #
      #The programmer should close or destroy the socket object after reading it.
      #
      #
      #    packet = res.bgread(socket)
      #    socket = nil
      #
      def bgread(sock)
        buf = '';
        
        begin
          
          buf, from = sock.recvfrom(_packetsz)
          
          if (from)
            print ';; answer from ', from[2], ':',
            from[1], ' : ', buf.length, " bytes\n" if @debug
            
            ans, err = Net::DNS::Packet.new_from_binary(buf, @debug)
            
            if (defined?ans)
              @errorstring=(ans.header.rcode)
            elsif (defined?err)
              @errorstring=(err)
            end
            
            return ans
          end
        rescue SocketError => e
          @errorstring=e.message
          return;
        end
      end
      
      
      #Determines whether a socket is ready for reading.  The argument is
      #an IO::Socket object returned by res.bgsend.
      #
      #Returns true if the socket is ready, false if not.
      #
      #
      #    socket = res.bgsend('foo.example.com')
      #    until (res.bgisready(socket))
      #        # do some other processing
      #    end
      #    packet = res.bgread(socket)
      #    socket = nil
      #
      def bgisready(socket)
        ready = IO.select([socket], nil, nil, 0)
        return ready!=nil
        #        return socket.ready? > 0
      end
      
      def make_query_packet(args)
        packet=""
        
        if (args[0]!=nil and args[0].class == Net::DNS::Packet)
          packet = args[0]
        else
          name, type, klass = args
          
          name  ||= ''
          type  ||= 'A'
          klass ||= 'IN'
          
          # If the name looks like an IP address then do an appropriate
          # PTR query.
          if (name =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/o)
            name = "#{$4}.#{$3}.#{$2}.#{$1}.in-addr.arpa."
            type = 'PTR'
          end
          
          packet = Net::DNS::Packet.new_from_values(name, type, klass)
        end
        
        if (packet.header.opcode == 'QUERY')
          packet.header.rd=(@recurse ? 1 : 0)
        end
        
        if (@dnssec)
          # RFC 3225
          print ";; Adding EDNS extention with UDP packetsize #{@udppacketsize} and DNS OK bit set\n"  if @debug
          
          optrr = Net::DNS::RR.create({
            :type         => 'OPT',
            :name         => '',
            :rrclass        => @udppacketsize,  # Decimal UDPpayload
            :ednsflags    => 0x8000, # first bit set see RFC 3225 
          })
          
          packet.push('additional', optrr)
          
        elsif (@udppacketsize > Net::DNS::PACKETSZ)
          print ";; Adding EDNS extention with UDP packetsize  #{@udppacketsize}.\n" if @debug
          # RFC 3225
          optrr = Net::DNS::RR.create( {
            :type         => 'OPT',
            :name         => '',
            :rrclass        => @udppacketsize,  # Decimal UDPpayload
            :ttl          => 0x0000 # RCODE 32bit Hex
          })
          
          packet.push('additional', optrr)
        end
        
        
        if (@tsig_rr != nil && @tsig_rr.length > 0)
          #          if (!grep { $_.type == 'TSIG' } packet.additional)
          if (packet.additional.select { |i| i.type == 'TSIG' }.length > 0)
            packet.push('additional', @tsig_rr)
          end
        end
        
        return packet
      end
      
      #    zone = res.axfr
      #    zone = res.axfr('example.com')
      #    zone = res.axfr('passwd.example.com', 'HS')
      #
      #Performs a zone transfer from the first nameserver listed in nameservers.
      #If the zone is omitted, it defaults to the first zone listed in the resolver's
      #search list.  If the class is omitted, it defaults to IN.
      #
      #Returns a list of Net::DNS::RR objects, or nil if the zone
      #transfer failed.
      #
      #The redundant SOA record that terminates the zone transfer is not
      #returned to the caller.
      #
      #See also /axfr_start and /axfr_next.
      #
      #Here's an example that uses a timeout:
      #
      #    res.tcp_timeout(10)
      #    zone = res.axfr('example.com')
      #
      #    if (zone)
      #        zone.each do | rr |
      #            print rr.inspect
      #    else
      #        print 'Zone transfer failed: ', res.errorstring, "\n"
      #    end
      #
      def axfr(*args)
        zone=[]
        
        if (axfr_start(args[0], args[1]))
          continueLoop= true
          err = nil
          while (continueLoop)
            rr, err = axfr_next
            continueLoop = rr!=nil && err==nil
            if (continueLoop)
              zone.push(rr)
            end
          end
          zone = [] if err
        end
        
        return zone
      end
      
      def axfr_old
        raise NotImplementedError, "Use of Net::DNS::Resolver::axfr_old() is deprecated, use axfr() or axfr_start()."
      end
      
      
      #    res.axfr_start
      #    res.axfr_start('example.com')
      #    res.axfr_start('example.com', 'HS')
      #
      #Starts a zone transfer from the first nameserver listed in nameservers.
      #If the zone is omitted, it defaults to the first zone listed in the resolver's
      #search list.  If the class is omitted, it defaults to IN.
      #
      #Use axfr_next to read the zone records one at a time.
      #
      def axfr_start(*args)
        dname = args[0]
        klass = args[1]
        dname ||= @searchlist[0]
        klass ||= 'IN'
        timeout = @tcp_timeout
        
        unless (dname)
          print ";; ERROR: axfr: no zone specified\n" if @debug
          @errorstring=('no zone')
          return
        end
        
        
        print ";; axfr_start(#{dname}, #{klass})\n" if @debug
        
        unless (@nameservers.length > 0)
          @errorstring=('no nameservers')
          print ";; ERROR: no nameservers\n" if @debug
          return
        end
        
        packet = make_query_packet([dname, 'AXFR', klass])
        packet_data = packet.data
        
        ns = @nameservers[0]
        
        
        srcport = @srcport
        srcaddr = @srcaddr
        dstport = @port
        
        print ";; axfr_start nameserver = #{ns}\n" if @debug
        print ";; axfr_start srcport: #{srcport}, srcaddr: #{srcaddr}, dstport: #{dstport}\n" if @debug
        
        
        sock=""
        sock_key = "#{ns}:#{@port}"
        
        
        if (@persistent_tcp && @axfr_sockets['AF_UNSPEC'][sock_key]!=nil)
          sock = @axfr_sockets['AF_UNSPEC'][sock_key]
          print ";; using persistent socket\n" if @debug
        else
          sock=_create_tcp_socket(ns)
          
          return unless (sock!=nil);  # all error messages 
          # are set by _create_tcp_socket
          
          
          @axfr_sockets['AF_UNSPEC'][sock_key] = sock if  @persistent_tcp
        end
        
        lenmsg = [packet_data.length].pack('n')
        
        unless (sock.send(lenmsg,0))
          @errorstring=($!)
          return
        end
        
        unless (sock.send(packet_data,0))
          @errorstring=($!)
          return
        end
        
        @axfr_sock       = sock
        @axfr_rr        = []
        @axfr_soa_count = 0
        
        return sock
      end
      
      
      #Reads records from a zone transfer one at a time.
      #
      #Returns nil at the end of the zone transfer.  The redundant
      #SOA record that terminates the zone transfer is not returned.
      #
      #See also axfr
      #
      #    res.axfr_start('example.com')
      #
      #    while (rr = res.axfr_next)
      #	    print rr.inspect
      #    end
      def axfr_next
        err  = ''
        
        # @todo this can't be right!!!
        unless (@axfr_rr!=[])
          unless (@axfr_sock!=nil)
            err = 'no zone transfer in progress'
            
            print ";; #{err}\n" if @debug
            @errorstring=(err)
            
            return nil, err
          end
          
          timeout = @tcp_timeout
          sock = @axfr_sock
          
          #--------------------------------------------------------------
          # Read the length of the response packet.
          #--------------------------------------------------------------
          
          #          ready = sock.wait(timeout)
          ready = IO.select([sock], nil, nil, timeout)
          unless (ready)
            err = 'timeout';
            @errorstring=(err);
            return nil, err
          end
          
          buf, from = read_tcp(sock, Net::DNS::INT16SZ, @debug)
          unless (buf.length > 0)
            err = 'truncated zone transfer'
            @errorstring=(err)
            return nil, err
          end
          
          len = buf.unpack('n')[0]
          unless (len != nil && len > 0)
            err = 'truncated zone transfer'
            @errorstring=(err)
            return nil, err
          end
          
          #--------------------------------------------------------------
          # Read the response packet.
          #--------------------------------------------------------------
          
          ready = IO.select([sock], nil, nil, timeout)
          #          ready = sel.wait(timeout) # should be sock.wait, anyway!
          unless (ready)
            err = 'timeout'
            @errorstring=(err)
            return nil, err
          end
          
          buf, from = read_tcp(sock, len, @debug)
          
          print ';; received ' + buf.length.to_s +  " bytes\n" if @debug
          
          unless (buf.length == len)
            err = "expected #{len} bytes, received " + buf.length.to_s
            @errorstring=(err)
            print ";; #{err}\n" if @debug
            return nil, err
          end
          
          ans, err = Net::DNS::Packet.new_from_binary(buf, @debug)
          
          if (ans)
            if (ans.header.rcode != 'NOERROR') 
              @errorstring=('Response code from server: ' + ans.header.rcode)
              print ';; Response code from server: ' + ans.header.rcode + "\n" if @debug
              return nil, err
            end
            if (ans.header.ancount < 1)
              err = 'truncated zone transfer'
              @errorstring=(err)
              print ";; #{err}\n" if @debug
              return nil, err
            end
          else
            err ||= 'unknown error during packet parsing'
            @errorstring=(err)
            print ";; #{err}\n" if @debug
            #			return wantarray ? (undef, $err) : undef;
            return nil, err
          end
          
          ans.answer.each do |rr|
            if (rr.type == 'SOA')
              @axfr_soa_count +=1
              if (@axfr_soa_count < 2)
                @axfr_rr.push(rr)
              end
            else
              @axfr_rr.push(rr)
            end
          end
          
          if (@axfr_soa_count >= 2)
            @axfr_sel = nil
            # we need to mark the transfer as over if the responce was in 
            # many answers.  Otherwise, the user will call axfr_next again
            # and that will cause a 'no transfer in progress' error.
            @axfr_rr.push(nil)
          end
        end
        
        rr = @axfr_rr.shift
        
        return rr # , nil)
      end
      
      def dnssec=(new_val)
        if (new_val!=nil)
          @dnssec = new_val
          # Setting the udppacket size to some higher default
          @udppacketsize=(2048) if new_val
        end
        
        raise RuntimeError, "You called the Net::DNS::Resolver::dnssec() method but do not have Net::DNS::SEC installed" if @dnssec && ! Net::DNS::DNSSEC
        return @dnssec
      end
      
      
      
      #Get or set the TSIG record used to automatically sign outgoing
      #queries and updates.  Call with an argument of 0 or '' to turn off
      #automatic signing.
      #
      #The default resolver behavior is not to sign any packets.  You must
      #call this method to set the key if you'd like the resolver to sign
      #packets automatically.
      #
      #You can also sign packets manually -- see the Net::DNS::Packet
      #and Net::DNS::Update manual pages for examples.  TSIG records
      #in manually-signed packets take precedence over those that the
      #resolver would add automatically.
      #
      #    tsig = res.tsig
      #
      #    res.tsig(Net::DNS::RR.create("#{key_name} TSIG #{key}"))
      #
      #    tsig = Net::DNS::RR.create("#{key_name} TSIG #{key}")
      #    tsig.fudge=(60)
      #    res.tsig=(tsig)
      #
      #    res.tsig=(#{key_name}, #{key})
      #
      #    res.tsig=(0)
      #
      def tsig=(*args)
        if (args.length == 1)
          if (args[0] != nil)
            @tsig_rr = args[0]		
          else
            @tsig_rr = nil
          end	
        elsif (args.length == 2)
          key_name, key = args
          @tsig_rr = Net::DNS::RR.new("#{key_name} TSIG #{key}")
        end
        
        return @tsig_rr
      end
      
      def tsig
        return @tsig_rr
      end
      
      #
      # Usage:  data, from = read_tcp(socket, nbytes, debug)
      #
      def read_tcp(sock, nbytes, debug=false)
        buf = ''
        from=nil
        
        while (buf.length < nbytes)
          nread = nbytes - buf.length;
          read_buf = ''
          
          print ";; read_tcp: expecting #{nread} bytes\n" if debug
          
          # During some of my tests recv() returned undef even
          # though there wasn't an error.  Checking for the amount
          # of data read appears to work around that problem.
          
          read_buf, from = sock.recvfrom(nread)
          if (read_buf.length < 1)
            errstr = $!
            
            print ";; ERROR: read_tcp: recv failed: #{$!}\n" if debug
            
            if (errstr == 'Resource temporarily unavailable')
              warn "ERROR: read_tcp: recv failed: #{errstr}\n";
              warn "ERROR: try setting res.timeout()\n";
            end
            
            break
          end
          
          print ';; read_tcp: received ', read_buf.length.inspect, " bytes\n" if debug
          
          break unless read_buf.length > 0
          buf += read_buf
        end
        
        return buf, from
      end
      
      def _create_tcp_socket(ns)
        sock=nil
        
        srcport = @srcport
        srcaddr = @srcaddr
        dstport = @port
        
        timeout = @tcp_timeout
        # IO::Socket carps on errors if Perl's -w flag is
        # turned on.  Uncomment the next two lines and the
        # line following the "new" call to turn off these
        # messages.
        
        #my $old_wflag = $^W;
        #$^W = 0;
        
        if (! @force_v4 && IPAddr.new(ns).ipv6? )
          # Perl note : IO::Socket::INET6 fails in a cryptic way upon send()
          # on AIX5L if "0" is passed in as LocalAddr
          # $srcaddr="0" if $srcaddr eq "0.0.0.0";  # Otherwise the INET6 socket will just fail
          
          srcaddr6 = srcaddr == '0.0.0.0' ? '::' : srcaddr
          
          sock=nil
          if (/java/=~RUBY_PLATFORM)
            sock = TCPSocket.new(ns, dstport, srcaddr, srcport)
            #    We need to use Socket.new rather than TCPSocket.new because of 
            #    a bug with TCPSocket#recvfrom in Windows
            #    But this breaks JRuby
          else
            sock = Socket.new( Socket::AF_INET6, Socket::SOCK_STREAM, 0 )
            sockaddr = Socket.pack_sockaddr_in( srcport, srcaddr6 )
            sock.bind( sockaddr )
            sockaddr = Socket.pack_sockaddr_in( dstport, ns )
            sock.connect(sockaddr)
          end
          
          if sock==nil
            @errorstring=('connection failed(IPv6 socket failure)')
            print ";; ERROR: send_tcp: IPv6 connection to #{ns}" + 
			    "failed: #{$!}\n" if @debug
            return();
          end
        end
        
        # At this point we have sucessfully obtained an
        # INET6 socket to an IPv6 nameserver, or we are
        # running forced v4, or we do not have v6 at all.
        # Try v4.
        
        if sock==nil
          if (IPAddr.new(ns).ipv6?)
            @errorstring=(
					   'connection failed (trying IPv6 nameserver without having IPv6)')
            print 
			    ';; ERROR: send_tcp: You are trying to connect to ' +
            ns + " but you do not have IPv6 available\n" if @debug
            return
          end
          
          
          sock=nil
          if (/java/=~RUBY_PLATFORM)
            sock = TCPSocket.new(ns, dstport, srcaddr, srcport)
            #    We need to use Socket.new rather than TCPSocket.new because of 
            #    a bug with TCPSocket#recvfrom in Windows
            #    But this breaks JRuby
          else
            sock = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
            sockaddr = Socket.pack_sockaddr_in( srcport, srcaddr )
            sock.bind( sockaddr )
            sockaddr = Socket.pack_sockaddr_in( dstport, ns )
            sock.connect(sockaddr)
          end
          
          
        end
        
        if sock == nil
          @errorstring=('connection failed')
          print ';; ERROR: send_tcp: connection ' +
		"failed: #{$!}\n" if @debug
          return
        end
        
        return sock
      end
      
    end
  end
end
