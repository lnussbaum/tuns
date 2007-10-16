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
require 'socket'
require 'ipaddr'
require 'Net/DNS'

module Net
  module DNS
    class Nameserver
      
      STATE_ACCEPTED = 1
      STATE_GOT_LENGTH = 2
      STATE_SENDING = 3
      
      DEFAULT_PORT=53
      DEFAULT_ADDR = Socket::INADDR_ANY
      
      
      #      def initialize(localaddr=DEFAULT_ADDR, localport=DEFAULT_PORT, verbose=false, &replyhandler)
      def initialize(opts={})
        #  LocalAddr		IP address on which to listen.	Defaults to INADDR_ANY.
        #  LocalPort		Port on which to listen.  	Defaults to 53.
        #  ReplyHandler		Reference to reply-handling 
        #			subroutine			Required.
        #  Verbose		Print info about received 
        #			queries.			Defaults to 0 (off).
        opts = {:localaddr => DEFAULT_ADDR, :localport => DEFAULT_PORT, :verbose => false}.merge(opts)
        if (!opts[:replyhandler] || opts[:replyhandler]==nil)
          raise RuntimeError,  "No reply handler!"
        end
        @replyhandler = opts[:replyhandler]
        @verbose = opts[:verbose]
        @sockets = []
        @_tcp = Hash.new
        
        port=opts[:localport]
        
        # make sure we have an array.
        #        localaddr= [DEFAULT_ADDR] unless opts[:localaddr]!=nil
        localaddr= [ opts[:localaddr] ] unless (opts[:localaddr].is_a?(Array))
        
        localaddresses = localaddr
        
        print "Nameserver on #{localaddresses.inspect}:#{port}\n" if @verbose
        
        # while we are here, print incomplete lines as they come along.
        #        local $| = 1 if @verbose
        
        localaddresses.each do |localaddress|
          
          addr = localaddress
          
          # If not, it will do DNS lookups trying to resolve it as a hostname
          # We could also just set it to undef?
          
          #          addr = IPAddr.ntop(addr) unless IPAddr.ipv4?(addr) || IPAddr.ipv6?(addr)
          
          # Pretty IP-addresses, if they are otherwise binary.
          #          addrname = addr
          #          addrname = IPAddr.ntop(addrname) unless addrname =~ /^[\w\.:\-]+$/
          addrname = IPAddr.new(addr, Socket::AF_INET)         
          print "Setting up listening sockets for #{addrname}...\n" if @verbose
          
          print "Creating TCP socket for #{addrname} - " if @verbose
          
          #--------------------------------------------------------------------------
          # Create the TCP socket.
          #--------------------------------------------------------------------------
          
          #            sock_tcp = inet_new(
          #                                    LocalAddr => $addr,
          #                                    LocalPort => $port,
          #                                    Listen	  => 64,
          #                                    Proto	  => "tcp",
          #            Reuse	  => 1,
          #            );
          #          sock_tcp = TCPSocket.new(addr, port)                        
          @tcpserver = TCPServer.new(addr, port)
          if (!@tcpserver)
            raise RuntimError, "Couldn't create TCP socket: #{$!}"
            return
          end
          @tcpserver.listen(64) 
          @sockets.push(@tcpserver)
          print "done.\n" if @verbose
          
          #--------------------------------------------------------------------------
          # Create the UDP Socket.
          #--------------------------------------------------------------------------
          
          print "Creating UDP socket for #{addrname} - " if @verbose
          
          sock_udp = UDPSocket.new()
          sock_udp.bind(addr, port)
          
          if (!sock_udp)
            raise RuntimeError, "Couldn't create UDP socket: #{$!}"
            return
          end
          @sockets.push(sock_udp)
          print "done.\n" if @verbose
        end
        
      end
      
      #------------------------------------------------------------------------------
      # make_reply - Make a reply packet.
      #------------------------------------------------------------------------------
      
      def make_reply(query, peerhost)
        reply=""
        headermask=""
        
        if (not query)
          print "ERROR: invalid packet\n" if @verbose
          reply = Net::DNS::Packet.new_from_values("", "ANY", "ANY")
          reply.header.rcode=("FORMERR")
          
          return reply
        end
        
        if (query.header.qr==1)
          print "ERROR: invalid packet (qr was set, dropping)\n" if @verbose
          return
        end
        
        
        qr = (query.question)[0]
        
        qname  = qr ? qr.qname  : ""
        qclass = qr ? qr.qclass : "ANY"
        qtype  = qr ? qr.qtype  : "ANY"
        
        reply = Net::DNS::Packet.new_from_values(qname, qtype, qclass)
        
        if (query.header.opcode == "QUERY")
          if (query.header.qdcount == 1)
            print "query ", query.header.id,
			": (#{qname}, #{qclass}, #{qtype}) - " if @verbose
            
            rcode, ans, auth, add, headermask = @replyhandler.call(qname, qclass, qtype, peerhost, query)
            
            print "#{rcode}\n" if @verbose
            
            reply.header.rcode=(rcode)
            
            reply.push("answer",	   ans)  if ans
            reply.push("authority",  auth) if auth
            reply.push("additional", add)  if add
          else
            print "ERROR: qdcount ", query.header.qdcount, "unsupported\n" if @verbose
            reply.header.rcode=("FORMERR")
          end
        else
          print "ERROR: opcode ", query.header.opcode, " unsupported\n" if @verbose
          reply.header.rcode=("FORMERR")
        end
        
        
        
        if (!headermask)
          reply.header.ra=(1)
          reply.header.ad=(0)
        else
          reply.header.aa=(1) if headermask['aa']
          reply.header.ra=(1) if headermask['ra']
          reply.header.ad=(1) if headermask['ad']
        end
        
        
        reply.header.qr=(1)
        reply.header.cd=(query.header.cd)
        reply.header.rd=(query.header.rd)	
        reply.header.id=(query.header.id)
        
        
        print reply.header.inspect if @verbose && headermask
        
        return reply
      end
      
      #------------------------------------------------------------------------------
      # readfromtcp - read from a TCP client
      #------------------------------------------------------------------------------
      
      def readfromtcp(sock)
        return -1 unless @_tcp[sock]
        peer = @_tcp[sock]["peer"]
        #        charsread = sock.sysread(@_tcp[sock]["inbuffer"], 16384)
        @_tcp[sock]["inbuffer"] = sock.recv_nonblock(16384)
        charsread = @_tcp[sock]["inbuffer"].length
        @_tcp[sock]["timeout"] = Time.now()+120; # Reset idle timer
        print "Received #{charsread} octets from #{peer}\n" if @verbose
        if (charsread == 0) # 0 octets means socket has closed
          print "Connection to #{peer} closed or lost.\n" if @verbose
          @sockets.delete(sock)
          sock.close()
          @_tcp.delete(sock)
          return charsread
        end
        return charsread
      end
      
      #------------------------------------------------------------------------------
      # tcp_connection - Handle a TCP connection.
      #------------------------------------------------------------------------------
      
      def tcp_connection(sock)
        #        if (not @_tcp[sock])
        if ((sock == @tcpserver)) # || (not @_tcp[sock]))
          # We go here if we are called with a listener socket.
          client = sock.accept_nonblock
          if (!client)
            print "TCP connection closed by peer before we could accept it.\n" if @verbose
            return 0
          end
          peerport= client.addr[1]
          peerhost = client.addr[3]
          
          print "TCP connection from #{peerhost}:#{peerport}\n" if @verbose
          #          client.blocking=(0)
          @_tcp[client]=Hash.new
          @_tcp[client]["peer"] = "tcp:"+peerhost.inspect+":"+peerport.inspect
          @_tcp[client]["state"] = STATE_ACCEPTED
          @_tcp[client]["socket"] = client
          @_tcp[client]["timeout"] = Time.now()+120
          @_tcp[client]["outbuffer"] = ""
          @sockets.push(client)
          # After we accepted we will look at the socket again 
          # to see if there is any data there. ---Olaf
          loop_once(0)
        elsif @_tcp[sock]
          # We go here if we are called with a client socket
          peer = @_tcp[sock]["peer"]
          
          if (@_tcp[sock]["state"] == STATE_ACCEPTED)
            if (not @_tcp[sock]["inbuffer"].sub!(/^(..)/, ""))
              return; # Still not 2 octets ready
            end
            msglen = $1.unpack("n")[0]
            print "Removed 2 octets from the input buffer from #{peer}.\n" +
		  	"#{peer} said his query contains #{msglen} octets.\n" if @verbose
            @_tcp[sock]["state"] = STATE_GOT_LENGTH
            @_tcp[sock]["querylength"] = msglen
          end
          # Not elsif, because we might already have all the data
          if (@_tcp[sock]["state"] == STATE_GOT_LENGTH)
            # return if not all data has been received yet.
            return if @_tcp[sock]["querylength"] > @_tcp[sock]["inbuffer"].length
            
            qbuf = @_tcp[sock]["inbuffer"][0, @_tcp[sock]["querylength"]]
            #            substr($self->{"_tcp"}{$sock}{"inbuffer"}, 0, $self->{"_tcp"}{$sock}{"querylength"}) = "";
            @_tcp[sock]["inbuffer"][0, @_tcp[sock]["querylength"]]=""
            query = Net::DNS::Packet.new_from_binary(qbuf)
            reply = make_reply(query, sock.addr[3])
            if (!reply) 
              print "I couldn't create a reply for #{peer}. Closing socket.\n" if @verbose
              #              @select.remove(sock)
              @sockets.delete(sock)
              sock.close()
              @_tcp.delete(sock)
              return
            end
            reply_data = reply.data
            len = reply_data.length
            @_tcp[sock]["outbuffer"] = [len].pack("n") + reply_data
            print "Queued #{@_tcp[sock]['outbuffer'].length} octets to #{peer}.\n" if @verbose
            # We are done.
            @_tcp[sock]["state"] = STATE_SENDING
          end
        end
      end
      
      #------------------------------------------------------------------------------
      # udp_connection - Handle a UDP connection.
      #------------------------------------------------------------------------------
      
      def udp_connection(sock)
        buf, sender = sock.recvfrom(Net::DNS::PACKETSZ)
        peerhost = sender[2]
        peerport= sender[1]
        
        print "UDP connection from #{peerhost}:#{peerport}\n" if @verbose
        
        query = Net::DNS::Packet.new_from_binary(buf)
        
        reply = make_reply(query, peerhost) || return
        reply_data = reply.data
        
        #        local $| = 1 if @verbose
        print "Writing response - " if @verbose
        # die() ?!??  I think we need something better. --robert
        sock.send(reply_data, 0, peerhost, peerport) or raise RuntimError, "send: #{$!}"
        print "done\n" if @verbose
      end
      
      
      def get_open_tcp
        return @_tcp.keys
      end
      
      
      #------------------------------------------------------------------------------
      # loop_once - Just check "once" on sockets already set up
      #------------------------------------------------------------------------------
      
      # This function might not actually return immediately. If an AXFR request is
      # coming in which will generate a huge reply, we will not relinquish control
      # until our outbuffers are empty.
      
      #
      #  NB  this method may be subject to change and is therefore left 'undocumented'
      #
      
      def loop_once(timeout=0)
        #        print ";loop_once called with #{timeout} \n" if @verbose
        @_tcp.keys.each do |sock|
          timeout = 0.1 if @_tcp[sock]["outbuffer"]!=""
        end
        #        ready = @select.can_read(timeout)
        ret = IO::select(@sockets, nil, nil, timeout)
        if (ret!=nil) 
          ready = ret[0]
          print "ready : " + ready.inspect + "\n"
          
          ready.each do |sock|
            if (!(sock.is_a?UDPSocket))
              
              self.readfromtcp(sock) &&
              self.tcp_connection(sock)
            else
              self.udp_connection(sock)
              #          else
              #            print "ERROR: connection with unsupported protocol #{proto}\n" if @verbose
            end
          end
        end
        
        now = Time.now()
        # Lets check if any of our TCP clients has pending actions.
        # (outbuffer, timeout)
        #        @_tcp.keys.each do |s|
        @_tcp.keys.each do |s|
          sock = @_tcp[s]["socket"]
          if (@_tcp[s]["outbuffer"].length>0)
            # If we have buffered output, then send as much as the OS will accept
            # and wait with the rest
            len = @_tcp[s]["outbuffer"].length
            #            charssent = sock.syswrite(@_tcp[s]["outbuffer"]
            charssent = sock.write_nonblock(@_tcp[s]["outbuffer"])
            print "Sent #{charssent} of #{len} octets to " + @_tcp[s]["peer"] + ".\n" if @verbose
            #            substr($self->{"_tcp"}{$s}{"outbuffer"}, 0, charssent) = ""
            @_tcp[s]["outbuffer"] [0, charssent] = ""
            if (@_tcp[s]["outbuffer"].length == 0)
              @_tcp[s]["outbuffer"] = ""
              @_tcp[s]["state"] = STATE_ACCEPTED
              if (@_tcp[s]["inbuffer"].length >= 2)
                # See if the client has send us enough data to process the
                # next query.
                # We do this here, because we only want to process (and buffer!!)
                # a single query at a time, per client. If we allowed a STATE_SENDING
                # client to have new requests processed. We could be easilier
                # victims of DoS (client sending lots of queries and never reading
                # from it's socket).
                # Note that this does not disable serialisation on part of the
                # client. The split second it should take for us to lookip the
                # next query, is likely faster than the time it takes to
                # send the response... well, unless it's a lot of tiny queries,
                # in which case we will be generating an entire TCP packet per
                # reply. --robert
                tcp_connection(@_tcp["socket"])
              end
            end
            @_tcp[s]["timeout"] = Time.now()+120
          else
            # Get rid of idle clients.
            timeout = @_tcp[s]["timeout"]
            if (timeout - now < 0)
              print @_tcp[s]["peer"]," has been idle for too long and will be disconnected.\n" if @verbose
              #              @select.remove(sock)
              @sockets.delete(sock)
              sock.close()
              @_tcp.delete(s)
            end
          end
        end
      end
      
      #------------------------------------------------------------------------------
      # main_loop - Main nameserver loop.
      #------------------------------------------------------------------------------
      
      def main_loop
        while (true) do
          print "Waiting for connections...\n" if @verbose
          # You really need an argument otherwise you'll be burning
          # CPU.
          loop_once(10)
        end
      end
      
    end
  end
end

#= NAME
#
#Net::DNS::Nameserver - DNS server class
#
#= SYNOPSIS
#
#require 'Net\DNS'
#
#= DESCRIPTION
#
#Instances of the Net::DNS::Nameserver class represent DNS server
#objects.  See EXAMPLE for an example.
#
#= METHODS
#
#== new
#
# ns = Net::DNS::Nameserver.new({
#	:localaddr	 => "10.1.2.3",
#	:localport	 => 5353,
#	:replyhandler => reply_handler_proc,
#	:verbose		 => 1})
#
#
#
# ns = Net::DNS::Nameserver.new(
#	:localaddr	 => ['::1' , '127.0.0.1' ],
#	:localport	 => 5353,
#	:replyhandler => reply_handler_proc,
#	:verbose		 => 1
# })
#
#Creates a nameserver object.  Attributes are:
#
#  localaddr		IP address on which to listen.	Defaults to INADDR_ANY.
#  localport		Port on which to listen.  	Defaults to 53.
#  replyhandler		Reference to reply-handling 
#			subroutine			Required.
#  verbose		Print info about received 
#			queries.			Defaults to 0 (off).
#
#
#The LocalAddr attribute may alternatively be specified as a list of IP
#addresses to listen to. 
#
#
#The ReplyHandler proc is passed the query name, query class,
#query type and optionally an argument containing header bit settings
#(see below).  It must return the response code and references to the
#answer, authority, and additional sections of the response.  Common
#response codes are:
#
#  NOERROR	No error
#  FORMERR	Format error
#  SERVFAIL	Server failure
#  NXDOMAIN	Non-existent domain (name doesn't exist)
#  NOTIMP	Not implemented
#  REFUSED	Query refused
#
#For advanced usage there is an optional argument containing an
#hashref with the settings for the aa, ra, and ad 
#header bits. The argument is of the form 
# { :ad => 1, :aa => 0, :ra => 1 }
#
#
#See RFC 1035 and the IANA dns-parameters file for more information:
#
#  ftp://ftp.rfc-editor.org/in-notes/rfc1035.txt
#  http://www.isi.edu/in-notes/iana/assignments/dns-parameters
#
#The nameserver will listen for both UDP and TCP connections.  On
#Unix-like systems, the program will probably have to run as root
#to listen on the default port, 53.	A non-privileged user should
#be able to listen on ports 1024 and higher.
#
#Returns a Net::DNS::Nameserver object, or undef if the object
#couldn't be created.
#
#See EXAMPLE for an example.	 
#
#== main_loop
#
#	ns.main_loop
#
#Start accepting queries. Calling main_loop never returns.
#
#== loop_once
#
#	ns.loop_once( [TIMEOUT_IN_SECONDS] )
#
#Start accepting queries, but returns. If called without a parameter,
#the call will not return until a request has been received (and
#replied to). If called with a number, that number specifies how many
#seconds (even fractional) to maximum wait before returning. If called
#with 0 it will return immediately unless there's something to do.
#
#Handling a request and replying obviously depends on the speed of
#ReplyHandler. Assuming ReplyHandler is super fast, loop_once should spend
#just a fraction of a second, if called with a timeout value of 0 seconds.
#One exception is when an AXFR has requested a huge amount of data that
#the OS is not ready to receive in full. In that case, it will keep
#running through a loop (while servicing new requests) until the reply
#has been sent.
#
#In case loop_once accepted a TCP connection it will immediatly check
#if there is data to be read from the socket. If not it will return and
#you will have to call loop_once() again to check if there is any data
#waiting on the socket to be processed. In most cases you will have to
#count on calling "loop_once" twice.
#
#A code fragment like:
#	ns.loop_once(10)
#        while( ns.get_open_tcp.length > 0 ) do
#	      ns.loop_once(0)
#	end
#
#Would wait for 10 seconds for the initial connection and would then
#process all TCP sockets until none is left. 
#
#== get_open_tcp
#
# Returns IO::Socket objects, these could
#be useful for troubleshooting but be careful using them.
#
#= EXAMPLE
#
#The following example will listen on port 5353 and respond to all queries
#for A records with the IP address 10.1.2.3.	 All other queries will be
#answered with NXDOMAIN.	 Authority and additional sections are left empty.
#The peerhost variable catches the IP address of the peer host, so that
#additional filtering on its basis may be applied.
#
# require 'Net\DNS'
# 
# def reply_handler(qname, qclass, qtype, peerhost)
#	 rcode="NOERROR"
#    ans = []
#    auth= []
#    add = []
#	 
#	 if (qtype == "A" && qname == "foo.example.com" )
#		 ttl, rdata = 3600, "10.1.2.3"
#		 push ans, Net::DNS::RR.new("#{qname} #{ttl} #{qclass} #{qtype} #{rdata}")
#		 rcode = "NOERROR"
#	 elsif( qname eq "foo.example.com" )
#		 rcode = "NOERROR"
#
#	 else
#  	          rcode = "NXDOMAIN"
#	 end
#	 
#	 # mark the answer as authoritive (by setting the 'aa' flag
#	 return (rcode, ans, auth, add, { :aa => 1 })
# end
# 
# ns = Net::DNS::Nameserver.new({
#     :localport    => 5353,
#     :replyhandler => proc {|qname, qclass, qtype, peerhost|, reply_handler(qname, qclass, qtype, peerhost)},
#     :verbose      => 1
# }) || die "couldn't create nameserver object\n"
#
# ns.main_loop
#
#= COPYRIGHT
#
#Copyright (c) 1997-2002 Michael Fuhr. 
#
#Portions Copyright (c) 2002-2004 Chris Reinhardt.
#
#Portions Copyright (c) 2005 O.M, Kolkman, RIPE NCC.
# 
#Portions Copyright (c) 2005 Robert Martin-Legene.
#
#Ruby version Copyright (C) 2006 AlexD (Nominet UK)
#
#All rights reserved.  This program is free software; you may redistribute
#it and/or modify it under the same terms as Perl itself.
#
#= SEE ALSO
#
#Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
#Net::DNS::Update, Net::DNS::Header, Net::DNS::Question,
#Net::DNS::RR, RFC 1035
