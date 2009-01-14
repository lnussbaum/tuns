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
    class Resolver
      #= NAME
      #
      #Net::DNS::Resolver::Recurse - Perform recursive dns lookups
      #
      #= SYNOPSIS
      #
      #  require 'Net/DNS'
      #  res = Net::DNS::Resolver::Recurse.new
      #
      #= DESCRIPTION
      #
      #This module is a sub class of Net::DNS::Resolver. So the methods for
      #Net::DNS::Resolver still work for this module as well.  There are just a
      #couple methods added
      #
      #=head1 AUTHOR
      #
      #Rob Brown, bbb@cpan.org
      #
      #=head1 SEE ALSO
      #
      #L<Net::DNS::Resolver>,
      #
      #=head1 COPYRIGHT
      #
      #Copyright (c) 2002, Rob Brown.  All rights reserved.
      #Portions Copyright (c) 2005, Olaf M Kolkman.
      #Ruby version Copyright (c) 2006, AlexD (Nominet UK)
      #
      #This module is free software; you can redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #Example lookup process:
      #
      #[root@box root]# dig +trace www.rob.com.au.
      #
      #; <<>> DiG 9.2.0 <<>> +trace www.rob.com.au.
      #;; global options:  printcmd
      #.                       507343  IN      NS      C.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      D.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      E.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      F.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      G.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      H.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      I.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      J.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      K.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      L.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      M.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      A.ROOT-SERVERS.NET.
      #.                       507343  IN      NS      B.ROOT-SERVERS.NET.
      #;; Received 436 bytes from 127.0.0.1#53(127.0.0.1) in 9 ms
      #  ;;; But these should be hard coded as the hints
      #
      #  ;;; Ask H.ROOT-SERVERS.NET gave:
      #au.                     172800  IN      NS      NS2.BERKELEY.EDU.
      #au.                     172800  IN      NS      NS1.BERKELEY.EDU.
      #au.                     172800  IN      NS      NS.UU.NET.
      #au.                     172800  IN      NS      BOX2.AUNIC.NET.
      #au.                     172800  IN      NS      SEC1.APNIC.NET.
      #au.                     172800  IN      NS      SEC3.APNIC.NET.
      #;; Received 300 bytes from 128.63.2.53#53(H.ROOT-SERVERS.NET) in 322 ms
      #  ;;; A little closer than before
      #
      #  ;;; Ask NS2.BERKELEY.EDU gave:
      #com.au.                 259200  IN      NS      ns4.ausregistry.net.
      #com.au.                 259200  IN      NS      dns1.telstra.net.
      #com.au.                 259200  IN      NS      au2ld.CSIRO.au.
      #com.au.                 259200  IN      NS      audns01.syd.optus.net.
      #com.au.                 259200  IN      NS      ns.ripe.net.
      #com.au.                 259200  IN      NS      ns1.ausregistry.net.
      #com.au.                 259200  IN      NS      ns2.ausregistry.net.
      #com.au.                 259200  IN      NS      ns3.ausregistry.net.
      #com.au.                 259200  IN      NS      ns3.melbourneit.com.
      #;; Received 387 bytes from 128.32.206.12#53(NS2.BERKELEY.EDU) in 10312 ms
      #  ;;; A little closer than before
      #
      #  ;;; Ask ns4.ausregistry.net gave:
      #com.au.                 259200  IN      NS      ns1.ausregistry.net.
      #com.au.                 259200  IN      NS      ns2.ausregistry.net.
      #com.au.                 259200  IN      NS      ns3.ausregistry.net.
      #com.au.                 259200  IN      NS      ns4.ausregistry.net.
      #com.au.                 259200  IN      NS      ns3.melbourneit.com.
      #com.au.                 259200  IN      NS      dns1.telstra.net.
      #com.au.                 259200  IN      NS      au2ld.CSIRO.au.
      #com.au.                 259200  IN      NS      ns.ripe.net.
      #com.au.                 259200  IN      NS      audns01.syd.optus.net.
      #;; Received 259 bytes from 137.39.1.3#53(ns4.ausregistry.net) in 606 ms
      #  ;;; Uh... yeah... I already knew this
      #  ;;; from what NS2.BERKELEY.EDU told me.
      #  ;;; ns4.ausregistry.net must have brain damage
      #
      #  ;;; Ask ns1.ausregistry.net gave:
      #rob.com.au.             86400   IN      NS      sy-dns02.tmns.net.au.
      #rob.com.au.             86400   IN      NS      sy-dns01.tmns.net.au.
      #;; Received 87 bytes from 203.18.56.41#53(ns1.ausregistry.net) in 372 ms
      #  ;;; Ah, much better.  Something more useful.
      #
      #  ;;; Ask sy-dns02.tmns.net.au gave:
      #www.rob.com.au.         7200    IN      A       139.134.5.123
      #rob.com.au.             7200    IN      NS      sy-dns01.tmns.net.au.
      #rob.com.au.             7200    IN      NS      sy-dns02.tmns.net.au.
      #;; Received 135 bytes from 139.134.2.18#53(sy-dns02.tmns.net.au) in 525 ms
      #  ;;; FINALLY, THE ANSWER!
      class Recurse < Resolver
        attr_accessor :nameservers, :callback, :recurse
        attr_reader :hints
        #Initialize the hint servers.  Recursive queries need a starting name
        #server to work off of. This method takes a list of IP addresses to use
        #as the starting servers.  These name servers should be authoritative for
        #the root (.) zone.
        #
        #  res.hints=(ips)
        #
        #If no hints are passed, the default nameserver is asked for the hints. 
        #Normally these IPs can be obtained from the following location:
        #
        #  ftp://ftp.internic.net/domain/named.root
        #  
        def hints=(hints)
          print ";; hints(#{hints.inspect})\n" if @debug
          if (!hints && @nameservers)
            @hints=(@nameservers)
          else
            @nameservers=(hints)
          end
          print ";; verifying (root) zone...\n" if @debug
          # bind always asks one of the hint servers
          # for who it thinks is authoritative for
          # the (root) zone as a sanity check.
          # Nice idea.
          
          recurse=(1)
          packet=query(".", "NS", "IN")
          
          hints = Hash.new
          if (packet)
            if (ans = packet.answer)
              #      foreach my $rr (@ans)
              ans.each do |rr|
                if (rr.name =~ /^\.?$/ and
                  rr.type == "NS")
                  # Found root authority
                  server = rr.rdatastr.downcase
                  server.sub!(/\.$/,"")
                  print ";; FOUND HINT: #{server}\n" if @debug
                  hints[server] = []
                end
              end
              #              foreach my $rr ($packet->additional) {
              packet.additional.each do |rr|
                print ";; ADDITIONAL: ",rr.inspect,"\n" if @debug
                if (server = rr.name.downcase)
                  if ( rr.type == "A")
                    #print ";; ADDITIONAL HELP: $server -> [".$rr->rdatastr."]\n" if $self->{'debug'};
                    if (hints[server]!=nil)
                      print ";; STORING IP: #{server} IN A ",rr.rdatastr,"\n" if @debug
                      hints[server]=rr.rdatastr
                    end
                  end
                  if ( rr.type == "AAAA")
                    #print ";; ADDITIONAL HELP: $server -> [".$rr->rdatastr."]\n" if $self->{'debug'};
                    if (hints[server])
                      print ";; STORING IP6: #{server} IN AAAA ",rr.rdatastr,"\n" if @debug
                      hints[server]=rr.rdatastr
                    end
                  end
                  
                end 
              end
            end
            #                      foreach my $server (keys %hints) {
            hints.keys.each do |server|
              if (!hints[server] || hints[server]==[])
                # Wipe the servers without lookups
                hints.delete(server)
              end
            end
            @hints = hints
          else
            @hints = []
          end
          if (@hints.size > 0)
            if (@debug)
              print ";; USING THE FOLLOWING HINT IPS:\n";
              #      foreach my $ips (values %{ $self->{'hints'} }) {
              @hints.values.each do |ips|
                #	foreach my $server (@{ $ips }) {
                ips.each do |server|
                  print ";;  #{server}\n";
                end
              end
            end
          else
            warn "Server ["+(@nameservers)[0]+"] did not give answers"
          end
          
          # Disable recursion flag.
          @recurse=(0)
          
          #  return $self->nameservers( map { @{ $_ } } values %{ $self->{'hints'} } );
          @nameservers = @hints.values
          return @nameservers
        end
        
        
        #This method is takes a code reference, which is then invoked each time a
        #packet is received during the recursive lookup.  For example to emulate
        #dig's C<+trace> function:
        #
        # res.recursion_callback(Proc.new { |packet|
        #     print packet.additional.inspect
        #		
        #     print";; Received %d bytes from %s\n\n", 
        #         packetanswersize, 
        #         packet.answerfrom);
        # })
        #
        def recursion_callback=(sub)
          #          if (sub && UNIVERSAL::isa(sub, 'CODE'))
          @callback = sub
          #          end
        end  
        
        def recursion_callback
          return @callback
        end
        
        
        #
        #This method is much like the normal query() method except it disables
        #the recurse flag in the packet and explicitly performs the recursion.
        #
        #  packet = res.query_dorecursion( "www.netscape.com.", "A")
        #
        #
        def query_dorecursion(*args)
          
          # Make sure the hint servers are initialized.
          @hints=Hash.new unless @hints
          @recurse=(0)
          # Make sure the authority cache is clean.
          # It is only used to store A and AAAA records of
          # the suposedly authoritative name servers.
          @authority_cache = Hash.new
          
          # Obtain real question Net::DNS::Packet
          query_packet = make_query_packet(args)
          
          # Seed name servers with hints
          return _dorecursion( query_packet, ".", @hints, 0)
        end
        
        def _dorecursion(query_packet, known_zone, known_authorities, depth)
          cache = @authority_cache
          
          # die "Recursion too deep, aborting..." if $depth > 255;
          if ( depth > 255 )
            print ";; _dorecursion() Recursion too deep, aborting...\n" if @debug
            @errorstring="Recursion too deep, aborted"
            return nil
          end
          
          known_zone.sub!(/\.*$/, ".")
          
          # Get IPs from authorities
          ns = []
          #  foreach my $ns (keys %{ $known_authorities }) {
          known_authorities.keys.each do |ns_rec|
            if (known_authorities[ns_rec] != nil  && known_authorities[ns_rec] != [] )
              cache[ns_rec] = known_authorities[ns_rec]
              ns.push(cache[ns_rec])
            elsif (cache[ns_rec]!=nil && cache[ns_rec]!=[])
              known_authorities[ns_rec] = cache[ns_rec]
              ns.push(cache[ns_rec])
            end
          end
          
          if (ns.length == 0)
            found_auth = 0
            if (@debug)
              print ";; _dorecursion() Failed to extract nameserver IPs:\n";
              print known_authorities.inspect + cache.inspect + "\n"
            end
            #    foreach my $ns (keys %{ $known_authorities }) {
            known_authorities.keys.each do |ns_rec|
              if (known_authorities[ns_rec]==nil || known_authorities[ns_rec]==[])
                print ";; _dorecursion() Manual lookup for authority [#{ns_rec}]\n" if @debug
                
                auth_packet=nil
                ans=[]
                
                # Don't query for V6 if its not there.
                if (! @force_v4)
                  auth_packet = _dorecursion(make_query_packet([ns_rec,"AAAA"]),  # packet
		 ".",               # known_zone
                  @hints,  # known_authorities
                  depth+1);         # depth
                  ans = auth_packet.answer if auth_packet
                end
                
                auth_packet = _dorecursion(make_query_packet([ns_rec,"A"]),  # packet
	     ".",               # known_zone
                @hints,  # known_authorities
                depth+1);         # depth
                
                ans.push(auth_packet.answer ) if auth_packet
                
                if ( ans.length > 0 )
                  print ";; _dorecursion() Answers found for [#{ns_rec}]\n" if @debug
                  #          foreach my $rr (@ans) {
                  ans.each do |rr_arr|
                    rr_arr.each do |rr|
                      print ";; RR:" + rr.inspect + "\n" if @debug
                      if (rr.type == "CNAME")
                        # Follow CNAME
                        server = rr.name.downcase
                        if (server)
                          server.sub!(/\.*$/, ".")
                          if (server == ns_rec)
                            cname = rr.rdatastr.downcase
                            cname.sub!(/\.*$/, ".")
                            print ";; _dorecursion() Following CNAME ns [#{ns_rec}] -> [#{cname}]\n" if @debug
                            known_authorities[cname] ||= []
                            known_authorities.delete[ns_rec]
                            next
                          end
                        end
                      elsif (rr.type == "A" || rr.type == "AAAA" )
                        server = rr.name.downcase
                        if (server)
                          server.sub!(/\.*$/, ".")
                          if (known_authorities[server]!=nil)
                            ip = rr.rdatastr
                            print ";; _dorecursion() Found ns: #{server} IN A #{ip}\n" if @debug
                            cache[server] = known_authorities[server]
                            cache[ns_rec].push(ip)
                            found_auth+=1
                            next
                          end
                        end
                      end
                      print ";; _dorecursion() Ignoring useless answer: " + rr.inspect + "\n" if @debug
                    end
                  end
                else
                  print ";; _dorecursion() Could not find A records for [#{ns_rec}]\n" if @debug
                end
              end
            end
            if (found_auth > 0)
              print ";; _dorecursion() Found #{found_auth} new NS authorities...\n" if @debug
              return _dorecursion( query_packet, known_zone, known_authorities, depth+1)
            end
            print ";; _dorecursion() No authority information could be obtained.\n" if @debug
            return nil
          end
          
          # Cut the deck of IPs in a random place.
          print ";; _dorecursion() cutting deck of (" + ns.length.to_s + ") authorities...\n" if @debug
          splitpos = rand(ns.length)
          start = ns[0, splitpos]
          endarr = ns[splitpos, ns.length - splitpos]
          ns = endarr + start
          
          
          ns.each do |levelns|
            print ";; _dorecursion() Trying nameserver [#{levelns}]\n" if @debug
            @nameservers=(levelns)
            
            packet = send( query_packet )
            if (packet)
              
              if (@callback)
                @callback.call(packet)
              end
              
              of = nil
              print ";; _dorecursion() Response received from [" + @answerfrom + "]\n" if @debug
              status = packet.header.rcode
              authority = packet.authority
              if (status)
                if (status == "NXDOMAIN")
                  # I guess NXDOMAIN is the best we'll ever get
                  print ";; _dorecursion() returning NXDOMAIN\n" if @debug
                  return packet
                elsif (packet.answer.length > 0)
                  print ";; _dorecursion() Answers were found.\n" if @debug
                  return packet
                elsif (authority.length > 0)
                  auth = Hash.new
                  #	 foreach my $rr (@authority) {
                  authority.each do |rr|
                    if (rr.type =~ /^(NS|SOA)$/)
                      server = (rr.type == "NS" ? rr.nsdname : rr.mname).downcase
                      server.sub!(/\.*$/, ".")
                      of = rr.name.downcase
                      of.sub!(/\.*$/, ".")
                      print ";; _dorecursion() Received authority [#{of}] [" + rr.type() + "] [#{server}]\n" if @debug
                      if (of.length <= known_zone.length)
                        print ";; _dorecursion() Deadbeat name server did not provide new information.\n" if @debug
                        next
                      elsif (of =~ /#{known_zone}/)
                        print ";; _dorecursion() FOUND closer authority for [#{of}] at [#{server}].\n" if @debug
                        auth[server] ||= []
                      else
                        print ";; _dorecursion() Confused name server [" + @answerfrom + "] thinks [#{of}] is closer than [#{known_zone}]?\n" if @debug
                        last
                      end
                    else
                      print ";; _dorecursion() Ignoring NON NS entry found in authority section: " + rr.inspect + "\n" if @debug
                    end
                  end
                  #	 foreach my $rr ($packet->additional)
                  packet.additional.each do |rr|
                    if (rr.type == "CNAME")
                      # Store this CNAME into %auth too
                      server = rr.name.downcase
                      if (server)
                        server.sub!(/\.*$/, ".")
                        if (auth[server]!=nil && auth[server]!=[])
                          cname = rr.rdatastr.downcase
                          cname.sub!(/\.*$/, ".")
                          print ";; _dorecursion() FOUND CNAME authority: " + rr.string + "\n" if @debug
                          auth[cname] ||= []
                          auth[server] = auth[cname]
                          next
                        end
                        
                      end
                    elsif (rr.type == "A" || rr.type == "AAAA")
                      server = rr.name.downcase
                      if (server)
                        server.sub!(/\.*$/, ".")
                        if (auth[server]!=nil)
                          print ";; _dorecursion() STORING: #{server} IN A    " + rr.rdatastr + "\n" if @debug &&  rr.type == "A"
                          print ";; _dorecursion() STORING: #{server} IN AAAA " + rr.rdatastr + "\n" if @debug &&  rr.type == "AAAA"
                          auth[server].push(rr.rdatastr)
                          next
                        end
                      end
                    end
                    print ";; _dorecursion() Ignoring useless: " + rr.inspect + "\n" if @debug
                  end
                  if (of =~ /#{known_zone}/)
                    return _dorecursion( query_packet, of, auth, depth+1 )
                  else
                    return _dorecursion( query_packet, known_zone, known_authorities, depth+1 )
                  end
                end
              end
            end
          end
          
          return nil
        end
      end
    end
  end
end
