#= NAME
#
#mresolv - Perform multiple DNS lookups in parallel
#
#= SYNOPSIS
#
#mresolv [ -d ] [ -n number ] [ -t timeout ] [ filename... ]
#
#= DESCRIPTION
#
#mresolv performs multiple DNS lookups in parallel.  Names to query
#are read from the list of files given on the command line, or from the
#standard input.
#
#= OPTIONS
#
#*-d : Turn on debugging output.
#
#*-n number : Set the number of queries to have outstanding at any time.
#
#*-t timeout : Set the timeout in seconds.  If no replies are received for this
#amount of time, all outstanding queries will be flushed and new
#names will be read from the input stream.
#
#= COPYRIGHT
#
#Copyright (c) 1997-2000 Michael Fuhr.  All rights reserved.  This
#program is free software; you can redistribute it and/or modify it
#under the same terms as Perl itself.
#
#= SEE ALSO
#
#axfr, check_soa, check_zone, mx, perldig, Net::DNS

require 'Net/DNS'
require 'GetoptLong'

# $| = 1;

opts = GetoptLong.new(["-d", GetoptLong::NO_ARGUMENT],
["-n", GetoptLong::REQUIRED_ARGUMENT],
["-t", GetoptLong::REQUIRED_ARGUMENT])

max_num = 32	# number of requests to have outstanding at any time
timeout = 15    # timeout (seconds)
debug = false
opts.each do |opt, arg|
  case opt
  when '-d'
    debug=true
  when '-n'
    max_num = arg
  when '-t'
    timeout = arg
  end
end

res = Net::DNS::Resolver.new
sockets = []
eof = false

while (true) do
  name=""
  sock=nil
  
  #----------------------------------------------------------------------
  # Read names until we've filled our quota of outstanding requests.
  #----------------------------------------------------------------------
  
  while (!eof && sockets.length < max_num) do
    print "DEBUG: reading..." if debug
    name = gets
    unless (name)
      print "EOF.\n" if debug
      eof = true
      break
    end
    name.chomp!
    sock = res.bgsend(name)
    sockets.push(sock)
    print "name = #{name}, outstanding = ", sockets.length, "\n" if debug
  end
  
  #----------------------------------------------------------------------
  # Wait for any replies.  Remove any replies from the outstanding pool.
  #----------------------------------------------------------------------
  
  timed_out = true
  
  print "DEBUG: waiting for replies\n" if debug
  
  ready = IO::select(sockets, nil, nil, timeout)[0]
  
  #  for (ready = $sel->can_read(opts["-t"]); ready; ready = $sel->can_read(0))
  if (ready != nil)
    
    timed_out = false
    
    print "DEBUG: replies received: ", ready.length, "\n" if debug
    
    ready.each do |sock|
      print "DEBUG: handling a reply\n" if debug
      sockets.delete(sock)
      ans = res.bgread(sock)
      sock.close()
      next unless ans != nil
      ans.answer.each do |rr|
        print rr.inspect + "\n"
      end
    end
    #  end
    
    #----------------------------------------------------------------------
    # If we timed out waiting for replies, remove all entries from the
    # outstanding pool.
    #----------------------------------------------------------------------
    
    if (timed_out)
      print "DEBUG: timeout: clearing the outstanding pool.\n" if debug
      #                foreach $sock ($sel->handles)
      sockets.each do |s|
        # $sel->remove($sock);
        s.close()
      end
    end
    
    print "DEBUG: outstanding = ", sockets.length, ", eof = #{eof}\n" if debug
    
    #----------------------------------------------------------------------
    # We're done if there are no outstanding queries and we've read EOF.
    #----------------------------------------------------------------------
    
    break if (sockets.length == 0) && eof
  end
end
