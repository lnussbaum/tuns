#= NAME
#
#check_soa - Check a domain's nameservers
#
#= SYNOPSIS
#
#check_soa domain
#
#= DESCRIPTION
#
#check_soa queries each of a domain's nameservers for the Start
#of Authority (SOA) record and prints the serial number.  Errors
#are printed for nameservers that couldn't be reached or didn't
#answer authoritatively.
#
#= AUTHOR
#
#The original Bourne Shell and C versions were printed in
#"DNS and BIND" by Paul Albitz & Cricket Liu.
#
#This Perl version was written by Michael Fuhr <mike@fuhr.org>.
#
#= SEE ALSO
#
#axfr, check_zone, mresolv, mx, perldig, Net::DNS

require 'Net/DNS'

#------------------------------------------------------------------------------
# Get the domain from the command line.
#------------------------------------------------------------------------------

if ARGV.length ==1 
  domain = ARGV[0]
  
  #------------------------------------------------------------------------------
  # Find all the nameservers for the domain.
  #------------------------------------------------------------------------------
  
  res = Net::DNS::Resolver.new
  
  res.defnames=(0)
  res.retry=(2)
  
  ns_req = res.query(domain, "NS")
  if (!ns_req || ns_req.header.ancount == 0)
    print "No nameservers found for $domain: ", res.errorstring, "\n"
    return
  end 
  
  # Send out non-recursive queries
  res.recurse=(0)
  # Do not buffer standard out
  #  $| = 1;
  
  
  #------------------------------------------------------------------------------
  # Check the SOA record on each nameserver.
  #------------------------------------------------------------------------------
  
  #  foreach my $nsrr (grep {$_->type eq "NS" } $ns_req->answer) {
   (ns_req.answer.select {|r| r.type == "NS"}).each do |nsrr|
    
    #----------------------------------------------------------------------
    # Set the resolver to query this nameserver.
    #----------------------------------------------------------------------
    ns = nsrr.nsdname
    
    # In order to lookup the IP(s) of the nameserver, we need a Resolver
    # object that is set to our local, recursive nameserver.  So we create
    # a new object just to do that.
    
    local_res = Net::DNS::Resolver.new
    
    a_req = local_res.query(ns, 'A')
    
    
    unless (a_req)
      print "Can not find address for #{ns}: ", res.errorstring, "\n"
      next
    end
    
    #    foreach my $ip (map { $_->address } grep { $_->type eq 'A' } $a_req->answer) {
     (a_req.answer.select {|r| r.type == 'A'}).each do |r|
      ip = r.address
      #----------------------------------------------------------------------
      # Ask this IP.
      #----------------------------------------------------------------------
      res.nameservers=(ip)
      
      print "#{ns} (#{ip}): "
      
      #----------------------------------------------------------------------
      # Get the SOA record.
      #----------------------------------------------------------------------
      
      soa_req = res.send(domain, 'SOA', 'IN')
      
      unless (soa_req)
        print res.errorstring, "\n"
        next
      end
      
      #----------------------------------------------------------------------
      # Is this nameserver authoritative for the domain?
      #----------------------------------------------------------------------
      
      unless (soa_req.header.aa)
        print "isn't authoritative for #{domain}\n"
        next
      end
      
      #----------------------------------------------------------------------
      # We should have received exactly one answer.
      #----------------------------------------------------------------------
      
      unless (soa_req.header.ancount == 1)
        print "expected 1 answer, got ", soa_req.header.ancount, "\n"
        next
      end
      
      #----------------------------------------------------------------------
      # Did we receive an SOA record?
      #----------------------------------------------------------------------
      
      unless ((soa_req.answer)[0].type == "SOA")
        print "expected SOA, got ", (soa_req.answer)[0].type, "\n"
        next
      end
      
      #----------------------------------------------------------------------
      # Print the serial number.
      #----------------------------------------------------------------------
      
      print "has serial number ", (soa_req.answer)[0].serial, "\n"
    end
  end
else
  print "Usage: #{$0} domain\n"
end
