#= NAME
#
#rbuydig - Ruby script to perform DNS queries
#
#= SYNOPSIS
#
#rubydig [ @nameserver ] name [ type [ class ] ]
#
#= DESCRIPTION
#
#Performs a DNS query on the given name.  The record type
#and class can also be specified; if left blank they default
#to A and IN.
#
#= AUTHOR
#
#Michael Fuhr <mike@fuhr.org>
#
#= SEE ALSO
#
#axfr, check_soa, check_zone, mresolv, mx,
#Net::DNS

require 'Net/DNS'

res = Net::DNS::Resolver.new

if (ARGV && (ARGV[0] =~ /^@/))
  nameserver = ARGV.shift 
  print "Setting nameserver : #{nameserver}\n"
  res.nameservers=(nameserver.sub(/^@/, ""))
  print "nameservers = #{res.nameservers.inspect}\n"
end

raise RuntimeError, "Usage: #{$0} [ \@nameserver ] name [ type [ class ] ]\n" unless (ARGV.length >= 1) && (ARGV.length <= 3)
  
  name, type, klass = ARGV
  type  ||= "A"
  klass ||= "IN"
  
  if (type.upcase == "AXFR")
    
    rrs = res.axfr(name, klass)
    
    if (rrs)
      rrs.each do |rr|
        print rr.inspect
      end
    else
      raise RuntimeError, "zone transfer failed: ", res.errorstring, "\n"
    end
    
  else
    
    answer = res.send(name, type, klass)
    
    if (answer)
      print answer.inspect
    else
      raise RuntimeError, "query failed: " + res.errorstring + "\n"
    end
  end
