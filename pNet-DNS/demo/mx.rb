require 'Net/DNS'

#= NAME
#
#mx - Print a domain's MX records
#
#= SYNOPSIS
#
#mx domain
#
#= DESCRIPTION
#
#mx prints a domain's MX records, sorted by preference.
#
#= AUTHOR
#
#Michael Fuhr <mike@fuhr.org>
#(Ruby port AlexD, Nominet UK)
#
#= SEE ALSO
#
#axfr, check_soa, check_zone, mresolv, rubydig,
#Net::DNS


if ARGV.length == 1
  dname = ARGV[0]
  res   = Net::DNS::Resolver.new
  mx    = Net::DNS.mx(dname, res)
  
  if (mx)
    mx.each do |rr|
      print rr.preference, "\t", rr.exchange, "\n"
    end
  else
    print "Can't find MX hosts for #{dname}: ", res.errorstring, "\n"
  end
else
  print "Usage: #{$0} domain\n"
end
