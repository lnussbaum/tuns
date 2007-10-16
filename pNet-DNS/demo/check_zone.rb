#= NAME
#
#check_zone - Check a DNS zone for errors
#
#= SYNOPSIS
#
#check_zone [ -r ] <domain> [ <class> ]
#
#= DESCRIPTION
#
#Checks a DNS zone for errors.  Current checks are:
#
#* Checks that all A records have corresponding PTR records.
#
#* Checks that hosts listed in NS, MX, and CNAME records have
#A records.
#
#= OPTIONS
#
#* -r Perform a recursive check on subdomains.
#
#= AUTHOR
#
#Michael Fuhr <mike@fuhr.org>
#(Ruby version AlexD, Nominet UK)
#
#= SEE ALSO
#
#axfr, check_soa, mresolv, mx, perldig, Net::DNS

require 'Net/DNS'
require 'GetoptLong'

def check_domain(args)
  domain = args[0]
  klass = "IN"
  if (args.length > 1) 
    klass = args[1]
  end
  print "----------------------------------------------------------------------\n"
  print "#{domain} (class #{klass}\n"
  print "\n"
  
  res = Net::DNS::Resolver.new
  res.defnames=(0)
  res.retry=(2)
  
  nspack = res.query(domain, "NS", klass)
  
  if (!nspack)
    warn "Couldn't find nameservers for #{domain}: ", res.errorstring, "\n"
    return
  end
  
  print "nameservers (will request zone from first available):\n"
  ns=""
  #    foreach $ns (grep { $_->type eq "NS" } $nspack->answer) {
   (nspack.answer.select {|r| r.type == "NS"}).each do |ns|
    print "\t", ns.nsdname, "\n"
  end
  print "\n"
  
  #    res.nameservers(map  { $_->nsdname } grep { $_->type == "NS" } nspack.answer)
  res.nameservers= (nspack.answer.select {|i| i.type == "NS"}).collect {|i| i.nsdname}
  
  zone = res.axfr(domain, klass)
  unless (zone)
    print "Zone transfer failed: ", res.errorstring, "\n"
    return
  end
  
  print "checking PTR records\n"
  check_ptr(domain, klass, zone)
  print "\n"
  
  print "checking NS records\n"
  check_ns(domain, klass, zone)
  print "\n"
  
  print "checking MX records\n"
  check_mx(domain, klass, zone)
  print "\n"
  
  print "checking CNAME records\n"
  check_cname(domain, klass, zone)
  print "\n"
  
  if (@recurse)
    print "checking subdomains\n\n"
    subdomains = Hash.new
    #          foreach (grep { $_->type eq "NS" and $_->name ne $domain } @zone) {
     (zone.select {|i| i.type == "NS" && i.name != domain}).each do |z|
      subdomains[z.name] = 1
    end
    #          foreach (sort keys %subdomains) {
    subdomains.keys.sort.each do |k|
      check_domain(k, klass)
    end
  end
end

def check_ptr(domain, klass, zone)
  res = Net::DNS::Resolver.new
  #  foreach $rr (grep { $_->type eq "A" } @zone) {
   (zone.select {|z| z.type == "A"}).each do |r|
    host = rr.name
    addr = rr.address
    ans = res.send(addr, "A", klass)
    print "\t#{host} (#{addr}) has no PTR record\n" if (ans.header.ancount < 1)
  end
end

def check_ns(domain, klass, zone)
  res = Net::DNS::Resolver.new
  #  foreach $rr (grep { $_->type eq "NS" } @zone) {
   (zone.select { |z| z.type == "NS" }).each do |rr|
    ans = res.send(rr.nsdname, "A", klass)
    print "\t", rr.nsdname, " has no A record\n" if (ans.header.ancount < 1)
  end
end

def check_mx(domain, klass, zone)
  res = Net::DNS::Resolver.new
  #  foreach $rr (grep { $_->type eq "MX" } @zone) {
  zone.select {|z| z.type == "MX"}.each do |rr|
    ans = res.send(rr.exchange, "A", klass)
    print "\t", rr.exchange, " has no A record\n" if (ans.header.ancount < 1)
  end
end

def check_cname(domain, klass, zone)
  res = Net::DNS::Resolver.new
  #  foreach $rr (grep { $_->type eq "CNAME" } @zone)
  zone.select {|z| z.type == "CNAME"}.each do |rr|
    ans = res.send(rr.cname, "A", klass)
    print "\t", rr.cname, " has no A record\n" if (ans.header.ancount < 1)
  end
end

opts = GetoptLong.new(["-r", GetoptLong::NO_ARGUMENT])
@recurse = false
opts.each do |opt, arg|
  case opt
  when '-r'
    @recurse=true
  end
end

if (ARGV.length >=1 && ARGV.length <=2)
  
  check_domain(ARGV)
  exit
else 
  print "Usage: #{$0} [ -r ] domain [ class ]\n"
end
