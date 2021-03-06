#= NAME
#
#axfr - Perform a DNS zone transfer
#
#= SYNOPSIS
#
#axfr [ -fqs ] [ -D directory ] [ nameserver ] zone
#
#= DESCRIPTION
#
#axfr performs a DNS zone transfer, prints each record to the standard
#output, and stores the zone to a file.  If the zone has already been
#stored in a file, axfr will read the file instead of performing a
#zone transfer.
#
#Zones will be stored in a directory hierarchy.  For example, the
#zone transfer for foo.bar.com will be stored in the file
#  HOME/.dns-zones/com/bar/foo/axfr.  The directory can be changed
#  with the B<-D> option.
#  
#  This programs requires that the Storable module be installed.
#    
#= OPTIONS
#    
#    * -f     Force a zone transfer, even if the zone has already been stored
#    in a file.
#    
#    * -q    Be quiet -- don't print the records from the zone.
#    
#    * -s    Perform a zone transfer if the SOA serial number on the nameserver
#    is different than the serial number in the zone file.
#    
#    * -D directory   Store zone files under I<directory> instead of the default directory (see "FILES")
#    
#    * nameserver    Query nameserver instead of the default nameserver.
#    
#= FILES
#    
#  * ${HOME}/.dns-zones   Default directory for storing zone files.
#      
#= AUTHOR
#      
#      Michael Fuhr <mike@fuhr.org>
#      
#= SEE ALSO
#      
#      check_soa, check_zone, mresolv, mx, rubydig,
#      Net::DNS, Storable

require 'GetoptLong'
require 'Net/DNS'

#------------------------------------------------------------------------------
# Read any command-line options and check syntax.
#------------------------------------------------------------------------------

#getopts("fqsD:");
opts = GetoptLong.new(["-f", GetoptLong::NO_ARGUMENT],
["-q", GetoptLong::NO_ARGUMENT],
["-D", GetoptLong::REQUIRED_ARGUMENT],
["-s", GetoptLong::NO_ARGUMENT])

opt_q = false
opt_f = false 
opt_s = false 
opt_D = nil
opts.each do |opt, arg|
  case opt
  when '-q'
    opt_q=true
  when '-f'
    opt_f = true
  when '-s'
    opt_s = true
  when '-D'
    opt_D = arg
  end
end

if (ARGV.length < 1) || (ARGV.length > 2)
  print "Usage: #{$0} [ -fqs ] [ -D directory ] [ nameserver ] zone\n" 
else
  #------------------------------------------------------------------------------
  # Get the nameserver (if specified) and set up the zone transfer directory
  # hierarchy.
  #------------------------------------------------------------------------------
  
  nameserver = (ARGV[0] =~ /^@/) ? ARGV.shift : ""
  nameserver = nameserver.sub(/^@/, "")
  
  zone = ARGV.shift 
  basedir = opt_D!=nil ? opt_D : (ENV["HOME"]!=nil ? ENV["HOME"] : "") + "/.dns-zones"
  #  zonedir = join("/", reverse(split(/\./, $zone)));
  zonedir = zone.split(/\./).reverse.join("/")
  zonefile = basedir + "/" + zonedir + "/axfr"
  
  # Don't worry about the 0777 permissions here - the current umask setting
  # will be applied.
  if !(FileTest.directory?basedir) 
    Dir.mkdir(basedir, 0777) or raise RuntimeError, "can't mkdir #{basedir}: #{$!}\n"
  end
  
  dir = basedir
  #  foreach $subdir (split(m#/#, $zonedir)) {
  zonedir.split("/").each do |subdir|
    dir += "/" + subdir
    if (!FileTest.directory?dir)
      Dir.mkdir(dir, 0777) or raise RuntimeError, "can't mkdir #{dir}: #{$!}\n"
    end
  end
  
  #------------------------------------------------------------------------------
  # Get the zone.
  #------------------------------------------------------------------------------
  
  res = Net::DNS::Resolver.new
  res.nameservers=(nameserver) if nameserver!=""
  res.debug=true
  
  zoneArray = nil
  
  if (FileTest.exist?(zonefile) && !opt_f)
    zoneref = retrieve(zonefile)
    if (zoneref==nil)
      raise RuntimeError, "couldn't retrieve zone from #{zonefile}: #{$!}\n"
    end
    
    #----------------------------------------------------------------------
    # Check the SOA serial number if desired.
    #----------------------------------------------------------------------
    
    if (opt_s)
      serial_file, serial_zone = nil
      
      rr = nil
      #      foreach $rr (@$zoneref) {
      zoneref.each do |rr|
        if (rr.type == "SOA")
          serial_file = rr.serial
          break
        end
      end
      if serial_file==nil
        raise RuntimeError,  "no SOA in #{zonefile}\n" 
      end
      
      soa = res.query(zone, "SOA")
      if soa==nil
        raise RuntimeError, "couldn't get SOA for #{zone}: " + res.errorstring + "\n" 
      end
      
      #          foreach $rr ($soa->answer) {
      soa.answer.each do |rr|
        if (rr.type == "SOA")
          serial_zone = rr.serial
          break
        end
      end
      
      if (serial_zone != serial_file)
        opt_f = true
      end
    end 
  else
    opt_f = true
  end
  
  if (opt_f)
    zoneArray = res.axfr(zone)
    if zoneArray==nil
      raise RuntimeError,  "couldn't transfer zone: " + res.errorstring + "\n"
    end
    #    store zoneArray, zonefile or raise RuntimeError, "couldn't store zone to #{zonefile}: #{$!}\n"
    print zoneArray.inspect
  end
  
  #------------------------------------------------------------------------------
  # Print the records in the zone.
  #------------------------------------------------------------------------------
  
  if (!opt_q) 
    #      $_->print for @$zoneref
    zoneArray.each do |z|
      print z.inspect
    end
  end  
end  
