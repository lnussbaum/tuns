require 'Net/DNS'
require 'Net/DNS/Resolver/Recurse'

res = Net::DNS::Resolver::Recurse.new


res.recursion_callback=(Proc.new { |packet|
	
	packet.additional.each { |a| a.print }
	
	print(";; Received #{packet.answersize} bytes from #{packet.answerfrom}\n\n")
})


res.query_dorecursion(ARGV[0])
