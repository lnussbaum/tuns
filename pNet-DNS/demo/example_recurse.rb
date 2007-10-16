# Example usage for Net::DNS::Resolver::Recurse
# Performs recursion for a query.

require 'Net/DNS'
require 'Net/DNS/Resolver/Recurse'

res = Net::DNS::Resolver::Recurse.new
res.debug=(true)
res.hints=("198.41.0.4") # A.ROOT-SERVER.NET.
packet = res.query_dorecursion("www.rob.com.au.", "A")
print packet.inspect
