#!/usr/bin/ruby

require 'tun'

t = File::new('/dev/net/tun', File::RDWR)
p t.fileno
dev = Tun::alloc(t.fileno)
system("ifconfig #{dev} 10.0.0.1 mtu 140 up")
system("route add -net 10.0.0.0/24 dev #{dev}")
while (s = t.sysread(2000))
  p s
  p s.length
end
