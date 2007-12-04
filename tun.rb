TUNSETIFF = 0x400454ca
def tun_allocate(fd)
  # ifr set with:
	#   struct ifreq ifr;
  #   memset(&ifr, 0, sizeof(ifr));
  #   ifr.ifr_flags = IFF_NO_PI;
  #   ifr.ifr_flags |= IFF_TUN;
  ifr = "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001\020\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
  fd.ioctl(TUNSETIFF, ifr)
  idx = ifr.index("\000")
  if idx.nil?
    raise "No tun allocated!!"
  else
    return ifr[0...idx]
  end
end
