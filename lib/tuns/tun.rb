# Tuns -- prototype of an IP over DNS tunnel
# Copyright (C) 2007 Lucas Nussbaum <lucas@lucas-nussbaum.net>
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

TUNSETIFF = 0x400454ca
# allocate a tun device. Returns the device name.
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
