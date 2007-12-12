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

# This file contains wrappers to encode binary data in DNS labels.

require 'base32'

def dns_split(unsplit)
  split = ""
  while unsplit.length > 63
    split = split + unsplit[0...63] + '.'
    unsplit = unsplit[63..-1]
  end
  if unsplit.length == 0
    text = split[0..-2]
  else
    text = split + unsplit
  end
  return text
end

def dns_unsplit(data)
  return data.gsub(/\./, '')
end

def dns_encode(pack)
  return dns_split(Base32::encode(pack))
end

def dns_decode(text)
  begin
    return Base32::decode(dns_unsplit(text))
  rescue
    puts $!
    puts text
  end

end
