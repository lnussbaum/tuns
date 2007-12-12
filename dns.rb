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
