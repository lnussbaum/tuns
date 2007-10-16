#--
#Copyright 2007 Nominet UK
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License. 
#You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0 
#
#Unless required by applicable law or agreed to in writing, software 
#distributed under the License is distributed on an "AS IS" BASIS, 
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#See the License for the specific language governing permissions and 
#limitations under the License.
#++
module Net
  module DNS
    class RR
      #= NAME
      #
      #Net::DNS::RR::NULL - DNS NULL resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Null (NULL) resource records.
      #
      #= METHODS
      #
      #== rdlength
      #
      #    print "rdlength = ", rr.rdlength, "\n"
      #
      #Returns the length of the record's data section.
      #
      #= rdata
      #
      #    rdata = rr.rdata
      #
      #Returns the record's data section as binary data.
      #
      #= COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 1035 Section 3.3.10
      
      class NULL < RR
        def new_from_data(data, offset)
        end
        
        def new_from_hash(values)
        end
        
        def new_from_string(string)
        end
      end
    end
  end
end
