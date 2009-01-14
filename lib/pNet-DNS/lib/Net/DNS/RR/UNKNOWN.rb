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
      #Net::DNS::RR::Unknown - Unknown RR record
      #
      #= DESCRIPTION
      #
      #Class for dealing with unknown RR types (RFC3597)
      #
      #= COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #
      #Portions Copyright (c) 2003  Olaf M. Kolkman, RIPE NCC.
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::RR, RFC 3597
      class UNKNOWN < RR
        def initialize(*args)
          @rdatastr=""
        end
        def new_from_data(data, offset)
          if (@rdlength!=nil && @rdlength > 0)
            #          @rData    = substr($$data, $offset,$length);
            @rData = data.slice(offset, @rdlength)
            @rdatastr = "\\# #{@rdlength} " + @rData.unpack('H*')[0];
          end
        end
        
        
        def rdatastr
          
          if (@rDatastr!=nil)
            return @rDatastr;
          else
            if (@rData!=nil)
              #              return  "\\# " +  @rData.length.to_s +  "  " + @rData.unpack('H*')[0];
              return  "\\# " +  @rData.length.to_s +  " " + @rData.unpack('H*')[0];
            end
          end
          ret = @rdlength!=nil ? "; rdlength = #{@rdlength}" : '';
          
          return ret         
          #          return "#NO DATA";
        end
        
        
        # sub rr_rdata is inherited from RR.pm. Note that $self->{'rdata'}
        # should always be defined        
      end
    end
  end
end
