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
require 'shellwords'
module Net
  module DNS
    class RR
      #= NAME
      #
      #Net::DNS::RR::TXT - DNS TXT resource record
      #
      #= DESCRIPTION
      #
      #Class for DNS Text (TXT) resource records.
      #
      #= FEATURES
      #
      #The RR class accepts semi-colons as a start of a comment. This is
      #to allow the RR.pm to deal with RFC1035 specified zonefile format.
      #
      #For some applications of the TXT RR the semicolon is relevant, you
      #will need to escape it on input.
      #
      #Also note that you should specify the several character strings
      #separately. The easiest way to do so is to include the whole argument
      #in single quotes and the several character strings in double
      #quotes. Double quotes inside the character strings will need to be
      #escaped.
      #
      #  TXTrr=Net::DNS::RR.create('txt2.t.net-dns.org.	60	IN
      #	TXT  "Test1 \" \; more stuff"  "Test2"')
      #
      #would result in 
      # TXTrr.char_str_list())[0] containing 'Test1 " ; more stuff'
      #and
      # TXTrr.char_str_list())[1] containing 'Test2'
      #
      #
      #= COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #Portions Copyright (c) 2005 Olaf Kolkman (NLnet Labs)
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #<Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 1035 Section 3.3.14
      class TXT < RR
        #        attr_accessor :char_str_list
        def new_from_data(data, offset)
          init_char_str_list()
          if (@rdlength == nil || @rdlength == 0) 
            return
          end
          endpos = offset + @rdlength
          
          while (offset < endpos)
            strlen = data.unpack("\@#{offset} C")[0]
            offset += 1
            
            char_str = data[offset,strlen]
            offset += strlen
            
            @char_str_list.push(char_str)
          end
        end
        
        def new_from_hash(values)
          if (values.has_key?:txtdata)
            _build_char_str_list(values[:txtdata])
          end
        end
        
        def new_from_string (rdata_string)
          _build_char_str_list(rdata_string)
        end
        
        #Returns the descriptive text as a single string, regardless of actual 
        #number of <character-string> elements.  Of questionable value.  Should 
        #be deprecated.  
        #
        #Use txt.rdatastr() or txt.char_str_list() instead.
        #
        def txtdata
          return @char_str_list.join(' ')
        end
        
        def rdatastr
          if (defined?@char_str_list)
            temp = @char_str_list.map {|str|
              str.gsub(/"/, '\\"')
              %<"#{str}">
            }
            return temp.join(' ')
          end          
          return ''
        end
        
        def init_char_str_list
          @char_str_list = []
        end
        
        def _build_char_str_list(rdata_string)
          words = Shellwords.shellwords(rdata_string)
          
          init_char_str_list()
          
          if (words != nil)
            words.each { |string|
              string .gsub!(/\\"/, '"')
              @char_str_list.push(string)
            }
          end
        end
        
        #Returns a list of the individual <character-string> elements, 
        #as unquoted strings.  Used by TXT->rdatastr and TXT->rr_rdata.
        #
        # print "Individual <character-string> list: \n\t", 
        #       rr.char_str_list().join("\n\t")
        #
        def char_str_list
          if (!defined?(@char_str_list))
            _build_char_str_list( @txtdata )
          end
          
          return @char_str_list # unquoted strings
        end
        
        def rr_rdata(*args)
          rdata = ''
          
          if (@char_str_list!=nil)
            @char_str_list.each { |string|
              rdata += [string.length].pack("C")
              rdata += string
            }
          end 
          return rdata
        end
      end
    end
  end
end
