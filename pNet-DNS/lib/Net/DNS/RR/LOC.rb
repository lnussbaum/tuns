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
      #Net::DNS::RR::LOC - DNS LOC resource record
      #
      #=head1 DESCRIPTION
      #
      #Class for DNS Location (LOC) resource records.  See RFC 1876 for
      #details.
      #
      #=head1 COPYRIGHT
      #
      #Copyright (c) 1997-2002 Michael Fuhr. 
      #
      #Portions Copyright (c) 2002-2004 Chris Reinhardt.
      #
      #Ruby version Copyright (c) 2006 AlexD (Nominet UK)
      #
      #All rights reserved.  This program is free software; you may redistribute
      #it and/or modify it under the same terms as Perl itself.
      #Some of the code and documentation is based on RFC 1876 and on code
      #contributed by Christopher Davis.
      #
      #= SEE ALSO
      #
      #Net::DNS, Net::DNS::Resolver, Net::DNS::Packet,
      #Net::DNS::Header, Net::DNS::Question, Net::DNS::RR,
      #RFC 1876
      class LOC < RR
        #Returns the version number of the representation; programs should
        #always check this.  C<Net::DNS> currently supports only version 0.
        #
        #    print "version = ", rr.version, "\n"
        #
        attr_accessor :version
        #Returns the diameter of a sphere enclosing the described entity,
        #in centimeters.
        #
        #    print "size = ", rr.size, "\n"
        #
        attr_accessor :size
        #Returns the horizontal precision of the data, in centimeters.
        #
        #    print "horiz_pre = ", rr.horiz_pre, "\n"
        #
        attr_accessor :horiz_pre
        #Returns the vertical precision of the data, in centimeters.
        #
        #    print "vert_pre = ", rr.vert_pre, "\n"
        #
        attr_accessor :vert_pre
        #Returns the latitude of the center of the sphere described by
        #the size method, in thousandths of a second of arc.  2**31
        #represents the equator; numbers above that are north latitude.
        #
        #    print "latitude = ", rr.latitude, "\n"
        #
        attr_accessor :latitude
        #Returns the longitude of the center of the sphere described by
        #the size method, in thousandths of a second of arc.  2**31
        #represents the prime meridian; numbers above that are east
        #longitude.
        #
        #    print "longitude = ", rr.longitude, "\n"
        #
        attr_accessor :longitude
        #Returns the altitude of the center of the sphere described by
        #the size method, in centimeters, from a base of 100,000m
        #below the WGS 84 reference spheroid used by GPS.
        #
        #    print "altitude = ", rr.altitude, "\n"
        #
        attr_accessor :altitude
        # Powers of 10 from 0 to 9 (used to speed up calculations).
        POWEROFTEN = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000]
        
        # Reference altitude in centimeters (see RFC 1876).
        REFERENCE_ALT = 100_000 * 100;
        
        # Reference lat/lon (see RFC 1876).
        REFERENCE_LATLON = 2**31;
        
        # Conversions to/from thousandths of a degree.
        CONV_SEC = 1000;
        CONV_MIN = 60 * CONV_SEC;
        CONV_DEG = 60 * CONV_MIN;
        
        # Defaults (from RFC 1876, Section 3).
        DEFAULT_MIN       = 0;
        DEFAULT_SEC       = 0;
        DEFAULT_SIZE      = 1;
        DEFAULT_HORIZ_PRE = 10_000;
        DEFAULT_VERT_PRE  = 10;
        
        def new_from_data(data, offset)
          if (@rdlength > 0)
            version = data.unpack("\@#{offset} C")[0]
            offset+=1
            
            @version = version;
            
            if (version == 0)
              size = data.unpack("\@#{offset} C")[0];
              @size = precsize_ntoval(size);
              offset+=1;
              
              horiz_pre = data.unpack("\@#{offset} C")[0];
              @horiz_pre = precsize_ntoval(horiz_pre);
              offset+=1;
              
              vert_pre = data.unpack("\@#{offset} C")[0];
              @vert_pre = precsize_ntoval(vert_pre);
              offset+=1
              
              @latitude = data.unpack("\@#{offset} N")[0];
              offset += Net::DNS::INT32SZ;
              
              @longitude = data.unpack("\@#{offset} N")[0];
              offset += Net::DNS::INT32SZ;
              
              @altitude = data.unpack("\@#{offset} N")[0]
              offset += Net::DNS::INT32SZ;
            else
              # What to do for unsupported versions?
            end
          end
        end
        
        def new_from_hash(values)
          if values.has_key?(:size)
            @size = values[:size]
          else
            @size = DEFAULT_SIZE
          end
          if values.has_key?(:horiz_pre)
            @horiz_pre = values[:horiz_pre]
          else
            @horiz_pre = DEFAULT_HORIZ_PRE * 100
          end
          if values.has_key?(:vert_pre)
            @vert_pre = values[:vert_pre]
          else
            @vert_pre = DEFAULT_VERT_PRE * 100
          end
          if values.has_key?(:latitude)
            @latitude = values[:latitude]
          end
          if values.has_key?(:longitude)
            @longitude = values[:longitude]
          end
          if values.has_key?(:altitude)
            @altitude = values[:altitude]
          end
          if values.has_key?(:version)
            @version = values[:version]
#          else
#            @version = DEFAULT_VERSION
          end
        end
        
        def new_from_string(string)
          if (string && 
              string =~ /^ (\d+) \s+		# deg lat
           ((\d+) \s+)?		# min lat
           (([\d.]+) \s+)?	# sec lat
           (N|S) \s+		# hem lat
           (\d+) \s+		# deg lon
           ((\d+) \s+)?		# min lon
           (([\d.]+) \s+)?	# sec lon
           (E|W) \s+		# hem lon
           (-?[\d.]+) m? 	# altitude
           (\s+ ([\d.]+) m?)?	# size
           (\s+ ([\d.]+) m?)?	# horiz precision
           (\s+ ([\d.]+) m?)? 	# vert precision
            /ix)  # 
            
            # What to do for other versions?
            version = 0;
            
            latdeg, latmin, latsec, lathem = $1.to_i, $3.to_i, $5.to_i, $6;
            londeg, lonmin, lonsec, lonhem = $7.to_i, $9.to_i, $11.to_i, $12
            alt, size, horiz_pre, vert_pre = $13.to_i, $15.to_i, $17.to_i, $19.to_i
            
            latmin    = DEFAULT_MIN       unless latmin;
            latsec    = DEFAULT_SEC       unless latsec;
            lathem    = lathem.upcase;
            
            lonmin    = DEFAULT_MIN       unless lonmin;
            lonsec    = DEFAULT_SEC       unless lonsec;
            lonhem    = lonhem.upcase
            
            size      = DEFAULT_SIZE      unless size;
            horiz_pre = DEFAULT_HORIZ_PRE unless horiz_pre;
            vert_pre  = DEFAULT_VERT_PRE  unless vert_pre;
            
            @version   = version;
            @size      = size * 100;
            @horiz_pre = horiz_pre * 100;
            @vert_pre  = vert_pre * 100;
            @latitude  = dms2latlon(latdeg, latmin, latsec, lathem);
            @longitude = dms2latlon(londeg, lonmin, lonsec, lonhem);
            @altitude  = alt * 100 + REFERENCE_ALT;
          end
        end
        
        def rdatastr
          rdatastr=""
          
          if (defined?@version)
            if (@version == 0)
              lat       = @latitude;
              lon       = @longitude;
              altitude  = @altitude;
              size      = @size;
              horiz_pre = @horiz_pre;
              vert_pre  = @vert_pre;
              
              altitude   = (altitude - REFERENCE_ALT) / 100;
              size      /= 100;
              horiz_pre /= 100;
              vert_pre  /= 100;
              
              rdatastr = latlon2dms(lat, "NS") + " " +
              latlon2dms(lon, "EW") + " " +
              sprintf("%.2fm", altitude)  + " " +
              sprintf("%.2fm", size)      + " " +
              sprintf("%.2fm", horiz_pre) + " " +
              sprintf("%.2fm", vert_pre);
            else
              rdatastr = "; version " + @version + " not supported";
            end
          else
            rdatastr = '';
          end
          
          return rdatastr;
        end
        
        def rr_rdata(*args)
          rdata = "";
          
          if (defined?@version)
            rdata += [@version].pack("C");
            if (@version == 0)
              rdata += [precsize_valton(@size), precsize_valton(@horiz_pre), precsize_valton(@vert_pre)].pack("C3");
              rdata += [@latitude, @longitude, @altitude].pack("N3");
            else
              # What to do for other versions?
            end
          end
          
          return rdata;
        end
        
        def precsize_ntoval(prec)
          mantissa = ((prec >> 4) & 0x0f) % 10;
          exponent = (prec & 0x0f) % 10;
          return mantissa * POWEROFTEN[exponent];
        end
        
        def precsize_valton(val)
          exponent = 0;
          while (val >= 10)
            val /= 10;
            exponent+=1
          end
          return (val.round << 4) | (exponent & 0x0f);
        end
        
        def latlon2dms(rawmsec, hems)
          # Tried to use modulus here, but Perl dumped core if
          # the value was >= 2**31.
          
          abs  = (rawmsec - REFERENCE_LATLON).abs;
          deg  = (abs / CONV_DEG).round;
          abs  -= deg * CONV_DEG;
          min  = (abs / CONV_MIN).round; 
          abs -= min * CONV_MIN;
          sec  = (abs / CONV_SEC).round;  # $conv_sec
          abs -= sec * CONV_SEC;
          msec = abs;
          
          hem = hems[(rawmsec >= REFERENCE_LATLON ? 0 : 1), 1]
          
          return sprintf("%d %02d %02d.%03d %s", deg, min, sec, msec, hem);
        end
        
        def dms2latlon(deg, min, sec, hem)
          retval=0
          
          retval = (deg * CONV_DEG) + (min * CONV_MIN) + (sec * CONV_SEC);
          retval = -retval if ((hem != nil) && ((hem == "S") || (hem == "W")));
          retval += REFERENCE_LATLON;
          return retval;
        end
        
        #Returns the latitude and longitude as floating-point degrees.
        #Positive numbers represent north latitude or east longitude;
        #negative numbers represent south latitude or west longitude.
        #
        #    lat, lon = rr.latlon
        #    system("xearth", "-pos", "fixed #{lat} #{lon}")
        #
        def latlon
          retlat, retlon = nil
          
          if (@version == 0)
            retlat = latlon2deg(@latitude);
            retlon = latlon2deg(@longitude);
          end
          
          return retlat, retlon
        end
        
        def latlon2deg(rawmsec)
          deg=0;
          
          deg = (rawmsec - reference_latlon) / CONV_DEG;
          return deg;
        end
      end
    end
  end
end
