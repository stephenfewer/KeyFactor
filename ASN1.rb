#
# Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
#

# http://luca.ntop.org/Teaching/Appunti/asn1.html
module ASN1
	NOT_PRIMITIVE     = 0x20 # well bit 6 set to 0 is primitive so this i not primitive?
	
	INTEGER           = 0x02
	BITSTRING         = 0x03
	OCTET_STRING      = 0x04
	NULL              = 0x05
	OBJECT_IDENTIFIER = 0x06
	SEQUENCE          = 0x10
	SET               = 0x11
	PRINTABLESTRING   = 0x13
	T61STRIN          = 0x14
	IA5STRING         = 0x16
	UTCTIME           = 0x17
	
protected
	
	def next_tlv( consume=true )

		offset = 1
		length = 0

		type = @tlvdata[0,1].unpack( 'C' ).first
		
		length = @tlvdata[offset,1].unpack( 'C' ).first
		
		if( length & 0x80 == 0x80 )
			count  = length & 0x7F
			length = 0
			0.upto( count ) do
				offset += 1
				length += @tlvdata[offset,1].unpack( 'C' ).first
			end
		else
			offset += 1
		end

		value = @tlvdata[offset,length]
		
		if( consume )
			@tlvdata = @tlvdata[offset+length,@tlvdata.length]
		end
		
		return [ type, length, value ]
	end
	
	def make_tlv( type, value )
		tlvdata = [type].pack( 'C' )
		
		value = value.to_s
		
		if( value.length < 0x7F )
			tlvdata << [value.length].pack( 'C' )
		else
			count = value.length / 0xFF
			
			tlvdata << [0x80 & count].pack( 'C' )
			
			len = value.length
			while( true ) do
				if( len <= 0xFF )
					tlvdata << [len].pack( 'C' )
					break
				end
				tlvdata << [0xFF].pack( 'C' )
				len -= 0xFF
			end
		end
		
		tlvdata << value
		
		return tlvdata
	end
	
	def next_tlv_integer
		type, length, value = next_tlv()
		return nil if( type != INTEGER )
		return value.unpack( 'H*' ).first.to_i( 16 )
	end
	
	def make_tlv_integer( value )
		value_hex = value.to_s( 16 )
		if( value_hex.length % 2 != 0 )
			value_hex = "0" + value_hex
		else
			value_hex = "00" + value_hex
		end
		return make_tlv( INTEGER, [ value_hex ].pack( 'H*' ) )
	end
end