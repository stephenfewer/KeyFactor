#
# Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
#
require 'RSAKey'

# http://tools.ietf.org/html/rfc3447#page-44
# RSAPublicKey ::= SEQUENCE {
#    modulus           INTEGER,  -- n
#    publicExponent    INTEGER   -- e
# }
class RSAPublicKey < RSAKey
	
	attr_accessor :modulus, :publicExponent
	
	alias_method :n, :modulus
	alias_method :n=, :modulus=
	alias_method :e, :publicExponent
	alias_method :e=, :publicExponent=
	
	def initialize
		super
		@modulus        = 0
		@publicExponent = 0
	end
	
	def public?
		true
	end
	
	def public_key
		self
	end
	
	def encode

		modulus_tlv = make_tlv_integer( @modulus )
		
		publicExponent_tlv = make_tlv_integer( @publicExponent )
		
		@tlvdata = make_tlv( SEQUENCE +	NOT_PRIMITIVE, modulus_tlv + publicExponent_tlv )
		
		@raw = @tlvdata
		
		return true
	end

	# http://lapo.it/asn1js/
	
	def decode( data=nil )

		@tlvdata = data if data
	
		type, length, value = next_tlv( false )
		return false if( type & 0x1F != SEQUENCE )
		
		@tlvdata = value
		
		# now test if we have a newer X509 SubjectPublicKeyInfo format of the simpler RSAPublicKey format
		type, length, value = next_tlv( false )
		if( type & 0x1F == SEQUENCE )
			# consume the object id sequence
			next_tlv( true )
			# and move on the the bitstring
			type, length, value = next_tlv( true )
			if( type & 0x1F == BITSTRING )

				@tlvdata = value[1, value.length]
				
				type, length, value = next_tlv( false )
				return false if( type & 0x1F != SEQUENCE )
				
				@tlvdata = value
					
				@modulus = next_tlv_integer
				return false if not @modulus

				@publicExponent = next_tlv_integer
				return false if not @publicExponent
				
				return true
			end
		elsif( type & 0x1F == INTEGER )

			@modulus = next_tlv_integer
			return false if not @modulus

			@publicExponent = next_tlv_integer
			return false if not @publicExponent
			
			return true
		end

		return false
	end

end