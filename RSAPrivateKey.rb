#
# Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
#
require 'RSAKey'
require 'RSAPublicKey'

# RSAPrivateKey ::= SEQUENCE {
#     version           Version,
#     modulus           INTEGER,  -- n
#     publicExponent    INTEGER,  -- e
#     privateExponent   INTEGER,  -- d
#     prime1            INTEGER,  -- p
#     prime2            INTEGER,  -- q
#     exponent1         INTEGER,  -- d mod (p-1)
#     exponent2         INTEGER,  -- d mod (q-1)
#     coefficient       INTEGER,  -- (inverse of q) mod p
#     otherPrimeInfos   OtherPrimeInfos OPTIONAL
# }
#
# Version ::= INTEGER { two-prime(0), multi(1) }
# (CONSTRAINED BY {-- version must be multi if otherPrimeInfos present --})
#
# OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
#
# OtherPrimeInfo ::= SEQUENCE {
#     prime             INTEGER,  -- ri
#     exponent          INTEGER,  -- di
#     coefficient       INTEGER   -- ti
# }
class RSAPrivateKey < RSAKey

	attr_accessor :modulus, :publicExponent, :privateExponent, :prime1, :prime2, :exponent1, :exponent2, :coefficient
	
	alias_method :n, :modulus
	alias_method :n=, :modulus=
	alias_method :e, :publicExponent
	alias_method :e=, :publicExponent=
	alias_method :d, :privateExponent
	alias_method :d=, :privateExponent=
	alias_method :p, :prime1
	alias_method :p=, :prime1=
	alias_method :q, :prime2
	alias_method :q=, :prime2=
	alias_method :dmp1, :exponent1
	alias_method :dmp1=, :exponent1=
	alias_method :dmq1, :exponent2
	alias_method :dmq1=, :exponent2=
	alias_method :iqmp, :coefficient
	alias_method :iqmp=, :coefficient=
	
	def initialize
		super
		@version         = 0
		@modulus         = 0
		@publicExponent  = 0
		@privateExponent = 0
		@prime1          = 0
		@prime2          = 0
		@exponent1       = 0
		@exponent2       = 0
		@coefficient     = 0
	end
	
	def public?
		true
	end
	
	def private?
		true
	end
	
	def public_key
		key = RSAPublicKey.new
		
		key.modulus        = @modulus
		key.publicExponent = @publicExponent
		
		if( key.encode )
			return key
		end
		
		return nil
	end
	
	def private_key
		self
	end

	def fix
		# validate we have at least n, e, p and q...
		return false if( @modulus == 0 or @publicExponent == 0 or @prime1 == 0 or @prime2 == 0 ) 

		if( @prime1 < @prime2 )
			tmp = @prime1
			@prime1 = @prime2
			@prime2 = tmp
		end
		
		# Calculate the decryption exponent...
		@privateExponent = modInverse( @publicExponent, ( @prime1 - 1 ) * ( @prime2 - 1 ) )
		
		# Calculate the Chinese Remainder Theorem (CRT) exponents...
		@exponent1 = @privateExponent % ( @prime1 - 1 )
		@exponent2 = @privateExponent % ( @prime2 - 1 )
		
		# Calculate the Chinese Remainder Theorem (CRT) coefficient...
		@coefficient = modInverse( @prime2, @prime1 )
		
		return true
	end
	
	def encode

		return false if not fix()

		version_tlv = make_tlv_integer( @version )

		modulus_tlv = make_tlv_integer( @modulus )

		publicExponent_tlv = make_tlv_integer( @publicExponent )

		privateExponent_tlv = make_tlv_integer( @privateExponent )

		prime1_tlv = make_tlv_integer( @prime1 )

		prime2_tlv = make_tlv_integer( @prime2 )

		exponent1_tlv = make_tlv_integer( @exponent1 )
		
		exponent2_tlv = make_tlv_integer( @exponent2 )
		
		coefficient_tlv = make_tlv_integer( @coefficient )
		
		@tlvdata = make_tlv( SEQUENCE +	NOT_PRIMITIVE,  version_tlv + 
														modulus_tlv + 
														publicExponent_tlv + 
														privateExponent_tlv +
														prime1_tlv + 
														prime2_tlv +
														exponent1_tlv +
														exponent2_tlv +
														coefficient_tlv )
		
		@raw = @tlvdata
		
		return true
	end
	
	def decode( data=nil )
		
		@tlvdata = data if data
	
		type, length, value = next_tlv( false )
		return false if( type & 0x1F != SEQUENCE )
		
		@tlvdata = value
		
		@version = next_tlv_integer
		return false if not @version

		@modulus = next_tlv_integer
		return false if not @modulus
		
		@publicExponent = next_tlv_integer
		return false if not @publicExponent

		@privateExponent = next_tlv_integer
		return false if not @privateExponent

		@prime1 = next_tlv_integer
		return false if not @prime1

		@prime2 = next_tlv_integer
		return false if not @prime2

		@exponent1 = next_tlv_integer
		return false if not @exponent1
		
		@exponent2 = next_tlv_integer
		return false if not @exponent2

		@coefficient = next_tlv_integer
		return false if not @coefficient

		return true
	end
	
private

	# http://snippets.dzone.com/posts/show/4256
	def modInverse( a, n )
		i = n
		v = 0
		d = 1
		
		while ( a > 0 ) do
			t = i / a
			x = a
			a = i % x
			i = x
			x = d
			d = v - t * x
			v = x
		end
		
		v %= n
		
		if( v < 0 )
			v = ( v + n ) % n
		end
		
		return v
	end
	
end