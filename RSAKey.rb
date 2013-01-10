#
# Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
#
require 'base64'
require 'ASN1'

class RSAKey
	
	include ASN1
	
	def initialize
		@raw = ''
	end
	
	def self.from_raw( raw )
		k = self.new
		if( k.decode( raw ) )
			return k
		end
		return nil
	end
	
	def self.from_s( str )

		start_tag = ''
		stop_tag  = ''

		if( self == RSAPrivateKey )
			start_tag = '-----BEGIN RSA PRIVATE KEY-----'
			stop_tag  = '-----END RSA PRIVATE KEY-----'
		else
			if( str.index( '-----BEGIN RSA PUBLIC KEY-----' ) )
				start_tag = '-----BEGIN RSA PUBLIC KEY-----'
				stop_tag  = '-----END RSA PUBLIC KEY-----'
			else
				start_tag = '-----BEGIN PUBLIC KEY-----'
				stop_tag  = '-----END PUBLIC KEY-----'
			end
		end
		
		start = str.index( start_tag )
		stop  = str.index( stop_tag )

		if( start and start >= 0 and stop and stop > 0 )
			str = str[(start+start_tag.length+1)..(stop-1)].strip
		else
			return nil
		end

		return self.from_raw( ::Base64.decode64( str ) )
	end
	
	def to_raw
		return @raw
	end
	
	def to_s
		type = ''
		if( not private? and public? )
			type = 'RSA PUBLIC'
		elsif( private? )
			type = 'RSA PRIVATE'
		end
		str  = "-----BEGIN #{ type } KEY-----\n"
		str << ::Base64.encode64( self.to_raw )
		str << "-----END #{ type } KEY-----\n"
		return str
	end
	
	def to_file( path )
		begin
			::File.open( path, 'w' ) do | f |
				f.write( self.to_s )
			end
		rescue
			return false
		end
		return true
	end
	
	def public?
		false
	end
	
	def private?
		false
	end
	
	def public_key
		nil
	end
	
	def private_key
		nil
	end
	
end