#
# Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
#
# A very basic example in factoring tiny RSA public keys in order to generate a corresponding RSA private key.
#

$:.unshift( '.' )

require 'openssl'
require 'RSAPublicKey'
require 'RSAPrivateKey'
require 'FactorFactory'

#
# 1. Generate a new RSA private key (With a tiny key size)
#        >openssl genrsa -out private.rsa 96
#
# 2. Extract the public key from the new private key (In PEM format so KeyFactor can read it)
#        >openssl rsa -in private.rsa -out public.rsa -pubout -outform PEM
#
# 3. Create a text file with the data to encrypt. We have to use a small plaintext due to the tiny key size, e.g. 96 bit keysize is a max of 12 bytes plaintext (96/8 = 12).
#        >echo 0123456789! > plaintext.txt
#
# 4. Encrypt the data with the public key so only the private key may decrypt it
#        >openssl rsautl -in plaintext.txt -out ciphertext.txt -inkey public.rsa -pubin -raw
#
# 5. Use the public key to create a new private key (About ~4 minutes for a 96 bit key)
#        >ruby KeyFactor.rb -verbose -public public.rsa -private solved_private.rsa
#
# 6. Decrypt the data with the newly found private key
#        >openssl rsautl -decrypt -in ciphertext.txt -inkey solved_private.rsa -raw
#
if( $0 == __FILE__ )
	algorithm        = 'PollardsRho'
	public_key_file  = 'public.rsa'
	private_key_file = nil
	duration         = nil
	openssl_rsa_key  = nil
	verbose          = false
	password         = ''

	puts ""
	puts "               Key Factor!"
	puts ""

	ARGV.each_index do | index |
		arg = ARGV[index].downcase
		if( arg == '-algorithm' or arg == '/algorithm' )
			algorithm = ARGV[index+1]
		elsif( arg == '-list' or arg == '/list' )
			puts "[+] Supported algorithms:"
			FactorFactory.algorithms.each do | a |
				puts "[+]     * #{a}"
			end
			::Kernel.exit( 0 )
		elsif( arg == '-private' or arg == '/private' )
			private_key_file = ARGV[index+1]
		elsif( arg == '-public' or arg == '/public' )
			public_key_file = ARGV[index+1]
		elsif( arg == '-password' or arg == '/password' )
			password = ARGV[index+1]
		elsif( arg == '-verbose' or arg == '/verbose' )
			verbose = true
		end
	end
		
	puts "[+] Reading key file '#{public_key_file}'..."
	
	openssl_rsa_key = OpenSSL::PKey::RSA.new( ::File.read( public_key_file ), password )
		
	if( not openssl_rsa_key or not openssl_rsa_key.public? )
		puts "[-] Error, no public key to get N from."
		::Kernel.exit( -1 )
	end
	
	public = RSAPublicKey.from_s( openssl_rsa_key.public_key.to_s )
	
	if( not public )
		puts "[-] Failed to decode the public key"
		::Kernel.exit( -2 )
	end
	
	solve = FactorFactory.create( algorithm, public.n )
	
	puts "[+] Trying to factor via #{algorithm} algorithm..."
	
	puts "[+] n    = #{public.n}" if verbose

	start = ::Time.now
	
	if( solve.factor )
		duration = ::Time.now - start
		
		puts "[+] Solved."
		
		private = RSAPrivateKey.new
		
		private.n = public.n
		private.e = public.e
		private.p = solve.p
		private.q = solve.q
		
		private.encode
		
		if( verbose )
			puts "[+] e    = #{private.e}"
			puts "[+] p    = #{private.p}"
			puts "[+] q    = #{private.q}"
			puts "[+] d    = #{private.d}"
			puts "[+] dmp1 = #{private.dmp1}"
			puts "[+] dmq1 = #{private.dmq1}"
			puts "[+] iqmp = #{private.iqmp}"
		else
			
		end

		puts private.to_s if verbose

		if( private_key_file )
			if( private.to_file( private_key_file ) )
				puts "[+] Saved private key to file '#{private_key_file}'"
			else
				puts "[-] Failed to save private to key file '#{private_key_file}'"
			end
		end
	else
		duration = ::Time.now - start
		puts "[-] Failed to factor."
	end
	
	puts "[+] Finished in #{duration} seconds."
end
