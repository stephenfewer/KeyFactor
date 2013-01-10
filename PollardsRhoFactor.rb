#
# Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
#
require 'Factor'

class PollardsRhoFactor < Factor

	def initialize( n )
		super
		@pollard_brent_optimize = true
	end

	# http://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm
	def factor
		x = 2
		y = 2
		z = 1
		
		count = 0

		while( @p != @n ) do
		
			x = ( ( x ** 2 ) % @n ) + 1
			
			y = ( ( y ** 2 ) % @n ) + 1
			y = ( ( y ** 2 ) % @n ) + 1
			
			if( @pollard_brent_optimize )
				count += 1
				z = ( ( ( x - y ) * z ) % @n )
				if( count == 100 )
					@p = ( z ).gcd( @n )
					count = 0
					z = 1
				end
			else
				@p = ( x - y ).gcd( @n )
			end
			
			if( @p > 1 and @p < @n )
				@q = @n / @p
				return true
			end
			
		end
		
		return false
	end
	
end

if( $0 == __FILE__ )
	n = 2041

	if( ARGV.length > 0 )
		n = ARGV[0].to_i
	end
	
	sieve = PollardsRhoFactor.new( n )
	
	if( sieve.factor )
		puts "[+] Success!"
		puts "n = #{sieve.n}"
		puts "p = #{sieve.p}"
		puts "q = #{sieve.q}"
	else
		puts "[-] Failed to factor."
	end
	
end