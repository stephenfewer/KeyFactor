#
# Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
#
require 'Factor'

# http://en.wikipedia.org/wiki/Fermat%27s_factorization_method
class FermatsFactor < Factor

	def factor

		x = Math.sqrt( @n ).ceil
		
		while( x < @n ) do
		
			y = ( x ** 2 ) - @n
			
			if( perfect_square( y ) )
				break
			end
			
			x += 1
		end
		
		@p = x - Math.sqrt( y )
		
		@q = @n / @p
		
		@p = @p.round.to_i
		@q = @q.round.to_i
		
		if( @p * @q != @n  )
			return false
		end
		
		return true
	end
	
	protected
	
	# http://en.wikipedia.org/wiki/Square_number
	def perfect_square( x2 )
		x = Math.sqrt( x2 ).round
		if( x * x == x2 )
			return true
		end
		return false
	end
	
end

if( $0 == __FILE__ )
	n = 2041

	if( ARGV.length > 0 )
		n = ARGV[0].to_i
	end
	
	sieve = FermatsFactor.new( n )
	
	if( sieve.factor )
		puts "[+] Success!"
		puts "n = #{sieve.n}"
		puts "p = #{sieve.p}"
		puts "q = #{sieve.q}"
	else
		puts "[-] Failed to factor."
	end
	
end