#
# Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
#

class Factor

	attr_reader :n, :p, :q
	
	def initialize( n )
		@n = n
		@p = 0
		@q = 0
	end

	def factor
		return false
	end
		
end