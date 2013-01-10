#
# Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
#
require 'FermatsFactor'
require 'PollardsRhoFactor'
#require 'QuadraticSieveFactor'

class FactorFactory

	@@factor_algorithms = { 
		'Fermats'        => FermatsFactor,
		'PollardsRho'    => PollardsRhoFactor,
		#'QuadraticSieve' => QuadraticSieveFactor
	}

	def self.create( algorithm, n )
		@@factor_algorithms.each_key do | key |
			if( key.downcase == algorithm.downcase )
				return @@factor_algorithms[key].new( n )
			end
		end
		return nil
	end
	
	def self.algorithms
		return @@factor_algorithms.keys
	end
	
end