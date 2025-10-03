// Header guard
#ifndef CONSENSUS_H
#define CONSENSUS_H


// Classes

// Consensus class
class Consensus final {

	// Public
	public:
	
		// Constructor
		Consensus() = delete;
		
		// Number base
		static const int NUMBER_BASE;
		
		// Kernel commitment explorer URL
		static const char *KERNEL_COMMITMENT_EXPLORER_URL;
		
		// Output commitment explorer URL
		static const char *OUTPUT_COMMITMENT_EXPLORER_URL;
		
		// Currency abbreviation
		static const char *CURRENCY_ABBREVIATION;
};


#endif
