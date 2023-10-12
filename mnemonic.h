// Header guard
#ifndef MNEMONIC_H
#define MNEMONIC_H


// Header files
#include <cstdint>
#include <limits>

using namespace std;


// Classes

// Mnemonic class
class Mnemonic final {

	// Public
	public:
	
		// Constructor
		Mnemonic() = delete;
		
		// Seed size
		static const size_t SEED_SIZE = 256 / numeric_limits<uint8_t>::digits;
		
		// Display passphrase
		static void displayPassphrase(const uint8_t seed[SEED_SIZE]);
};


#endif
