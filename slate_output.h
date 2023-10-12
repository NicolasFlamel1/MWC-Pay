// Header guard
#ifndef SLATE_OUTPUT_H
#define SLATE_OUTPUT_H


// Header files
#include "./bit_writer.h"
#include "./crypto.h"

using namespace std;


// Classes

// Slate output class
class SlateOutput final {

	// Public
	public:
	
		// Constructor
		explicit SlateOutput(const uint8_t commitment[Crypto::COMMITMENT_SIZE], const uint8_t proof[Crypto::BULLETPROOF_SIZE]);
		
		// Serialize
		void serialize(BitWriter &bitWriter) const;
	
	// Private
	private:
	
		// Commitment
		uint8_t commitment[Crypto::COMMITMENT_SIZE];
		
		// Proof
		uint8_t proof[Crypto::BULLETPROOF_SIZE];
};


#endif
