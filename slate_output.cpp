// Header files
#include <cstring>
#include "./slate_output.h"

using namespace std;


// Constants

// Compressed proof size size
static const size_t COMPRESSED_PROOF_SIZE_SIZE = 10;


// Supporting function implementation

// Constructor
SlateOutput::SlateOutput(const uint8_t commitment[Crypto::COMMITMENT_SIZE], const uint8_t proof[Crypto::BULLETPROOF_SIZE]) {

	// Set commitment
	memcpy(this->commitment, commitment, sizeof(this->commitment));
	
	// Set proof
	memcpy(this->proof, proof, sizeof(this->proof));
}

// Serialize
void SlateOutput::serialize(BitWriter &bitWriter) const {

	// Write commitment
	bitWriter.setBytes(commitment, sizeof(commitment));
	
	// Write proof length
	bitWriter.setBits(sizeof(proof), COMPRESSED_PROOF_SIZE_SIZE);
	
	// Write proof
	bitWriter.setBytes(proof, sizeof(proof));
}
