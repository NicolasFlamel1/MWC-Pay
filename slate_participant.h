// Header guard
#ifndef SLATE_PARTICIPANT_H
#define SLATE_PARTICIPANT_H


// Header files
#include "./bit_reader.h"
#include "./bit_writer.h"
#include "./crypto.h"

using namespace std;


// Classes

// Slate participant class
class SlateParticipant final {

	// Public
	public:
	
		// Constructor
		explicit SlateParticipant(const uint8_t publicBlindExcess[Crypto::SECP256K1_PUBLIC_KEY_SIZE], const uint8_t publicNonce[Crypto::SECP256K1_PUBLIC_KEY_SIZE]);
		
		// Constructor
		SlateParticipant(BitReader &bitReader);
		
		// Get public blind excess
		const uint8_t *getPublicBlindExcess() const;
		
		// Get public nonce
		const uint8_t *getPublicNonce() const;
		
		// Get partial signature
		const uint8_t *getPartialSignature() const;
		
		// Set partial signature
		void setPartialSignature(const uint8_t partialSignature[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE]);
		
		// Serialize
		void serialize(BitWriter &bitWriter) const;
	
	// Private
	private:
	
		// Public blind excess
		uint8_t publicBlindExcess[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
		
		// Public nonce
		uint8_t publicNonce[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
		
		// Partial signature
		uint8_t partialSignature[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE];
};


#endif
