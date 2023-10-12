// Header files
#include <cstring>
#include <stdexcept>
#include "./common.h"
#include "./slate.h"
#include "./slate_participant.h"
#include "./smaz.h"

using namespace std;


// Constants

// Compressed message size size
static const size_t COMPRESSED_MESSAGE_SIZE_SIZE = 16;


// Supporting function implementation

// Constructor
SlateParticipant::SlateParticipant(const uint8_t publicBlindExcess[Crypto::SECP256K1_PUBLIC_KEY_SIZE], const uint8_t publicNonce[Crypto::SECP256K1_PUBLIC_KEY_SIZE]) {

	// Set public blind excess
	memcpy(this->publicBlindExcess, publicBlindExcess, sizeof(this->publicBlindExcess));
	
	// Set public nonce
	memcpy(this->publicNonce, publicNonce, sizeof(this->publicNonce));
}

// Constructor
SlateParticipant::SlateParticipant(BitReader &bitReader) {

	// Get public blind excess
	const vector publicBlindExcess = bitReader.getBytes(bitReader.getBits(Slate::COMPRESSED_PUBLIC_KEY_SIZE_SIZE));
	
	// Check if public blind excess is invalid
	if(!Crypto::isValidSecp256k1PublicKey(publicBlindExcess.data(), publicBlindExcess.size())) {
	
		// Throw exception
		throw runtime_error("Public blind excess is invalid");
	}
	
	// Set public blind excess
	memcpy(this->publicBlindExcess, publicBlindExcess.data(), publicBlindExcess.size());
	
	// Get public nonce
	const vector publicNonce = bitReader.getBytes(bitReader.getBits(Slate::COMPRESSED_PUBLIC_KEY_SIZE_SIZE));
	
	// Check if public nonce is invalid
	if(!Crypto::isValidSecp256k1PublicKey(publicNonce.data(), publicNonce.size())) {
	
		// Throw exception
		throw runtime_error("Public nonce is invalid");
	}
	
	// Set public nonce
	memcpy(this->publicNonce, publicNonce.data(), publicNonce.size());
	
	// Check if partial signature exists
	if(bitReader.getBits(Slate::COMPRESSED_BOOLEAN_SIZE)) {
	
		// Throw exception
		throw runtime_error("Partial signature is invalid");
	}
	
	// Check if message and message signature exists
	if(bitReader.getBits(Slate::COMPRESSED_BOOLEAN_SIZE)) {
	
		// Get compressed message
		const vector compressedMessage = bitReader.getBytes(bitReader.getBits(COMPRESSED_MESSAGE_SIZE_SIZE));
		
		// Decompress message
		const vector message = Smaz::decompress(compressedMessage.data(), compressedMessage.size());
		
		// Check if message is invalid
		if(!Common::isValidUtf8String(message.data(), message.size())) {
		
			// Throw exception
			throw runtime_error("Message is invalid");
		}
		
		// Get message signature
		const vector messageSignature = bitReader.getBytes(Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE);
		
		// Check if message signature is invalid
		if(!Crypto::verifySecp256k1CompleteSingleSignerSignature(publicBlindExcess.data(), messageSignature.data(), message.data(), message.size())) {
		
			// Throw exception
			throw runtime_error("Message signature is invalid");
		}
	}
}

// Get public blind excess
const uint8_t *SlateParticipant::getPublicBlindExcess() const {

	// Return public blind excess
	return publicBlindExcess;
}

// Get public nonce
const uint8_t *SlateParticipant::getPublicNonce() const {

	// Return public nonce
	return publicNonce;
}

// Get partial signature
const uint8_t *SlateParticipant::getPartialSignature() const {

	// Return partial signature
	return partialSignature;
}

// Set partial signature
void SlateParticipant::setPartialSignature(const uint8_t partialSignature[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE]) {

	// Set partial signature
	memcpy(this->partialSignature, partialSignature, sizeof(this->partialSignature));
}

// Serialize
void SlateParticipant::serialize(BitWriter &bitWriter) const {

	// Write public blind excess length
	bitWriter.setBits(sizeof(publicBlindExcess), Slate::COMPRESSED_PUBLIC_KEY_SIZE_SIZE);
	
	// Write public blind excess
	bitWriter.setBytes(publicBlindExcess, sizeof(publicBlindExcess));
	
	// Write public nonce length
	bitWriter.setBits(sizeof(publicNonce), Slate::COMPRESSED_PUBLIC_KEY_SIZE_SIZE);
	
	// Write public nonce
	bitWriter.setBytes(publicNonce, sizeof(publicNonce));
	
	// Write partial signature exists
	bitWriter.setBits(true, Slate::COMPRESSED_BOOLEAN_SIZE);
	
	// Write partial signature
	bitWriter.setBytes(partialSignature, sizeof(partialSignature));
	
	// Write message and message signature don't exist
	bitWriter.setBits(false, Slate::COMPRESSED_BOOLEAN_SIZE);
}
