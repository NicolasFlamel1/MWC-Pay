// Header guard
#ifndef WALLET_H
#define WALLET_H


// Header files
#include <cstdint>
#include <vector>
#include "./crypto.h"
#include "sqlite3.h"

using namespace std;


// Classes

// Wallet class
class Wallet final {

	// Public
	public:
	
		// Constructor
		Wallet();
			
		// Destructor
		~Wallet();
		
		// Open
		bool open(sqlite3 *databaseConnection, const char *providedPassword, const bool showRecoveryPassphrase);
		
		// Display root public key
		void displayRootPublicKey() const;
		
		// Get blinding factor
		bool getBlindingFactor(uint8_t blindingFactor[Crypto::BLINDING_FACTOR_SIZE], const uint64_t identifierPath, const uint64_t value) const;
		
		// Get commitment
		bool getCommitment(uint8_t commitment[Crypto::COMMITMENT_SIZE], const uint64_t identifierPath, const uint64_t value) const;
		
		// Get Bulletproof
		bool getBulletproof(uint8_t bulletproof[Crypto::BULLETPROOF_SIZE], const uint64_t identifierPath, const uint64_t value) const;
		
		// Get Tor payment proof address
		string getTorPaymentProofAddress(const uint64_t index) const;
		
		// Get Tor payment proof address public key
		bool getTorPaymentProofAddressPublicKey(uint8_t publicKey[Crypto::ED25519_PUBLIC_KEY_SIZE], const uint64_t index) const;
		
		// Get Tor payment proof signature
		bool getTorPaymentProofSignature(uint8_t signature[Crypto::ED25519_SIGNATURE_SIZE], const uint64_t index, const uint8_t kernelCommitment[Crypto::COMMITMENT_SIZE], const char *senderAddress, const uint64_t value) const;
		
		// Get MQS payment proof address
		string getMqsPaymentProofAddress(const uint64_t index) const;
		
		// Get MQS payment proof address public key
		bool getMqsPaymentProofAddressPublicKey(uint8_t publicKey[Crypto::SECP256K1_PUBLIC_KEY_SIZE], const uint64_t index) const;
		
		// Get MQS payment proof signature
		vector<uint8_t> getMqsPaymentProofSignature(const uint64_t index, const uint8_t kernelCommitment[Crypto::COMMITMENT_SIZE], const char *senderAddress, const uint64_t value) const;
		
		// Encrypt address message
		pair<vector<uint8_t>, array<uint8_t, Crypto::CHACHA20_NONCE_SIZE>> encryptAddressMessage(const uint8_t *data, const size_t length, const uint8_t recipientPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE], const uint64_t index, const uint8_t version) const;
		
		// Decrypt address message
		vector<uint8_t> decryptAddressMessage(const uint8_t *encryptedData, const size_t length, const uint8_t nonce[Crypto::CHACHA20_NONCE_SIZE], const uint8_t senderPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE], const uint64_t index, const uint8_t version) const;
		
	// Private
	private:
	
		// Get address private key
		bool getAddressPrivateKey(uint8_t addressPrivateKey[Crypto::SECP256K1_PRIVATE_KEY_SIZE], const uint64_t index) const;
		
		// Extended private key
		uint8_t extendedPrivateKey[Crypto::EXTENDED_PRIVATE_KEY_SIZE];
		
		// Opened
		bool opened;
};


#endif
