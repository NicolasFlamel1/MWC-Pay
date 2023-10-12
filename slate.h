// Header guard
#ifndef SLATE_H
#define SLATE_H


// Header files
#include <list>
#include <optional>
#include <string>
#include <vector>
#include "./crypto.h"
#include "./slate_output.h"
#include "./slate_participant.h"

using namespace std;


// Classes

// Slate class
class Slate final {

	// Public
	public:
	
		// Compressed boolean size
		static const size_t COMPRESSED_BOOLEAN_SIZE;
		
		// Compressed public key size size
		static const size_t COMPRESSED_PUBLIC_KEY_SIZE_SIZE;
		
		// Kernel features
		enum class KernelFeatures {

			// Plain
			PLAIN,
			
			// Coinbase
			COINBASE,
			
			// Height locked
			HEIGHT_LOCKED
		};
		
		// Constructor
		explicit Slate(const uint8_t *data, const size_t length);
		
		// Create random offset
		bool createRandomOffset(const uint8_t blindingFactor[Crypto::BLINDING_FACTOR_SIZE]);
		
		// Get amount
		uint64_t getAmount() const;
		
		// Get lock height
		uint64_t getLockHeight() const;
		
		// Get sender payment proof address public key
		const vector<uint8_t> &getSenderPaymentProofAddressPublicKey() const;
		
		// Get recipient payment proof address public key
		const vector<uint8_t> &getRecipientPaymentProofAddressPublicKey() const;
		
		// Set recipient payment proof address public key
		void setRecipientPaymentProofAddressPublicKey(const uint8_t *recipientPaymentProofAddressPublicKey, const size_t recipientPaymentProofAddressPublicKeyLength);
		
		// Set output
		void setOutput(const SlateOutput &output);
		
		// Get offset
		const uint8_t *getOffset() const;
		
		// Add participant
		void addParticipant(const SlateParticipant &participant);
		
		// Get public blind excess sum
		bool getPublicBlindExcessSum(uint8_t publicBlindExcessSum[Crypto::SECP256K1_PUBLIC_KEY_SIZE]) const;
		
		// Get public nonce sum
		bool getPublicNonceSum(uint8_t publicNonceSum[Crypto::SECP256K1_PUBLIC_KEY_SIZE]) const;
		
		// Get kernel data
		vector<uint8_t> getKernelData() const;
		
		// Set participant's partial signature
		void setParticipantsPartialSignature(const uint8_t partialSignature[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE]);
		
		// Get excess
		bool getExcess(uint8_t excess[Crypto::COMMITMENT_SIZE]) const;
		
		// Set recipient payment proof signature
		void setRecipientPaymentProofSignature(const uint8_t *recipientPaymentProofSignature, const size_t recipientPaymentProofSignatureLength);
		
		// Serialize
		vector<uint8_t> serialize() const;
		
		// Get kernel features
		KernelFeatures getKernelFeatures() const;
		
		// Get participants
		const list<SlateParticipant> &getParticipants() const;
	
	// Private
	private:
	
		// ID
		uint8_t id[Common::UUID_SIZE];
		
		// Amount
		uint64_t amount;
		
		// Fee
		uint64_t fee;
		
		// Height
		uint64_t height;
		
		// Lock height
		uint64_t lockHeight;
		
		// Time to live cut off height
		optional<uint64_t> timeToLiveCutOffHeight;
		
		// Participants
		list<SlateParticipant> participants;
		
		// Output
		optional<SlateOutput> output;
		
		// Sender payment proof address public key
		vector<uint8_t> senderPaymentProofAddressPublicKey;
		
		// Recipient payment proof address public key
		vector<uint8_t> recipientPaymentProofAddressPublicKey;
		
		// Recipient payment proof signature
		vector<uint8_t> recipientPaymentProofSignature;
		
		// Offset
		uint8_t offset[Crypto::SCALAR_SIZE];
};


#endif
