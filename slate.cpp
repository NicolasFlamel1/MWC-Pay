// Header files
#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>
#include "./bit_reader.h"
#include "./bit_writer.h"
#include "./common.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "./slate.h"

using namespace std;


// Constants

// Compressed boolean size
const size_t Slate::COMPRESSED_BOOLEAN_SIZE = 1;

// Compressed public key size size
const size_t Slate::COMPRESSED_PUBLIC_KEY_SIZE_SIZE = 7;

// Compressed purpose size
static const size_t COMPRESSED_PURPOSE_SIZE = 3;

// Compressed payment proof signature size size
static const size_t COMPRESSED_PAYMENT_PROOF_SIGNATURE_SIZE_SIZE = 4;

// Compressed number of hundreds size
static const size_t COMPRESSED_NUMBER_OF_HUNDREDS_SIZE = 3;

// Compressed number of digits size
static const size_t COMPRESSED_NUMBER_OF_DIGITS_SIZE = 6;

// Compressed hundreds scaling factor
static const size_t COMPRESSED_HUNDREDS_SCALING_FACTOR = 100;

// Purpose
enum class Purpose {

	// Send initial
	SEND_INITIAL,
	
	// Send response
	SEND_RESPONSE
};


// Function prototypes

// Uncompress uint64
static uint64_t uncompressUint64(BitReader &bitReader, const bool hasHundreds);

// Compress uint64
static void compressUint64(const uint64_t value, BitWriter &bitWriter, const bool hasHundreds);

// Uncompress public key
static vector<uint8_t> uncompressPublicKey(BitReader &bitReader);

// Compress public key
static void compressPublicKey(const vector<uint8_t> &publicKey, BitWriter &bitWriter);


// Supporting function implementation

// Constructor
Slate::Slate(const uint8_t *data, const size_t length) {

	// Initialize bit reader
	BitReader bitReader(data, length);
	
	// Check if purpose is invalid
	if(bitReader.getBits(COMPRESSED_PURPOSE_SIZE) != static_cast<underlying_type<Purpose>::type>(Purpose::SEND_INITIAL)) {
	
		// Throw exception
		throw runtime_error("Purpose is invalid");
	}
	
	// Get ID
	const vector id = bitReader.getBytes(sizeof(this->id));
	
	// Check if ID is a variant two UUID
	if(((id[Common::UUID_DATA_VARIANT_INDEX] >> 4) & Common::UUID_VARIANT_TWO_BITMASK) == Common::UUID_VARIANT_TWO_BITMASK_RESULT) {
	
		// Check if ID is invalid
		if((id[Common::UUID_VARIANT_TWO_DATA_VERSION_INDEX] >> 4) != 4) {
		
			// Throw exception
			throw runtime_error("ID is invalid");
		}
	}
	
	// Otherwise
	else {
	
		// Check if ID is invalid
		if((id[Common::UUID_VARIANT_ONE_DATA_VERSION_INDEX] >> 4) != 4) {
		
			// Throw exception
			throw runtime_error("ID is invalid");
		}
	}
	
	// Set ID
	memcpy(this->id, id.data(), id.size());
	
	// Check if floonet
	#ifdef ENABLE_FLOONET
	
		// Check if is mainnet is invalid
		if(bitReader.getBits(COMPRESSED_BOOLEAN_SIZE)) {
		
			// Throw exception
			throw runtime_error("Is mainnet is invalid");
		}
		
	// Otherwise
	#else
	
		// Check if is mainnet is invalid
		if(!bitReader.getBits(COMPRESSED_BOOLEAN_SIZE)) {
		
			// Throw exception
			throw runtime_error("Is mainnet is invalid");
		}
	#endif
	
	// Get amount
	amount = uncompressUint64(bitReader, true);
	
	// Check if amount is invalid
	if(!amount) {
	
		// Throw exception
		throw runtime_error("Amount is invalid");
	}
	
	// Get fee
	fee = uncompressUint64(bitReader, true);
	
	// Check if fee is invalid
	if(!fee) {
	
		// Throw exception
		throw runtime_error("Fee is invalid");
	}
	
	// Get height
	height = uncompressUint64(bitReader, false);
	
	// Get lock height
	lockHeight = uncompressUint64(bitReader, false);
	
	// Check if time to live cut off height exists
	if(bitReader.getBits(COMPRESSED_BOOLEAN_SIZE)) {
	
		// Get time to live cut off height
		*timeToLiveCutOffHeight = uncompressUint64(bitReader, false);
		
		// Check if time to live cut off height is invalid
		if(*timeToLiveCutOffHeight <= height || *timeToLiveCutOffHeight < lockHeight) {
		
			// Throw exception
			throw runtime_error("Time to live cut off height is invalid");
		}
	}
	
	// Add participant to list
	participants.emplace_back(bitReader);
	
	// Check if payment proof exists
	if(bitReader.getBits(COMPRESSED_BOOLEAN_SIZE)) {
	
		// Get sender payment proof address public key
		senderPaymentProofAddressPublicKey = uncompressPublicKey(bitReader);
		
		// Get recipient payment proof address
		recipientPaymentProofAddressPublicKey = uncompressPublicKey(bitReader);
	}
}

// Create random offset
bool Slate::createRandomOffset(const uint8_t blindingFactor[Crypto::BLINDING_FACTOR_SIZE]) {

	// While offset isn't a valid secp256k1 private key or its equal to the blinding factor
	do {
	
		// Check if creating random offset failed
		if(RAND_bytes_ex(nullptr, offset, sizeof(offset), RAND_DRBG_STRENGTH) != 1) {
		
			// Return false
			return false;
		}
		
	} while(!Crypto::isValidSecp256k1PrivateKey(offset, sizeof(offset)) || !CRYPTO_memcmp(offset, blindingFactor, sizeof(offset)));
	
	// Return true
	return true;
}

// Get amount
uint64_t Slate::getAmount() const {

	// Return amount
	return amount;
}

// Get lock height
uint64_t Slate::getLockHeight() const {

	// Return lock height
	return lockHeight;
}

// Get sender payment proof address public key
const vector<uint8_t> &Slate::getSenderPaymentProofAddressPublicKey() const {

	// Return sender payment proof address public key
	return senderPaymentProofAddressPublicKey;
}

// Get recipient payment proof address public key
const vector<uint8_t> &Slate::getRecipientPaymentProofAddressPublicKey() const {

	// Return recipient payment proof address public key
	return recipientPaymentProofAddressPublicKey;
}

// Set recipient payment proof address public key
void Slate::setRecipientPaymentProofAddressPublicKey(const uint8_t *recipientPaymentProofAddressPublicKey, const size_t recipientPaymentProofAddressPublicKeyLength) {

	// Set recipient payment proof address public key
	this->recipientPaymentProofAddressPublicKey.assign(recipientPaymentProofAddressPublicKey, recipientPaymentProofAddressPublicKey + recipientPaymentProofAddressPublicKeyLength);
}

// Set output
void Slate::setOutput(const SlateOutput &output) {

	// Set output
	this->output = output;
}

// Get offset
const uint8_t *Slate::getOffset() const {

	// Return offset
	return offset;
}

// Add participant
void Slate::addParticipant(const SlateParticipant &participant) {

	// Add participant to participants
	participants.push_back(participant);
}

// Get public blind excess sum
bool Slate::getPublicBlindExcessSum(uint8_t publicBlindExcessSum[Crypto::SECP256K1_PUBLIC_KEY_SIZE]) const {

	// Initialize public blind excesses
	const uint8_t *publicBlindExcesses[participants.size()];
	
	// Go through all participants
	size_t i = 0;
	for(list<SlateParticipant>::const_iterator j = participants.cbegin(); j != participants.cend(); ++j) {
	
		// Add participant's public blind excess to list
		publicBlindExcesses[i++] = j->getPublicBlindExcess();
	}
	
	// Check if combining public blind excesses failed
	if(!Crypto::combineSecp256k1PublicKeys(publicBlindExcessSum, publicBlindExcesses, sizeof(publicBlindExcesses) / sizeof(publicBlindExcesses[0]))) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get public nonce sum
bool Slate::getPublicNonceSum(uint8_t publicNonceSum[Crypto::SECP256K1_PUBLIC_KEY_SIZE]) const {

	// Initialize public nonces
	const uint8_t *publicNonces[participants.size()];
	
	// Go through all participants
	size_t i = 0;
	for(list<SlateParticipant>::const_iterator j = participants.cbegin(); j != participants.cend(); ++j) {
	
		// Add participant's public nonce to list
		publicNonces[i++] = j->getPublicNonce();
	}
	
	// Check if combining public nonces failed
	if(!Crypto::combineSecp256k1PublicKeys(publicNonceSum, publicNonces, sizeof(publicNonces) / sizeof(publicNonces[0]))) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get kernel data
vector<uint8_t> Slate::getKernelData() const {

	// Check kernel features
	switch(getKernelFeatures()) {
	
		// Plain kernel features
		case KernelFeatures::PLAIN: {
		
			// Set kernel data
			vector<uint8_t> kernelData(sizeof(uint8_t) + sizeof(fee));
			kernelData[0] = static_cast<underlying_type<KernelFeatures>::type>(KernelFeatures::PLAIN);
			memcpy(&kernelData[sizeof(uint8_t)], &fee, sizeof(fee));
			
			// Check if little endian
			#if BYTE_ORDER == LITTLE_ENDIAN
			
				// Make fee in the kernel data big endian
				*reinterpret_cast<uint64_t *>(&kernelData[sizeof(uint8_t)]) = __builtin_bswap64(*reinterpret_cast<uint64_t *>(&kernelData[sizeof(uint8_t)]));
			#endif
			
			// Return kernel data
			return kernelData;
		}
		
		// Coinbase features or default
		case KernelFeatures::COINBASE:
		default: {
		
			// Set kernel data
			vector<uint8_t> kernelData(sizeof(uint8_t));
			kernelData[0] = static_cast<underlying_type<KernelFeatures>::type>(KernelFeatures::COINBASE);
			
			// Return kernel data
			return kernelData;
		}
		
		// Height locked kernel features
		case KernelFeatures::HEIGHT_LOCKED: {
		
			// Set kernel data
			vector<uint8_t> kernelData(sizeof(uint8_t) + sizeof(fee) + sizeof(lockHeight));
			kernelData[0] = static_cast<underlying_type<KernelFeatures>::type>(KernelFeatures::HEIGHT_LOCKED);
			memcpy(&kernelData[sizeof(uint8_t)], &fee, sizeof(fee));
			memcpy(&kernelData[sizeof(uint8_t) + sizeof(fee)], &lockHeight, sizeof(lockHeight));
			
			// Check if little endian
			#if BYTE_ORDER == LITTLE_ENDIAN
			
				// Make fee and lock height in the kernel data big endian
				*reinterpret_cast<uint64_t *>(&kernelData[sizeof(uint8_t)]) = __builtin_bswap64(*reinterpret_cast<uint64_t *>(&kernelData[sizeof(uint8_t)]));
				*reinterpret_cast<uint64_t *>(&kernelData[sizeof(uint8_t) + sizeof(fee)]) = __builtin_bswap64(*reinterpret_cast<uint64_t *>(&kernelData[sizeof(uint8_t) + sizeof(fee)]));
			#endif
			
			// Return kernel data
			return kernelData;
		}
	}
}

// Set participant's partial signature
void Slate::setParticipantsPartialSignature(const uint8_t partialSignature[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE]) {

	// Set participant's partial signature
	participants.rbegin()->setPartialSignature(partialSignature);
}

// Get excess
bool Slate::getExcess(uint8_t excess[Crypto::COMMITMENT_SIZE]) const {

	// Check if getting public blind excess sum failed
	uint8_t publicBlindExcessSum[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
	if(!getPublicBlindExcessSum(publicBlindExcessSum)) {
	
		// Return false
		return false;
	}
	
	// Check if getting commitment from public blind excess sum failed
	if(!Crypto::secp256k1PublicKeyToCommitment(excess, publicBlindExcessSum)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Set recipient payment proof signature
void Slate::setRecipientPaymentProofSignature(const uint8_t *recipientPaymentProofSignature, const size_t recipientPaymentProofSignatureLength) {

	// Set recipient payment proof signature
	this->recipientPaymentProofSignature.assign(recipientPaymentProofSignature, recipientPaymentProofSignature + recipientPaymentProofSignatureLength);
}

// Serialize
vector<uint8_t> Slate::serialize() const {

	// Initialize bit writer
	BitWriter bitWriter;
	
	// Write purpose
	bitWriter.setBits(static_cast<underlying_type<Purpose>::type>(Purpose::SEND_RESPONSE), COMPRESSED_PURPOSE_SIZE);
	
	// Write ID
	bitWriter.setBytes(id, sizeof(id));
	
	// Check if floonet
	#ifdef ENABLE_FLOONET
	
		// Write is mainnet
		bitWriter.setBits(false, COMPRESSED_BOOLEAN_SIZE);
		
	// Otherwise
	#else
	
		// Write is mainnet
		bitWriter.setBits(true, COMPRESSED_BOOLEAN_SIZE);
	#endif
	
	// Write height
	compressUint64(height, bitWriter, false);
	
	// Write lock height
	compressUint64(lockHeight, bitWriter, false);
	
	// Check if time to live cut off height exists
	if(timeToLiveCutOffHeight) {
	
		// Write time to live cut off height exists
		bitWriter.setBits(true, COMPRESSED_BOOLEAN_SIZE);
		
		// Write time to live cut off height
		compressUint64(*timeToLiveCutOffHeight, bitWriter, false);
	}
	
	// Otherwise
	else {
	
		// Write time to live cut off height doesn't exist
		bitWriter.setBits(false, COMPRESSED_BOOLEAN_SIZE);
	}
	
	// Write offset
	bitWriter.setBytes(offset, sizeof(offset));
	
	// Serialize output
	output->serialize(bitWriter);
	
	// Write end of outputs
	bitWriter.setBits(false, COMPRESSED_BOOLEAN_SIZE);
	
	// Check if kernel features isn't plain
	if(getKernelFeatures() != KernelFeatures::PLAIN) {
	
		// Throw exception
		throw runtime_error("Kernel features isn't plain");
	}
	
	// Write kernel fee
	compressUint64(fee, bitWriter, true);
	
	// Write kernel excess
	const uint8_t kernelExcess[Crypto::COMMITMENT_SIZE] = {};
	bitWriter.setBytes(kernelExcess, sizeof(kernelExcess));
	
	// Writer kernel excess signature
	const uint8_t kernelExcessSignature[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE] = {};
	bitWriter.setBytes(kernelExcessSignature, sizeof(kernelExcessSignature));
	
	// Write end of kernels
	bitWriter.setBits(false, COMPRESSED_BOOLEAN_SIZE);
	
	// Serialize participant
	participants.crbegin()->serialize(bitWriter);
	
	// Write payment proof exists
	bitWriter.setBits(true, COMPRESSED_BOOLEAN_SIZE);
	
	// Write sender payment proof address public key
	compressPublicKey(senderPaymentProofAddressPublicKey, bitWriter);
	
	// Write recipient payment proof address public key
	compressPublicKey(recipientPaymentProofAddressPublicKey, bitWriter);
	
	// Write recipient payment proof signature exists
	bitWriter.setBits(true, COMPRESSED_BOOLEAN_SIZE);
	
	// Write recipient payment proof signature length
	bitWriter.setBits(recipientPaymentProofSignature.size() - Crypto::ED25519_SIGNATURE_SIZE, COMPRESSED_PAYMENT_PROOF_SIGNATURE_SIZE_SIZE);
	
	// Write recipient payment proof signature
	bitWriter.setBytes(recipientPaymentProofSignature.data(), recipientPaymentProofSignature.size());
	
	// Return bit writer's bytes
	return bitWriter.getBytes();
}

// Get kernel features
Slate::KernelFeatures Slate::getKernelFeatures() const {

	// Check if lock height exists
	if(lockHeight) {
	
		// Return height locked kernel features
		return KernelFeatures::HEIGHT_LOCKED;
	}
	
	// Otherwise
	else {
	
		// Return plain kernel features
		return KernelFeatures::PLAIN;
	}
}

// Get participants
const list<SlateParticipant> &Slate::getParticipants() const {

	// Return participants
	return participants;
}

// Uncompress uint64
uint64_t uncompressUint64(BitReader &bitReader, const bool hasHundreds) {

	// Get number of hundreds
	const uint64_t numberOfHundreds = hasHundreds ? bitReader.getBits(COMPRESSED_NUMBER_OF_HUNDREDS_SIZE) : 0;
	
	// Get number of digits
	const uint64_t numberOfDigits = bitReader.getBits(COMPRESSED_NUMBER_OF_DIGITS_SIZE) + 1;
	
	// Go through all digits
	uint8_t digitBytes[1 + (numberOfDigits - 1) / numeric_limits<uint8_t>::digits];
	for(size_t i = 0, j = numberOfDigits;; ++i, j -= numeric_limits<uint8_t>::digits) {
	
		// Get digit byte
		digitBytes[i] = bitReader.getBits(min(j, static_cast<size_t>(numeric_limits<uint8_t>::digits)));
		
		// Check if at the last digit byte
		if(j <= numeric_limits<uint8_t>::digits) {
		
			// Break
			break;
		}
	}
	
	// Check if number of digits isn't an exact number of bytes
	if(numberOfDigits > numeric_limits<uint8_t>::digits && numberOfDigits % numeric_limits<uint8_t>::digits) {
	
		// Go through all digit bytes backwards
		for(size_t i = sizeof(digitBytes) - 1;; --i) {
		
			// Check if byte isn't the last byte
			if(i != sizeof(digitBytes) - 1) {
			
				// Shift bits in the byte right
				digitBytes[i] >>= numeric_limits<uint8_t>::digits - numberOfDigits % numeric_limits<uint8_t>::digits;
			}
			
			// Check if byte isn't the first byte
			if(i) {
			
				// Update byte with shifted bits from the next byte
				digitBytes[i] |= digitBytes[i - 1] << (numberOfDigits % numeric_limits<uint8_t>::digits);
			}
			
			// Otherwise
			else {
			
				// Break
				break;
			}
		}
	}
	
	// Get result of digit bytes
	uint64_t result = 0;
	memcpy(&reinterpret_cast<uint8_t *>(&result)[sizeof(result) - sizeof(digitBytes)], digitBytes, sizeof(digitBytes));
	
	// Check if little endian
	#if BYTE_ORDER == LITTLE_ENDIAN
	
		// Make result little endian
		result = __builtin_bswap64(result);
	#endif
	
	// Go through all hundreds
	for(uint64_t i = 0; i < numberOfHundreds; ++i) {
	
		// Check if result will overflow
		if(result && COMPRESSED_HUNDREDS_SCALING_FACTOR > numeric_limits<uint64_t>::max() / result) {
		
			// Throw exception
			throw runtime_error("Result will overflow");
		}
	
		// Update result
		result *= COMPRESSED_HUNDREDS_SCALING_FACTOR;
	}
	
	// Return result
	return result;
}

// Compress uint64
void compressUint64(uint64_t value, BitWriter &bitWriter, const bool hasHundreds) {

	// Check if has hundreds
	uint64_t numberOfhundreds = 0;
	if(hasHundreds) {
		
		// Go through all hundreds in the value
		while(value % COMPRESSED_HUNDREDS_SCALING_FACTOR == 0 && numberOfhundreds < pow(2, COMPRESSED_NUMBER_OF_HUNDREDS_SIZE) - 1) {
		
			// Remove hundred from the value
			value /= COMPRESSED_HUNDREDS_SCALING_FACTOR;
			
			// Increment number of hundreds
			++numberOfhundreds;
		}
	}
	
	// Initialize number of digits
	uint64_t numberOfDigits = 1;
	
	// Go through all digits in the value
	for(uint64_t i = 1; numberOfDigits < pow(2, COMPRESSED_NUMBER_OF_DIGITS_SIZE) && i < value; i <<= 1) {
	
		// Increment number of digits
		++numberOfDigits;
	}
	
	// Check if has hundreds
	if(hasHundreds) {
	
		// Write number of hundreds
		bitWriter.setBits(numberOfhundreds, COMPRESSED_NUMBER_OF_HUNDREDS_SIZE);
	}
	
	// Write number of digits
	bitWriter.setBits(numberOfDigits - 1, COMPRESSED_NUMBER_OF_DIGITS_SIZE);
	
	// Check if little endian
	#if BYTE_ORDER == LITTLE_ENDIAN
	
		// Make value big endian
		value = __builtin_bswap64(value);
	#endif
	
	uint8_t bytes[(numberOfDigits + (numeric_limits<uint8_t>::digits - 1)) / numeric_limits<uint8_t>::digits];
	memcpy(bytes, &reinterpret_cast<const uint8_t *>(&value)[sizeof(value) - sizeof(bytes)], sizeof(bytes));
	
	// Go through all bytes
	for(size_t i = 0; i < sizeof(bytes); ++i) {
	
		// Check if there isn't an exact number of bytes
		if(numberOfDigits % numeric_limits<uint8_t>::digits) {
		
			// Check if not the last byte
			if(i != sizeof(bytes) - 1) {
			
				// Remove upper bits
				bytes[i] <<= numeric_limits<uint8_t>::digits - numberOfDigits % numeric_limits<uint8_t>::digits;
			
				// Include lower bits from next byte
				bytes[i] |= bytes[i + 1] >> (numberOfDigits % numeric_limits<uint8_t>::digits);
				
				// Write byte
				bitWriter.setBits(bytes[i], numeric_limits<uint8_t>::digits);
			}
			
			// Otherwise
			else {
			
				// Write byte
				bitWriter.setBits(bytes[i], numberOfDigits % numeric_limits<uint8_t>::digits);
			}
		}
		
		// Otherwise
		else {
		
			// Write byte
			bitWriter.setBits(bytes[i], numeric_limits<uint8_t>::digits);
		}
	}
}

// Uncompress public key
vector<uint8_t> uncompressPublicKey(BitReader &bitReader) {

	// Check if public key is a Secp256k1 public key
	if(bitReader.getBits(Slate::COMPRESSED_BOOLEAN_SIZE)) {
	
		// Get public key
		vector publicKey = bitReader.getBytes(bitReader.getBits(Slate::COMPRESSED_PUBLIC_KEY_SIZE_SIZE));
		
		// Check if public key isn't a valid secp256k1 public key
		if(!Crypto::isValidSecp256k1PublicKey(publicKey.data(), publicKey.size())) {
		
			// Throw exception
			throw runtime_error("Public key isn't a valid secp256k1 public key");
		}
		
		// Return public key
		return publicKey;
	}
	
	// Otherwise
	else {
	
		// Get public key
		vector publicKey = bitReader.getBytes(Crypto::ED25519_PUBLIC_KEY_SIZE);
		
		// Check if public key isn't a valid Ed25519 public key
		if(!Crypto::isValidEd25519PublicKey(publicKey.data(), publicKey.size())) {
		
			// Throw exception
			throw runtime_error("Public key isn't a valid Ed25519 public key");
		}
		
		// Return public key
		return publicKey;
	}
}

// Compress public key
void compressPublicKey(const vector<uint8_t> &publicKey, BitWriter &bitWriter) {

	// Check if public key is a secp256k1 public key
	if(publicKey.size() == Crypto::SECP256K1_PUBLIC_KEY_SIZE) {
	
		// Write that public key is a secp256k1 public key
		bitWriter.setBits(true, Slate::COMPRESSED_BOOLEAN_SIZE);
		
		// Write public key length
		bitWriter.setBits(publicKey.size(), Slate::COMPRESSED_PUBLIC_KEY_SIZE_SIZE);
		
		// Write public key
		bitWriter.setBytes(publicKey.data(), publicKey.size());
	}
	
	// Otherwise
	else {
	
		// Write that public key is an Ed25519 public key
		bitWriter.setBits(false, Slate::COMPRESSED_BOOLEAN_SIZE);
		
		// Write public key
		bitWriter.setBytes(publicKey.data(), publicKey.size());
	}
}
