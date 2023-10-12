// Header files
#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include "./base58.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "./slatepack.h"

using namespace std;


// Constants

// Header
static const char HEADER[] = "BEGINSLATE_BIN. ";

// Footer
static const char FOOTER[] = ". ENDSLATE_BIN.";

// Encrypted header
static const char ENCRYPTED_HEADER[] = "BEGINSLATEPACK. ";

// Encrypted footer
static const char ENCRYPTED_FOOTER[] = ". ENDSLATEPACK.";

// Checksum digest algorithm
static const char *CHECKSUM_DIGEST_ALGORITHM = "SHA-256";

// Checksum size
static const size_t CHECKSUM_SIZE = 4;

// Version
static const uint8_t VERSION = 0;


// Function prototypes

// Get checksum
static void getChecksum(uint8_t checksum[CHECKSUM_SIZE], const uint8_t *data, const size_t length);


// Supporting function implementation

// Encode
string Slatepack::encode(const uint8_t *data, const size_t length, const uint8_t recipientPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE], const Wallet &wallet, const uint64_t index) {

	// Check if not encrypting
	if(!recipientPublicKey) {
	
		// Check if length is invalid
		if(length > numeric_limits<uint16_t>::max()) {
		
			// Throw exception
			throw runtime_error("Length is invalid");
		}
		
		// Create payload
		uint8_t payload[CHECKSUM_SIZE + sizeof(VERSION) + sizeof(uint16_t) + length];
		payload[CHECKSUM_SIZE] = VERSION;
		payload[CHECKSUM_SIZE + sizeof(VERSION)] = length >> numeric_limits<uint8_t>::digits;
		payload[CHECKSUM_SIZE + sizeof(VERSION) + 1] = length & numeric_limits<uint8_t>::max();
		memcpy(&payload[CHECKSUM_SIZE + sizeof(VERSION) + sizeof(uint16_t)], data, length);
		getChecksum(payload, &payload[CHECKSUM_SIZE], sizeof(payload) - CHECKSUM_SIZE);
		
		// Return encoded payload with a header and footer
		return HEADER + Base58::encode(payload, sizeof(payload)) + FOOTER;
	}
	
	// Otherwise
	else {
	
		// Encrypt data
		const pair encryptedData = wallet.encryptAddressMessage(data, length, recipientPublicKey, index, VERSION);
		
		// Check if encrypted data's length is invalid
		if(encryptedData.first.size() > numeric_limits<uint16_t>::max()) {
		
			// Throw exception
			throw runtime_error("Encrypted data's length is invalid");
		}
		
		// Check if getting sender public key from wallet failed
		uint8_t senderPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE];
		if(!wallet.getTorPaymentProofAddressPublicKey(senderPublicKey, index)) {
		
			// Throw exception
			throw runtime_error("Getting sender public key from wallet failed");
		}
		
		// Create payload
		uint8_t payload[CHECKSUM_SIZE + sizeof(VERSION) + sizeof(senderPublicKey) + Crypto::ED25519_PUBLIC_KEY_SIZE + encryptedData.second.size() + sizeof(uint16_t) + encryptedData.first.size()];
		payload[CHECKSUM_SIZE] = VERSION;
		memcpy(&payload[CHECKSUM_SIZE + sizeof(VERSION)], senderPublicKey, sizeof(senderPublicKey));
		memcpy(&payload[CHECKSUM_SIZE + sizeof(VERSION) + sizeof(senderPublicKey)], recipientPublicKey, Crypto::ED25519_PUBLIC_KEY_SIZE);
		memcpy(&payload[CHECKSUM_SIZE + sizeof(VERSION) + sizeof(senderPublicKey) + Crypto::ED25519_PUBLIC_KEY_SIZE], encryptedData.second.data(), encryptedData.second.size());
		payload[CHECKSUM_SIZE + sizeof(VERSION) + sizeof(senderPublicKey) + Crypto::ED25519_PUBLIC_KEY_SIZE + encryptedData.second.size()] = encryptedData.first.size() >> numeric_limits<uint8_t>::digits;
		payload[CHECKSUM_SIZE + sizeof(VERSION) + sizeof(senderPublicKey) + Crypto::ED25519_PUBLIC_KEY_SIZE + encryptedData.second.size() + 1] = encryptedData.first.size() & numeric_limits<uint8_t>::max();
		memcpy(&payload[CHECKSUM_SIZE + sizeof(VERSION) + sizeof(senderPublicKey) + Crypto::ED25519_PUBLIC_KEY_SIZE + encryptedData.second.size() + sizeof(uint16_t)], encryptedData.first.data(), encryptedData.first.size());
		getChecksum(payload, &payload[CHECKSUM_SIZE], sizeof(payload) - CHECKSUM_SIZE);
		
		// Return encoded payload with an encrypted header and footer
		return ENCRYPTED_HEADER + Base58::encode(payload, sizeof(payload)) + ENCRYPTED_FOOTER;
	}
}

// Decode
pair<vector<uint8_t>, optional<array<uint8_t, Crypto::ED25519_PUBLIC_KEY_SIZE>>> Slatepack::decode(const char *data, const Wallet &wallet, const uint64_t index) {

	// Get length
	const size_t length = strlen(data);
	
	// Check if data has a header and footer
	if(length >= sizeof(HEADER) - sizeof('\0') + sizeof(FOOTER) - sizeof('\0') && !strncmp(data, HEADER, sizeof(HEADER) - sizeof('\0')) && !strncmp(&data[length - (sizeof(FOOTER) - sizeof('\0'))], FOOTER, sizeof(FOOTER) - sizeof('\0'))) {
	
		// Get encoded payload from data and remove spaces and newlines from it
		string encodedPayload(&data[sizeof(HEADER) - sizeof('\0')], &data[sizeof(HEADER) - sizeof('\0')] + length - (sizeof(HEADER) - sizeof('\0') + sizeof(FOOTER) - sizeof('\0')));
		encodedPayload.erase(remove_if(encodedPayload.begin(), encodedPayload.end(), ([](const char character) -> bool {
		
			// Return if character is a space or newline
			return character == ' ' || character == '\n';
			
		})), encodedPayload.end());
		
		// Decode encoded payload
		vector payload = Base58::decode(encodedPayload.c_str());
		
		// Check if payload doesn't contain a checksum and version
		if(payload.size() < CHECKSUM_SIZE + sizeof(VERSION)) {
		
			// Throw exception
			throw runtime_error("Payload doesn't contain a checksum and version");
		}
		
		// Get payload's checksum
		uint8_t checksum[CHECKSUM_SIZE];
		getChecksum(checksum, &payload[CHECKSUM_SIZE], payload.size() - CHECKSUM_SIZE);
		
		// Check if payload's checksum is invalid
		if(memcmp(payload.data(), checksum, sizeof(checksum))) {
		
			// Throw exception
			throw runtime_error("Payload's checksum is invalid");
		}
		
		// Get payload's version
		const uint8_t version = payload[CHECKSUM_SIZE];
		
		// Check if payload's version is invalid
		if(version != VERSION) {
		
			// Throw exception
			throw runtime_error("Payload's version is invalid");
		}
		
		// Check if payload doesn't contain a length
		if(payload.size() < CHECKSUM_SIZE + sizeof(version) + sizeof(uint16_t)) {
		
			// Throw exception
			throw runtime_error("Payload doesn't contain a length");
		}
		
		// Get payload's slate length
		const uint16_t slateLength = (payload[CHECKSUM_SIZE + sizeof(version)] << numeric_limits<uint8_t>::digits) | payload[CHECKSUM_SIZE + sizeof(version) + 1];
		
		// Check if slate length is invalid
		if(slateLength != payload.size() - (CHECKSUM_SIZE + sizeof(version) + sizeof(slateLength))) {
		
			// Throw exception
			throw runtime_error("Slate length is invalid");
		}
		
		// Remove everything except the slate from the payload
		payload.erase(payload.begin(), payload.begin() + CHECKSUM_SIZE + sizeof(version) + sizeof(slateLength));
		
		// Return payload
		return {payload, nullopt};
	}
	
	// Otherwise check if data has an encrypted header and footer
	else if(length >= sizeof(ENCRYPTED_HEADER) - sizeof('\0') + sizeof(ENCRYPTED_FOOTER) - sizeof('\0') && !strncmp(data, ENCRYPTED_HEADER, sizeof(ENCRYPTED_HEADER) - sizeof('\0')) && !strncmp(&data[length - (sizeof(ENCRYPTED_FOOTER) - sizeof('\0'))], ENCRYPTED_FOOTER, sizeof(ENCRYPTED_FOOTER) - sizeof('\0'))) {
	
		// Get encoded payload from data and remove spaces and newlines from it
		string encodedPayload(&data[sizeof(ENCRYPTED_HEADER) - sizeof('\0')], &data[sizeof(ENCRYPTED_HEADER) - sizeof('\0')] + length - (sizeof(ENCRYPTED_HEADER) - sizeof('\0') + sizeof(ENCRYPTED_FOOTER) - sizeof('\0')));
		encodedPayload.erase(remove_if(encodedPayload.begin(), encodedPayload.end(), ([](const char character) -> bool {
		
			// Return if character is a space or newline
			return character == ' ' || character == '\n';
			
		})), encodedPayload.end());
		
		// Decode encoded payload
		const vector payload = Base58::decode(encodedPayload.c_str());
		
		// Check if payload doesn't contain a checksum and version
		if(payload.size() < CHECKSUM_SIZE + sizeof(VERSION)) {
		
			// Throw exception
			throw runtime_error("Payload doesn't contain a checksum and version");
		}
		
		// Get payload's checksum
		uint8_t checksum[CHECKSUM_SIZE];
		getChecksum(checksum, &payload[CHECKSUM_SIZE], payload.size() - CHECKSUM_SIZE);
		
		// Check if payload's checksum is invalid
		if(memcmp(payload.data(), checksum, sizeof(checksum))) {
		
			// Throw exception
			throw runtime_error("Payload's checksum is invalid");
		}
		
		// Get payload's version
		const uint8_t version = payload[CHECKSUM_SIZE];
		
		// Check if payload's version is invalid
		if(version != VERSION) {
		
			// Throw exception
			throw runtime_error("Payload's version is invalid");
		}
		
		// Check if payload doesn't contain a sender public key, recipient public key, nonce, and length
		if(payload.size() < CHECKSUM_SIZE + sizeof(version) + Crypto::ED25519_PUBLIC_KEY_SIZE + Crypto::ED25519_PUBLIC_KEY_SIZE + Crypto::CHACHA20_NONCE_SIZE + sizeof(uint16_t)) {
		
			// Throw exception
			throw runtime_error("Payload doesn't contain a sender public key, recipient public key, nonce, and length");
		}
		
		// Get payload's sender public key
		array<uint8_t, Crypto::ED25519_PUBLIC_KEY_SIZE> senderPublicKey;
		memcpy(senderPublicKey.data(), &payload[CHECKSUM_SIZE + sizeof(version)], Crypto::ED25519_PUBLIC_KEY_SIZE);
		
		// Check if sender public key is invalid
		if(!Crypto::isValidEd25519PublicKey(senderPublicKey.data(), senderPublicKey.size())) {
		
			// Throw exception
			throw runtime_error("Sender public key is invalid");
		}
		
		// Get payload's recipient public key
		const uint8_t *recipientPublicKey = &payload[CHECKSUM_SIZE + sizeof(version) + senderPublicKey.size()];
		
		// Check if getting expected recipient public key from wallet failed
		uint8_t expectedRecipientPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE];
		if(!wallet.getTorPaymentProofAddressPublicKey(expectedRecipientPublicKey, index)) {
		
			// Throw exception
			throw runtime_error("Getting expected recipient public key from wallet failed");
		}
		
		// Check if recipient public key is invalid
		if(memcmp(expectedRecipientPublicKey, recipientPublicKey, sizeof(expectedRecipientPublicKey))) {
		
			// Throw exception
			throw runtime_error("Recipient public key is invalid");
		}
		
		// Get payload's nonce
		const uint8_t *nonce = &payload[CHECKSUM_SIZE + sizeof(version) + senderPublicKey.size() + Crypto::ED25519_PUBLIC_KEY_SIZE];
		
		// Get payload's encrypted slate length
		const uint16_t encryptedSlateLength = (payload[CHECKSUM_SIZE + sizeof(version) + senderPublicKey.size() + Crypto::ED25519_PUBLIC_KEY_SIZE + Crypto::CHACHA20_NONCE_SIZE] << numeric_limits<uint8_t>::digits) | payload[CHECKSUM_SIZE + sizeof(version) + senderPublicKey.size() + Crypto::ED25519_PUBLIC_KEY_SIZE + Crypto::CHACHA20_NONCE_SIZE + 1];
		
		// Check if encrypted slate length is invalid
		if(encryptedSlateLength != payload.size() - (CHECKSUM_SIZE + sizeof(version) + senderPublicKey.size() + Crypto::ED25519_PUBLIC_KEY_SIZE + Crypto::CHACHA20_NONCE_SIZE + sizeof(encryptedSlateLength))) {
		
			// Throw exception
			throw runtime_error("Encrypted slate length is invalid");
		}
		
		// Get payload's encrypted slate
		const uint8_t *encryptedSlate = &payload[CHECKSUM_SIZE + sizeof(version) + senderPublicKey.size() + Crypto::ED25519_PUBLIC_KEY_SIZE + Crypto::CHACHA20_NONCE_SIZE + sizeof(encryptedSlateLength)];
		
		// Return decrypted slate and sender public key
		return {wallet.decryptAddressMessage(encryptedSlate, encryptedSlateLength, nonce, senderPublicKey.data(), index, version), senderPublicKey};
	}
	
	// Otherwise
	else {
	
		// Throw exception
		throw runtime_error("Data doesn't have a valid header and footer");
	}
}

// Get checksum
void getChecksum(uint8_t checksum[CHECKSUM_SIZE], const uint8_t *data, const size_t length) {

	// Check if getting digest failed
	const unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(EVP_MD_fetch(nullptr, CHECKSUM_DIGEST_ALGORITHM, nullptr), EVP_MD_free);
	if(!digest) {
	
		// Throw exception
		throw runtime_error("Getting digest failed");
	}
	
	// Check if creating digest context failed
	const unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if(!digestContext) {
	
		// Throw exception
		throw runtime_error("Creating digest context failed");
	}
	
	// Check if initializing digest context failed
	if(!EVP_DigestInit_ex2(digestContext.get(), digest.get(), nullptr)) {
	
		// Throw exception
		throw runtime_error("Initializing digest context failed");
	}
	
	// Check if hashing data failed
	if(!EVP_DigestUpdate(digestContext.get(), data, length)) {
	
		// Throw exception
		throw runtime_error("Hashing data failed");
	}
	
	// Check if getting digest length failed
	size_t digestLength;
	OSSL_PARAM getDigestLengthParameters[] = {
	
		// Digest length
		OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &digestLength),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_MD_get_params(digest.get(), getDigestLengthParameters)) {
	
		// Throw exception
		throw runtime_error("Getting digest length failed");
	}
	
	// Check if getting hash failed
	uint8_t hash[digestLength];
	unsigned int hashLength;
	if(!EVP_DigestFinal_ex(digestContext.get(), hash, &hashLength) || hashLength != sizeof(hash)) {
	
		// Throw exception
		throw runtime_error("Getting hash failed");
	}
	
	// Check if initializing digest context failed
	if(!EVP_DigestInit_ex2(digestContext.get(), digest.get(), nullptr)) {
	
		// Throw exception
		throw runtime_error("Initializing digest context failed");
	}
	
	// Check if hashing hash failed
	if(!EVP_DigestUpdate(digestContext.get(), hash, sizeof(hash))) {
	
		// Throw exception
		throw runtime_error("Hashing hash failed");
	}
	
	// Check if getting hash failed
	if(!EVP_DigestFinal_ex(digestContext.get(), hash, &hashLength) || hashLength != sizeof(hash)) {
	
		// Throw exception
		throw runtime_error("Getting hash failed");
	}
	
	// Get checksum from hash
	memcpy(checksum, hash, CHECKSUM_SIZE);
}
