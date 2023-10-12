// Header files
#include <cstring>
#include <memory>
#include "./base32.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "./tor.h"

using namespace std;


// Constants

// Address checksum size
static const size_t ADDRESS_CHECKSUM_SIZE = 2;

// Address checksum seed
static const char ADDRESS_CHECKSUM_SEED[] = ".onion checksum";

// Address checksum digest algorithm
static const char *ADDRESS_CHECKSUM_DIGEST_ALGORITHM = "SHA3-256";

// Address version
static const uint8_t ADDRESS_VERSION = 3;


// Function prototypes

// Get address checksum
static void getAddressChecksum(uint8_t addressChecksum[ADDRESS_CHECKSUM_SIZE], const uint8_t publicKey[Crypto::ED25519_PUBLIC_KEY_SIZE]);


// Supporting function implementation

// Ed25519 public key to address
string Tor::ed25519PublicKeyToAddress(const uint8_t publicKey[Crypto::ED25519_PUBLIC_KEY_SIZE]) {

	// Get address checksum from public key
	uint8_t addressChecksum[ADDRESS_CHECKSUM_SIZE];
	getAddressChecksum(addressChecksum, publicKey);
	
	// Create decoded address from public key
	uint8_t decodedAddress[Crypto::ED25519_PUBLIC_KEY_SIZE + sizeof(addressChecksum) + sizeof(ADDRESS_VERSION)];
	memcpy(decodedAddress, publicKey, Crypto::ED25519_PUBLIC_KEY_SIZE);
	memcpy(&decodedAddress[Crypto::ED25519_PUBLIC_KEY_SIZE], addressChecksum, sizeof(addressChecksum));
	decodedAddress[Crypto::ED25519_PUBLIC_KEY_SIZE + sizeof(addressChecksum)] = ADDRESS_VERSION;
	
	// Return decoded address encoded to base32
	return Base32::encode(decodedAddress, sizeof(decodedAddress));
}

// Get address checksum
void getAddressChecksum(uint8_t addressChecksum[ADDRESS_CHECKSUM_SIZE], const uint8_t publicKey[Crypto::ED25519_PUBLIC_KEY_SIZE]) {

	// Create address data from public key
	uint8_t addressData[sizeof(ADDRESS_CHECKSUM_SEED) - sizeof('\0') + Crypto::ED25519_PUBLIC_KEY_SIZE + sizeof(ADDRESS_VERSION)];
	memcpy(addressData, ADDRESS_CHECKSUM_SEED, sizeof(ADDRESS_CHECKSUM_SEED) - sizeof('\0'));
	memcpy(&addressData[sizeof(ADDRESS_CHECKSUM_SEED) - sizeof('\0')], publicKey, Crypto::ED25519_PUBLIC_KEY_SIZE);
	addressData[sizeof(ADDRESS_CHECKSUM_SEED) - sizeof('\0') + Crypto::ED25519_PUBLIC_KEY_SIZE] = ADDRESS_VERSION;
	
	// Check if getting digest failed
	const unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(EVP_MD_fetch(nullptr, ADDRESS_CHECKSUM_DIGEST_ALGORITHM, nullptr), EVP_MD_free);
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
	
	// Check if hashing address data failed
	if(!EVP_DigestUpdate(digestContext.get(), addressData, sizeof(addressData))) {
	
		// Throw exception
		throw runtime_error("Hashing address data failed");
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
	
	// Get address checksum from hash
	memcpy(addressChecksum, hash, ADDRESS_CHECKSUM_SIZE);
}
