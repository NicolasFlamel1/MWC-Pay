// Header files
#include <cstring>
#include "./base58.h"
#include "./mqs.h"

using namespace std;


// Constants

// Check if floonet
#ifdef FLOONET

	// Address version
	static const uint8_t ADDRESS_VERSION[] = {1, 121};

// Otherwise
#else

	// Address version
	static const uint8_t ADDRESS_VERSION[] = {1, 69};
#endif


// Supporting function implementation

// Secp256k1 public key to address
string Mqs::secp256k1PublicKeyToAddress(const uint8_t publicKey[Crypto::SECP256K1_PUBLIC_KEY_SIZE]) {

	// Create decoded address from public key
	uint8_t decodedAddress[sizeof(ADDRESS_VERSION) + Crypto::SECP256K1_PUBLIC_KEY_SIZE];
	memcpy(decodedAddress, ADDRESS_VERSION, sizeof(ADDRESS_VERSION));
	memcpy(&decodedAddress[sizeof(ADDRESS_VERSION)], publicKey, Crypto::SECP256K1_PUBLIC_KEY_SIZE);
	
	// Return decoded address encoded to base58 with checksum
	return Base58::encodeWithChecksum(decodedAddress, sizeof(decodedAddress));
}
