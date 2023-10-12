// Header guard
#ifndef SLATEPACK_H
#define SLATEPACK_H


// Header files
#include <array>
#include <optional>
#include <string>
#include <vector>
#include "./crypto.h"
#include "./wallet.h"

using namespace std;


// Classes

// Slatepack class
class Slatepack final {

	// Public
	public:
	
		// Constructor
		Slatepack() = delete;
		
		// Encode
		static string encode(const uint8_t *data, const size_t length, const uint8_t recipientPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE], const Wallet &wallet, const uint64_t index);
		
		// Decode
		static pair<vector<uint8_t>, optional<array<uint8_t, Crypto::ED25519_PUBLIC_KEY_SIZE>>> decode(const char *data, const Wallet &wallet, const uint64_t index);
		
};


#endif
