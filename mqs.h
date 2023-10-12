// Header guard
#ifndef MQS_H
#define MQS_H


// Header files
#include <string>
#include "./crypto.h"

using namespace std;


// Classes

// MQS class
class Mqs final {

	// Public
	public:
	
		// Constructor
		Mqs() = delete;
		
		// Secp256k1 public key to address
		static string secp256k1PublicKeyToAddress(const uint8_t publicKey[Crypto::SECP256K1_PUBLIC_KEY_SIZE]);
};


#endif
