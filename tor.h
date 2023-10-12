// Header guard
#ifndef TOR_H
#define TOR_H


// Header files
#include <string>
#include "./crypto.h"

using namespace std;


// Classes

// Tor class
class Tor final {

	// Public
	public:
	
		// Constructor
		Tor() = delete;
		
		// Ed25519 public key to address
		static string ed25519PublicKeyToAddress(const uint8_t publicKey[Crypto::ED25519_PUBLIC_KEY_SIZE]);
};


#endif
