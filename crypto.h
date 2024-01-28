// Header guard
#ifndef CRYPTO_H
#define CRYPTO_H


// Header files
#include <cstdint>
#include <vector>
#include "secp256k1_commitment.h"

using namespace std;


// Classes

// Crypto class
class Crypto final {

	// Public
	public:
	
		// Constructor
		Crypto() = delete;
		
		// Commitment size
		static const size_t COMMITMENT_SIZE = 33;
		
		// Secp256k1 private key size
		static const size_t SECP256K1_PRIVATE_KEY_SIZE = 32;
		
		// Secp256k1 public key size
		static const size_t SECP256K1_PUBLIC_KEY_SIZE = 33;
		
		// Ed25519 private key size
		static const size_t ED25519_PRIVATE_KEY_SIZE = 32;
		
		// Ed25519 public key size
		static const size_t ED25519_PUBLIC_KEY_SIZE = 32;
		
		// Ed25519 signature size
		static const size_t ED25519_SIGNATURE_SIZE = 64;
		
		// Chain code size
		static const size_t CHAIN_CODE_SIZE = 32;
		
		// Extended private key size
		static const size_t EXTENDED_PRIVATE_KEY_SIZE = SECP256K1_PRIVATE_KEY_SIZE + CHAIN_CODE_SIZE;
		
		// Blinding factor size
		static const size_t BLINDING_FACTOR_SIZE = 32;
		
		// Scalar size
		static const size_t SCALAR_SIZE = 32;
		
		// Bulletproof message size
		static const size_t BULLETPROOF_MESSAGE_SIZE = 20;

		// Bulletproof message switch type index
		static const size_t BULLETPROOF_MESSAGE_SWITCH_TYPE_INDEX;

		// Bulletproof message path depth index
		static const size_t BULLETPROOF_MESSAGE_PATH_DEPTH_INDEX;

		// Bulletproof message path index
		static const size_t BULLETPROOF_MESSAGE_PATH_INDEX;
		
		// Bulletproof size
		static const size_t BULLETPROOF_SIZE = 675;
		
		// Secp256k1 single-signer signature size
		static const size_t SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE = 64;
		
		// X25519 private key size
		static const size_t X25519_PRIVATE_KEY_SIZE = 32;
		
		// X25519 public key size
		static const size_t X25519_PUBLIC_KEY_SIZE = 32;
		
		// ChaCha20 nonce size
		static const size_t CHACHA20_NONCE_SIZE = 12;
		
		// Get blinding factor
		static bool getBlindingFactor(uint8_t blindingFactor[BLINDING_FACTOR_SIZE], const uint8_t blind[SECP256K1_PRIVATE_KEY_SIZE], const uint64_t value);
		
		// Derive child extended private key
		static bool deriveChildExtendedPrivateKey(uint8_t extendedPrivateKey[EXTENDED_PRIVATE_KEY_SIZE], const uint32_t *path, const size_t pathLength);
		
		// Get commitment
		static bool getCommitment(uint8_t serializedCommitment[COMMITMENT_SIZE], const uint8_t blindingFactor[BLINDING_FACTOR_SIZE], const uint64_t value);
		
		// Get Bulletproof
		static bool getBulletproof(uint8_t bulletproof[BULLETPROOF_SIZE], const uint8_t blindingFactor[BLINDING_FACTOR_SIZE], const uint64_t value, const uint8_t rewindNonce[SCALAR_SIZE], const uint8_t privateNonce[SCALAR_SIZE], const uint8_t message[BULLETPROOF_MESSAGE_SIZE]);
		
		// Create private nonce
		static bool createPrivateNonce(uint8_t privateNonce[SCALAR_SIZE]);
		
		// Is valid secp256k1 private key
		static bool isValidSecp256k1PrivateKey(const uint8_t *privateKey, const size_t length);
		
		// Is valid secp256k1 public key
		static bool isValidSecp256k1PublicKey(const uint8_t *serializedPublicKey, const size_t length);
		
		// Get secp256k1 public key
		static bool getSecp256k1PublicKey(uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t privateKey[SECP256K1_PRIVATE_KEY_SIZE]);
		
		// Get secp256k1 ECDSA signature
		static vector<uint8_t> getSecp256k1EcdsaSignature(const uint8_t privateKey[SECP256K1_PRIVATE_KEY_SIZE], const uint8_t *data, const size_t dataLength);
		
		// Get secp256k1 partial single-signer signature
		static bool getSecp256k1PartialSingleSignerSignature(uint8_t serializedSignature[SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t privateKey[SECP256K1_PRIVATE_KEY_SIZE], const uint8_t *data, const size_t dataLength, const uint8_t privateNonce[SCALAR_SIZE], const uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t serializedPublicNonce[SECP256K1_PUBLIC_KEY_SIZE]);
		
		// Verify secp256k1 complete single-signer signatures
		static bool verifySecp256k1CompleteSingleSignerSignatures(const uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t serializedPublicNonce[SECP256K1_PUBLIC_KEY_SIZE], const secp256k1_pedersen_commitment &publicKeyTotalCommitment, const uint8_t completeSignature[SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t serializedPartialSignature[SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t *data, const size_t dataLength);
		
		// Verify secp256k1 complete single-signer signature
		static bool verifySecp256k1CompleteSingleSignerSignature(const uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t serializedSignature[SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t *data, const size_t dataLength);
		
		// Combine secp256k1 public keys
		static bool combineSecp256k1PublicKeys(uint8_t serializedCombinedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t *serializedPublicKeys[SECP256K1_PUBLIC_KEY_SIZE], const size_t numberOfSerializedPublicKeys);
		
		// Secp256k1 public key to commitment
		static bool secp256k1PublicKeyToCommitment(uint8_t serializedCommitment[COMMITMENT_SIZE], const uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE]);
		
		// Is valid Ed25519 private key
		static bool isValidEd25519PrivateKey(const uint8_t *privateKey, const size_t length);
		
		// Is valid Ed25519 public key
		static bool isValidEd25519PublicKey(const uint8_t *publicKey, const size_t length);
		
		// Get Ed25519 public key
		static bool getEd25519PublicKey(uint8_t publicKey[ED25519_PUBLIC_KEY_SIZE], const uint8_t privateKey[ED25519_PRIVATE_KEY_SIZE]);
		
		// Get Ed25519 signature
		static bool getEd25519Signature(uint8_t signature[ED25519_SIGNATURE_SIZE], const uint8_t privateKey[ED25519_PRIVATE_KEY_SIZE], const uint8_t *data, const size_t dataLength);
		
		// Is valid X25519 private key
		static bool isValidX25519PrivateKey(const uint8_t *privateKey, const size_t length);
		
		// Is valid X25519 public key
		static bool isValidX25519PublicKey(const uint8_t *publicKey, const size_t length);
		
		// Get X25519 private key
		static bool getX25519PrivateKey(uint8_t *x25519PrivateKey, const uint8_t ed25519PrivateKey[ED25519_PRIVATE_KEY_SIZE], const bool includePrf = false);
		
		// Get X25519 public key
		static bool getX25519PublicKey(uint8_t x25519PublicKey[X25519_PUBLIC_KEY_SIZE], const uint8_t ed25519PublicKey[ED25519_PUBLIC_KEY_SIZE]);
		
		// Get X25519 shared key
		static bool getX25519SharedKey(uint8_t sharedKey[SCALAR_SIZE], const uint8_t privateKey[X25519_PRIVATE_KEY_SIZE], const uint8_t publicKey[X25519_PUBLIC_KEY_SIZE]);
};


#endif
