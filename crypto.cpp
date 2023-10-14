// Header files
#include <cstring>
#include <limits>
#include <memory>
#include <sys/random.h>
#include "./common.h"
#include "./crypto.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/core_names.h"
#include "openssl/rand.h"
#include "secp256k1_aggsig.h"
#include "secp256k1_bulletproofs.h"

using namespace std;


// Function prototypes

// Create context
static secp256k1_context *createContext();


// Constants

// Bulletproof message switch type index
const size_t Crypto::BULLETPROOF_MESSAGE_SWITCH_TYPE_INDEX = 2;

// Bulletproof message path depth index
const size_t Crypto::BULLETPROOF_MESSAGE_PATH_DEPTH_INDEX = 3;

// Bulletproof message path index
const size_t Crypto::BULLETPROOF_MESSAGE_PATH_INDEX = 4;

// Derive child extended private key MAC algorithm
static const char *DERIVE_CHILD_EXTENDED_PRIVATE_KEY_MAC_ALGORITHM = "HMAC";

// Derive child extended private key MAC digest
static const char *DERIVE_CHILD_EXTENDED_PRIVATE_KEY_MAC_DIGEST = "SHA-512";

// Path hardened mask
static const uint32_t PATH_HARDENED_MASK = 0x80000000;

// Generator J public
static const secp256k1_pubkey GENERATOR_J = {{0x5F, 0x15, 0x21, 0x36, 0x93, 0x93, 0x01, 0x2A, 0x8D, 0x8B, 0x39, 0x7E, 0x9B, 0xF4, 0x54, 0x29, 0x2F, 0x5A, 0x1B, 0x3D, 0x38, 0x85, 0x16, 0xC2, 0xF3, 0x03, 0xFC, 0x95, 0x67, 0xF5, 0x60, 0xB8, 0x3A, 0xC4, 0xC5, 0xA6, 0xDC, 0xA2, 0x01, 0x59, 0xFC, 0x56, 0xCF, 0x74, 0x9A, 0xA6, 0xA5, 0x65, 0x31, 0x6A, 0xA5, 0x03, 0x74, 0x42, 0x3F, 0x42, 0x53, 0x8F, 0xAA, 0x2C, 0xD3, 0x09, 0x3F, 0xA4}};

// Secp256k1 context
static const unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)> secp256k1Context(createContext(), secp256k1_context_destroy);

// Secp256k1 scratch space size
static const size_t SECP256K1_SCRATCH_SPACE_SIZE = 30 * Common::BYTES_IN_A_KILOBYTE;

// Secp256k1 scratch space
static thread_local const unique_ptr<secp256k1_scratch_space, decltype(&secp256k1_scratch_space_destroy)> secp256k1ScratchSpace(secp256k1_scratch_space_create(secp256k1Context.get(), SECP256K1_SCRATCH_SPACE_SIZE), secp256k1_scratch_space_destroy);

// Secp256k1 number of generators
static const size_t SECP256k1_NUMBER_OF_GENERATORS = 256;

// Secp256k1 generators
static const unique_ptr<secp256k1_bulletproof_generators, void(*)(secp256k1_bulletproof_generators *)> secp256k1Generators(secp256k1_bulletproof_generators_create(secp256k1Context.get(), &secp256k1_generator_const_g, SECP256k1_NUMBER_OF_GENERATORS), [](secp256k1_bulletproof_generators *secp256k1Generators) {

	// Free secp256k1 generators
	secp256k1_bulletproof_generators_destroy(secp256k1Context.get(), secp256k1Generators);
});

// Secp256k1 ECDSA signature digest algorithm
static const char *SECP256K1_ECDSA_SIGNATURE_DIGEST_ALGORITHM = "SHA-256";

// DER signature maximum size
static const size_t DER_SIGNATURE_MAXIMUM_SIZE = 72;

// Single-signer hash digest algorithm
static const char *SINGLE_SIGNER_HASH_DIGEST_ALGORITHM = "BLAKE2B-512";

// Ed25519 key type
static const char *ED25519_KEY_TYPE = "ED25519";

// X25519 key type
static const char *X25519_KEY_TYPE = "X25519";

// X25519 private key digest algorithm
static const char *X25519_PRIVATE_KEY_DIGEST_ALGORITHM = "SHA-512";

// Ed25519 curve prime
static const uint8_t ED25519_CURVE_PRIME[] = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED};

// Ed25519 public key x mask
static const uint8_t ED25519_PUBLIC_KEY_X_MASK = 0x80;


// Supporting function implementation

// Get blinding factor
bool Crypto::getBlindingFactor(uint8_t blindingFactor[BLINDING_FACTOR_SIZE], const uint8_t blind[SECP256K1_PRIVATE_KEY_SIZE], const uint64_t value) {

	// Check if deriving root key failed
	if(!secp256k1_blind_switch(secp256k1Context.get(), blindingFactor, blind, value, &secp256k1_generator_const_h, &secp256k1_generator_const_g, &GENERATOR_J)) {
	
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, BLINDING_FACTOR_SIZE);
		
		// Return false
		return false;
	}
	
	// Check if blinding factor isn't a valid secp256k1 private key
	if(!isValidSecp256k1PrivateKey(blindingFactor, BLINDING_FACTOR_SIZE)) {
	
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, BLINDING_FACTOR_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Derive child extended private key
bool Crypto::deriveChildExtendedPrivateKey(uint8_t extendedPrivateKey[EXTENDED_PRIVATE_KEY_SIZE], const uint32_t *path, const size_t pathLength) {

	// Check if getting MAC failed
	const unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(EVP_MAC_fetch(nullptr, DERIVE_CHILD_EXTENDED_PRIVATE_KEY_MAC_ALGORITHM, nullptr), EVP_MAC_free);
	if(!mac) {
	
		// Securely clear extended private key
		explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
	
		// Return false
		return false;
	}
	
	// Check if creating MAC context failed
	const unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> macContext(EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free);
	if(!macContext) {
	
		// Securely clear extended private key
		explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Go through all paths
	for(size_t i = 0; i < pathLength; ++i) {
	
		// Check if initializing MAC context with the extended private key's chain code failed
		const OSSL_PARAM setDigestParameters[] = {
					
			// Digest
			OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(DERIVE_CHILD_EXTENDED_PRIVATE_KEY_MAC_DIGEST), 0),
			
			// end
			OSSL_PARAM_END
		};
		if(!EVP_MAC_init(macContext.get(), &extendedPrivateKey[SECP256K1_PRIVATE_KEY_SIZE], CHAIN_CODE_SIZE, setDigestParameters)) {
		
			// Securely clear extended private key
			explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
		
		// Check if path is hardened
		if(path[i] & PATH_HARDENED_MASK) {
		
			// Check if hashing zero and extended private key's private key failed
			const uint8_t zero = 0;
			if(!EVP_MAC_update(macContext.get(), &zero, sizeof(zero)) || !EVP_MAC_update(macContext.get(), extendedPrivateKey, SECP256K1_PRIVATE_KEY_SIZE)) {
			
				// Securely clear extended private key
				explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
				
				// Return false
				return false;
			}
		}
		
		// Otherwise
		else {
		
			// Check if getting extended private key's private key's public key failed
			uint8_t publicKey[SECP256K1_PUBLIC_KEY_SIZE];
			if(!getSecp256k1PublicKey(publicKey, extendedPrivateKey)) {
			
				// Securely clear extended private key
				explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
				
				// Return false
				return false;
			}
			
			// Check if hashing public key failed
			if(!EVP_MAC_update(macContext.get(), publicKey, sizeof(publicKey))) {
			
				// Securely clear public key
				explicit_bzero(publicKey, sizeof(publicKey));
				
				// Securely clear extended private key
				explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
				
				// Return false
				return false;
			}
			
			// Securely clear public key
			explicit_bzero(publicKey, sizeof(publicKey));
		}
		
		// Get current path
		uint32_t currentPath = path[i];
		
		// Check if little endian
		#if BYTE_ORDER == LITTLE_ENDIAN
		
			// Make current path big endian
			currentPath = __builtin_bswap32(currentPath);
		#endif
		
		// Check if hashing current path failed
		if(!EVP_MAC_update(macContext.get(), reinterpret_cast<const uint8_t *>(&currentPath), sizeof(currentPath))) {
		
			// Securely clear extended private key
			explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
		
		// Check if getting result length failed
		size_t resultLength;
		OSSL_PARAM getResultLengthParameters[] = {
		
			// MAC length
			OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &resultLength),
			
			// End
			OSSL_PARAM_END
		};
		if(!EVP_MAC_CTX_get_params(macContext.get(), getResultLengthParameters)) {
		
			// Securely clear extended private key
			explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
		
		// Check if result length is invalid
		if(resultLength != EXTENDED_PRIVATE_KEY_SIZE) {
		
			// Securely clear extended private key
			explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
		
		// Check if getting new extended private key failed
		uint8_t newExtendedPrivateKey[EXTENDED_PRIVATE_KEY_SIZE];
		size_t newExtendedPrivateKeyLength;
		if(!EVP_MAC_final(macContext.get(), newExtendedPrivateKey, &newExtendedPrivateKeyLength, sizeof(newExtendedPrivateKey)) || newExtendedPrivateKeyLength != sizeof(newExtendedPrivateKey)) {
		
			// Securely clear new extended private key
			explicit_bzero(newExtendedPrivateKey, sizeof(newExtendedPrivateKey));
			
			// Securely clear extended private key
			explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
		
		// Check if new extended private key's private key isn't a valid secp256k1 private key
		if(!isValidSecp256k1PrivateKey(newExtendedPrivateKey, SECP256K1_PRIVATE_KEY_SIZE)) {
		
			// Securely clear new extended private key
			explicit_bzero(newExtendedPrivateKey, sizeof(newExtendedPrivateKey));
			
			// Securely clear extended private key
			explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
		
		// Check if adding extended private key's private key to the new extended private key's private key failed
		if(!secp256k1_ec_privkey_tweak_add(secp256k1_context_no_precomp, newExtendedPrivateKey, extendedPrivateKey)) {
		
			// Securely clear new extended private key
			explicit_bzero(newExtendedPrivateKey, sizeof(newExtendedPrivateKey));
			
			// Securely clear extended private key
			explicit_bzero(extendedPrivateKey, EXTENDED_PRIVATE_KEY_SIZE);
			
			// Return false
			return false;
		}
		
		// Set extended private key to the new extended private key
		memcpy(extendedPrivateKey, newExtendedPrivateKey, sizeof(newExtendedPrivateKey));
		
		// Securely clear new extended private key
		explicit_bzero(newExtendedPrivateKey, sizeof(newExtendedPrivateKey));
	}
	
	// Return true
	return true;
}

// Get commitment
bool Crypto::getCommitment(uint8_t serializedCommitment[COMMITMENT_SIZE], const uint8_t blindingFactor[BLINDING_FACTOR_SIZE], const uint64_t value) {

	// Check if committing to value with the blinding factor failed
	secp256k1_pedersen_commitment commitment;
	if(!secp256k1_pedersen_commit(secp256k1_context_no_precomp, &commitment, blindingFactor, value, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing the commitment failed
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitment, &commitment)) {
	
		// Securely clear serialized commitment
		explicit_bzero(serializedCommitment, COMMITMENT_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get Bulletproof
bool Crypto::getBulletproof(uint8_t bulletproof[BULLETPROOF_SIZE], const uint8_t blindingFactor[BLINDING_FACTOR_SIZE], const uint64_t value, const uint8_t rewindNonce[SCALAR_SIZE], const uint8_t privateNonce[SCALAR_SIZE], const uint8_t message[BULLETPROOF_MESSAGE_SIZE]) {

	// Check if getting Bulletproof failed
	size_t bulletproofLength = BULLETPROOF_SIZE;
	if(!secp256k1_bulletproof_rangeproof_prove(secp256k1Context.get(), secp256k1ScratchSpace.get(), secp256k1Generators.get(), bulletproof, &bulletproofLength, nullptr, nullptr, nullptr, &value, nullptr, &blindingFactor, nullptr, 1, &secp256k1_generator_const_h, numeric_limits<uint64_t>::digits, rewindNonce, privateNonce, nullptr, 0, message) || bulletproofLength != BULLETPROOF_SIZE) {
	
		// Securely clear Bulletproof
		explicit_bzero(bulletproof, BULLETPROOF_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Create private nonce
bool Crypto::createPrivateNonce(uint8_t privateNonce[SCALAR_SIZE]) {

	// Check if creating random seed failed
	uint8_t seed[SCALAR_SIZE];
	if(RAND_priv_bytes_ex(nullptr, seed, sizeof(seed), RAND_DRBG_STRENGTH) != 1) {
	
		// Securely clear seed
		explicit_bzero(seed, sizeof(seed));
		
		// Return false
		return false;
	}
	
	// Check if creating private nonce failed
	if(!secp256k1_aggsig_export_secnonce_single(secp256k1Context.get(), privateNonce, seed)) {
	
		// Securely clear private nonce
		explicit_bzero(privateNonce, SCALAR_SIZE);
		
		// Securely clear seed
		explicit_bzero(seed, sizeof(seed));
		
		// Return false
		return false;
	}
	
	// Securely clear seed
	explicit_bzero(seed, sizeof(seed));
	
	// Return true
	return true;
}

// Is valid secp256k1 private key
bool Crypto::isValidSecp256k1PrivateKey(const uint8_t *privateKey, const size_t length) {

	// Check if length is invalid
	if(length != SECP256K1_PRIVATE_KEY_SIZE) {
	
		// Return false
		return false;
	}
	
	// Return if private key is a valid secp256k1 private key
	return secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, privateKey);
}

// Is valid secp256k1 public key
bool Crypto::isValidSecp256k1PublicKey(const uint8_t *serializedPublicKey, const size_t length) {

	// Check if length is invalid
	if(length != SECP256K1_PUBLIC_KEY_SIZE) {
	
		// Return false
		return false;
	}
	
	// Return if parsing serialized public key was successful
	secp256k1_pubkey publicKey;
	return secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &publicKey, serializedPublicKey, length);
}

// Get secp256k1 public key
bool Crypto::getSecp256k1PublicKey(uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t privateKey[SECP256K1_PRIVATE_KEY_SIZE]) {

	// Check if getting private key's public key failed
	secp256k1_pubkey publicKey;
	if(!secp256k1_ec_pubkey_create(secp256k1Context.get(), &publicKey, privateKey)) {
	
		// Securely clear public key
		explicit_bzero(&publicKey, sizeof(publicKey));
		
		// Return false
		return false;
	}
	
	// Check if serializing public key failed
	size_t serializedPublicKeyLength = SECP256K1_PUBLIC_KEY_SIZE;
	if(!secp256k1_ec_pubkey_serialize(secp256k1_context_no_precomp, serializedPublicKey, &serializedPublicKeyLength, &publicKey, SECP256K1_EC_COMPRESSED) || serializedPublicKeyLength != SECP256K1_PUBLIC_KEY_SIZE) {
	
		// Securely clear public key
		explicit_bzero(&publicKey, sizeof(publicKey));
		
		// Securely clear serialized public key
		explicit_bzero(serializedPublicKey, SECP256K1_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Securely clear public key
	explicit_bzero(&publicKey, sizeof(publicKey));
	
	// Return true
	return true;
}

// Get secp256k1 ECDSA signature
vector<uint8_t> Crypto::getSecp256k1EcdsaSignature(const uint8_t privateKey[SECP256K1_PRIVATE_KEY_SIZE], const uint8_t *data, const size_t dataLength) {

	// Check if getting digest failed
	const unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(EVP_MD_fetch(nullptr, SECP256K1_ECDSA_SIGNATURE_DIGEST_ALGORITHM, nullptr), EVP_MD_free);
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
	if(!EVP_DigestUpdate(digestContext.get(), data, dataLength)) {
	
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
	
	// Check if signing hash failed
	secp256k1_ecdsa_signature signature;
	if(!secp256k1_ecdsa_sign(secp256k1Context.get(), &signature, hash, privateKey, secp256k1_nonce_function_rfc6979, nullptr)) {
	
		// Throw exception
		throw runtime_error("Signing hash failed");
	}
	
	// Check if getting private key's public key failed
	secp256k1_pubkey privateKeysPublicKey;
	if(!secp256k1_ec_pubkey_create(secp256k1Context.get(), &privateKeysPublicKey, privateKey)) {
	
		// Throw exception
		throw runtime_error("Getting private key's public key failed");
	}
	
	// Check if verifying signature failed
	if(!secp256k1_ecdsa_verify(secp256k1Context.get(), &signature, hash, &privateKeysPublicKey)) {
	
		// Throw exception
		throw runtime_error("Verifying signature failed");
	}
	
	// Check if serializing signature failed
	vector<uint8_t> serializedSignature(DER_SIGNATURE_MAXIMUM_SIZE);
	size_t serializedSignatureLength = serializedSignature.size();
	if(!secp256k1_ecdsa_signature_serialize_der(secp256k1_context_no_precomp, serializedSignature.data(), &serializedSignatureLength, &signature)) {
	
		// Throw exception
		throw runtime_error("Serializing signature failed");
	}
	
	// Remove unused bytes from serialized signature
	serializedSignature.resize(serializedSignatureLength);
	
	// Return serialized signature
	return serializedSignature;
}

// Get secp256k1 partial single-signer signature
bool Crypto::getSecp256k1PartialSingleSignerSignature(uint8_t serializedSignature[SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t privateKey[SECP256K1_PRIVATE_KEY_SIZE], const uint8_t *data, const size_t dataLength, const uint8_t privateNonce[SCALAR_SIZE], const uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t serializedPublicNonce[SECP256K1_PUBLIC_KEY_SIZE]) {

	// Check if getting digest failed
	const unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(EVP_MD_fetch(nullptr, SINGLE_SIGNER_HASH_DIGEST_ALGORITHM, nullptr), EVP_MD_free);
	if(!digest) {
	
		// Return false
		return false;
	}
	
	// Check if creating digest context failed
	const unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if(!digestContext) {
	
		// Return false
		return false;
	}
	
	// Check if initializing digest context failed
	if(!EVP_DigestInit_ex2(digestContext.get(), digest.get(), nullptr)) {
	
		// Return false
		return false;
	}
	
	// Check if hashing data failed
	if(!EVP_DigestUpdate(digestContext.get(), data, dataLength)) {
	
		// Return false
		return false;
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
	
		// Return false
		return false;
	}
	
	// Check if getting hash failed
	uint8_t hash[digestLength];
	unsigned int hashLength;
	if(!EVP_DigestFinal_ex(digestContext.get(), hash, &hashLength) || hashLength != sizeof(hash)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing public key failed
	secp256k1_pubkey publicKey;
	if(!secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &publicKey, serializedPublicKey, SECP256K1_PUBLIC_KEY_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing public nonce failed
	secp256k1_pubkey publicNonce;
	if(!secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &publicNonce, serializedPublicNonce, SECP256K1_PUBLIC_KEY_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if creating random seed failed
	uint8_t seed[SCALAR_SIZE];
	if(RAND_priv_bytes_ex(nullptr, seed, sizeof(seed), RAND_DRBG_STRENGTH) != 1) {
	
		// Securely clear seed
		explicit_bzero(seed, sizeof(seed));
		
		// Return false
		return false;
	}
	
	// Check if signing hash failed
	secp256k1_ecdsa_signature signature;
	if(!secp256k1_aggsig_sign_single(secp256k1Context.get(), signature.data, hash, privateKey, privateNonce, nullptr, &publicNonce, &publicNonce, &publicKey, seed)) {
	
		// Securely clear seed
		explicit_bzero(seed, sizeof(seed));
		
		// Return false
		return false;
	}
	
	// Securely clear seed
	explicit_bzero(seed, sizeof(seed));
	
	// Check if getting private key's public key failed
	secp256k1_pubkey privateKeysPublicKey;
	if(!secp256k1_ec_pubkey_create(secp256k1Context.get(), &privateKeysPublicKey, privateKey)) {
	
		// Return false
		return false;
	}
	
	// Check if verifying signature failed
	if(!secp256k1_aggsig_verify_single(secp256k1Context.get(), signature.data, hash, &publicNonce, &privateKeysPublicKey, &publicKey, nullptr, true)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing signature failed
	if(!secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_no_precomp, serializedSignature, &signature)) {
	
		// Securely clear serialized signature
		explicit_bzero(serializedSignature, SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Verify secp256k1 complete single-signer signatures
bool Crypto::verifySecp256k1CompleteSingleSignerSignatures(const uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t serializedPublicNonce[SECP256K1_PUBLIC_KEY_SIZE], const secp256k1_pedersen_commitment &publicKeyTotalCommitment, const uint8_t completeSignature[SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t serializedPartialSignature[SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t *data, const size_t dataLength) {

	// Check if getting digest failed
	const unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(EVP_MD_fetch(nullptr, SINGLE_SIGNER_HASH_DIGEST_ALGORITHM, nullptr), EVP_MD_free);
	if(!digest) {
	
		// Return false
		return false;
	}
	
	// Check if creating digest context failed
	const unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if(!digestContext) {
	
		// Return false
		return false;
	}
	
	// Check if initializing digest context failed
	if(!EVP_DigestInit_ex2(digestContext.get(), digest.get(), nullptr)) {
	
		// Return false
		return false;
	}
	
	// Check if hashing data failed
	if(!EVP_DigestUpdate(digestContext.get(), data, dataLength)) {
	
		// Return false
		return false;
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
	
		// Return false
		return false;
	}
	
	// Check if getting hash failed
	uint8_t hash[digestLength];
	unsigned int hashLength;
	if(!EVP_DigestFinal_ex(digestContext.get(), hash, &hashLength) || hashLength != sizeof(hash)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing serialzied public key failed
	secp256k1_pubkey publicKey;
	if(!secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &publicKey, serializedPublicKey, SECP256K1_PUBLIC_KEY_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing serialzied public nonce failed
	secp256k1_pubkey publicNonce;
	if(!secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &publicNonce, serializedPublicNonce, SECP256K1_PUBLIC_KEY_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting public key total failed
	secp256k1_pubkey publicKeyTotal;
	if(!secp256k1_pedersen_commitment_to_pubkey(secp256k1_context_no_precomp, &publicKeyTotal, &publicKeyTotalCommitment)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing serialized partial signature failed
	secp256k1_ecdsa_signature partialSignature;
	if(!secp256k1_ecdsa_signature_parse_compact(secp256k1_context_no_precomp, &partialSignature, serializedPartialSignature)) {
	
		// Return false
		return false;
	}
	
	// Check if getting other partial signature candidates failed
	uint8_t otherPartialSignatureCandidateOne[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE];
	uint8_t otherPartialSignatureCandidateTwo[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE];
	const int count = secp256k1_aggsig_subtract_partial_signature(secp256k1_context_no_precomp, otherPartialSignatureCandidateOne, otherPartialSignatureCandidateTwo, completeSignature, partialSignature.data);
	if(count <= 0) {
	
		// Return false
		return false;
	}
	
	// Check if verifying first other partial signature candidate was successful
	if(count >= 1 && secp256k1_aggsig_verify_single(secp256k1Context.get(), otherPartialSignatureCandidateOne, hash, &publicNonce, &publicKey, &publicKeyTotal, nullptr, true)) {
	
		// Return true
		return true;
	}
	
	// Check if verifying second other partial signature candidate was successful
	if(count >= 2 && secp256k1_aggsig_verify_single(secp256k1Context.get(), otherPartialSignatureCandidateTwo, hash, &publicNonce, &publicKey, &publicKeyTotal, nullptr, true)) {
	
		// Return true
		return true;
	}
	
	// Return false
	return false;
}

// Verify secp256k1 complete single-signer signature
bool Crypto::verifySecp256k1CompleteSingleSignerSignature(const uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t serializedSignature[SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t *data, const size_t dataLength) {

	// Check if getting digest failed
	const unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(EVP_MD_fetch(nullptr, SINGLE_SIGNER_HASH_DIGEST_ALGORITHM, nullptr), EVP_MD_free);
	if(!digest) {
	
		// Return false
		return false;
	}
	
	// Check if creating digest context failed
	const unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if(!digestContext) {
	
		// Return false
		return false;
	}
	
	// Check if initializing digest context failed
	if(!EVP_DigestInit_ex2(digestContext.get(), digest.get(), nullptr)) {
	
		// Return false
		return false;
	}
	
	// Check if hashing data failed
	if(!EVP_DigestUpdate(digestContext.get(), data, dataLength)) {
	
		// Return false
		return false;
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
	
		// Return false
		return false;
	}
	
	// Check if getting hash failed
	uint8_t hash[digestLength];
	unsigned int hashLength;
	if(!EVP_DigestFinal_ex(digestContext.get(), hash, &hashLength) || hashLength != sizeof(hash)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing serialized signature failed
	secp256k1_ecdsa_signature signature;
	if(!secp256k1_ecdsa_signature_parse_compact(secp256k1_context_no_precomp, &signature, serializedSignature)) {
	
		// Return false
		return false;
	}
	
	// Check if parsing serialzied public key failed
	secp256k1_pubkey publicKey;
	if(!secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &publicKey, serializedPublicKey, SECP256K1_PUBLIC_KEY_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Return if signature verifies the hash
	return secp256k1_aggsig_verify_single(secp256k1Context.get(), signature.data, hash, nullptr, &publicKey, &publicKey, nullptr, false);
}

// Combine secp256k1 public keys
bool Crypto::combineSecp256k1PublicKeys(uint8_t serializedCombinedPublicKey[SECP256K1_PUBLIC_KEY_SIZE], const uint8_t *serializedPublicKeys[SECP256K1_PUBLIC_KEY_SIZE], const size_t numberOfSerializedPublicKeys) {

	// Go through all serialized publc keys
	secp256k1_pubkey publicKeys[numberOfSerializedPublicKeys];
	const secp256k1_pubkey *publicKeysAddresses[numberOfSerializedPublicKeys];
	for(size_t i = 0; i < numberOfSerializedPublicKeys; ++i) {
	
		// Check if parsing serialized public key failed
		if(!secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &publicKeys[i], serializedPublicKeys[i], SECP256K1_PUBLIC_KEY_SIZE)) {
		
			// Return false
			return false;
		}
		
		// Get public key's address
		publicKeysAddresses[i] = &publicKeys[i];
	}

	// Check if combining public keys failed
	secp256k1_pubkey combinedPublicKey;
	if(!secp256k1_ec_pubkey_combine(secp256k1_context_no_precomp, &combinedPublicKey, publicKeysAddresses, numberOfSerializedPublicKeys)) {
		
		// Return false
		return false;
	}
	
	// Check if serializing combined public key failed
	size_t serializedCombinedPublicKeyLength = SECP256K1_PUBLIC_KEY_SIZE;
	if(!secp256k1_ec_pubkey_serialize(secp256k1_context_no_precomp, serializedCombinedPublicKey, &serializedCombinedPublicKeyLength, &combinedPublicKey, SECP256K1_EC_COMPRESSED) || serializedCombinedPublicKeyLength != SECP256K1_PUBLIC_KEY_SIZE) {
	
		// Securely clear serialized combined public key
		explicit_bzero(serializedCombinedPublicKey, SECP256K1_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Secp256k1 public key to commitment
bool Crypto::secp256k1PublicKeyToCommitment(uint8_t serializedCommitment[COMMITMENT_SIZE], const uint8_t serializedPublicKey[SECP256K1_PUBLIC_KEY_SIZE]) {

	// Check if parsing serialized public key failed
	secp256k1_pubkey publicKey;
	if(!secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &publicKey, serializedPublicKey, SECP256K1_PUBLIC_KEY_SIZE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting commitment from public key failed
	secp256k1_pedersen_commitment commitment;
	if(!secp256k1_pubkey_to_pedersen_commitment(secp256k1_context_no_precomp, &commitment, &publicKey)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing commitment failed
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitment, &commitment)) {
	
		// Securely clear serialized commitment
		explicit_bzero(serializedCommitment, COMMITMENT_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid Ed25519 private key
bool Crypto::isValidEd25519PrivateKey(const uint8_t *privateKey, const size_t length) {

	// Check if loading private key was successful
	return static_cast<bool>(unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(EVP_PKEY_new_raw_private_key_ex(nullptr, ED25519_KEY_TYPE, nullptr, privateKey, length), EVP_PKEY_free));
}

// Is valid Ed25519 public key
bool Crypto::isValidEd25519PublicKey(const uint8_t *publicKey, const size_t length) {

	// Check if loading public key was successful
	return static_cast<bool>(unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(EVP_PKEY_new_raw_public_key_ex(nullptr, ED25519_KEY_TYPE, nullptr, publicKey, length), EVP_PKEY_free));
}

// Get Ed25519 public key
bool Crypto::getEd25519PublicKey(uint8_t publicKey[ED25519_PUBLIC_KEY_SIZE], const uint8_t privateKey[ED25519_PRIVATE_KEY_SIZE]) {

	// Check if loading private key failed
	const unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ed25519PrivateKey(EVP_PKEY_new_raw_private_key_ex(nullptr, ED25519_KEY_TYPE, nullptr, privateKey, ED25519_PRIVATE_KEY_SIZE), EVP_PKEY_free);
	if(!ed25519PrivateKey) {
	
		// Return false
		return false;
	}
	
	// Check if getting private key's public key failed
	size_t publicKeyLength = ED25519_PUBLIC_KEY_SIZE;
	if(!EVP_PKEY_get_raw_public_key(ed25519PrivateKey.get(), publicKey, &publicKeyLength) || publicKeyLength != ED25519_PUBLIC_KEY_SIZE) {
	
		// Securely clear public key
		explicit_bzero(publicKey, ED25519_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get Ed25519 signature
bool Crypto::getEd25519Signature(uint8_t signature[ED25519_SIGNATURE_SIZE], const uint8_t privateKey[ED25519_PRIVATE_KEY_SIZE], const uint8_t *data, const size_t dataLength) {

	// Check if loading private key failed
	const unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ed25519PrivateKey(EVP_PKEY_new_raw_private_key_ex(nullptr, ED25519_KEY_TYPE, nullptr, privateKey, ED25519_PRIVATE_KEY_SIZE), EVP_PKEY_free);
	if(!ed25519PrivateKey) {
	
		// Return false
		return false;
	}
	
	// Check if creating signing context failed
	const unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> signingContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if(!signingContext) {
	
		// Return false
		return false;
	}
	
	// Check if initializing signing context failed
	if(!EVP_DigestSignInit_ex(signingContext.get(), nullptr, nullptr, nullptr, nullptr, ed25519PrivateKey.get(), nullptr)) {
	
		// Return false
		return false;
	}
	
	// Check if signing data failed
	size_t signatureLength = ED25519_SIGNATURE_SIZE;
	if(!EVP_DigestSign(signingContext.get(), signature, &signatureLength, data, dataLength) || signatureLength != ED25519_SIGNATURE_SIZE) {
	
		// Securely clear signature
		explicit_bzero(signature, ED25519_SIGNATURE_SIZE);
		
		// Return false
		return false;
	}
	
	// Check if creating verifying context failed
	const unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> verifyingContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if(!verifyingContext) {
	
		// Securely clear signature
		explicit_bzero(signature, ED25519_SIGNATURE_SIZE);
		
		// Return false
		return false;
	}
	
	// Check if initializing verifying context failed
	if(!EVP_DigestVerifyInit_ex(verifyingContext.get(), nullptr, nullptr, nullptr, nullptr, ed25519PrivateKey.get(), nullptr)) {
	
		// Securely clear signature
		explicit_bzero(signature, ED25519_SIGNATURE_SIZE);
		
		// Return false
		return false;
	}
	
	// Check if verifying signature failed
	if(EVP_DigestVerify(verifyingContext.get(), signature, ED25519_SIGNATURE_SIZE, data, dataLength) != 1) {
	
		// Securely clear signature
		explicit_bzero(signature, ED25519_SIGNATURE_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Is valid X25519 private key
bool Crypto::isValidX25519PrivateKey(const uint8_t *privateKey, const size_t length) {

	// Check if loading private key was successful
	return static_cast<bool>(unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(EVP_PKEY_new_raw_private_key_ex(nullptr, X25519_KEY_TYPE, nullptr, privateKey, length), EVP_PKEY_free));
}

// Is valid X25519 public key
bool Crypto::isValidX25519PublicKey(const uint8_t *publicKey, const size_t length) {

	// Check if loading public key was successful
	return static_cast<bool>(unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(EVP_PKEY_new_raw_public_key_ex(nullptr, X25519_KEY_TYPE, nullptr, publicKey, length), EVP_PKEY_free));
}

// Get X25519 private key
bool Crypto::getX25519PrivateKey(uint8_t x25519PrivateKey[X25519_PRIVATE_KEY_SIZE], const uint8_t ed25519PrivateKey[ED25519_PRIVATE_KEY_SIZE]) {

	// Check if getting digest failed
	const unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(EVP_MD_fetch(nullptr, X25519_PRIVATE_KEY_DIGEST_ALGORITHM, nullptr), EVP_MD_free);
	if(!digest) {
	
		// Return false;
		return false;
	}
	
	// Check if creating digest context failed
	const unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if(!digestContext) {
	
		// Return false;
		return false;
	}
	
	// Check if initializing digest context failed
	if(!EVP_DigestInit_ex2(digestContext.get(), digest.get(), nullptr)) {
	
		// Return false;
		return false;
	}
	
	// Check if hashing Ed25519 private key failed
	if(!EVP_DigestUpdate(digestContext.get(), ed25519PrivateKey, ED25519_PRIVATE_KEY_SIZE)) {
	
		// Return false;
		return false;
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
	
		// Return false;
		return false;
	}
	
	// Check if getting hash failed
	uint8_t hash[digestLength];
	unsigned int hashLength;
	if(!EVP_DigestFinal_ex(digestContext.get(), hash, &hashLength) || hashLength != sizeof(hash)) {
	
		// Securely clear hash
		explicit_bzero(hash, sizeof(hash));
		
		// Return false;
		return false;
	}
	
	// Clamp the hash
	hash[0] &= 0b11111000;
	hash[X25519_PRIVATE_KEY_SIZE - sizeof(uint8_t)] &= 0b01111111;
	hash[X25519_PRIVATE_KEY_SIZE - sizeof(uint8_t)] |= 0b01000000;
	
	// Check if the hash isn't a valid X25519 private key
	if(!isValidX25519PrivateKey(hash, X25519_PRIVATE_KEY_SIZE)) {
	
		// Securely clear hash
		explicit_bzero(hash, sizeof(hash));
		
		// Return false;
		return false;
	}
	
	// Set X25519 private key to the hash
	memcpy(x25519PrivateKey, hash, X25519_PRIVATE_KEY_SIZE);
	
	// Securely clear hash
	explicit_bzero(hash, sizeof(hash));
	
	// Return true
	return true;
}

// Get X25519 public key
bool Crypto::getX25519PublicKey(uint8_t x25519PublicKey[X25519_PUBLIC_KEY_SIZE], const uint8_t ed25519PublicKey[ED25519_PUBLIC_KEY_SIZE]) {

	// Check if creating big number context failed
	const unique_ptr<BN_CTX, decltype(&BN_CTX_free)> bigNumberContext(BN_CTX_new_ex(nullptr), BN_CTX_free);
	if(!bigNumberContext) {
	
		// Return false
		return false;
	}
	
	// Check if creating curve prime big number failed
	const unique_ptr<BIGNUM, decltype(&BN_free)> curvePrimeBigNumber(BN_new(), BN_free);
	if(!curvePrimeBigNumber) {
	
		// Return false
		return false;
	}
	
	// Check if loading Ed25519 curve prime as a big number failed
	if(!BN_bin2bn(ED25519_CURVE_PRIME, sizeof(ED25519_CURVE_PRIME), curvePrimeBigNumber.get())) {
	
		// Return false
		return false;
	}
	
	// Check if creating y big number failed
	const unique_ptr<BIGNUM, decltype(&BN_free)> yBigNumber(BN_new(), BN_free);
	if(!yBigNumber) {
	
		// Return false
		return false;
	}
	
	// Check if loading Ed25519 public key's y as a big number failed
	uint8_t y[SCALAR_SIZE];
	memcpy(y, ed25519PublicKey, ED25519_PUBLIC_KEY_SIZE);
	y[sizeof(y) - sizeof(uint8_t)] &= ~ED25519_PUBLIC_KEY_X_MASK;
	
	if(!BN_lebin2bn(y, sizeof(y), yBigNumber.get())) {
	
		// Return false
		return false;
	}
	
	// Check if creating one plus y big number failed
	const unique_ptr<BIGNUM, decltype(&BN_free)> onePlusYBigNumber(BN_new(), BN_free);
	if(!onePlusYBigNumber) {
	
		// Return false
		return false;
	}
	
	// Check if getting one plus y failed
	if(!BN_mod_add(onePlusYBigNumber.get(), BN_value_one(), yBigNumber.get(), curvePrimeBigNumber.get(), bigNumberContext.get())) {
	
		// Return false
		return false;
	}
	
	// Check if getting one minus y failed
	if(!BN_mod_sub(yBigNumber.get(), BN_value_one(), yBigNumber.get(), curvePrimeBigNumber.get(), bigNumberContext.get())) {
	
		// Return false
		return false;
	}
	
	// Check if one minus y is zero
	if(BN_is_zero(yBigNumber.get())) {
	
		// Return false
		return false;
	}
	
	// Check if getting the inverse of one minus y failed
	if(!BN_mod_inverse(yBigNumber.get(), yBigNumber.get(), curvePrimeBigNumber.get(), bigNumberContext.get())) {
	
		// Return false
		return false;
	}
	
	// Check if getting the product of one plus y and the inverse of one minus y failed
	if(!BN_mod_mul(yBigNumber.get(), onePlusYBigNumber.get(), yBigNumber.get(), curvePrimeBigNumber.get(), bigNumberContext.get())) {
	
		// Return false
		return false;
	}
	
	// Check if getting X25519 public key from the result failed
	if(BN_bn2lebinpad(yBigNumber.get(), x25519PublicKey, X25519_PUBLIC_KEY_SIZE) != X25519_PUBLIC_KEY_SIZE) {
	
		// Securely clear X25519 public key
		explicit_bzero(x25519PublicKey, X25519_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Check if X25519 public key isn't a valid X25519 public key
	if(!isValidX25519PublicKey(x25519PublicKey, X25519_PUBLIC_KEY_SIZE)) {
	
		// Securely clear X25519 public key
		explicit_bzero(x25519PublicKey, X25519_PUBLIC_KEY_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get X25519 shared key
bool Crypto::getX25519SharedKey(uint8_t sharedKey[SCALAR_SIZE], const uint8_t privateKey[X25519_PRIVATE_KEY_SIZE], const uint8_t publicKey[X25519_PUBLIC_KEY_SIZE]) {

	// Check if loading private key failed
	const unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> x25519PrivateKey(EVP_PKEY_new_raw_private_key_ex(nullptr, X25519_KEY_TYPE, nullptr, privateKey, X25519_PRIVATE_KEY_SIZE), EVP_PKEY_free);
	if(!x25519PrivateKey) {
	
		// Return false
		return false;
	}
	
	// Check if loading public key failed
	const unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> x25519PublicKey(EVP_PKEY_new_raw_public_key_ex(nullptr, X25519_KEY_TYPE, nullptr, publicKey, X25519_PUBLIC_KEY_SIZE), EVP_PKEY_free);
	if(!x25519PublicKey) {
	
		// Return false
		return false;
	}
	
	// Check if creating key context failed
	const unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> keyContext(EVP_PKEY_CTX_new_from_pkey(nullptr, x25519PrivateKey.get(), nullptr), EVP_PKEY_CTX_free);
	if(!keyContext) {
	
		// Return false
		return false;
	}
	
	// Check if initializing key context to pad the result failed
	const unsigned int padding = true;
	const OSSL_PARAM setPaddingParameters[] = {
					
		// Padding
		OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, const_cast<unsigned int *>(&padding)),
		
		// end
		OSSL_PARAM_END
	};
	if(EVP_PKEY_derive_init_ex(keyContext.get(), setPaddingParameters) != 1) {
	
		// Return false
		return false;
	}
	
	// Check if setting the key context's peer key failed
	if(EVP_PKEY_derive_set_peer_ex(keyContext.get(), x25519PublicKey.get(), true) != 1) {
	
		// Return false
		return false;
	}
	
	// Check if deriving shared key failed
	size_t sharedKeySize = SCALAR_SIZE;
	if(EVP_PKEY_derive(keyContext.get(), sharedKey, &sharedKeySize) != 1 || sharedKeySize != SCALAR_SIZE) {
	
		// Securely clear shared key
		explicit_bzero(sharedKey, SCALAR_SIZE);
		
		// Return false
		return false;
	}
	
	// Check if shared keys is zero
	if(all_of(sharedKey, sharedKey + SCALAR_SIZE, [](const uint8_t value) {
	
		// Return if value is zero
		return !value;
	})) {
	
		// Securely clear shared key
		explicit_bzero(sharedKey, SCALAR_SIZE);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Create context
secp256k1_context *createContext() {

	// Check if creating context failed
	secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	if(!context) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating random seed failed
	uint8_t seed[Crypto::SCALAR_SIZE];
	if(getentropy(seed, sizeof(seed))) {
	
		// Securely clear seed
		explicit_bzero(seed, sizeof(seed));
		
		// Destroy context
		secp256k1_context_destroy(context);
		
		// Return nothing
		return nullptr;
	}
	
	// Check if randomizing context failed
	if(!secp256k1_context_randomize(context, seed)) {
	
		// Securely clear seed
		explicit_bzero(seed, sizeof(seed));
		
		// Destroy context
		secp256k1_context_destroy(context);
		
		// Return nothing
		return nullptr;
	}
	
	// Securely clear seed
	explicit_bzero(seed, sizeof(seed));
	
	// Return context
	return context;
};
