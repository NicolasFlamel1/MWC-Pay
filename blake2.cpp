// Header files
#include <cstring>
#include <memory>
#include "./blake2.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"

using namespace std;


// Constants

// Hash digest algorithm
static const char *HASH_DIGEST_ALGORITHM = "BLAKE2B-512";


// Supporting function implementation

// BLAKE2b
int blake2b(uint8_t *output, const size_t outputLength, const uint8_t *input, const size_t inputLength, const uint8_t *key, const size_t keyLength) {

	// Check if key exists
	if(keyLength) {
	
		// Return one
		return 1;
	}
	
	// Check if getting digest failed
	const unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(EVP_MD_fetch(nullptr, HASH_DIGEST_ALGORITHM, nullptr), EVP_MD_free);
	if(!digest) {
	
		// Return one
		return 1;
	}
	
	// Check if creating digest context failed
	const unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if(!digestContext) {
	
		// Return one
		return 1;
	}
	
	// Check if initializing digest context with the output length failed
	const OSSL_PARAM setDigestLengthParameters[] = {
					
		// Digest length
		OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, const_cast<size_t *>(&outputLength)),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_DigestInit_ex2(digestContext.get(), digest.get(), setDigestLengthParameters)) {
	
		// Return one
		return 1;
	}
	
	// Check if hashing input failed
	if(!EVP_DigestUpdate(digestContext.get(), input, inputLength)) {
	
		// Return one
		return 1;
	}
	
	// Check if getting output failed
	unsigned int resultLength;
	if(!EVP_DigestFinal_ex(digestContext.get(), output, &resultLength) || resultLength != outputLength) {
	
		// Securely clear output
		explicit_bzero(output, outputLength);
		
		// Return one
		return 1;
	}
	
	// Return zero
	return 0;
}
