// Header files
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include "./base58.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"

using namespace std;


// Constants

// Alphabet
static const char ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Size percent increase
static const int SIZE_PERCENT_INCREASE = 138;

// Size percent decrease
static const int SIZE_PERCENT_DECREASE = 733;

// Number base
static const int NUMBER_BASE = 58;

// Checksum digest algorithm
static const char *CHECKSUM_DIGEST_ALGORITHM = "SHA-256";

// Checksum size
static const size_t CHECKSUM_SIZE = 4;


// Function prototypes

// Get checksum
static void getChecksum(uint8_t checksum[CHECKSUM_SIZE], const uint8_t *data, const size_t length);


// Supporting function implementation

// Encode
string Base58::encode(const uint8_t *data, const size_t length) {

	// Go through all leading zeros in the data
	size_t numberOfLeadingZeros = 0;
	while(numberOfLeadingZeros < length && !data[numberOfLeadingZeros]) {

		// Increment number of leading zeros
		++numberOfLeadingZeros;
	}

	// Create buffer
	uint8_t buffer[(length - numberOfLeadingZeros) * SIZE_PERCENT_INCREASE / 100 + 1];
	memset(buffer, 0, sizeof(buffer));

	// Go through all bytes in the data after the leading zeros
	size_t currentLength = 0;
	for(size_t i = numberOfLeadingZeros; i < length; ++i) {

		// Get byte
		uint8_t byte = data[i];

		// Go through all affected bytes in the buffer
		size_t j = 0;
		for(size_t k = sizeof(buffer) - 1; byte || j < currentLength; --k) {

			// Get the affected byte's value after it's changed
			const uint16_t value = (buffer[k] << numeric_limits<uint8_t>::digits) | byte;

			// Reduce affected byte
			buffer[k] = value % NUMBER_BASE;

			// Set byte to the overflow
			byte = value / NUMBER_BASE;
			
			// Increment j
			++j;
			
			// Check if at the last component
			if(!k) {

				// Break
				break;
			}
		}

		// Update current length
		currentLength = j;
	}

	// Go through all leading zeros in the buffer
	size_t bufferIndex = sizeof(buffer) - currentLength;
	while(bufferIndex < sizeof(buffer) && !buffer[bufferIndex]) {

		// Increment buffer index
		++bufferIndex;
	}

	// Initialize result to the zero alphabet character
	string result(sizeof(buffer) - bufferIndex + numberOfLeadingZeros, ALPHABET[0]);

	// Go through all bytes in the buffer after the leading zeros
	for(size_t i = 0; bufferIndex < sizeof(buffer); ++i, ++bufferIndex) {

		// Set byte as an alphabet character in the result
		result[i + numberOfLeadingZeros] = ALPHABET[buffer[bufferIndex]];
	}

	// Return result
	return result;
}

// Encode with checksum
string Base58::encodeWithChecksum(const uint8_t *data, const size_t length) {

	// Get data and its checksum
	uint8_t dataAndChecksum[length + CHECKSUM_SIZE];
	memcpy(dataAndChecksum, data, length);
	getChecksum(&dataAndChecksum[length], data, length);
	
	// Return encoding data and checksum
	return encode(dataAndChecksum, sizeof(dataAndChecksum));
}

// Decode
vector<uint8_t> Base58::decode(const char *data) {

	// Get length
	const size_t length = strlen(data);
	
	// Go through all leading alphabet zeros in the data
	size_t numberOfLeadingZeros = 0;
	while(numberOfLeadingZeros < length && data[numberOfLeadingZeros] == ALPHABET[0]) {

		// Increment number of leading zeros
		++numberOfLeadingZeros;
	}

	// Create buffer
	uint8_t buffer[(length - numberOfLeadingZeros) * SIZE_PERCENT_DECREASE / 1000 + 1];
	memset(buffer, 0, sizeof(buffer));

	// Go through all characters in the data after the leading alphabet zeros
	size_t currentLength = 0;
	for(size_t i = numberOfLeadingZeros; i < length; ++i) {

		// Check if character is invalid
		const char *characterOffset = strchr(ALPHABET, data[i]);
		if(!characterOffset) {

			// Throw exception
			throw runtime_error("Character is invalid");
		}

		// Get character as a byte
		uint8_t byte = characterOffset - ALPHABET;

		// Go through all affected bytes in the buffer
		size_t j = 0;
		for(size_t k = sizeof(buffer) - 1; byte || j < currentLength; --k) {

			// Get the affected byte's value after it's changed
			const uint16_t value = buffer[k] * NUMBER_BASE + byte;

			// Reduce affected byte
			buffer[k] = value & numeric_limits<uint8_t>::max();

			// Set byte to the overflow
			byte = value >> numeric_limits<uint8_t>::digits;

			// Increment j
			++j;

			// Check if at the last component
			if(!k) {

				// Break
				break;
			}
		}

		// Update current length
		currentLength = j;
	}

	// Go through all leading zeros in the buffer
	size_t bufferIndex = sizeof(buffer) - currentLength;
	while(bufferIndex < sizeof(buffer) && !buffer[bufferIndex]) {

		// Increment buffer index
		++bufferIndex;
	}
	
	// Initialize result to zero
	vector<uint8_t> result(sizeof(buffer) - bufferIndex + numberOfLeadingZeros, 0);

	// Go through all bytes in the buffer after the leading zeros
	for(size_t i = 0; bufferIndex < sizeof(buffer); ++i, ++bufferIndex) {

		// Set byte in the result
		result[i + numberOfLeadingZeros] = buffer[bufferIndex];
	}

	// Return result
	return result;
}

// Decode with checksum
vector<uint8_t> Base58::decodeWithChecksum(const char *data) {

	// Decode data
	vector decodedData = decode(data);
	
	// Check if decoded data doesn't contain a checksum
	if(decodedData.size() < CHECKSUM_SIZE) {
	
		// Throw exception
		throw runtime_error("Decoded data doesn't contain a checksum");
	}
	
	// Get decoded data's checksum
	uint8_t checksum[CHECKSUM_SIZE];
	getChecksum(checksum, decodedData.data(), decodedData.size() - CHECKSUM_SIZE);
	
	// Check if decoded data's checksum is invalid
	if(memcmp(&decodedData[decodedData.size() - CHECKSUM_SIZE], checksum, sizeof(checksum))) {
	
		// Throw exception
		throw runtime_error("Decoded data's checksum is invalid");
	}
	
	// Remove checksum from decoded data
	decodedData.resize(decodedData.size() - CHECKSUM_SIZE);
	
	// Return decoded data
	return decodedData;
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
