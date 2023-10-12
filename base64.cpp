// Header files
#include <memory>
#include <stdexcept>
#include "./base64.h"
#include "openssl/bio.h"
#include "openssl/evp.h"

using namespace std;


// Supporting function implementation

// Encode
string Base64::encode(const uint8_t *data, const size_t length) {

	// Check if creating base64 BIO failed
	const unique_ptr<BIO, decltype(&BIO_free)> base64Bio(BIO_new(BIO_f_base64()), BIO_free);
	if(!base64Bio) {
	
		// Throw exception
		throw runtime_error("Creating base64 BIO failed");
	}
	
	// Configure base64 BIO
	BIO_set_flags(base64Bio.get(), BIO_FLAGS_BASE64_NO_NL);
	
	// Check if creating memory BIO failed
	const unique_ptr<BIO, decltype(&BIO_free)> memoryBio(BIO_new(BIO_s_mem()), BIO_free);
	if(!memoryBio) {
	
		// Throw exception
		throw runtime_error("Creating memory BIO failed");
	}
	
	// Create BIO chain
	BIO_push(base64Bio.get(), memoryBio.get());
	
	// Check if encoding data failed
	if(BIO_write(base64Bio.get(), data, length) != static_cast<ssize_t>(length)) {
	
		// Throw exception
		throw runtime_error("Encoding data failed");
	}
	
	// Loop while BIO isn't flushed
	while(true) {
	
		// Check if flushing BIO was successful
		if(BIO_flush(base64Bio.get()) == 1) {
		
			// Break
			break;
		}
		
		// Check if flushing BIO failed
		if(!BIO_should_retry(base64Bio.get())) {
		
			// Throw exception
			throw runtime_error("Flushing BIO failed");
		}
	}
	
	// Check if getting result from memory BIO failed
	char *result;
	const long resultLength = BIO_get_mem_data(memoryBio.get(), &result);
	if(resultLength < 0) {
	
		// Throw exception
		throw runtime_error("Getting result from memory BIO failed");
	}
	
	// Return result
	return string(result, resultLength);
}
