// Header files
#include <limits>
#include <memory>
#include <stdexcept>
#include "./common.h"
#include "./gzip.h"
#include "zlib.h"

using namespace std;


// Constants

// Compression level
static const int COMPRESSION_LEVEL = Z_DEFAULT_COMPRESSION;

// Window bits
static const int WINDOW_BITS = MAX_WBITS;

// Gzip flag
static const int GZIP_FLAG = 0x10;

// Memory level
static const int MEMORY_LEVEL = MAX_MEM_LEVEL;

// Strategy
static const int STRATEGY = Z_DEFAULT_STRATEGY;

// Chunk size
static const size_t CHUNK_SIZE = Common::BYTES_IN_A_KILOBYTE;


// Supporting function implementation

// Compress
vector<uint8_t> Gzip::compress(const uint8_t *data, const size_t length) {

	// Check if length is invalid
	if(length > numeric_limits<uInt>::max()) {
	
		// Throw exception
		throw runtime_error("Length is invalid");
	}

	// Check if initializing stream failed
	z_stream stream = {
	
		// Next in
		.next_in = const_cast<uint8_t *>(data),
		
		// Available in
		.avail_in = static_cast<uInt>(length)
	};
	
	if(deflateInit2(&stream, COMPRESSION_LEVEL, Z_DEFLATED, WINDOW_BITS | GZIP_FLAG, MEMORY_LEVEL, STRATEGY) != Z_OK) {
	
		// Throw exception
		throw runtime_error("Initializing stream failed");
	}
	
	// Automatically free stream
	const unique_ptr<z_stream, decltype(&deflateEnd)> streamUniquePointer(&stream, deflateEnd);
	
	// Initialize result
	vector<uint8_t> result;
	
	// Go through all data
	int status;
	do {
	
		// Go through data in the current chunk
		do {
		
			// Set stream to deflate chunk
			uint8_t chunk[CHUNK_SIZE];
			stream.next_out = chunk;
			stream.avail_out = sizeof(chunk);
			
			// Check if deflating chunk failed
			status = deflate(&stream, Z_FINISH);
			if(status != Z_OK && status != Z_STREAM_END && status != Z_BUF_ERROR) {
			
				// Throw exception
				throw runtime_error("Deflating chunk failed");
			}
			
			// Add deflated chunk to result
			result.insert(result.end(), chunk, chunk + sizeof(chunk) - stream.avail_out);
		
		} while(!stream.avail_out);
		
	} while(status != Z_STREAM_END && status != Z_BUF_ERROR && stream.avail_in);
	
	// Return result
	return result;
}
