// Header guard
#ifndef BASE58_H
#define BASE58_H


// Header files
#include <string>
#include <vector>

using namespace std;


// Classes

// Base58 class
class Base58 final {

	// Public
	public:
	
		// Constructor
		Base58() = delete;
		
		// Encode
		static string encode(const uint8_t *data, const size_t length);
		
		// Encode with checksum
		static string encodeWithChecksum(const uint8_t *data, const size_t length);
		
		// Decode
		static vector<uint8_t> decode(const char *data);
		
		// Decode with checksum
		static vector<uint8_t> decodeWithChecksum(const char *data);
};


#endif
