// Header guard
#ifndef BASE32_H
#define BASE32_H


// Header files
#include <cstdint>
#include <string>
#include <vector>

using namespace std;


// Classes

// Base32 class
class Base32 final {

	// Public
	public:
	
		// Constructor
		Base32() = delete;
		
		// Encode
		static string encode(const uint8_t *data, const size_t length);
		
		// Decode
		static vector<uint8_t> decode(const char *data);
};


#endif
