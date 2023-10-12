// Header guard
#ifndef BASE64_H
#define BASE64_H


// Header files
#include <string>

using namespace std;


// Classes

// Base64 class
class Base64 final {

	// Public
	public:
	
		// Constructor
		Base64() = delete;
		
		// Encode
		static string encode(const uint8_t *data, const size_t length);
};


#endif
