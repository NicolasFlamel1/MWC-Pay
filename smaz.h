// Header guard
#ifndef SMAZ_H
#define SMAZ_H


// Header files
#include <cstdint>
#include <vector>

using namespace std;


// Classes

// SMAZ class
class Smaz final {

	// Public
	public:
	
		// Constructor
		Smaz() = delete;
		
		// Decompress
		static vector<uint8_t> decompress(const uint8_t *data, const size_t length);
};


#endif
