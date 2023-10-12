// Header guard
#ifndef GZIP_H
#define GZIP_H


// Header files
#include <cstdint>
#include <vector>

using namespace std;


// Classes

// Gzip class
class Gzip final {

	// Public
	public:
	
		// Constructor
		Gzip() = delete;
		
		// Compress
		static vector<uint8_t> compress(const uint8_t *data, const size_t length);
};


#endif
