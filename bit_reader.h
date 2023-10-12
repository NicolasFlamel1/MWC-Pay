// Header guard
#ifndef BIT_READER_H
#define BIT_READER_H


// Header files
#include <cstdint>
#include <vector>

using namespace std;


// Classes

// Bit reader class
class BitReader final {

	// Public
	public:
	
		// Constructor
		explicit BitReader(const uint8_t *bytes, const size_t length);
		
		// Get bits
		uint64_t getBits(size_t numberOfBits);
		
		// Get bytes
		vector<uint8_t> getBytes(const size_t length);
	
	// Private
	private:
	
		// Data
		const uint8_t *bytes;
		
		// Length
		const size_t length;
		
		// Bytes index
		size_t byteIndex;
		
		// Bit index
		size_t bitIndex;
};


#endif
