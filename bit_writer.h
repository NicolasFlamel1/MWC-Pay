// Header guard
#ifndef BIT_WRITER_H
#define BIT_WRITER_H


// Header files
#include <cstdint>
#include <vector>

using namespace std;


// Classes

// Bit writer class
class BitWriter final {

	// Public
	public:
	
		// Constructor
		BitWriter();
		
		// Set bits
		void setBits(const uint64_t bits, size_t numberOfBits);
		
		// Set bytes
		void setBytes(const uint8_t *bytes, const size_t length);
		
		// Get bytes
		const vector<uint8_t> &getBytes() const;
	
	// Private
	private:
	
		// Bytes
		vector<uint8_t> bytes;
		
		// Byte index
		vector<uint8_t>::size_type byteIndex;
		
		// Bit index
		size_t bitIndex;
		
		
};


#endif
