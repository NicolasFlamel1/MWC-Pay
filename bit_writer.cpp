// Header files
#include <limits>
#include "./bit_writer.h"

using namespace std;


// Supporting function implementation

// Constructor
BitWriter::BitWriter() :

	// Set byte index
	byteIndex(0),
	
	// Set bit index
	bitIndex(0)
{
}

// Set bits
void BitWriter::setBits(const uint64_t bits, size_t numberOfBits) {

	// Go through all bytes past one byte
	while(numberOfBits > numeric_limits<uint8_t>::digits) {
	
		// Set byte's bits
		setBits(bits >> (numeric_limits<uint8_t>::digits * (numberOfBits / numeric_limits<uint8_t>::digits - 1) + numberOfBits % numeric_limits<uint8_t>::digits), numeric_limits<uint8_t>::digits);
	
		// Update number of bits
		numberOfBits -= numeric_limits<uint8_t>::digits;
	}
	
	// Check if bits exist
	if(numberOfBits) {
	
		// Check if more space is needed
		if(!bitIndex || bitIndex + numberOfBits > numeric_limits<uint8_t>::digits) {
		
			// Increase byte's size by one
			bytes.push_back(0);
		}
		
		// Check if bits will overflow into the next byte
		if(bitIndex + numberOfBits > numeric_limits<uint8_t>::digits) {
		
			// Include bits in bytes at byte index
			bytes[byteIndex] |= bits >> ((bitIndex + numberOfBits) - numeric_limits<uint8_t>::digits);
			
			// Include bits in bytes at the next byte index
			bytes[byteIndex + 1] |= bits << (numeric_limits<uint16_t>::digits - (bitIndex + numberOfBits));
		}
		
		// Otherwise
		else {
		
			// Include bits in bytes at byte index
			bytes[byteIndex] |= bits << (numeric_limits<uint8_t>::digits - (bitIndex + numberOfBits));
		}
		
		// Update bit index
		bitIndex += numberOfBits;
		
		// Check if bit index overflowed into the next byte
		if(bitIndex >= numeric_limits<uint8_t>::digits) {
		
			// Increment byte index
			++byteIndex;
		
			// Correct bit index
			bitIndex %= numeric_limits<uint8_t>::digits;
		}
	}
}

// Set bytes
void BitWriter::setBytes(const uint8_t *bytes, const size_t length) {

	// Go through all bytes
	for(size_t i = 0; i < length; ++i) {
	
		// Set byte's bits
		setBits(bytes[i], numeric_limits<uint8_t>::digits);
	}
}

// Get bytes
const vector<uint8_t> &BitWriter::getBytes() const {

	// Return bytes
	return bytes;
}
