// Header files
#include <limits>
#include <stdexcept>
#include "./bit_reader.h"

using namespace std;


// Supporting function implementation

// Constructor
BitReader::BitReader(const uint8_t *bytes, const size_t length) :

	// Set bytes
	bytes(bytes),
	
	// Set length
	length(length),
	
	// Set byte index
	byteIndex(0),
	
	// Set bit index
	bitIndex(0)
{	
}

// Get bits
uint64_t BitReader::getBits(size_t numberOfBits) {

	// Check if more than one byte is requested
	if(numberOfBits > numeric_limits<uint8_t>::digits) {
	
		// Initialize result
		uint64_t result = 0;
	
		// Go through all bits
		while(numberOfBits) {
		
			// Get used number of bits
			const size_t usedNumberOfBits = min(numberOfBits, static_cast<size_t>(numeric_limits<uint8_t>::digits));
		
			// Update result to make space for more bits
			result <<= usedNumberOfBits;
			
			// Include bits in result
			result |= getBits(usedNumberOfBits);
		
			// Update number of bits
			numberOfBits -= usedNumberOfBits;
		}
		
		// Return result
		return result;
	}
	
	// Otherwise
	else {
	
		// Check if no bits are requested
		if(!numberOfBits) {
		
			// Return zero
			return 0;
		}

		// Check if number of bits is invalid
		if(byteIndex == length || (byteIndex == length - 1 && bitIndex + numberOfBits > numeric_limits<uint8_t>::digits)) {
		
			// Throw exception
			throw runtime_error("Number of bits is invalid");
		}
	
		// Set result to the byte at the byte index
		uint64_t result = bytes[byteIndex] << numeric_limits<uint8_t>::digits;
		
		// Check if more bytes are needed
		if(bitIndex + numberOfBits > numeric_limits<uint8_t>::digits) {
		
			// Append next byte to the result
			result |= bytes[byteIndex + 1];
		}
		
		// Remove upper bits from the result
		result &= (1 << (numeric_limits<uint16_t>::digits - bitIndex)) - 1;
		
		// Remove lower bits from the result
		result >>= (numeric_limits<uint16_t>::digits - (bitIndex + numberOfBits));
	
		// Update bit index
		bitIndex += numberOfBits;
		
		// Check if bit index overflowed into the next byte
		if(bitIndex >= numeric_limits<uint8_t>::digits) {
		
			// Increment byte index
			++byteIndex;
		
			// Correct bit index
			bitIndex %= numeric_limits<uint8_t>::digits;
		}
		
		// Return result
		return result;
	}
}

// Get bytes
vector<uint8_t> BitReader::getBytes(const size_t length) {

	// Initialize result
	vector<uint8_t> result(length);
	
	// Go through all bytes
	for(size_t i = 0; i < length; ++i) {
	
		// Set byte in the result
		result[i] = getBits(numeric_limits<uint8_t>::digits);
	}
	
	// Return result
	return result;
}
