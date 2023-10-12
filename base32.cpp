// Header files
#include <cstring>
#include <limits>
#include <stdexcept>
#include "./base32.h"

using namespace std;


// Constants

// Bits per character
static const int BITS_PER_CHARACTER = 5;

// Padding character
static const char PADDING_CHARACTER = '=';

// Alphabet
static const char ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";


// Function prototypes

// Get encoded length
static size_t getEncodedLength(const size_t length);

// Get decoded length
static size_t getDecodedLength(const char *data, const size_t length);

// Get number of padding characters
static size_t getNumberOfPaddingCharacters(const size_t length);


// Supporting function implementation

// Encode
string Base32::encode(const uint8_t *data, const size_t length) {

	// Initialize result to padding
	string result(getEncodedLength(length), PADDING_CHARACTER);
	
	// Get number of padding characters
	const size_t numberOfPaddingCharacters = getNumberOfPaddingCharacters(length);

	// Go through all non-padding characters in the result
	for(size_t i = 0; i < result.size() - numberOfPaddingCharacters; ++i) {

		// Get position in the data
		const size_t position = i * BITS_PER_CHARACTER / numeric_limits<uint8_t>::digits;

		// Get first byte
		const uint8_t firstByte = data[position];

		// Get second byte
		const uint8_t secondByte = (position + 1 < length) ? data[position + 1] : 0;

		// Check byte position in the group
		uint8_t quantum;
		switch(i % numeric_limits<uint8_t>::digits) {

			// Zero
			case 0:

				// Set quantum
				quantum = (firstByte & 0b11111000) >> 3;

				// Break
				break;

			// One
			case 1:

				// Set quantum
				quantum = ((firstByte & 0b00000111) << 2) | ((secondByte & 0b11000000) >> 6);

				// Break
				break;

			// Two
			case 2:

				// Set quantum
				quantum = (firstByte & 0b00111110) >> 1;

				// Break
				break;

			// Three
			case 3:

				// Set quantum
				quantum = ((firstByte & 0b00000001) << 4) | ((secondByte & 0b11110000) >> 4);

				// Break
				break;

			// Four
			case 4:

				// Set quantum
				quantum = ((firstByte & 0b00001111) << 1) | ((secondByte & 0b10000000) >> 7);

				// Break
				break;

			// Five
			case 5:

				// Set quantum
				quantum = (firstByte & 0b01111100) >> 2;

				// Break
				break;

			// Six
			case 6:

				// Set quantum
				quantum = ((firstByte & 0b00000011) << 3) | ((secondByte & 0b11100000) >> 5);

				// Break
				break;

			// Seven
			case 7:

				// Set quantum
				quantum = firstByte & 0b00011111;

				// Break
				break;
		}

		// Set quantum as an alphabet character in the result
		result[i] = ALPHABET[quantum];
	}
	
	// Return result
	return result;
}

// Decode
vector<uint8_t> Base32::decode(const char *data) {

	// Get length
	const size_t length = strlen(data);
	
	// Initialize result
	vector<uint8_t> result(getDecodedLength(data, length));

	// Go through all bytes in the result
	for(size_t i = 0; i < result.size(); ++i) {

		// Get position in the data
		const size_t position = i * numeric_limits<uint8_t>::digits / BITS_PER_CHARACTER;

		// Get first quantum
		const uint8_t firstQuantum = strchr(ALPHABET, data[position]) - ALPHABET;

		// Get second quantum
		const uint8_t secondQuantum = (position + 1 < length) ? strchr(ALPHABET, data[position + 1]) - ALPHABET : 0;

		// Get third quantum
		const uint8_t thirdQuantum = (position + 2 < length) ? strchr(ALPHABET, data[position + 2]) - ALPHABET : 0;

		// Check quantum position in group
		uint8_t byte;
		switch(i % BITS_PER_CHARACTER) {

			// Zero
			case 0:

				// Set byte
				byte = ((firstQuantum & 0b11111) << 3) | ((secondQuantum & 0b11100) >> 2);

				// Break
				break;

			// One
			case 1:

				// Set byte
				byte = ((firstQuantum & 0b00011) << 6) | ((secondQuantum & 0b11111) << 1) | ((thirdQuantum & 0b10000) >> 4);

				// Break
				break;

			// Two
			case 2:

				// Set byte
				byte = ((firstQuantum & 0b01111) << 4) | ((secondQuantum & 0b11110) >> 1);

				// Break
				break;

			// Three
			case 3:

				// Set byte
				byte = ((firstQuantum & 0b00001) << 7) | ((secondQuantum & 0b11111) << 2) | ((thirdQuantum & 0b11000) >> 3);

				// Break
				break;

			// Four
			case 4:

				// Set byte
				byte = ((firstQuantum & 0b00111) << 5) | (secondQuantum & 0b11111);

				// Break
				break;
		}

		// Set byte in the result
		result[i] = byte;
	}
	
	// Return result
	return result;
}

// Get encoded length
size_t getEncodedLength(const size_t length) {

	// Return encoded length
	return length * numeric_limits<uint8_t>::digits / BITS_PER_CHARACTER + ((length % BITS_PER_CHARACTER) ? 1 : 0) + getNumberOfPaddingCharacters(length);
}

// Get decoded length
size_t getDecodedLength(const char *data, const size_t length) {

	// Get start of padding in the data
	const char *startOfPadding = strchr(data, PADDING_CHARACTER);

	// Go through all the padding
	for(const char *i = startOfPadding; i && i != data + length; ++i) {

		// Check if padding isn't a padding character
		if(*i != PADDING_CHARACTER) {

			// Throw exception
			throw runtime_error("Padding isn't a padding character");
		}
	}

	// Get number of bytes
	const size_t numberOfBytes = (startOfPadding ? startOfPadding - data : length) * BITS_PER_CHARACTER / numeric_limits<uint8_t>::digits;

	// Check if number of padding characters is invalid
	const size_t numberOfPaddingCharacters = getNumberOfPaddingCharacters(numberOfBytes);
	if(numberOfPaddingCharacters != static_cast<size_t>(startOfPadding ? data + length - startOfPadding : 0)) {

		// Throw exception
		throw runtime_error("Number of padding characters is invalid");
	}

	// Go through all non-padding characters
	for(size_t i = 0; i < length - numberOfPaddingCharacters; ++i) {

		// Check if character isn't a valid alphabet character
		if(!strchr(ALPHABET, data[i])) {

			// Throw exception
			throw runtime_error("Character isn't a valid alphabet character");
		}
	}

	// Return number of bytes
	return numberOfBytes;
}

// Get number of padding characters
size_t getNumberOfPaddingCharacters(const size_t length) {

	// Check how many bits the final quantum represents
	switch(length % BITS_PER_CHARACTER) {

		// One
		case 1:

			// Return number of padding characters
			return 6;

		// Two
		case 2:

			// Return number of padding characters
			return 4;

		// Three
		case 3:

			// Return number of padding characters
			return 3;

		// Four
		case 4:

			// Return number of padding characters
			return 1;

		// Default
		default:

			// Return number of padding characters
			return 0;
	}
}
