// Header guard
#ifndef BLAKE2_H
#define BLAKE2_H


// Header files
#include <cstdint>

using namespace std;


// Function prototypes

// BLAKE2b
int blake2b(uint8_t *output, const size_t outputLength, const uint8_t *input, const size_t inputLength, const uint8_t *key, const size_t keyLength);


#endif
