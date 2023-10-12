// Header files
#include <cstring>
#include <stdexcept>
#include "./smaz.h"

using namespace std;


// Constants

// Decompress codebook
static const char *DECOMPRESS_CODEBOOK[] = {
	" ",
	"the",
	"e",
	"t",
	"a",
	"of",
	"o",
	"and",
	"i",
	"n",
	"s",
	"e ",
	"r",
	" th",
	" t",
	"in",
	"he",
	"th",
	"h",
	"he ",
	"to",
	"\r\n",
	"l",
	"s ",
	"d",
	" a",
	"an",
	"er",
	"c",
	" o",
	"d ",
	"on",
	" of",
	"re",
	"of ",
	"t ",
	", ",
	"is",
	"u",
	"at",
	"   ",
	"n ",
	"or",
	"which",
	"f",
	"m",
	"as",
	"it",
	"that",
	"\n",
	"was",
	"en",
	"  ",
	" w",
	"es",
	" an",
	" i",
	"\r",
	"f ",
	"g",
	"p",
	"nd",
	" s",
	"nd ",
	"ed ",
	"w",
	"ed",
	"http://",
	"for",
	"te",
	"ing",
	"y ",
	"The",
	" c",
	"ti",
	"r ",
	"his",
	"st",
	" in",
	"ar",
	"nt",
	",",
	" to",
	"y",
	"ng",
	" h",
	"with",
	"le",
	"al",
	"to ",
	"b",
	"ou",
	"be",
	"were",
	" b",
	"se",
	"o ",
	"ent",
	"ha",
	"ng ",
	"their",
	"\"",
	"hi",
	"from",
	" f",
	"in ",
	"de",
	"ion",
	"me",
	"v",
	".",
	"ve",
	"all",
	"re ",
	"ri",
	"ro",
	"is ",
	"co",
	"f t",
	"are",
	"ea",
	". ",
	"her",
	" m",
	"er ",
	" p",
	"es ",
	"by",
	"they",
	"di",
	"ra",
	"ic",
	"not",
	"s, ",
	"d t",
	"at ",
	"ce",
	"la",
	"h ",
	"ne",
	"as ",
	"tio",
	"on ",
	"n t",
	"io",
	"we",
	" a ",
	"om",
	", a",
	"s o",
	"ur",
	"li",
	"ll",
	"ch",
	"had",
	"this",
	"e t",
	"g ",
	"e\r\n",
	" wh",
	"ere",
	" co",
	"e o",
	"a ",
	"us",
	" d",
	"ss",
	"\n\r\n",
	"\r\n\r",
	"=\"",
	" be",
	" e",
	"s a",
	"ma",
	"one",
	"t t",
	"or ",
	"but",
	"el",
	"so",
	"l ",
	"e s",
	"s,",
	"no",
	"ter",
	" wa",
	"iv",
	"ho",
	"e a",
	" r",
	"hat",
	"s t",
	"ns",
	"ch ",
	"wh",
	"tr",
	"ut",
	"/",
	"have",
	"ly ",
	"ta",
	" ha",
	" on",
	"tha",
	"-",
	" l",
	"ati",
	"en ",
	"pe",
	" re",
	"there",
	"ass",
	"si",
	" fo",
	"wa",
	"ec",
	"our",
	"who",
	"its",
	"z",
	"fo",
	"rs",
	">",
	"ot",
	"un",
	"<",
	"im",
	"th ",
	"nc",
	"ate",
	"><",
	"ver",
	"ad",
	" we",
	"ly",
	"ee",
	" n",
	"id",
	" cl",
	"ac",
	"il",
	"</",
	"rt",
	" wi",
	"div",
	"e, ",
	" it",
	"whi",
	" ma",
	"ge",
	"x",
	"e c",
	"men",
	".com"
};


// Supporting function implementation

// Decompress
vector<uint8_t> Smaz::decompress(const uint8_t *data, const size_t length) {

	// Initialize result
	vector<uint8_t> result;
	
	// Go through all bytes in the data
	for(size_t i = 0; i < length; ++i) {
	
		// Get byte
		const uint8_t byte = data[i];
		
		// Check byte
		switch(byte) {
		
			// Verbatim byte
			case 254:
			
				// Check if verbatim byte doesn't exist
				if(i >= length - 1) {
				
					// Throw exception
					throw runtime_error("Verbatim byte doesn't exist");
				}
				
				// Add verbatim byte to result
				result.push_back(data[i + 1]);
				
				// Go to next byte
				++i;
				
				// Break
				break;
			
			// Verbatim string
			case 255: {
			
				// Check if verbatim string length doesn't exist
				if(i >= length - 1) {
				
					// Throw exception
					throw runtime_error("Verbatim string length doesn't exist");
				}
				
				// Get verbatim string length
				const size_t verbatimStringLength = data[i + 1] + 1;
				
				// Check if verbatim string doesn't exist
				if(length < 1 + verbatimStringLength || i >= length - (1 + verbatimStringLength)) {
				
					// Throw exception
					throw runtime_error("Verbatim string doesn't exist");
				}
				
				// Add verbatim string to result
				result.insert(result.end(), &data[i + 1 + 1], &data[i + 1 + 1] + verbatimStringLength);
				
				// Go to next byte
				i += 1 + verbatimStringLength;
				
				// Break
				break;
			}
			
			// Default
			default: {
			
				// Get decompress codebook entry at byte
				const char *decompressCodeBookEntry = DECOMPRESS_CODEBOOK[byte];
				
				// Add decompress codebook entry to result
				result.insert(result.end(), decompressCodeBookEntry, decompressCodeBookEntry + strlen(decompressCodeBookEntry));
			
				// Break
				break;
			}
		}
	}
	
	// Return result
	return result;
}
