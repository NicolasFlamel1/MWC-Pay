// Header guard
#ifndef COMMON_H
#define COMMON_H


// Header files
#include <atomic>
#include <cstdint>
#include <signal.h>

using namespace std;


// Classes

// Common class
class Common final {

	// Public
	public:
	
		// Constructor
		Common() = delete;
		
		// Bytes in a kilobyte
		static const int BYTES_IN_A_KILOBYTE;
		
		// Decimal number base
		static const int DECIMAL_NUMBER_BASE;
		
		// HTTP port
		static const uint16_t HTTP_PORT;
		
		// HTTPS port
		static const uint16_t HTTPS_PORT;
		
		// UUID size
		static const size_t UUID_SIZE = 16;
		
		// UUID data variant index
		static const size_t UUID_DATA_VARIANT_INDEX;

		// UUId variant two bitmask
		static const uint8_t UUID_VARIANT_TWO_BITMASK;

		// UUID variant two bitmask result
		static const uint8_t UUID_VARIANT_TWO_BITMASK_RESULT;
		
		// UUID variant one data version index
		static const size_t UUID_VARIANT_ONE_DATA_VERSION_INDEX;
		
		// UUID variant two data version index
		static const size_t UUID_VARIANT_TWO_DATA_VERSION_INDEX;
		
		// Hex character size
		static const size_t HEX_CHARACTER_SIZE;
		
		// Set error occurred
		static void setErrorOccurred();
		
		// Get error occurred
		static bool getErrorOccurred();
		
		// Get number in number base
		static string getNumberInNumberBase(const uint64_t number, const int numberBase);
		
		// To hex string
		static string toHexString(const uint8_t *data, const size_t length);
		
		// Is valid UTF-8 string
		static bool isValidUtf8String(const uint8_t *data, const size_t length);
		
		// Block signals
		static bool blockSignals();
		
		// Allow signals
		static bool allowSignals();
		
		// Set signal received
		static void setSignalReceived();
		
		// Get signal received
		static bool getSignalReceived();
		
		// Send HTTP request
		static bool sendHttpRequest(const char *destination);
	
	// Private
	private:
		
		// Error occurred
		static atomic_bool errorOccurred;
		
		// Signal received
		static volatile sig_atomic_t signalReceived;
};


#endif
