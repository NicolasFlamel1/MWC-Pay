// Header files
#include <cmath>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include "./base64.h"
#include "./common.h"
#include "event2/bufferevent_ssl.h"
#include "event2/event.h"
#include "event2/http.h"
#include "openssl/ssl.h"

using namespace std;


// Constants

// Bytes in a kilobyte
const int Common::BYTES_IN_A_KILOBYTE = pow(2, 10);

// Seconds in a minute
const int Common::SECONDS_IN_A_MINUTE = 60;

// Minutes in an hours
const int Common::MINUTES_IN_AN_HOUR = 60;

// Hours in a day
const int Common::HOURS_IN_A_DAY = 24;

// Days in a week
const int Common::DAYS_IN_A_WEEK = 7;

// Decimal number base
const int Common::DECIMAL_NUMBER_BASE = 10;

// HTTP port
const uint16_t Common::HTTP_PORT = 80;

// HTTPS port
const uint16_t Common::HTTPS_PORT = 443;

// UUID data variant index
const size_t Common::UUID_DATA_VARIANT_INDEX = 8;

// UUID variant one data version index
const size_t Common::UUID_VARIANT_ONE_DATA_VERSION_INDEX = 6;

// UUID variant two data version index
const size_t Common::UUID_VARIANT_TWO_DATA_VERSION_INDEX = 7;

// UUId variant two bitmask
const uint8_t Common::UUID_VARIANT_TWO_BITMASK = 0b1110;

// UUID variant two bitmask result
const uint8_t Common::UUID_VARIANT_TWO_BITMASK_RESULT = 0b1100;

// Hex character size
const size_t Common::HEX_CHARACTER_SIZE = sizeof("FF") - sizeof('\0');

// MPRF precision
const int Common::MPFR_PRECISION = 256;

// Minimum TLS version
static const int MINIMUM_TLS_VERSION = TLS1_VERSION;


// Global variables

// Error occurred
atomic_bool Common::errorOccurred(false);

// Signal received
volatile sig_atomic_t Common::signalReceived = false;


// Supporting function implementation

// Set error occurred
void Common::setErrorOccurred() {

	// Set error occurred to true
	errorOccurred.store(true);
}

// Get error occurred
bool Common::getErrorOccurred() {

	// Return if error occurred
	return errorOccurred.load();
}

// Get number in number base
string Common::getNumberInNumberBase(const uint64_t number, const int numberBase) {

	// Get number's decimal string
	string decimalString = to_string(number % numberBase);
	
	// Check if number has a decimal part
	if(decimalString != "0") {
	
		// Pad decimal string to be in the number base
		decimalString.insert(0, ceil(log10(numberBase)) - decimalString.size(), '0');
	}
	
	// Return number in number base and the decimal string in number base
	return to_string(number / numberBase) + ((decimalString != "0") ? '.' + ((decimalString.back() == '0') ? decimalString.substr(0, decimalString.find_last_not_of('0') + sizeof('0')) : decimalString) : "");
}

// To hex string
string Common::toHexString(const uint8_t *data, const size_t length) {

	// Initialize result
	stringstream result;
	result << hex << nouppercase << setfill('0');
	
	// Go through all bytes in the data
	for(size_t i = 0; i < length; ++i) {
	
		// Append byte as text to the result
		result << setw(HEX_CHARACTER_SIZE) << static_cast<uint16_t>(data[i]);
	}
	
	// Return result
	return result.str();
}

// Is valid UTF-8 string
bool Common::isValidUtf8String(const uint8_t *data, const size_t length) {

	// Go through all UTF-8 code points in the data
	for(size_t i = 0; i < length;) {

		// Check if UTF-8 code point is an ASCII character
		if(data[i] <= 0x7F) {

			// Go to next UTF-8 code point
			++i;
		}

		// Otherwise check if UTF-8 code point is a non-overlong two byte character
		else if(length >= 1 && i < length - 1 && data[i] >= 0xC2 && data[i] <= 0xDF && data[i + 1] >= 0x80 && data[i + 1] <= 0xBF) {

			// Go to next UTF-8 code point
			i += 2;
		}

		// Otherwise check if UTF-8 code point is an excluding overlongs character
		else if(length >= 2 && i < length - 2 && data[i] == 0xE0 && data[i + 1] >= 0xA0 && data[i + 1] <= 0xBF && data[i + 2] >= 0x80 && data[i + 2] <= 0xBF) {

			// Go to next UTF-8 code point
			i += 3;
		}

		// Otherwise check if UTF-8 code point is a straight three byte character
		else if(length >= 2 && i < length - 2 && ((data[i] >= 0xE1 && data[i] <= 0xEC) || data[i] == 0xEE || data[i] == 0xEF) && data[i + 1] >= 0x80 && data[i + 1] <= 0xBF && data[i + 2] >= 0x80 && data[i + 2] <= 0xBF) {

			// Go to next UTF-8 code point
			i += 3;
		}

		// Otherwise check if UTF-8 code point is an excluding surrogates character
		else if(length >= 2 && i < length - 2 && data[i] == 0xED && data[i + 1] >= 0x80 && data[i + 1] <= 0x9F && data[i + 2] >= 0x80 && data[i + 2] <= 0xBF) {

			// Go to next UTF-8 code point
			i += 3;
		}

		// Otherwise check if UTF-8 code point is a planes one to three character
		else if(length >= 3 && i < length - 3 && data[i] == 0xF0 && data[i + 1] >= 0x90 && data[i + 1] <= 0xBF && data[i + 2] >= 0x80 && data[i + 2] <= 0xBF && data[i + 3] >= 0x80 && data[i + 3] <= 0xBF) {

			// Go to next UTF-8 code point
			i += 4;
		}

		// Otherwise check if UTF-8 code point is a planes four to fifteen character
		else if(length >= 3 && i < length - 3 && data[i] >= 0xF1 && data[i] <= 0xF3 && data[i + 1] >= 0x80 && data[i + 1] <= 0xBF && data[i + 2] >= 0x80 && data[i + 2] <= 0xBF && data[i + 3] >= 0x80 && data[i + 3] <= 0xBF) {

			// Go to next UTF-8 code point
			i += 4;
		}

		// Otherwise check if UTF-8 code point is a plane sixteen character
		else if(length >= 3 && i < length - 3 && data[i] == 0xF4 && data[i + 1] >= 0x80 && data[i + 1] <= 0x8F && data[i + 2] >= 0x80 && data[i + 2] <= 0xBF && data[i + 3] >= 0x80 && data[i + 3] <= 0xBF) {

			// Go to next UTF-8 code point
			i += 4;
		}

		// Otherwise
		else {

			// Return false
			return false;
		}
	}

	// Return true
	return true;
}

// Block signals
bool Common::blockSignals() {

	// Return if blocking signals was successful
	sigset_t signalMask;
	return !sigfillset(&signalMask) && !sigdelset(&signalMask, SIGUSR1) && !pthread_sigmask(SIG_SETMASK, &signalMask, nullptr);
}

// Allow signals
bool Common::allowSignals() {

	// Return if allowing signals was successful
	sigset_t signalMask;
	return !sigfillset(&signalMask) && !sigdelset(&signalMask, SIGUSR1) && !sigdelset(&signalMask, SIGINT) && !sigdelset(&signalMask, SIGTERM) && !pthread_sigmask(SIG_SETMASK, &signalMask, nullptr);
}

// Set signal received
void Common::setSignalReceived() {

	// Set signal received
	signalReceived = true;
}

// Get signal received
bool Common::getSignalReceived() {

	// Return signal received
	return signalReceived;
}

// Send HTTP request
bool Common::sendHttpRequest(const char *destination) {

	// Try
	try {
	
		// Check if parsing destination failed
		const unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> uri(evhttp_uri_parse(destination), evhttp_uri_free);
		if(!uri) {
		
			// Return false
			return false;
		}
		
		// Check if creating event base failed
		const unique_ptr<event_base, decltype(&event_base_free)> eventBase(event_base_new(), event_base_free);
		if(!eventBase) {
		
			// Return false
			return false;
		}
		
		// Check if host is to an IPv6 address
		string host;
		if(evhttp_uri_get_host(uri.get())[0] == '[' && evhttp_uri_get_host(uri.get())[strlen(evhttp_uri_get_host(uri.get())) - sizeof('\0')] == ']') {
		
			// Set host
			host = string(&evhttp_uri_get_host(uri.get())[sizeof('[')], strlen(evhttp_uri_get_host(uri.get())) - sizeof('[') - sizeof(']'));
		}
		
		// Otherwise
		else {
		
			// Set host
			host = evhttp_uri_get_host(uri.get());
		}
		
		// Check if no port is specified
		uint16_t port;
		if(evhttp_uri_get_port(uri.get()) == -1) {
		
			// Set port
			port = !strcasecmp(evhttp_uri_get_scheme(uri.get()), "http") ? HTTP_PORT : HTTPS_PORT;
		}
		
		// Otherwise
		else {
		
			// Set port
			port = evhttp_uri_get_port(uri.get());
		}
		
		// Initialize connection
		unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)> connection(nullptr, evhttp_connection_free);
		
		// Check if using TLS
		unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> tlsContext(nullptr, SSL_CTX_free);
		if(!strcasecmp(evhttp_uri_get_scheme(uri.get()), "https")) {
		
			// Check if getting TLS method failed
			const SSL_METHOD *tlsMethod = TLS_client_method();
			if(!tlsMethod) {
			
				// Return false
				return false;
			}
			
			// Check if creating TLS context failed
			tlsContext = unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(SSL_CTX_new_ex(nullptr, nullptr, tlsMethod), SSL_CTX_free);
			if(!tlsContext) {
			
				// Return false
				return false;
			}
			
			// Check if setting TLS context's minimum TLS version failed
			if(!SSL_CTX_set_min_proto_version(tlsContext.get(), MINIMUM_TLS_VERSION)) {
			
				// Return false
				return false;
			}
			
			// Check if using the default verify paths for the TLS context failed
			if(!SSL_CTX_set_default_verify_paths(tlsContext.get())) {
			
				// Return false
				return false;
			}
			
			// Set TLS context to verify server certificate
			SSL_CTX_set_verify(tlsContext.get(), SSL_VERIFY_PEER, nullptr);
			
			// Check if creating TLS connection from the TLS context failed
			unique_ptr<SSL, decltype(&SSL_free)> tlsConnection(SSL_new(tlsContext.get()), SSL_free);
			if(!tlsConnection) {
			
				// Return false
				return false;
			}
			
			// Check if enabling the TLS connection's hostname checking failed
			if(!SSL_set1_host(tlsConnection.get(), host.c_str())) {
			
				// Return false
				return false;
			}
			
			// Check if setting the TLS connection's server name indication failed
			if(!SSL_set_tlsext_host_name(tlsConnection.get(), host.c_str())) {
			
				// Return false
				return false;
			}
			
			// Check if creating TLS buffer from TLS connection failed
			unique_ptr<bufferevent, decltype(&bufferevent_free)> tlsBuffer(bufferevent_openssl_socket_new(eventBase.get(), -1, tlsConnection.get(), BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS), bufferevent_free);
			if(!tlsBuffer) {
			
				// Return false
				return false;
			}
			
			// Release TLS connection
			tlsConnection.release();
			
			// Check if allow dirty shutdown for the TLS buffer failed
			if(bufferevent_ssl_set_flags(tlsBuffer.get(), BUFFEREVENT_SSL_DIRTY_SHUTDOWN) == EV_UINT64_MAX) {
			
				// Return false
				return false;
			}
			
			// Check if creating connection from TLS buffer failed
			connection = unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(evhttp_connection_base_bufferevent_new(eventBase.get(), nullptr, tlsBuffer.get(), host.c_str(), port), evhttp_connection_free);
			if(!connection) {
			
				// Return false
				return false;
			}
			
			// Release TLS buffer
			tlsBuffer.release();
			
			// Set connection close callback
			evhttp_connection_set_closecb(connection.get(), [](evhttp_connection *connection, void *argument) {
			
				// Check if connection's buffer event exists
				bufferevent *bufferEvent = evhttp_connection_get_bufferevent(connection);
				if(bufferEvent) {

					// Check if buffer event's TLS connection exists
					SSL *tlsConnection = bufferevent_openssl_get_ssl(bufferEvent);
					if(tlsConnection) {
					
						// Shutdown TLS connection
						SSL_shutdown(tlsConnection);
					}
				}
			}, nullptr);
		}
		
		// Otherwise
		else {
		
			// Check if creating connection failed
			connection = unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(evhttp_connection_base_new(eventBase.get(), nullptr, host.c_str(), port), evhttp_connection_free);
			if(!connection) {
			
				// Return false
				return false;
			}
		}
		
		// Initialize result
		bool result = false;
		
		// Check if creating request failed
		unique_ptr<evhttp_request, decltype(&evhttp_request_free)> request(evhttp_request_new([](evhttp_request *request, void *argument) {
		
			// Get result from argument
			bool *result = reinterpret_cast<bool *>(argument);
			
			// Set result to if the request was successful
			*result = request && evhttp_request_get_response_code(request) == HTTP_OK;
			
		}, &result), evhttp_request_free);
		
		if(!request) {
		
			// Return false
			return false;
		}
		
		// Check if setting request's host and connection headers failed
		if(!evhttp_request_get_output_headers(request.get()) || evhttp_add_header(evhttp_request_get_output_headers(request.get()), "Host", (evhttp_uri_get_host(uri.get()) + (((!strcasecmp(evhttp_uri_get_scheme(uri.get()), "http") && port != HTTP_PORT) || (!strcasecmp(evhttp_uri_get_scheme(uri.get()), "https") && port != HTTPS_PORT)) ? ':' + to_string(port) : "")).c_str()) || evhttp_add_header(evhttp_request_get_output_headers(request.get()), "Connection", "close")) {
		
			// Return false
			return false;
		}
		
		// Check if user info is provided
		if(evhttp_uri_get_userinfo(uri.get()) && *evhttp_uri_get_userinfo(uri.get())) {
		
			// Check if settings request's authorization header failed
			if(evhttp_add_header(evhttp_request_get_output_headers(request.get()), "Authorization", ("Basic " + Base64::encode(reinterpret_cast<const uint8_t *>(evhttp_uri_get_userinfo(uri.get())), strlen(evhttp_uri_get_userinfo(uri.get())))).c_str())) {
			
				// Return false
				return false;
			}
		}
		
		// Check if making request failed
		if(evhttp_make_request(connection.get(), request.get(), EVHTTP_REQ_GET, (string((evhttp_uri_get_path(uri.get()) && *evhttp_uri_get_path(uri.get())) ? evhttp_uri_get_path(uri.get()) : "/") + ((evhttp_uri_get_query(uri.get()) && *evhttp_uri_get_query(uri.get())) ? string("?") + evhttp_uri_get_query(uri.get()) : "")).c_str())) {
		
			// Release request
			request.release();
			
			// Return false
			return false;
		}
		
		// Release request
		request.release();
		
		// Check if running event loop failed
		if(event_base_dispatch(eventBase.get()) == -1) {
		
			// Return false
			return false;
		}
		
		// Return result
		return result;
	}
	
	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
}

// Apply substitutions
void Common::applySubstitutions(string &text, const unordered_map<string, string> &substitutions) {

	// Go through all substitutions
	for(unordered_map<string, string>::const_iterator i = substitutions.begin(); i != substitutions.end(); ++i) {
	
		// Loop through all occurances in the text
		string::size_type index = 0;
		while((index = text.find(i->first, index)) != string::npos) {
		
			// Replace occurance with substitution
			text.replace(index, i->first.size(), i->second);
			
			// Update index
			index += i->second.size();
		}
	}
}
