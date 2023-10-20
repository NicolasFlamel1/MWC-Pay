// Header guard
#ifndef PRICE_ORACLE_H
#define PRICE_ORACLE_H


// Header files
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include "event2/event.h"
#include "event2/http.h"
#include "openssl/ssl.h"
#include "./tor_proxy.h"

using namespace std;


// Classes

// Price oracle class
class PriceOracle {

	// Public
	public:
	
		// Constructor
		explicit PriceOracle(const TorProxy &torProxy);
		
		// Get price
		pair<chrono::time_point<chrono::system_clock>, string> getPrice() const;
	
	// Protected
	protected:
		
		// Create request
		unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)> createRequest(const char *host, const uint16_t port, const char *path, vector<uint8_t> &response) const;
		
		// Perform requests
		bool performRequests() const;
	
	// Private
	private:
	
		// Get new price
		virtual pair<chrono::time_point<chrono::system_clock>, string> getNewPrice() const = 0;
		
		// Tor proxy
		const TorProxy &torProxy;
		
		// TLS method
		const SSL_METHOD *tlsMethod;
		
		// TLS context
		const unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> tlsContext;
		
		// Event base
		const unique_ptr<event_base, decltype(&event_base_free)> eventBase;
		
		// Previous timestamp
		mutable chrono::time_point<chrono::system_clock> previousTimestamp;
		
		// Previous price
		mutable string previousPrice;
};


#endif
