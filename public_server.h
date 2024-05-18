// Header guard
#ifndef PUBLIC_SERVER_H
#define PUBLIC_SERVER_H


// Header files
#include <filesystem>
#include <getopt.h>
#include <thread>
#include <unordered_map>
#include <vector>
#include "event2/event.h"
#include "event2/http.h"
#include "./payments.h"
#include "./price.h"
#include "./wallet.h"

using namespace std;


// Classes

// Public server class
class PublicServer final {

	// Public
	public:
	
		// Constructor
		explicit PublicServer(const unordered_map<char, const char *> &providedOptions, const filesystem::path &currentDirectory, const Wallet &wallet, Payments &payments, const Price &price);
		
		// Destructor
		~PublicServer();
		
		// Get options
		static vector<option> getOptions();
		
		// Display options help
		static void displayOptionsHelp();
		
		// Validate option
		static bool validateOption(const char option, const char *value, char *argv[]);
		
		// Default address
		static const char *DEFAULT_ADDRESS;
		
		// Default port
		static const uint16_t DEFAULT_PORT;
	
	// Private
	private:
	
		// Run
		void run(const unordered_map<char, const char *> &providedOptions, const filesystem::path &currentDirectory);
		
		// Handle generic request
		void handleGenericRequest(evhttp_request *request);
		
		// Started
		atomic_bool started;
		
		// Wallet
		const Wallet &wallet;
		
		// Payments
		Payments &payments;
		
		// Price
		const Price &price;
		
		// Event base
		unique_ptr<event_base, decltype(&event_base_free)> eventBase;
		
		// Price disable
		const bool priceDisable;
		
		// Main thread
		thread mainThread;
};


#endif
