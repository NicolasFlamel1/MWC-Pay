// Header guard
#ifndef PRIVATE_SERVER_H
#define PRIVATE_SERVER_H


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

// Private server class
class PrivateServer final {

	// Public
	public:
	
		// Constructor
		explicit PrivateServer(const unordered_map<char, const char *> &providedOptions, const filesystem::path &currentDirectory, const Wallet &wallet, Payments &payments, const Price &price);
		
		// Destructor
		~PrivateServer();
		
		// Get options
		static vector<option> getOptions();
		
		// Display options help
		static void displayOptionsHelp();
		
		// Validate option
		static bool validateOption(const char option, const char *value, char *argv[]);
	
	// Private
	private:
	
		// Run
		void run(const unordered_map<char, const char *> &providedOptions, const filesystem::path &currentDirectory);
		
		// Handle create payment request
		void handleCreatePaymentRequest(evhttp_request *request);
		
		// Handle get payment info request
		void handleGetPaymentInfoRequest(evhttp_request *request);
		
		// Handle get price request
		void handleGetPriceRequest(evhttp_request *request);
		
		// Handle get public server info request
		void handleGetPublicServerInfoRequest(evhttp_request *request);
		
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
		
		// Using Onion Service
		const bool usingOnionService;
		
		// Public server URL
		string publicServerUrl;
		
		// Main thread
		thread mainThread;
};


#endif
