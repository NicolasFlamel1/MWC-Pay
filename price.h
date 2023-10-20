// Header guard
#ifndef PRICE_H
#define PRICE_H


// Header files
#include <getopt.h>
#include <list>
#include <memory>
#include <unordered_map>
#include "event2/event.h"
#include "./price_oracle.h"
#include "./tor_proxy.h"

using namespace std;


// Classes

// Price class
class Price {

	// Public
	public:
	
		// Constructor
		explicit Price(const unordered_map<char, const char *> &providedOptions, const TorProxy &torProxy);
		
		// Destructor
		~Price();
		
		// Get current price
		string getCurrentPrice() const;
		
		// Get options
		static vector<option> getOptions();
		
		// Display options help
		static void displayOptionsHelp();
		
		// Validate option
		static bool validateOption(const char option, const char *value, char *argv[]);
	
	// Private
	private:
	
		// Run
		void run(const unordered_map<char, const char *> &providedOptions);
		
		// Update current price
		bool updateCurrentPrice();
		
		// Started
		atomic_bool started;
		
		// Failed
		atomic_bool failed;
		
		// Current price
		string currentPrice;
		
		// Current price lock
		mutable mutex currentPriceLock;
		
		// Average length
		size_t averageLength;
		
		// Update interval
		time_t updateInterval;
		
		// Prices
		list<string> prices;
		
		// Price oracles
		list<unique_ptr<PriceOracle>> priceOracles;
		
		// Event base
		unique_ptr<event_base, decltype(&event_base_free)> eventBase;
		
		// Main thread
		thread mainThread;
};


#endif
