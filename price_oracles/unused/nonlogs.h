// Header guard
#ifndef NONLOGS_H
#define NONLOGS_H


// Header files
#include "../price_oracle.h"

using namespace std;


// Classes

// NonLogs class
class NonLogs final : public PriceOracle {

	// Public
	public:
	
		// Constructor
		explicit NonLogs(const TorProxy &torProxy);
		
	// Private
	private:
		
		// Get new price
		virtual pair<chrono::time_point<chrono::system_clock>, string> getNewPrice() const override final;
};


#endif
