// Header guard
#ifndef COINSTORE_H
#define COINSTORE_H


// Header files
#include "../price_oracle.h"

using namespace std;


// Classes

// Coinstore class
class Coinstore final : public PriceOracle {

	// Public
	public:
	
		// Constructor
		explicit Coinstore(const TorProxy &torProxy);
		
	// Private
	private:
		
		// Get new price
		virtual pair<chrono::time_point<chrono::system_clock>, string> getNewPrice() const override final;
};


#endif
