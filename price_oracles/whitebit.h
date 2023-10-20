// Header guard
#ifndef WHITEBIT_H
#define WHITEBIT_H


// Header files
#include "../price_oracle.h"

using namespace std;


// Classes

// WhiteBIT class
class WhiteBit final : public PriceOracle {

	// Public
	public:
	
		// Constructor
		WhiteBit(const TorProxy &torProxy);
		
	// Private
	private:
	
		// Get new price
		virtual pair<chrono::time_point<chrono::system_clock>, string> getNewPrice() const override final;
};


#endif
