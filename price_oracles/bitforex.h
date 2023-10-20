// Header guard
#ifndef BITFOREX_H
#define BITFOREX_H


// Header files
#include "../price_oracle.h"

using namespace std;


// Classes

// BitForex class
class BitForex final : public PriceOracle {

	// Public
	public:
	
		// Constructor
		explicit BitForex(const TorProxy &torProxy);
		
	// Private
	private:
		
		// Get new price
		virtual pair<chrono::time_point<chrono::system_clock>, string> getNewPrice() const override final;
};


#endif
