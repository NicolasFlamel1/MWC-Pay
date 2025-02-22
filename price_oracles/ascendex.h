// Header guard
#ifndef ASCENDEX_H
#define ASCENDEX_H


// Header files
#include "../price_oracle.h"

using namespace std;


// Classes

// AscendEX class
class AscendEx final : public PriceOracle {

	// Public
	public:
	
		// Constructor
		explicit AscendEx(const TorProxy &torProxy);
		
	// Private
	private:
		
		// Get new price
		virtual pair<chrono::time_point<chrono::system_clock>, string> getNewPrice() const override final;
};


#endif
