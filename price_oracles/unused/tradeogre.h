// Header guard
#ifndef TRADEOGRE_H
#define TRADEOGRE_H


// Header files
#include "../price_oracle.h"

using namespace std;


// Classes

// TradeOgre class
class TradeOgre final : public PriceOracle {

	// Public
	public:
	
		// Constructor
		explicit TradeOgre(const TorProxy &torProxy);
		
	// Private
	private:
	
		// Get new price
		virtual pair<chrono::time_point<chrono::system_clock>, string> getNewPrice() const override final;
};


#endif
