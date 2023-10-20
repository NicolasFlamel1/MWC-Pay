// Header guard
#ifndef COINGECKO_H
#define COINGECKO_H


// Header files
#include "../price_oracle.h"

using namespace std;


// Classes

// CoinGecko class
class CoinGecko final : public PriceOracle {

	// Public
	public:
	
		// Constructor
		explicit CoinGecko(const TorProxy &torProxy);
		
	// Private
	private:
		
		// Get new price
		virtual pair<chrono::time_point<chrono::system_clock>, string> getNewPrice() const override final;
};


#endif
