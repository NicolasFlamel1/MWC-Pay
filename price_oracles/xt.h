// Header guard
#ifndef XT_H
#define XT_H


// Header files
#include "../price_oracle.h"

using namespace std;


// Classes

// XT class
class Xt final : public PriceOracle {

	// Public
	public:
	
		// Constructor
		explicit Xt(const TorProxy &torProxy);
		
	// Private
	private:
		
		// Get new price
		virtual pair<chrono::time_point<chrono::system_clock>, string> getNewPrice() const override final;
};


#endif
