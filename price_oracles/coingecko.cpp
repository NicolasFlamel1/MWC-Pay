// Header files
#include <cmath>
#include "./coingecko.h"
#include "../common.h"
#include "mpfr.h"
#include "simdjson.h"

using namespace std;


// Supporting function implementation

// Constructor
CoinGecko::CoinGecko(const TorProxy &torProxy) :

	// Delegate constructor
	PriceOracle(torProxy)
{
}

// Get new price
pair<chrono::time_point<chrono::system_clock>, string> CoinGecko::getNewPrice() const {

	// Check if creating MWC request failed
	vector<uint8_t> mwcResponse;
	const unique_ptr mwcRequest = createRequest("api.coingecko.com", Common::HTTPS_PORT, "/api/v3/simple/price?ids=mimblewimblecoin&vs_currencies=usd&include_last_updated_at=true", mwcResponse);
	if(!mwcRequest) {
	
		// Throw exception
		throw runtime_error("Creating CoinGecko MWC request failed");
	}
	
	// Check if creating USDT request failed
	vector<uint8_t> usdtResponse;
	const unique_ptr usdtRequest = createRequest("api.coingecko.com", Common::HTTPS_PORT, "/api/v3/simple/price?ids=tether&vs_currencies=usd", usdtResponse);
	if(!usdtRequest) {
	
		// Throw exception
		throw runtime_error("Creating CoinGecko USDT request failed");
	}
	
	// Check if performing requests failed
	if(!performRequests() || mwcResponse.empty() || usdtResponse.empty()) {
	
		// Throw exception
		throw runtime_error("Performing CoinGecko requests failed");
	}
	
	// Parse MWC response as JSON
	simdjson::padded_string paddedResponse(reinterpret_cast<const char *>(mwcResponse.data()), mwcResponse.size());
	simdjson::ondemand::parser parser;
	simdjson::ondemand::document json = parser.iterate(paddedResponse);
	
	// Get date
	const int64_t date = json["mimblewimblecoin"]["last_updated_at"].get_int64().value();
	
	// Check if date is invalid
	if(date < chrono::duration_cast<chrono::seconds>(chrono::time_point<chrono::system_clock>::min().time_since_epoch()).count() || date > chrono::duration_cast<chrono::seconds>(chrono::time_point<chrono::system_clock>::max().time_since_epoch()).count()) {
	
		// Throw exception
		throw runtime_error("CoinGecko date is invalid");
	}
	
	// Get timestamp from date
	chrono::time_point<chrono::system_clock> timestamp = chrono::time_point<chrono::system_clock>(chrono::seconds(date));
	
	// Check if timestamp is in the future
	if(timestamp > chrono::system_clock::now()) {
	
		// Set timestamp to now
		timestamp = chrono::system_clock::now();
	}
	
	// Get price
	double price = json["mimblewimblecoin"]["usd"].get_double().value();
	
	// Check if setting price is invalid
	if(!isfinite(price) || price <= 0) {
	
		// Throw exception
		throw runtime_error("CoinGecko MWC price is invalid");
	}
	
	// Initialize MWC price
	mpfr_t mwcPrice;
	mpfr_init2(mwcPrice, Common::MPFR_PRECISION);
	
	// Automatically free MWC price
	const unique_ptr<remove_pointer<mpfr_ptr>::type, decltype(&mpfr_clear)> mwcPriceUniquePointer(mwcPrice, mpfr_clear);
	
	// Check if setting MWC price is invalid
	mpfr_set_d(mwcPrice, price, MPFR_RNDN);
	if(mpfr_sgn(mwcPrice) <= 0) {
	
		// Throw exception
		throw runtime_error("CoinGecko MWC price is invalid");
	}
	
	// Initialize precision
	size_t precision = 0;
	
	// Get price string
	string_view priceString = json["mimblewimblecoin"]["usd"].raw_json_token();
	
	// Check if price has a decimal
	size_t decimal = priceString.find('.');
	if(decimal != string_view::npos) {
	
		// Check if price string is in scientific notation
		if(priceString.find('e') != string_view::npos || priceString.find('E') != string_view::npos) {
		
			// Update precision
			precision += numeric_limits<double>::digits10;
		}
		
		// Otherwise
		else {
		
			// Update precision
			precision += priceString.size() - (decimal + sizeof('.'));
		}
	}
	
	// Parse USDT response as JSON
	paddedResponse = simdjson::padded_string(reinterpret_cast<const char *>(usdtResponse.data()), usdtResponse.size());
	json = parser.iterate(paddedResponse);
	
	// Get price
	price = json["tether"]["usd"].get_double().value();
	
	// Check if setting price is invalid
	if(!isfinite(price) || price <= 0) {
	
		// Throw exception
		throw runtime_error("CoinGecko USDT price is invalid");
	}
	
	// Initialize USDT price
	mpfr_t usdtPrice;
	mpfr_init2(usdtPrice, Common::MPFR_PRECISION);
	
	// Automatically free USDT price
	const unique_ptr<remove_pointer<mpfr_ptr>::type, decltype(&mpfr_clear)> usdtPriceUniquePointer(usdtPrice, mpfr_clear);
	
	// Check if setting USDT price is invalid
	mpfr_set_d(usdtPrice, price, MPFR_RNDN);
	if(mpfr_sgn(usdtPrice) <= 0) {
	
		// Throw exception
		throw runtime_error("CoinGecko USDT price is invalid");
	}
	
	// Get price string
	priceString = json["tether"]["usd"].raw_json_token();
	
	// Check if price has a decimal
	decimal = priceString.find('.');
	if(decimal != string_view::npos) {
	
		// Check if price string is in scientific notation
		if(priceString.find('e') != string_view::npos || priceString.find('E') != string_view::npos) {
		
			// Update precision
			precision += numeric_limits<double>::digits10;
		}
		
		// Otherwise
		else {
		
			// Update precision
			precision += priceString.size() - (decimal + sizeof('.'));
		}
	}
	
	// Divide MWC price by USDT price to get the price in USDT
	mpfr_div(mwcPrice, mwcPrice, usdtPrice, MPFR_RNDA);
	
	// Check if result is invalid
	if(mpfr_sgn(mwcPrice) <= 0) {
	
		// Throw exception
		throw runtime_error("CoinGecko result is invalid");
	}
	
	// Check if getting result size failed
	const int resultSize = mpfr_snprintf(nullptr, 0, ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, mwcPrice);
	if(resultSize <= 0) {
	
		// Throw exception
		throw runtime_error("Getting CoinGecko result size failed");
	}
	
	// Check if getting result failed
	string result(resultSize, '\0');
	if(mpfr_sprintf(result.data(), ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, mwcPrice) != resultSize) {
	
		// Throw exception
		throw runtime_error("Getting CoinGecko result failed");
	}
	
	// Check if result isn't zero
	if(result != "0") {
	
		// Check if result has a trailing zero
		if(result.back() == '0') {
		
			// Remove trailing zeros from result
			result = result.substr(0, result.find_last_not_of('0') + sizeof('0'));
		}
		
		// Check if result has a trailing decimal
		if(result.back() == '.') {
		
			// Remove trailing decimal from result
			result.pop_back();
		}
	}
	
	// Return time and result
	return {timestamp, result};
}
