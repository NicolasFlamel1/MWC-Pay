// Header files
#include <cmath>
#include "./bitforex.h"
#include "../common.h"
#include "mpfr.h"
#include "simdjson.h"

using namespace std;


// Constants

// Precision
static const mpfr_prec_t PRECISION = 256;


// Supporting function implementation

// Constructor
BitForex::BitForex(const TorProxy &torProxy) :

	// Delegate constructor
	PriceOracle(torProxy)
{
}

// Get new price
pair<chrono::time_point<chrono::system_clock>, string> BitForex::getNewPrice() const {

	// Check if creating request failed
	vector<uint8_t> response;
	const unique_ptr request = createRequest("api.bitforex.com", Common::HTTPS_PORT, "/api/v1/market/ticker?symbol=coin-usdt-mwc", response);
	if(!request) {
	
		// Throw exception
		throw runtime_error("Creating BitForex request failed");
	}
	
	// Check if performing requests failed
	if(!performRequests() || response.empty()) {
	
		// Throw exception
		throw runtime_error("Performing BitForex requests failed");
	}
	
	// Parse response as JSON
	const simdjson::padded_string paddedResponse(reinterpret_cast<const char *>(response.data()), response.size());
	simdjson::ondemand::parser parser;
	simdjson::ondemand::document json = parser.iterate(paddedResponse);
	
	// Check if response is invalid
	if(!json["success"].get_bool().value()) {
	
		// Throw exception
		throw runtime_error("BitForex response is invalid");
	}
	
	// Get date
	const int64_t date = json["data"]["date"].get_int64().value();
	
	// Check if date is invalid
	if(date < chrono::duration_cast<chrono::milliseconds>(chrono::time_point<chrono::system_clock>::min().time_since_epoch()).count() || date > chrono::duration_cast<chrono::milliseconds>(chrono::time_point<chrono::system_clock>::max().time_since_epoch()).count()) {
	
		// Throw exception
		throw runtime_error("BitForex date is invalid");
	}
	
	// Get timestamp from date
	chrono::time_point<chrono::system_clock> timestamp = chrono::time_point<chrono::system_clock>(chrono::milliseconds(date));
	
	// Check if timestamp is in the future
	if(timestamp > chrono::system_clock::now()) {
	
		// Set timestamp to now
		timestamp = chrono::system_clock::now();
	}
	
	// Get price
	const double price = json["data"]["last"].get_double().value();
	
	// Check if setting price is invalid
	if(!isfinite(price) || price <= 0) {
	
		// Throw exception
		throw runtime_error("BitForex price is invalid");
	}
	
	// Initialize MWC price
	mpfr_t mwcPrice;
	mpfr_init2(mwcPrice, PRECISION);
	
	// Automatically free MWC price
	const unique_ptr<remove_pointer<mpfr_ptr>::type, decltype(&mpfr_clear)> mwcPriceUniquePointer(mwcPrice, mpfr_clear);
	
	// Check if setting MWC price is invalid
	mpfr_set_d(mwcPrice, price, MPFR_RNDN);
	if(mpfr_sgn(mwcPrice) <= 0) {
	
		// Throw exception
		throw runtime_error("BitForex price is invalid");
	}
	
	// Initialize precision
	unsigned int precision = 0;
	
	// Get price string
	const string_view priceString = json["data"]["last"].raw_json_token();
	
	// Check if price has a decimal
	const size_t decimal = priceString.find('.');
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
	
	// Check if getting result size failed
	const int resultSize = mpfr_snprintf(nullptr, 0, ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, mwcPrice);
	if(resultSize <= 0) {
	
		// Throw exception
		throw runtime_error("Getting BitForex result size failed");
	}
	
	// Check if getting result failed
	string result(resultSize, '\0');
	if(mpfr_sprintf(result.data(), ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, mwcPrice) != resultSize) {
	
		// Throw exception
		throw runtime_error("Getting BitForex result failed");
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
