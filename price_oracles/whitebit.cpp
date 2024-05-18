// Header files
#include "../common.h"
#include "mpfr.h"
#include "simdjson.h"
#include "./whitebit.h"

using namespace std;


// Supporting function implementation

// Constructor
WhiteBit::WhiteBit(const TorProxy &torProxy) :

	// Delegate constructor
	PriceOracle(torProxy)
{
}

// Get new price
pair<chrono::time_point<chrono::system_clock>, string> WhiteBit::getNewPrice() const {

	// Check if creating MWC request failed
	vector<uint8_t> mwcResponse;
	const unique_ptr mwcRequest = createRequest("whitebit.com", Common::HTTPS_PORT, "/api/v4/public/trades/MWC_BTC", mwcResponse);
	if(!mwcRequest) {
	
		// Throw exception
		throw runtime_error("Creating WhiteBIT MWC request failed");
	}
	
	// Check if creating BTC request failed
	vector<uint8_t> btcResponse;
	const unique_ptr btcRequest = createRequest("whitebit.com", Common::HTTPS_PORT, "/api/v4/public/trades/BTC_USDT", btcResponse);
	if(!btcRequest) {
	
		// Throw exception
		throw runtime_error("Creating WhiteBIT BTC request failed");
	}
	
	// Check if performing requests failed
	if(!performRequests() || mwcResponse.empty() || btcResponse.empty()) {
	
		// Throw exception
		throw runtime_error("Performing WhiteBIT requests failed");
	}
	
	// Parse MWC response as JSON
	mwcResponse.resize(mwcResponse.size() + simdjson::SIMDJSON_PADDING);
	simdjson::dom::parser parser;
	simdjson::dom::element json = parser.parse(mwcResponse.data(), mwcResponse.size() - simdjson::SIMDJSON_PADDING, false);
	
	// Check if MWC response is invalid
	if(!json.is_array() || !json.get_array().size()) {
	
		// Throw exception
		throw runtime_error("WhiteBIT MWC response is invalid");
	}
	
	// Check if MWC most recent price is invalid
	simdjson::dom::element mostRecentPrice = json.at(0);
	if(!mostRecentPrice.is_object() || !mostRecentPrice["trade_timestamp"].is_int64() || !mostRecentPrice["price"].is_string()) {
	
		// Throw exception
		throw runtime_error("WhiteBIT MWC most recent price is invalid");
	}
	
	// Get date
	const int64_t date = mostRecentPrice["trade_timestamp"].get_int64().value();
	
	// Check if date is invalid
	if(date < chrono::duration_cast<chrono::seconds>(chrono::time_point<chrono::system_clock>::min().time_since_epoch()).count() || date > chrono::duration_cast<chrono::seconds>(chrono::time_point<chrono::system_clock>::max().time_since_epoch()).count()) {
	
		// Throw exception
		throw runtime_error("WhiteBIT date is invalid");
	}
	
	// Get timestamp from date
	chrono::time_point<chrono::system_clock> timestamp = chrono::time_point<chrono::system_clock>(chrono::seconds(date));
	
	// Check if timestamp is in the future
	if(timestamp > chrono::system_clock::now()) {
	
		// Set timestamp to now
		timestamp = chrono::system_clock::now();
	}
	
	// Initialize MWC price
	mpfr_t mwcPrice;
	mpfr_init2(mwcPrice, Common::MPFR_PRECISION);
	
	// Automatically free MWC price
	const unique_ptr<remove_pointer<mpfr_ptr>::type, decltype(&mpfr_clear)> mwcPriceUniquePointer(mwcPrice, mpfr_clear);
	
	// Get price
	const char *price = mostRecentPrice["price"].get_c_str();
	
	// Go through all characters in the price
	for(const char *i = price; *i; ++i) {
	
		// Check if price is invalid
		if(!isdigit(*i) && *i != '.') {
		
			// Throw exception
			throw runtime_error("WhiteBIT MWC price is invalid");
		}
	}
	
	// Check if setting MWC price is invalid
	if(mpfr_set_str(mwcPrice, price, Common::DECIMAL_NUMBER_BASE, MPFR_RNDN) || mpfr_sgn(mwcPrice) <= 0) {
	
		// Throw exception
		throw runtime_error("WhiteBIT MWC price is invalid");
	}
	
	// Initialize precision
	size_t precision = 0;
	
	// Check if price has a decimal
	const char *decimal = strchr(price, '.');
	if(decimal) {
	
		// Update precision
		precision += strlen(price) - (decimal + sizeof('.') - price);
	}
	
	// Parse BTC response as JSON
	btcResponse.resize(btcResponse.size() + simdjson::SIMDJSON_PADDING);
	json = parser.parse(btcResponse.data(), btcResponse.size() - simdjson::SIMDJSON_PADDING, false);
	
	// Check if BTC response is invalid
	if(!json.is_array() || !json.get_array().size()) {
	
		// Throw exception
		throw runtime_error("WhiteBIT BTC response is invalid");
	}
	
	// Check if BTC most recent price is invalid
	mostRecentPrice = json.at(0);
	if(!mostRecentPrice.is_object() || !mostRecentPrice["price"].is_string()) {
	
		// Throw exception
		throw runtime_error("WhiteBIT BTC most recent price is invalid");
	}
	
	// Initialize BTC price
	mpfr_t btcPrice;
	mpfr_init2(btcPrice, Common::MPFR_PRECISION);
	
	// Automatically free BTC price
	const unique_ptr<remove_pointer<mpfr_ptr>::type, decltype(&mpfr_clear)> btcPriceUniquePointer(btcPrice, mpfr_clear);
	
	// Get price
	price = mostRecentPrice["price"].get_c_str();
	
	// Go through all characters in the price
	for(const char *i = price; *i; ++i) {
	
		// Check if price is invalid
		if(!isdigit(*i) && *i != '.') {
		
			// Throw exception
			throw runtime_error("WhiteBIT BTC price is invalid");
		}
	}
	
	// Check if setting BTC price is invalid
	if(mpfr_set_str(btcPrice, price, Common::DECIMAL_NUMBER_BASE, MPFR_RNDN) || mpfr_sgn(btcPrice) <= 0) {
	
		// Throw exception
		throw runtime_error("WhiteBIT BTC price is invalid");
	}
	
	// Check if price has a decimal
	decimal = strchr(price, '.');
	if(decimal) {
	
		// Update precision
		precision += strlen(price) - (decimal + sizeof('.') - price);
	}
	
	// Multiply MWC price by BTC price to get the price in USDT
	mpfr_mul(mwcPrice, mwcPrice, btcPrice, MPFR_RNDN);
	
	// Check if result is invalid
	if(mpfr_sgn(mwcPrice) <= 0) {
	
		// Throw exception
		throw runtime_error("WhiteBIT result is invalid");
	}
	
	// Check if getting result size failed
	const int resultSize = mpfr_snprintf(nullptr, 0, ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, mwcPrice);
	if(resultSize <= 0) {
	
		// Throw exception
		throw runtime_error("Getting WhiteBIT result size failed");
	}
	
	// Check if getting result failed
	string result(resultSize, '\0');
	if(mpfr_sprintf(result.data(), ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, mwcPrice) != resultSize) {
	
		// Throw exception
		throw runtime_error("Getting WhiteBIT result failed");
	}
	
	// Check if result isn't zero and it has precision
	if(result != "0" && precision) {
	
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
