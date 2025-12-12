// Header files
#include "../common.h"
#include "mpfr.h"
#include "simdjson.h"
#include "./nonlogs.h"

using namespace std;


// Supporting function implementation

// Constructor
NonLogs::NonLogs(const TorProxy &torProxy) :

	// Delegate constructor
	PriceOracle(torProxy)
{
}

// Get new price
pair<chrono::time_point<chrono::system_clock>, string> NonLogs::getNewPrice() const {

	// Check if creating request failed
	vector<uint8_t> response;
	const unique_ptr request = createRequest("api.nonlogs.io", Common::HTTPS_PORT, "/order/orderbook/MWC-USDT?depth=0", response);
	if(!request) {
	
		// Throw exception
		throw runtime_error("Creating NonLogs request failed");
	}
	
	// Check if performing requests failed
	if(!performRequests() || response.empty()) {
	
		// Throw exception
		throw runtime_error("Performing NonLogs requests failed");
	}
	
	// Parse response as JSON
	response.resize(response.size() + simdjson::SIMDJSON_PADDING);
	simdjson::dom::parser parser;
	const simdjson::dom::element json = parser.parse(response.data(), response.size() - simdjson::SIMDJSON_PADDING, false);
	
	// Check if response is invalid
	if(!json.is_object()) {
	
		// Throw exception
		throw runtime_error("NonLogs response is invalid");
	}
	
	// Check if most recent price is invalid
	if(!json["last_trade_time"].is_string() || !json["last_trade_price"].is_string()) {
	
		// Throw exception
		throw runtime_error("NonLogs most recent price is invalid");
	}
	
	// Check if parsing date failed
	tm time = {};
	const char *lastTimeCharacter = strptime(json["last_trade_time"].get_c_str(), "%FT%T", &time);
	if(!lastTimeCharacter || *lastTimeCharacter != '.') {
	
		// Throw exception
		throw runtime_error("NonLogs date is invalid");
	}
	
	// Check if date is invalid
	const time_t date = timegm(&time);
	if(date == -1) {
	
		// Throw exception
		throw runtime_error("NonLogs date is invalid");
	}
	
	// Get timestamp from date
	chrono::time_point<chrono::system_clock> timestamp = chrono::system_clock::from_time_t(date);
	
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
	const char *price = json["last_trade_price"].get_c_str();
	
	// Go through all characters in the price
	for(const char *i = price; *i; ++i) {
	
		// Check if price is invalid
		if(!isdigit(*i) && *i != '.') {
		
			// Throw exception
			throw runtime_error("NonLogs price is invalid");
		}
	}
	
	// Check if setting MWC price is invalid
	if(mpfr_set_str(mwcPrice, price, Common::DECIMAL_NUMBER_BASE, MPFR_RNDN) || mpfr_sgn(mwcPrice) <= 0) {
	
		// Throw exception
		throw runtime_error("NonLogs price is invalid");
	}
	
	// Initialize precision
	size_t precision = 0;
	
	// Check if price has a decimal
	const char *decimal = strchr(price, '.');
	if(decimal) {
	
		// Update precision
		precision += strlen(price) - (decimal + sizeof('.') - price);
	}
	
	// Check if getting result size failed
	const int resultSize = mpfr_snprintf(nullptr, 0, ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, mwcPrice);
	if(resultSize <= 0) {
	
		// Throw exception
		throw runtime_error("Getting NonLogs result size failed");
	}
	
	// Check if getting result failed
	string result(resultSize, '\0');
	if(mpfr_sprintf(result.data(), ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, mwcPrice) != resultSize) {
	
		// Throw exception
		throw runtime_error("Getting NonLogs result failed");
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
