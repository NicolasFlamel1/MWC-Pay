// Header files
#include <iostream>
#include <signal.h>
#include <syncstream>
#include "./common.h"
#include "event2/thread.h"
#include "mpfr.h"
#include "./price.h"
#include "./price_oracles/ascendex.h"
#include "./price_oracles/coingecko.h"
#include "./price_oracles/whitebit.h"
#include "./price_oracles/xt.h"

using namespace std;


// Constants

// Currency abbreviation
const char *Price::CURRENCY_ABBREVIATION = "USDT";

// Default update interval
static const time_t DEFAULT_UPDATE_INTERVAL = 1 * Common::MINUTES_IN_AN_HOUR * Common::SECONDS_IN_A_MINUTE;

// Default average length
static const size_t DEFAULT_AVERAGE_LENGTH = 1 * Common::DAYS_IN_A_WEEK * Common::HOURS_IN_A_DAY * Common::MINUTES_IN_AN_HOUR * Common::SECONDS_IN_A_MINUTE / DEFAULT_UPDATE_INTERVAL;


// Supporting function implementation

// Constructor
Price::Price(const unordered_map<char, const char *> &providedOptions, const TorProxy &torProxy) :

	// Set started
	started(false),
	
	// Set failed
	failed(false),
	
	// Set event base
	eventBase(nullptr, event_base_free)
{

	// Display message
	osyncstream(cout) << "Starting price" << endl;
	
	// Check if update interval is provided and disabling price
	if(providedOptions.contains('f') && providedOptions.contains('q')) {
	
		// Throw exception
		throw runtime_error("Price update interval can't be used when price is disabled");
	}
	
	// Check if average length is provided and disabling price
	if(providedOptions.contains('j') && providedOptions.contains('q')) {
	
		// Throw exception
		throw runtime_error("Price average length can't be used when price is disabled");
	}
	
	// Check if enabling threads support failed
	if(evthread_use_pthreads()) {
	
		// Throw exception
		throw runtime_error("Enabling price threads support failed");
	}
	
	// Add AscendEX price oracle to list
	priceOracles.emplace_back(make_unique<AscendEx>(torProxy));
	
	// Add CoinGecko price oracle to list
	priceOracles.emplace_back(make_unique<CoinGecko>(torProxy));
	
	// Add WhiteBIT price oracle to list
	priceOracles.emplace_back(make_unique<WhiteBit>(torProxy));
	
	// Add XT price oracle to list
	priceOracles.emplace_back(make_unique<Xt>(torProxy));
	
	// Check if creating event base failed
	eventBase = unique_ptr<event_base, decltype(&event_base_free)>(event_base_new(), event_base_free);
	if(!eventBase) {
	
		// Throw exception
		throw runtime_error("Creating price event base failed");
	}
	
	// Try
	try {
	
		// Create main thread
		mainThread = thread(&Price::run, this, providedOptions);
	}
	
	// Catch errors
	catch(...) {
	
		// Throw exception
		throw runtime_error("Creating price main thread failed");
	}
	
	// Check if main thread is invalid
	if(!mainThread.joinable()) {
	
		// Display message
		osyncstream(cout) << "Price main thread is invalid" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Get update internal from provided options
	updateInterval = providedOptions.contains('f') ? strtoull(providedOptions.at('f'), nullptr, Common::DECIMAL_NUMBER_BASE) : DEFAULT_UPDATE_INTERVAL;
	
	// Get average length from provided options
	averageLength = providedOptions.contains('j') ? strtoul(providedOptions.at('j'), nullptr, Common::DECIMAL_NUMBER_BASE) : DEFAULT_AVERAGE_LENGTH;
	
	// Get disable from provided options
	const bool disable = providedOptions.contains('q');
	
	// Check if disabling
	if(disable) {
	
		// Display message
		osyncstream(cout) << "Price is disabled" << endl;
	}
	
	// Otherwise
	else {
	
		// Check if a price update interval is provided
		if(providedOptions.contains('f')) {
		
			// Display message
			osyncstream(cout) << "Using provided price update interval: " << updateInterval << endl;
		}
		
		// Check if a price average length is provided
		if(providedOptions.contains('j')) {
		
			// Display message
			osyncstream(cout) << "Using provided price average length: " << averageLength << endl;
		}
		
		// Display message
		osyncstream(cout) << "Getting price" << flush;
		
		// Check if a signal was received
		if(!Common::allowSignals() || Common::getSignalReceived()) {
		
			// Block signals
			Common::blockSignals();
			
			// Display message
			osyncstream(cout) << endl << "Getting price failed" << endl;
			
			// Exit failure
			exit(EXIT_FAILURE);
		}
		
		// While not started and not failed
		for(int i = 0; !started.load() && !failed.load(); ++i) {
		
			// Check if a signal was received
			if(Common::getSignalReceived()) {
			
				// Block signals
				Common::blockSignals();
				
				// Display message
				osyncstream(cout) << endl << "Getting price failed" << endl;
				
				// Exit failure
				exit(EXIT_FAILURE);
			}
			
			// Check if time to show progress
			if(i && i % 3 == 0) {
			
				// Display message
				osyncstream(cout) << '.' << flush;
			}
			
			// Sleep
			sleep(1);
		}
		
		// Check if a signal was received or failed
		if(!Common::blockSignals() || Common::getSignalReceived() || failed.load()) {
		
			// Block signals
			Common::blockSignals();
			
			// Display message
			osyncstream(cout) << endl << "Getting price failed" << endl;
			
			// Exit failure
			exit(EXIT_FAILURE);
		}
		
		// Display message
		osyncstream(cout) << endl << "Got price" << endl;
	}
	
	// Display message
	osyncstream(cout) << "Price started" << endl;
}

// Destructor
Price::~Price() {

	// Check if started
	if(started.load()) {
	
		// Display message
		osyncstream(cout) << "Closing price" << endl;
	}
	
	// Check if exiting event loop failed
	if(event_base_loopexit(eventBase.get(), nullptr)) {
	
		// Display message
		osyncstream(cout) << "Exiting price event loop failed" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Send signal to main thread to fail syscalls
	pthread_kill(mainThread.native_handle(), SIGUSR1);
	
	// Try
	try {

		// Wait for main thread to finish
		mainThread.join();
	}

	// Catch errors
	catch(...) {
	
		// Display message
		osyncstream(cout) << "Waiting for price to finish failed" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Check if started
	if(started.load()) {
	
		// Display message
		osyncstream(cout) << "Price closed" << endl;
	}
}

// Get current price
string Price::getCurrentPrice() const {

	// Initialize result
	string result;
	
	{
		// Lock current price
		lock_guard guard(currentPriceLock);
		
		// Set result to current price
		result = currentPrice;
	}
	
	// Return result
	return result;
}

// Get options
vector<option> Price::getOptions() {

	// Return options
	return {
	
		// Price update interval
		{"price_update_interval", required_argument, nullptr, 'f'},
		
		// Price average length
		{"price_average_length", required_argument, nullptr, 'j'},
		
		// Price disable
		{"price_disable", no_argument, nullptr, 'q'}
	};
}

// Display options help
void Price::displayOptionsHelp() {

	// Display message
	cout << "\t-f, --price_update_interval\tSets the interval in seconds for updating the price (default: " << DEFAULT_UPDATE_INTERVAL << ')' << endl;
	cout << "\t-j, --price_average_length\tSets the number of previous prices used when determining the average price (default: " << DEFAULT_AVERAGE_LENGTH << ')' << endl;
	cout << "\t-q, --price_disable\t\tDisables the price API" << endl;
}

// Validate option
bool Price::validateOption(const char option, const char *value, char *argv[]) {

	// Check option
	switch(option) {
	
		// Price update interval
		case 'f': {
		
			// Check if price update interval is invalid
			char *end;
			errno = 0;
			const unsigned long long updateInterval = value ? strtoull(value, &end, Common::DECIMAL_NUMBER_BASE) : 0;
			if(!value || end == value || *end || !isdigit(value[0]) || (value[0] == '0' && isdigit(value[1])) || errno || !updateInterval || updateInterval > numeric_limits<time_t>::max()) {
			
				// Display message
				cout << argv[0] << ": invalid price update interval -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		}
		
		// Price average length
		case 'j': {
		
			// Check if price average length is invalid
			char *end;
			errno = 0;
			const unsigned long averageLength = value ? strtoul(value, &end, Common::DECIMAL_NUMBER_BASE) : 0;
			if(!value || end == value || *end || !isdigit(value[0]) || (value[0] == '0' && isdigit(value[1])) || errno || !averageLength || averageLength > numeric_limits<uint16_t>::max()) {
			
				// Display message
				cout << argv[0] << ": invalid price average length -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		}
	}
	
	// Return true
	return true;
}

// Run
void Price::run(const unordered_map<char, const char *> &providedOptions) {

	// Try
	try {
		
		// Check if creating timer event failed
		const unique_ptr<event, decltype(&event_free)> timerEvent(event_new(eventBase.get(), -1, EV_PERSIST, [](const evutil_socket_t fileDescriptor, const short signal, void *argument) {
		
			// Get self from argument
			Price *self = reinterpret_cast<Price *>(argument);
			
			// Update current price
			self->updateCurrentPrice();
			
		}, this), event_free);
		
		if(!timerEvent) {
		
			// Throw exception
			throw runtime_error("Creating price timer event failed");
		}
		
		// Set timer
		const timeval timer = {
		
			// Seconds
			.tv_sec = updateInterval
		};
		
		// Get disable from provided options
		const bool disable = providedOptions.contains('q');

		// Check if not disabling
		if(!disable) {
		
			// Check if configuring timer event failed
			if(evtimer_add(timerEvent.get(), &timer)) {
			
				// Throw exception
				throw runtime_error("Configuring price timer event failed");
			}
			
			// While updating current price fails
			while(!updateCurrentPrice()) {
			
				// Sleep
				sleep(1);
			}
		}
		
		// Set started
		started.store(true);
		
		// Check if running event loop failed
		if(event_base_dispatch(eventBase.get()) == -1) {
		
			// Throw exception
			throw runtime_error("Running price event loop failed");
		}
	}
	
	// Catch runtime errors
	catch(const runtime_error &error) {
	
		// Set failed
		failed.store(true);
		
		// Check if started
		if(started.load()) {
	
			// Display message
			osyncstream(cout) << error.what() << endl;
			
			// Set error occurred
			Common::setErrorOccurred();
			
			// Raise interrupt signal
			kill(getpid(), SIGINT);
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Set failed
		failed.store(true);
		
		// Check if started
		if(started.load()) {
		
			// Display message
			osyncstream(cout) << "Price failed for unknown reason" << endl;
			
			// Set error occurred
			Common::setErrorOccurred();
			
			// Raise interrupt signal
			kill(getpid(), SIGINT);
		}
	}
}

// Update current price
bool Price::updateCurrentPrice() {

	// Initialize new prices
	pair<chrono::time_point<chrono::system_clock>, string> newPrices[priceOracles.size()];
	
	// Go through all price oracles
	size_t index = 0;
	for(const unique_ptr<PriceOracle> &priceOracle : priceOracles) {
	
		// Get price oracle's new price
		newPrices[index++] = priceOracle->getPrice();
	}
	
	// Sort new prices
	sort(newPrices, newPrices + priceOracles.size(), [](const pair<chrono::time_point<chrono::system_clock>, string> &firstNewPrice, const pair<chrono::time_point<chrono::system_clock>, string> &secondNewPrice) -> bool {
	
		// Return if first new price's timestamp is greater than the second's
		return firstNewPrice.first > secondNewPrice.first;
	});
	
	// Check if no new price was obtained
	if(chrono::duration_cast<chrono::seconds>(newPrices[0].first.time_since_epoch()) == chrono::seconds(0)) {
	
		// Return false
		return false;
	}
	
	// Get timestamp threshold base on the newest price
	const chrono::time_point<chrono::system_clock> timestampThreshold = (chrono::seconds(updateInterval) <= chrono::duration_cast<chrono::seconds>(newPrices[0].first.time_since_epoch())) ? newPrices[0].first - chrono::seconds(updateInterval) : chrono::time_point<chrono::system_clock>(chrono::seconds(0));
	
	// Initialize total timestamp
	mpz_t totalTimestamp;
	mpz_init(totalTimestamp);
	
	// Automatically free total timestamp
	const unique_ptr<remove_pointer<mpz_ptr>::type, decltype(&mpz_clear)> totalTimestampUniquePointer(totalTimestamp, mpz_clear);
	
	// Go through all new prices
	for(size_t i = 0; i < priceOracles.size(); ++i) {
	
		// Check if new price is too old
		if(newPrices[i].first <= timestampThreshold) {
		
			// Break
			break;
		}
		
		// Update total timestamp
		mpz_add_ui(totalTimestamp, totalTimestamp, chrono::duration_cast<chrono::seconds>(newPrices[i].first - timestampThreshold).count());
		
		// Check if result is invalid
		if(mpz_sgn(totalTimestamp) <= 0) {
		
			// Return false
			return false;
		}
	}
	
	// Initialize new price number
	mpfr_t newPriceNumber;
	mpfr_init2(newPriceNumber, Common::MPFR_PRECISION);
	mpfr_set_zero(newPriceNumber, true);
	
	// Automatically free new price number
	const unique_ptr<remove_pointer<mpfr_ptr>::type, decltype(&mpfr_clear)> newPriceNumberUniquePointer(newPriceNumber, mpfr_clear);
	
	// Initialize precision
	size_t precision = 0;
	
	// Go through all new prices
	mpfr_t weightedPrice;
	mpfr_init2(weightedPrice, Common::MPFR_PRECISION);
	const unique_ptr<remove_pointer<mpfr_ptr>::type, decltype(&mpfr_clear)> weightedPriceUniquePointer(weightedPrice, mpfr_clear);
	for(size_t i = 0; i < priceOracles.size(); ++i) {
	
		// Check if new price is too old
		if(newPrices[i].first <= timestampThreshold) {
		
			// Break
			break;
		}
		
		// Check setting weighted price failed
		if(mpfr_set_str(weightedPrice, newPrices[i].second.c_str(), Common::DECIMAL_NUMBER_BASE, MPFR_RNDN) || mpfr_sgn(weightedPrice) < 0) {
		
			// Return false
			return false;
		}
		
		// Multiply weighted price by the new price's timestamp above the timestamp threshold
		mpfr_mul_ui(weightedPrice, weightedPrice, chrono::duration_cast<chrono::seconds>(newPrices[i].first - timestampThreshold).count(), MPFR_RNDN);
		
		// Check if result is invalid
		if(mpfr_sgn(weightedPrice) < 0) {
		
			// Return false
			return false;
		}
		
		// Divide weighted price by the total timestamp
		mpfr_div_z(weightedPrice, weightedPrice, totalTimestamp, MPFR_RNDA);
		
		// Check if result is invalid
		if(mpfr_sgn(weightedPrice) < 0) {
		
			// Return false
			return false;
		}
		
		// Add weighted price to new price number
		mpfr_add(newPriceNumber, newPriceNumber, weightedPrice, MPFR_RNDN);
		
		// Check if result is invalid
		if(mpfr_sgn(newPriceNumber) < 0) {
		
			// Return false
			return false;
		}
		
		// Check if new price has a decimal
		const size_t decimal = newPrices[i].second.find('.');
		if(decimal != string_view::npos) {
		
			// Update precision
			precision = max(precision, newPrices[i].second.size() - (decimal + sizeof('.')));
		}
	}
	
	// Check if new price number is invalid
	if(mpfr_sgn(newPriceNumber) < 0) {
	
		// Return false
		return false;
	}
	
	// Check if getting new price size failed
	const int newPriceSize = mpfr_snprintf(nullptr, 0, ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, newPriceNumber);
	if(newPriceSize <= 0) {
	
		// Return false
		return false;
	}
	
	// Check if getting new price failed
	string newPrice(newPriceSize, '\0');
	if(mpfr_sprintf(newPrice.data(), ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, newPriceNumber) != newPriceSize) {
	
		// Return false
		return false;
	}
	
	// Check if new price isn't zero and it has precision
	if(newPrice != "0" && precision) {
	
		// Check if new price has a trailing zero
		if(newPrice.back() == '0') {
		
			// Remove trailing zeros from new price
			newPrice = newPrice.substr(0, newPrice.find_last_not_of('0') + sizeof('0'));
		}
		
		// Check if new price has a trailing decimal
		if(newPrice.back() == '.') {
		
			// Remove trailing decimal from new price
			newPrice.pop_back();
		}
	}
	
	// Check if not floonet
	#ifndef FLOONET
	
		// Check if new price is zero
		if(newPrice == "0") {
		
			// Return false
			return false;
		}
	#endif
	
	// Add new price to list
	prices.emplace_back(move(newPrice));
	
	// Check if too many prices exist
	if(prices.size() > averageLength) {
	
		// Remove oldest prices
		prices.pop_front();
	}
	
	// Initialize average price
	mpfr_t averagePrice;
	mpfr_init2(averagePrice, Common::MPFR_PRECISION);
	mpfr_set_zero(averagePrice, true);
	
	// Automatically free average price
	const unique_ptr<remove_pointer<mpfr_ptr>::type, decltype(&mpfr_clear)> averagePriceUniquePointer(averagePrice, mpfr_clear);
	
	// Initialize precision
	precision = 0;
	
	// Go through all prices
	mpfr_t priceNumber;
	mpfr_init2(priceNumber, Common::MPFR_PRECISION);
	const unique_ptr<remove_pointer<mpfr_ptr>::type, decltype(&mpfr_clear)> priceNumberUniquePointer(priceNumber, mpfr_clear);
	for(const string &price : prices) {
	
		// Check setting price number failed
		if(mpfr_set_str(priceNumber, price.c_str(), Common::DECIMAL_NUMBER_BASE, MPFR_RNDN) || mpfr_sgn(priceNumber) < 0) {
		
			// Return false
			return false;
		}
		
		// Add price number to average price
		mpfr_add(averagePrice, averagePrice, priceNumber, MPFR_RNDN);
		
		// Check if result is invalid
		if(mpfr_sgn(averagePrice) < 0) {
		
			// Return false
			return false;
		}
		
		// Check if price has a decimal
		const size_t decimal = price.find('.');
		if(decimal != string_view::npos) {
		
			// Update precision
			precision = max(precision, price.size() - (decimal + sizeof('.')));
		}
	}
	
	// Divide average price by the number of prices
	mpfr_div_ui(averagePrice, averagePrice, prices.size(), MPFR_RNDA);
	
	// Check if result is invalid
	if(mpfr_sgn(averagePrice) < 0) {
	
		// Return false
		return false;
	}
	
	// Check if getting result size failed
	const int resultSize = mpfr_snprintf(nullptr, 0, ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, averagePrice);
	if(resultSize <= 0) {
	
		// Return false
		return false;
	}
	
	// Check if getting result failed
	string result(resultSize, '\0');
	if(mpfr_sprintf(result.data(), ("%." + to_string(precision) + "R*F").c_str(), MPFR_RNDN, averagePrice) != resultSize) {
	
		// Return false
		return false;
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
	
	// Check if not floonet
	#ifndef FLOONET
	
		// Check if result is zero
		if(result == "0") {
		
			// Return false
			return false;
		}
	#endif
	
	// Try
	try {
	
		// Lock current price
		lock_guard guard(currentPriceLock);
		
		// Set current price to result
		currentPrice = move(result);
	}
	
	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}
