// Header files
#include <arpa/inet.h>
#include <cinttypes>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <syncstream>
#include "./common.h"
#include "./consensus.h"
#include "event2/buffer.h"
#include "event2/bufferevent_ssl.h"
#include "event2/thread.h"
#include "event2/keyvalq_struct.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "./private_server.h"

using namespace std;


// Constants

// Default address
static const char *DEFAULT_ADDRESS = "localhost";

// Check if floonet
#ifdef FLOONET

	// Default port
	static const uint16_t DEFAULT_PORT = 19010;

// Otherwise
#else

	// Default port
	static const uint16_t DEFAULT_PORT = 9010;
#endif

// Minimum TLS version
static const int MINIMUM_TLS_VERSION = TLS1_VERSION;

// Maximum headers size
static const size_t MAXIMUM_HEADERS_SIZE = 3 * Common::BYTES_IN_A_KILOBYTE;

// Maximum body size
static const size_t MAXIMUM_BODY_SIZE = 0;


// Supporting function implementation

// Constructor
PrivateServer::PrivateServer(const unordered_map<char, const char *> &providedOptions, const filesystem::path &currentDirectory, const Wallet &wallet, Payments &payments, const Price &price) :

	// Set started
	started(false),
	
	// Set wallet
	wallet(wallet),
	
	// Set payments
	payments(payments),
	
	// Set price
	price(price),
	
	// Set event base
	eventBase(nullptr, event_base_free)
{

	// Display message
	osyncstream(cout) << "Starting private server" << endl;
	
	// Check if enabling threads support failed
	if(evthread_use_pthreads()) {
	
		// Throw exception
		throw runtime_error("Enabling private server threads support failed");
	}
	
	// Check if creating event base failed
	eventBase = unique_ptr<event_base, decltype(&event_base_free)>(event_base_new(), event_base_free);
	if(!eventBase) {
	
		// Throw exception
		throw runtime_error("Creating private server event base failed");
	}
	
	// Try
	try {
	
		// Create main thread
		mainThread = thread(&PrivateServer::run, this, providedOptions, currentDirectory);
	}
	
	// Catch errors
	catch(...) {
	
		// Throw exception
		throw runtime_error("Creating private server main thread failed");
	}
	
	// Check if main thread is invalid
	if(!mainThread.joinable()) {
	
		// Display message
		osyncstream(cout) << "Private server main thread is invalid" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
}

// Destructor
PrivateServer::~PrivateServer() {

	// Check if started
	if(started.load()) {
	
		// Display message
		osyncstream(cout) << "Closing private server" << endl;
	}
	
	// Check if exiting event loop failed
	if(event_base_loopexit(eventBase.get(), nullptr)) {
	
		// Display message
		osyncstream(cout) << "Exiting private server event loop failed" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Try
	try {

		// Wait for main thread to finish
		mainThread.join();
	}

	// Catch errors
	catch(...) {
	
		// Display message
		osyncstream(cout) << "Waiting for private server to finish failed" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Check if started
	if(started.load()) {
	
		// Display message
		osyncstream(cout) << "Private server closed" << endl;
	}
}

// Get options
vector<option> PrivateServer::getOptions() {

	// Return options
	return {
	
		// Private address
		{"private_address", required_argument, nullptr, 'a'},
		
		// Private port
		{"private_port", required_argument, nullptr, 'p'},
		
		// Private certificate
		{"private_certificate", required_argument, nullptr, 'c'},
		
		// Private key
		{"private_key", required_argument, nullptr, 'k'}
	};
}

// Display options help
void PrivateServer::displayOptionsHelp() {

	// Display message
	cout << "\t-a, --private_address\t\tSets the address for the private server to listen at (default: " << DEFAULT_ADDRESS << ')' << endl;
	cout << "\t-p, --private_port\t\tSets the port for the private server to listen at (default: " << DEFAULT_PORT << ')' << endl;
	cout << "\t-c, --private_certificate\tSets the TLS certificate file for the private server" << endl;
	cout << "\t-k, --private_key\t\tSets the TLS private key file for the private server" << endl;
}

// Validate option
bool PrivateServer::validateOption(const char option, const char *value, char *argv[]) {

	// Check option
	switch(option) {
	
		// Private address
		case 'a':
		
			// Check if private address is invalid
			if(!value || !strlen(value)) {
			
				// Display message
				cout << argv[0] << ": invalid private address -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		
		// Private port
		case 'p': {
		
			// Check if private port is invalid
			char *end;
			errno = 0;
			const unsigned long port = value ? strtoul(value, &end, Common::DECIMAL_NUMBER_BASE) : 0;
			if(!value || end == value || *end || !isdigit(value[0]) || (value[0] == '0' && isdigit(value[1])) || errno || !port || port > numeric_limits<uint16_t>::max()) {
			
				// Display message
				cout << argv[0] << ": invalid private port -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		}
		
		// Private certificate
		case 'c':
		
			// Check if private certificate is invalid
			if(!value || !strlen(value)) {
			
				// Display message
				cout << argv[0] << ": invalid private certificate -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		
		// Private key
		case 'k':
		
			// Check if private key is invalid
			if(!value || !strlen(value)) {
			
				// Display message
				cout << argv[0] << ": invalid private key -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
	}
	
	// Return true
	return true;
}

// Run
void PrivateServer::run(const unordered_map<char, const char *> &providedOptions, const filesystem::path &currentDirectory) {
	
	// Try
	try {
		
		// Check if creating HTTP server failed
		const unique_ptr<evhttp, decltype(&evhttp_free)> httpServer(evhttp_new(eventBase.get()), evhttp_free);
		if(!httpServer) {
		
			// Throw exception
			throw runtime_error("Creating private server HTTP server failed");
		}
		
		// Set HTTP server's maximum header size
		evhttp_set_max_headers_size(httpServer.get(), MAXIMUM_HEADERS_SIZE);
		
		// Set HTTP server's maximum body size
		evhttp_set_max_body_size(httpServer.get(), MAXIMUM_BODY_SIZE);
		
		// Set HTTP server to only allow GET requests
		evhttp_set_allowed_methods(httpServer.get(), EVHTTP_REQ_GET);
		
		// Get certificate from provided options
		const char *certificate = providedOptions.contains('c') ? providedOptions.at('c') : nullptr;
		
		// Get key from provided options
		const char *key = providedOptions.contains('k') ? providedOptions.at('k') : nullptr;
		
		// Check if certificate is provided without a key or a key is provided without a certificate
		if((certificate && !key) || (!certificate && key)) {
		
			// Throw exception
			throw runtime_error(certificate ? "No key provided for the private server certificate" : "No certificate provided for the private server key");
		}
		
		// Set using TLS server to if a certificate and key are provided
		const bool usingTlsServer = certificate && key;
		
		// Check if using TLS server
		unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> tlsContext(nullptr, SSL_CTX_free);
		if(usingTlsServer) {
		
			// Display message
			osyncstream(cout) << "Using provided private server certificate: " << certificate << endl;
			osyncstream(cout) << "Using provided private server key: " << key << endl;
		
			// Check if getting TLS method failed
			const SSL_METHOD *tlsMethod = TLS_server_method();
			if(!tlsMethod) {
			
				// Throw exception
				throw runtime_error("Getting private server TLS method failed");
			}
			
			// Check if creating TLS context failed
			tlsContext = unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(SSL_CTX_new_ex(nullptr, nullptr, tlsMethod), SSL_CTX_free);
			if(!tlsContext) {
			
				// Throw exception
				throw runtime_error("Creating private server TLS context failed");
			}
			
			// Check if setting TLS context's minimum TLS version failed
			if(!SSL_CTX_set_min_proto_version(tlsContext.get(), MINIMUM_TLS_VERSION)) {
			
				// Throw exception
				throw runtime_error("Setting private server TLS context's minimum protocol version failed");
			}
			
			// Check if setting the TLS context's certificate and key failed
			if(SSL_CTX_use_certificate_chain_file(tlsContext.get(), (filesystem::path(certificate).is_relative() ? currentDirectory / certificate : certificate).c_str()) != 1 || SSL_CTX_use_PrivateKey_file(tlsContext.get(), (filesystem::path(key).is_relative() ? currentDirectory / key : key).c_str(), SSL_FILETYPE_PEM) != 1 || SSL_CTX_check_private_key(tlsContext.get()) != 1) {
			
				// Throw exception
				throw runtime_error("Setting private server TLS context's certificate and key failed");
			}
			
			// Set HTTP server buffer event create callback
			evhttp_set_bevcb(httpServer.get(), ([](event_base *eventBase, void *argument) -> bufferevent * {
			
				// Get TLS context from argument
				SSL_CTX *tlsContext = reinterpret_cast<SSL_CTX *>(argument);
			
				// Check if creating TLS connection failed
				unique_ptr<SSL, decltype(&SSL_free)> tlsConnection(SSL_new(tlsContext), SSL_free);
				if(!tlsConnection) {
				
					// Return null
					return nullptr;
				}
				
				// Check if creating TLS buffer failed
				unique_ptr<bufferevent, decltype(&bufferevent_free)> tlsBuffer(bufferevent_openssl_socket_new(eventBase, -1, tlsConnection.get(), BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS), bufferevent_free);
				if(!tlsBuffer) {
				
					// Return null
					return nullptr;
				}
				
				// Release TLS connection
				tlsConnection.release();
				
				// Check if allow dirty shutdown for the TLS buffer failed
				if(bufferevent_ssl_set_flags(tlsBuffer.get(), BUFFEREVENT_SSL_DIRTY_SHUTDOWN) == EV_UINT64_MAX) {
				
					// Return null
					return nullptr;
				}
				
				// Get buffer event
				bufferevent *bufferEvent = tlsBuffer.get();
				
				// Release TLS buffer
				tlsBuffer.release();
				
				// Return buffer event
				return bufferEvent;
			
			}), tlsContext.get());
		
			// Set HTTP server new request callback
			evhttp_set_newreqcb(httpServer.get(), [](evhttp_request *request, void *argument) -> int {
			
				// Check if request's connection exists
				evhttp_connection *requestsConnection = evhttp_request_get_connection(request);
				if(requestsConnection) {
			
					// Set request's connection close callback
					evhttp_connection_set_closecb(requestsConnection, [](evhttp_connection *connection, void *argument) {
						
						// Check if connection's buffer event exists
						bufferevent *bufferEvent = evhttp_connection_get_bufferevent(connection);
						if(bufferEvent) {

							// Check if buffer event's TLS connection exists
							SSL *tlsConnection = bufferevent_openssl_get_ssl(bufferEvent);
							if(tlsConnection) {
							
								// Shutdown TLS connection
								SSL_shutdown(tlsConnection);
							}
						}
					}, nullptr);
				}
				
				// Return success
				return 0;
				
			}, nullptr);
		}
		
		// Check if setting HTTP server create payment request callback failed
		if(evhttp_set_cb(httpServer.get(), "/create_payment", ([](evhttp_request *request, void *argument) {
		
			// Get self from argument
			PrivateServer *self = reinterpret_cast<PrivateServer *>(argument);
			
			// Try
			try {
			
				// Handle create payment request
				self->handleCreatePaymentRequest(request);
			}
			
			// Catch errors
			catch(...) {
			
				// Remove request's response's content type header
				if(evhttp_request_get_output_headers(request)) {
				
					evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
				}
				
				// Reply with internal server error response to request
				evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
			}
		}), this)) {
		
			// Throw exception
			throw runtime_error("Setting private server HTTP server create payment request callback failed");
		}
		
		// Check if setting HTTP server get payment info request callback failed
		if(evhttp_set_cb(httpServer.get(), "/get_payment_info", ([](evhttp_request *request, void *argument) {
		
			// Get self from argument
			PrivateServer *self = reinterpret_cast<PrivateServer *>(argument);
			
			// Try
			try {
			
				// Handle get payment info request
				self->handleGetPaymentInfoRequest(request);
			}
			
			// Catch errors
			catch(...) {
			
				// Remove request's response's content type header
				if(evhttp_request_get_output_headers(request)) {
				
					evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
				}
			
				// Reply with internal server error response to request
				evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
			}
		}), this)) {
		
			// Throw exception
			throw runtime_error("Setting private server HTTP server get payment info request callback failed");
		}
		
		// Get price disable from provided options
		const bool priceDisable = providedOptions.contains('q');
		
		// Check if not disabling price
		if(!priceDisable) {
		
			// Check if setting HTTP server get price request callback failed
			if(evhttp_set_cb(httpServer.get(), "/get_price", ([](evhttp_request *request, void *argument) {
			
				// Get self from argument
				PrivateServer *self = reinterpret_cast<PrivateServer *>(argument);
				
				// Try
				try {
				
					// Handle get price request
					self->handleGetPriceRequest(request);
				}
				
				// Catch errors
				catch(...) {
				
					// Remove request's response's content type header
					if(evhttp_request_get_output_headers(request)) {
					
						evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
					}
					
					// Reply with internal server error response to request
					evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
				}
			}), this)) {
			
				// Throw exception
				throw runtime_error("Setting private server HTTP server get price request callback failed");
			}
		}
		
		// Set HTTP server generic request callback
		evhttp_set_gencb(httpServer.get(), ([](evhttp_request *request, void *argument) {
		
			// Check if setting request's response's cache control header failed
			if(!evhttp_request_get_output_headers(request) || evhttp_add_header(evhttp_request_get_output_headers(request), "Cache-Control", "no-store, no-transform")) {
			
				// Remove request's response's cache control header
				if(evhttp_request_get_output_headers(request)) {
				
					evhttp_remove_header(evhttp_request_get_output_headers(request), "Cache-Control");
				}
				
				// Reply with internal server error response to request
				evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
				
				// Return
				return;
			}
			
			// Reply with not found response to request
			evhttp_send_reply(request, HTTP_NOTFOUND, nullptr, nullptr);
			
		}), nullptr);
		
		// Get address from provided options
		const char *address = providedOptions.contains('a') ? providedOptions.at('a') : DEFAULT_ADDRESS;
		
		// Check if a private server address is provided
		if(providedOptions.contains('a')) {
		
			// Display message
			osyncstream(cout) << "Using provided private server address: " << address << endl;
		}
		
		// Get port from provided options
		const uint16_t port = providedOptions.contains('p') ? strtoul(providedOptions.at('p'), nullptr, Common::DECIMAL_NUMBER_BASE) : DEFAULT_PORT;
		
		// Check if a private server port is provided
		if(providedOptions.contains('p')) {
		
			// Display message
			osyncstream(cout) << "Using provided private server port: " << port << endl;
		}
		
		// Check if binding HTTP server to address and port failed
		if(evhttp_bind_socket(httpServer.get(), address, port)) {
		
			// Throw exception
			throw runtime_error("Binding private server HTTP server to address and port failed");
		}
		
		// Set display port to if the port doesn't match the default server port
		const bool displayPort = (!usingTlsServer && port != Common::HTTP_PORT) || (usingTlsServer && port != Common::HTTPS_PORT);
		
		// Check if address is an IPv6 address
		char temp[sizeof(in6_addr)];
		if(inet_pton(AF_INET6, address, temp) == 1) {
		
			// Display message
			osyncstream(cout) << "Private server started and listening at " << (usingTlsServer ? "https" : "http") << "://[" << address << ']' << (displayPort ? ':' + to_string(port) : "") << endl;
		}
		
		// Otherwise
		else {
		
			// Display message
			osyncstream(cout) << "Private server started and listening at " << (usingTlsServer ? "https" : "http") << "://" << address << (displayPort ? ':' + to_string(port) : "") << endl;
		}
		
		// Set started
		started.store(true);
		
		// Check if running event loop failed
		if(event_base_dispatch(eventBase.get()) == -1) {
		
			// Throw exception
			throw runtime_error("Running private server event loop failed");
		}
	}
	
	// Catch runtime errors
	catch(const runtime_error &error) {
	
		// Display message
		osyncstream(cout) << error.what() << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
		
		// Raise interrupt signal
		kill(getpid(), SIGINT);
	}
	
	// Catch errors
	catch(...) {
	
		// Display message
		osyncstream(cout) << "Private server failed for unknown reason" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
		
		// Raise interrupt signal
		kill(getpid(), SIGINT);
	}
}

// Handle create payment request
void PrivateServer::handleCreatePaymentRequest(evhttp_request *request) {

	// Check if setting request's response's cache control header failed
	if(!evhttp_request_get_output_headers(request) || evhttp_add_header(evhttp_request_get_output_headers(request), "Cache-Control", "no-store, no-transform")) {
	
		// Remove request's response's cache control header
		if(evhttp_request_get_output_headers(request)) {
		
			evhttp_remove_header(evhttp_request_get_output_headers(request), "Cache-Control");
		}
		
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if request doesn't have a URI
	const evhttp_uri *uri = evhttp_request_get_evhttp_uri(request);
	if(!uri) {
	
		// Reply with bad request response to request
		evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if parsing the URI's query string failed
	evkeyvalq queryValues;
	if(!evhttp_uri_get_query(uri) || evhttp_parse_query_str(evhttp_uri_get_query(uri), &queryValues)) {
	
		// Reply with bad request response to request
		evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Automatically free query values when done
	const unique_ptr<evkeyvalq, decltype(&evhttp_clear_headers)> queryValuesUniquePointer(&queryValues, evhttp_clear_headers);
	
	// Check if price parameter is provided
	uint64_t price;
	const char *priceParameter = evhttp_find_header(&queryValues, "price");
	if(priceParameter) {
	
		// Check if price parameter before decimal is invalid
		char *end;
		errno = 0;
		const unsigned long long priceNumber = strtoull(priceParameter, &end, Common::DECIMAL_NUMBER_BASE);
		if(end == priceParameter || (*end && *end != '.') || !isdigit(priceParameter[0]) || (priceParameter[0] == '0' && isdigit(priceParameter[1])) || errno || priceNumber > numeric_limits<decltype(price)>::max() / Consensus::NUMBER_BASE) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Set price to provided value in number base
		price = priceNumber * Consensus::NUMBER_BASE;
		
		// Check if price parameter has a decimal
		if(*end == '.') {
		
			// Check if price parameter after decimal is invalid
			const char *priceDecimalParameter = &end[sizeof('.')];
			errno = 0;
			const unsigned long long priceDecimal = strtoull(priceDecimalParameter, &end, Common::DECIMAL_NUMBER_BASE);
			
			if(end == priceDecimalParameter || *end || !isdigit(priceDecimalParameter[0]) || errno || priceDecimal >= static_cast<unsigned long long>(Consensus::NUMBER_BASE) || price > numeric_limits<decltype(price)>::max() - priceDecimal * static_cast<unsigned long long>(pow(10, ceil(log10(Consensus::NUMBER_BASE)) - (end - priceDecimalParameter)))) {
			
				// Reply with bad request response to request
				evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
				
				// Return
				return;
			}
			
			// Update price to include decimal part
			price += priceDecimal * static_cast<unsigned long long>(pow(10, ceil(log10(Consensus::NUMBER_BASE)) - (end - priceDecimalParameter)));
		}
		
		// Check if price is zero
		if(!price) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
	}
	
	// Otherwise
	else {
	
		// Set price to be any price
		price = Payments::ANY_PRICE;
	}
	
	// Check if required confirmations parameter is provided
	uint32_t requiredConfirmations;
	const char *requiredConfirmationsParameter = evhttp_find_header(&queryValues, "required_confirmations");
	if(requiredConfirmationsParameter) {
	
		// Check if required confirmations parameter is invalid
		char *end;
		errno = 0;
		const unsigned long requiredConfirmationsNumber = strtoul(requiredConfirmationsParameter, &end, Common::DECIMAL_NUMBER_BASE);
		if(end == requiredConfirmationsParameter || *end || !isdigit(requiredConfirmationsParameter[0]) || (requiredConfirmationsParameter[0] == '0' && isdigit(requiredConfirmationsParameter[1])) || errno || !requiredConfirmationsNumber || requiredConfirmationsNumber > numeric_limits<decltype(requiredConfirmations)>::max()) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Set required confirmations to provided value
		requiredConfirmations = requiredConfirmationsNumber;
	}
	
	// Otherwise
	else {
	
		// Set required confirmations to be confirmed when on-chain
		requiredConfirmations = Payments::CONFIRMED_WHEN_ON_CHAIN;
	}
	
	// Check if timeout parameter is provided
	uint32_t timeout;
	const char *timeoutParameter = evhttp_find_header(&queryValues, "timeout");
	if(timeoutParameter) {
	
		// Check if timeout parameter is invalid
		char *end;
		errno = 0;
		const unsigned long timeoutNumber = strtoul(timeoutParameter, &end, Common::DECIMAL_NUMBER_BASE);
		if(end == timeoutParameter || *end || !isdigit(timeoutParameter[0]) || (timeoutParameter[0] == '0' && isdigit(timeoutParameter[1])) || errno || !timeoutNumber || timeoutNumber > numeric_limits<decltype(timeout)>::max()) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Set timeout to provided value
		timeout = timeoutNumber;
	}
	
	// Otherwise
	else {
	
		// Set timeout to no timeout
		timeout = Payments::NO_TIMEOUT;
	}
	
	// Check if completed callback parameter is provided and it's not too long
	const char *completedCallback = evhttp_find_header(&queryValues, "completed_callback");
	if(completedCallback && strlen(completedCallback) <= Payments::MAXIMUM_COMPLETED_CALLBACK_SIZE) {
	
		// Check if completed callback is invalid
		const unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> completedCallbackUri(evhttp_uri_parse(completedCallback), evhttp_uri_free);
		if(!completedCallbackUri || (strncasecmp(completedCallback, "http://", sizeof("http://") - sizeof('\0')) && strncasecmp(completedCallback, "https://", sizeof("https://") - sizeof('\0'))) || !evhttp_uri_get_scheme(completedCallbackUri.get()) || !evhttp_uri_get_host(completedCallbackUri.get()) || evhttp_uri_get_unixsocket(completedCallbackUri.get()) || evhttp_uri_get_fragment(completedCallbackUri.get()) || (strcasecmp(evhttp_uri_get_scheme(completedCallbackUri.get()), "http") && strcasecmp(evhttp_uri_get_scheme(completedCallbackUri.get()), "https")) || !*evhttp_uri_get_host(completedCallbackUri.get()) || !evhttp_uri_get_port(completedCallbackUri.get())) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
	}
	
	// Otherwise
	else {
	
		// Reply with bad request response to request
		evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if received callback parameter is provided
	const char *receivedCallback = evhttp_find_header(&queryValues, "received_callback");
	if(receivedCallback) {
	
		// Check if received callback parameter isn't too long
		if(strlen(receivedCallback) <= Payments::MAXIMUM_RECEIVED_CALLBACK_SIZE) {
	
			// Check if received callback is invalid
			const unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> receivedCallbackUri(evhttp_uri_parse(receivedCallback), evhttp_uri_free);
			if(!receivedCallbackUri || (strncasecmp(receivedCallback, "http://", sizeof("http://") - sizeof('\0')) && strncasecmp(receivedCallback, "https://", sizeof("https://") - sizeof('\0'))) || !evhttp_uri_get_scheme(receivedCallbackUri.get()) || !evhttp_uri_get_host(receivedCallbackUri.get()) || evhttp_uri_get_unixsocket(receivedCallbackUri.get()) || evhttp_uri_get_fragment(receivedCallbackUri.get()) || (strcasecmp(evhttp_uri_get_scheme(receivedCallbackUri.get()), "http") && strcasecmp(evhttp_uri_get_scheme(receivedCallbackUri.get()), "https")) || !*evhttp_uri_get_host(receivedCallbackUri.get()) || !evhttp_uri_get_port(receivedCallbackUri.get())) {
			
				// Reply with bad request response to request
				evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
				
				// Return
				return;
			}
		}
		
		// Otherwise
		else {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
	}
	
	// Otherwise
	else {
	
		// Set received callback to no received callback
		receivedCallback = Payments::NO_RECEIVED_CALLBACK;
	}
	
	// Check if confirmed callback parameter is provided
	const char *confirmedCallback = evhttp_find_header(&queryValues, "confirmed_callback");
	if(confirmedCallback) {
	
		// Check if confirmed callback parameter isn't too long
		if(strlen(confirmedCallback) <= Payments::MAXIMUM_CONFIRMED_CALLBACK_SIZE) {
	
			// Check if confirmed callback is invalid
			const unique_ptr<evhttp_uri, decltype(&evhttp_uri_free)> confirmedCallbackUri(evhttp_uri_parse(confirmedCallback), evhttp_uri_free);
			if(!confirmedCallbackUri || (strncasecmp(confirmedCallback, "http://", sizeof("http://") - sizeof('\0')) && strncasecmp(confirmedCallback, "https://", sizeof("https://") - sizeof('\0'))) || !evhttp_uri_get_scheme(confirmedCallbackUri.get()) || !evhttp_uri_get_host(confirmedCallbackUri.get()) || evhttp_uri_get_unixsocket(confirmedCallbackUri.get()) || evhttp_uri_get_fragment(confirmedCallbackUri.get()) || (strcasecmp(evhttp_uri_get_scheme(confirmedCallbackUri.get()), "http") && strcasecmp(evhttp_uri_get_scheme(confirmedCallbackUri.get()), "https")) || !*evhttp_uri_get_host(confirmedCallbackUri.get()) || !evhttp_uri_get_port(confirmedCallbackUri.get())) {
			
				// Reply with bad request response to request
				evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
				
				// Return
				return;
			}
		}
		
		// Otherwise
		else {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
	}
	
	// Otherwise
	else {
	
		// Set confirmed callback to no confirmed callback
		confirmedCallback = Payments::NO_CONFIRMED_CALLBACK;
	}
	
	// Check if creating random ID failed
	uint64_t id;
	if(RAND_bytes_ex(nullptr, reinterpret_cast<uint8_t *>(&id), sizeof(id), RAND_DRBG_STRENGTH) != 1) {
	
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if creating random URL failed
	char url[Payments::URL_SIZE + sizeof('\0')];
	if(RAND_bytes_ex(nullptr, reinterpret_cast<unsigned char *>(url), sizeof(url) - sizeof('\0'), RAND_DRBG_STRENGTH) != 1) {
	
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	for(size_t i = 0; i < sizeof(url) - sizeof('\0'); ++i) {
	
		url[i] = Payments::URL_CHARACTERS[url[i] % (sizeof(Payments::URL_CHARACTERS) - sizeof('\0'))];
	}
	
	url[Payments::URL_SIZE] = '\0';
	
	// Check if creating buffer failed
	const unique_ptr<evbuffer, decltype(&evbuffer_free)> buffer(evbuffer_new(), evbuffer_free);
	if(!buffer) {
	
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if setting request's response's content type header failed
	if(evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "application/json; charset=utf-8")) {
	
		// Remove request's response's content type header
		evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
	
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if creating payment failed
	const uint64_t paymentProofIndex = payments.createPayment(id, url, price, requiredConfirmations, timeout, completedCallback, receivedCallback, confirmedCallback);
	if(!paymentProofIndex) {
	
		// Remove request's response's content type header
		evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
	
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Get wallet's Tor payment proof address at the payment proof index
	const string paymentProofAddress = wallet.getTorPaymentProofAddress(paymentProofIndex);
	
	// Check if adding payment info to buffer failed
	if(evbuffer_add_printf(buffer.get(), "{\"payment_id\":\"%" PRIu64 "\",\"url\":\"%s\",\"recipient_payment_proof_address\":\"%s\"}", id, url, paymentProofAddress.c_str()) == -1) {
	
		// Remove request's response's content type header
		evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
		
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Display message
	osyncstream(cout) << "Created payment " << id << endl;
	
	// Reply with ok response to request
	evhttp_send_reply(request, HTTP_OK, nullptr, buffer.get());
}

// Handle get payment info request
void PrivateServer::handleGetPaymentInfoRequest(evhttp_request *request) {

	// Check if setting request's response's cache control header failed
	if(!evhttp_request_get_output_headers(request) || evhttp_add_header(evhttp_request_get_output_headers(request), "Cache-Control", "no-store, no-transform")) {
	
		// Remove request's response's cache control header
		if(evhttp_request_get_output_headers(request)) {
		
			evhttp_remove_header(evhttp_request_get_output_headers(request), "Cache-Control");
		}
		
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if request doesn't have a URI
	const evhttp_uri *uri = evhttp_request_get_evhttp_uri(request);
	if(!uri) {
	
		// Reply with bad request response to request
		evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if parsing the URI's query string failed
	evkeyvalq queryValues;
	if(!evhttp_uri_get_query(uri) || evhttp_parse_query_str(evhttp_uri_get_query(uri), &queryValues)) {
	
		// Reply with bad request response to request
		evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Automatically free query values when done
	const unique_ptr<evkeyvalq, decltype(&evhttp_clear_headers)> queryValuesUniquePointer(&queryValues, evhttp_clear_headers);
	
	// Check if payment ID parameter is provided
	uint64_t paymentId;
	const char *paymentIdParameter = evhttp_find_header(&queryValues, "payment_id");
	if(paymentIdParameter) {
	
		// Check if payment ID parameter is invalid
		char *end;
		errno = 0;
		const unsigned long long paymentIdNumber = strtoull(paymentIdParameter, &end, Common::DECIMAL_NUMBER_BASE);
		if(end == paymentIdParameter || *end || !isdigit(paymentIdParameter[0]) || (paymentIdParameter[0] == '0' && isdigit(paymentIdParameter[1])) || errno || paymentIdNumber > numeric_limits<decltype(paymentId)>::max()) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Set payment ID to provided value
		paymentId = paymentIdNumber;
	}
	
	// Otherwise
	else {
	
		// Reply with bad request response to request
		evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if payment doesn't exist
	const tuple paymentInfo = payments.getPaymentInfo(paymentId);
	if(!get<0>(paymentInfo)) {
	
		// Reply with bad request response to request
		evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if creating buffer failed
	const unique_ptr<evbuffer, decltype(&evbuffer_free)> buffer(evbuffer_new(), evbuffer_free);
	if(!buffer) {
	
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Get payment proof index from payment's unique number
	const uint64_t &paymentProofIndex = get<0>(paymentInfo);
	
	// Get wallet's Tor payment proof address at the payment proof index
	const string paymentProofAddress = wallet.getTorPaymentProofAddress(paymentProofIndex);
	
	// Get payment's price as a string
	const string priceString = get<2>(paymentInfo).has_value() ? '"' + Common::getNumberInNumberBase(get<2>(paymentInfo).value(), Consensus::NUMBER_BASE) + '"' : "null";
	
	// Check if payment has a time remaining
	if(get<6>(paymentInfo).has_value()) {
	
		// Check if adding payment info to buffer failed
		if(evbuffer_add_printf(buffer.get(), "{\"url\":\"%s\",\"price\":%s,\"required_confirmations\":%" PRIu64 ",\"received\":%s,\"confirmations\":%" PRIu64 ",\"time_remaining\":%" PRIu64 ",\"status\":\"%s\",\"recipient_payment_proof_address\":\"%s\"}", get<1>(paymentInfo).c_str(), priceString.c_str(), get<3>(paymentInfo), get<4>(paymentInfo) ? "true" : "false", get<5>(paymentInfo), get<6>(paymentInfo).value(), get<7>(paymentInfo).c_str(), paymentProofAddress.c_str()) == -1) {
		
			// Reply with internal server error response to request
			evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
			
			// Return
			return;
		}
	}
	
	// Otherwise
	else {
	
		// Check if adding payment info to buffer failed
		if(evbuffer_add_printf(buffer.get(), "{\"url\":\"%s\",\"price\":%s,\"required_confirmations\":%" PRIu64 ",\"received\":%s,\"confirmations\":%" PRIu64 ",\"time_remaining\":null,\"status\":\"%s\",\"recipient_payment_proof_address\":\"%s\"}", get<1>(paymentInfo).c_str(), priceString.c_str(), get<3>(paymentInfo), get<4>(paymentInfo) ? "true" : "false", get<5>(paymentInfo), get<7>(paymentInfo).c_str(), paymentProofAddress.c_str()) == -1) {
		
			// Reply with internal server error response to request
			evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
			
			// Return
			return;
		}
	}
	
	// Check if setting request's response's content type header failed
	if(evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "application/json; charset=utf-8")) {
	
		// Remove request's response's content type header
		evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
		
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Reply with ok response to request
	evhttp_send_reply(request, HTTP_OK, nullptr, buffer.get());
}

// Handle get price request
void PrivateServer::handleGetPriceRequest(evhttp_request *request) {

	// Check if setting request's response's cache control header failed
	if(!evhttp_request_get_output_headers(request) || evhttp_add_header(evhttp_request_get_output_headers(request), "Cache-Control", "no-store, no-transform")) {
	
		// Remove request's response's cache control header
		if(evhttp_request_get_output_headers(request)) {
		
			evhttp_remove_header(evhttp_request_get_output_headers(request), "Cache-Control");
		}
		
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if creating buffer failed
	const unique_ptr<evbuffer, decltype(&evbuffer_free)> buffer(evbuffer_new(), evbuffer_free);
	if(!buffer) {
	
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Get current price
	const string currentPrice = price.getCurrentPrice();
	
	// Check if adding payment info to buffer failed
	if(evbuffer_add_printf(buffer.get(), "{\"price\":\"%s\"}", currentPrice.c_str()) == -1) {
	
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Check if setting request's response's content type header failed
	if(evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "application/json; charset=utf-8")) {
	
		// Remove request's response's content type header
		evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
		
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}
	
	// Reply with ok response to request
	evhttp_send_reply(request, HTTP_OK, nullptr, buffer.get());
}
