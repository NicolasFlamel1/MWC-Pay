// Header files
#include <arpa/inet.h>
#include <cinttypes>
#include <filesystem>
#include <iostream>
#include <syncstream>
#include "./common.h"
#include "./consensus.h"
#include "event2/buffer.h"
#include "event2/bufferevent_ssl.h"
#include "event2/keyvalq_struct.h"
#include "event2/thread.h"
#include "./gzip.h"
#include "./mqs.h"
#include "openssl/ssl.h"
#include "png.h"
#include "./public_server.h"
#include "qrcodegen.h"
#include "secp256k1_commitment.h"
#include "simdjson.h"
#include "./slate.h"
#include "./slatepack.h"
#include "./tor.h"

using namespace std;


// Constants

// Default address
const char *PublicServer::DEFAULT_ADDRESS = "0.0.0.0";

// Check if floonet
#ifdef FLOONET

	// Default port
	const uint16_t PublicServer::DEFAULT_PORT = 19011;

// Otherwise
#else

	// Default port
	const uint16_t PublicServer::DEFAULT_PORT = 9011;
#endif

// Minimum TLS version
static const int MINIMUM_TLS_VERSION = TLS1_VERSION;

// Maximum headers size
static const size_t MAXIMUM_HEADERS_SIZE = 3 * Common::BYTES_IN_A_KILOBYTE;

// Maximum body size
static const size_t MAXIMUM_BODY_SIZE = 2 * Common::BYTES_IN_A_KILOBYTE;

// Default QR code padding
static const int DEFAULT_QR_CODE_PADDING = 4;


// Supporting function implementation

// Constructor
PublicServer::PublicServer(const unordered_map<char, const char *> &providedOptions, const filesystem::path &currentDirectory, const Wallet &wallet, Payments &payments) :

	// Set started
	started(false),
	
	// Set wallet
	wallet(wallet),
	
	// Set payments
	payments(payments),
	
	// Set event base
	eventBase(nullptr, event_base_free)
{

	// Display message
	osyncstream(cout) << "Starting public server" << endl;
	
	// Check if enabling threads support failed
	if(evthread_use_pthreads()) {
	
		// Throw exception
		throw runtime_error("Enabling public server threads support failed");
	}
	
	// Check if creating event base failed
	eventBase = unique_ptr<event_base, decltype(&event_base_free)>(event_base_new(), event_base_free);
	if(!eventBase) {
	
		// Throw exception
		throw runtime_error("Creating public server event base failed");
	}
	
	// Try
	try {
	
		// Create main thread
		mainThread = thread(&PublicServer::run, this, providedOptions, currentDirectory);
	}
	
	// Catch errors
	catch(...) {
	
		// Throw exception
		throw runtime_error("Creating public server main thread failed");
	}
	
	// Check if main thread is invalid
	if(!mainThread.joinable()) {
	
		// Display message
		osyncstream(cout) << "Public server main thread is invalid" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
}

// Destructor
PublicServer::~PublicServer() {

	// Check if started
	if(started.load()) {
	
		// Display message
		osyncstream(cout) << "Closing public server" << endl;
	}
	
	// Check if exiting event loop failed
	if(event_base_loopexit(eventBase.get(), nullptr)) {
	
		// Display message
		osyncstream(cout) << "Exiting public server event loop failed" << endl;
		
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
		osyncstream(cout) << "Waiting for public server to finish failed" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Check if started
	if(started.load()) {
	
		// Display message
		osyncstream(cout) << "Public server closed" << endl;
	}
}

// Get options
vector<option> PublicServer::getOptions() {

	// Return options
	return {
	
		// Public address
		{"public_address", required_argument, nullptr, 'e'},
		
		// Public port
		{"public_port", required_argument, nullptr, 'o'},
		
		// Public certificate
		{"public_certificate", required_argument, nullptr, 't'},
		
		// Public key
		{"public_key", required_argument, nullptr, 'y'}
	};
}

// Display options help
void PublicServer::displayOptionsHelp() {

	// Display message
	cout << "\t-e, --public_address\t\tSets the address for the public server to listen at (default: " << DEFAULT_ADDRESS << ')' << endl;
	cout << "\t-o, --public_port\t\tSets the port for the public server to listen at (default: " << DEFAULT_PORT << ')' << endl;
	cout << "\t-t, --public_certificate\tSets the TLS certificate file for the public server" << endl;
	cout << "\t-y, --public_key\t\tSets the TLS private key file for the public server" << endl;
}

// Validate option
bool PublicServer::validateOption(const char option, const char *value, char *argv[]) {

	// Check option
	switch(option) {
	
		// Public address
		case 'e':
		
			// Check if public address is invalid
			if(!value || !strlen(value)) {
			
				// Display message
				cout << argv[0] << ": invalid public address -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		
		// Public port
		case 'o': {
		
			// Check if public port is invalid
			char *end;
			errno = 0;
			const unsigned long port = value ? strtoul(value, &end, Common::DECIMAL_NUMBER_BASE) : 0;
			if(!value || end == value || *end || !isdigit(value[0]) || (value[0] == '0' && isdigit(value[1])) || errno || !port || port > numeric_limits<uint16_t>::max()) {
			
				// Display message
				cout << argv[0] << ": invalid public port -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		}
		
		// Public certificate
		case 't':
		
			// Check if public certificate is invalid
			if(!value || !strlen(value)) {
			
				// Display message
				cout << argv[0] << ": invalid public certificate -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		
		// Public key
		case 'y':
		
			// Check if public key is invalid
			if(!value || !strlen(value)) {
			
				// Display message
				cout << argv[0] << ": invalid public key -- '" << (value ? value : "") << '\'' << endl;
		
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
void PublicServer::run(const unordered_map<char, const char *> &providedOptions, const filesystem::path &currentDirectory) {
	
	// Try
	try {
		
		// Check if creating HTTP server failed
		const unique_ptr<evhttp, decltype(&evhttp_free)> httpServer(evhttp_new(eventBase.get()), evhttp_free);
		if(!httpServer) {
		
			// Throw exception
			throw runtime_error("Creating public server HTTP server failed");
		}
		
		// Set HTTP server's maximum header size
		evhttp_set_max_headers_size(httpServer.get(), MAXIMUM_HEADERS_SIZE);
		
		// Set HTTP server's maximum body size
		evhttp_set_max_body_size(httpServer.get(), MAXIMUM_BODY_SIZE);
		
		// Set HTTP server to only allow GET, POST, and OPTIONS requests
		evhttp_set_allowed_methods(httpServer.get(), EVHTTP_REQ_GET | EVHTTP_REQ_POST | EVHTTP_REQ_OPTIONS);
		
		// Get certificate from provided options
		const char *certificate = providedOptions.contains('t') ? providedOptions.at('t') : nullptr;
		
		// Get key from provided options
		const char *key = providedOptions.contains('y') ? providedOptions.at('y') : nullptr;
		
		// Check if certificate is provided without a key or a key is provided without a certificate
		if((certificate && !key) || (!certificate && key)) {
		
			// Throw exception
			throw runtime_error(certificate ? "No key provided for the public server certificate" : "No certificate provided for the public server key");
		}
		
		// Set using TLS server to if a certificate and key are provided
		const bool usingTlsServer = certificate && key;
		
		// Check if using TLS server
		unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> tlsContext(nullptr, SSL_CTX_free);
		if(usingTlsServer) {
		
			// Display message
			osyncstream(cout) << "Using provided public server certificate: " << certificate << endl;
			osyncstream(cout) << "Using provided public server key: " << key << endl;
			
			// Check if getting TLS method failed
			const SSL_METHOD *tlsMethod = TLS_server_method();
			if(!tlsMethod) {
			
				// Throw exception
				throw runtime_error("Getting public server TLS method failed");
			}
			
			// Check if creating TLS context failed
			tlsContext = unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(SSL_CTX_new_ex(nullptr, nullptr, tlsMethod), SSL_CTX_free);
			if(!tlsContext) {
			
				// Throw exception
				throw runtime_error("Creating public server TLS context failed");
			}
			
			// Check if setting TLS context's minimum TLS version failed
			if(!SSL_CTX_set_min_proto_version(tlsContext.get(), MINIMUM_TLS_VERSION)) {
			
				// Throw exception
				throw runtime_error("Setting public server TLS context's minimum protocol version failed");
			}
			
			// Check if setting the TLS context's certificate and key failed
			if(SSL_CTX_use_certificate_chain_file(tlsContext.get(), (filesystem::path(certificate).is_relative() ? currentDirectory / certificate : certificate).c_str()) != 1 || SSL_CTX_use_PrivateKey_file(tlsContext.get(), (filesystem::path(key).is_relative() ? currentDirectory / key : key).c_str(), SSL_FILETYPE_PEM) != 1 || SSL_CTX_check_private_key(tlsContext.get()) != 1) {
			
				// Throw exception
				throw runtime_error("Setting public server TLS context's certificate and key failed");
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
		
		// Set HTTP server generic request callback
		evhttp_set_gencb(httpServer.get(), ([](evhttp_request *request, void *argument) {
		
			// Get self from argument
			PublicServer *self = reinterpret_cast<PublicServer *>(argument);
			
			// Try
			try {
			
				// Handle generic request
				self->handleGenericRequest(request);
			}
			
			// Catch errors
			catch(...) {
			
				// Remove request's response's content encoding, vary, and content type headers
				if(evhttp_request_get_output_headers(request)) {
				
					evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Encoding");
					evhttp_remove_header(evhttp_request_get_output_headers(request), "Vary");
					evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
				}
				
				// Reply with internal server error response to request
				evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
			}
		}), this);
		
		// Get address from provided options
		const char *address = providedOptions.contains('e') ? providedOptions.at('e') : DEFAULT_ADDRESS;
		
		// Check if a public server address is provided
		if(providedOptions.contains('e')) {
		
			// Display message
			osyncstream(cout) << "Using provided public server address: " << address << endl;
		}
		
		// Get port from provided options
		const uint16_t port = providedOptions.contains('o') ? strtoul(providedOptions.at('o'), nullptr, Common::DECIMAL_NUMBER_BASE) : DEFAULT_PORT;
		
		// Check if a public server port is provided
		if(providedOptions.contains('o')) {
		
			// Display message
			osyncstream(cout) << "Using provided public server port: " << port << endl;
		}
		
		// Check if binding HTTP server to address and port failed
		if(evhttp_bind_socket(httpServer.get(), address, port)) {
		
			// Throw exception
			throw runtime_error("Binding public server HTTP server to address and port failed");
		}
		
		// Set display port to if the port doesn't match the default server port
		const bool displayPort = (!usingTlsServer && port != Common::HTTP_PORT) || (usingTlsServer && port != Common::HTTPS_PORT);
		
		// Check if address is an IPv6 address
		char temp[sizeof(in6_addr)];
		if(inet_pton(AF_INET6, address, temp) == 1) {
		
			// Display message
			osyncstream(cout) << "Public server started and listening at " << (usingTlsServer ? "https" : "http") << "://[" << address << ']' << (displayPort ? ':' + to_string(port) : "") << endl;
		}
		
		// Otherwise
		else {
		
			// Display message
			osyncstream(cout) << "Public server started and listening at " << (usingTlsServer ? "https" : "http") << "://" << address << (displayPort ? ':' + to_string(port) : "") << endl;
		}
		
		// Set started
		started.store(true);
		
		// Check if running event loop failed
		if(event_base_dispatch(eventBase.get()) == -1) {
		
			// Throw exception
			throw runtime_error("Running public server event loop failed");
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
		osyncstream(cout) << "Public server failed for unknown reason" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
		
		// Raise interrupt signal
		kill(getpid(), SIGINT);
	}
}

// Handle generic request
void PublicServer::handleGenericRequest(evhttp_request *request) {

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
	
	// Check if setting request's response's allowed origin CORS header failed
	if(evhttp_add_header(evhttp_request_get_output_headers(request), "Access-Control-Allow-Origin", "*")) {
	
		// Remove request's response's CORS headers
		evhttp_remove_header(evhttp_request_get_output_headers(request), "Access-Control-Allow-Origin");
		
		// Reply with internal server error response to request
		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
		
		// Return
		return;
	}

	// Check if request is an OPTIONS request
	if(evhttp_request_get_command(request) == EVHTTP_REQ_OPTIONS) {
	
		// Check if setting request's response's allowed methods and headers CORS header failed
		if(evhttp_add_header(evhttp_request_get_output_headers(request), "Access-Control-Allow-Methods", "GET, POST, OPTIONS") || evhttp_add_header(evhttp_request_get_output_headers(request), "Access-Control-Allow-Headers", "Content-Type, Accept-Encoding")) {
		
			// Remove request's response's CORS headers
			evhttp_remove_header(evhttp_request_get_output_headers(request), "Access-Control-Allow-Origin");
			evhttp_remove_header(evhttp_request_get_output_headers(request), "Access-Control-Allow-Methods");
			evhttp_remove_header(evhttp_request_get_output_headers(request), "Access-Control-Allow-Headers");
			
			// Reply with internal server error response to request
			evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Reply with ok response to request
		evhttp_send_reply(request, HTTP_OK, nullptr, nullptr);
	}
	
	// Otherwise check if request is a GET request
	else if(evhttp_request_get_command(request) == EVHTTP_REQ_GET) {
	
		// Check if request doesn't have a URI
		const evhttp_uri *uri = evhttp_request_get_evhttp_uri(request);
		if(!uri) {
		
			// Reply with not found response to request
			evhttp_send_reply(request, HTTP_NOTFOUND, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Check if URI path is invalid
		const char *path = evhttp_uri_get_path(uri);
		if(!path || strlen(path) != sizeof('/') + Payments::URL_SIZE + sizeof(".png") - sizeof('\0') || path[0] != '/' || strcasecmp(&path[sizeof('/') + Payments::URL_SIZE], ".png")) {
		
			// Reply with not found response to request
			evhttp_send_reply(request, HTTP_NOTFOUND, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Get payment URL from the URI path
		char paymentUrl[Payments::URL_SIZE + sizeof('\0')];
		memcpy(paymentUrl, &path[sizeof('/')], Payments::URL_SIZE);
		paymentUrl[Payments::URL_SIZE] = '\0';
		
		// Check if payment doesn't exist
		const tuple paymentInfo = payments.getPaymentPrice(paymentUrl);
		if(!get<0>(paymentInfo)) {
		
			// Reply with not found response to request
			evhttp_send_reply(request, HTTP_NOTFOUND, nullptr, nullptr);
			
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
		
		// Check if URL parameter isn't provided or is invalid
		const char *url = evhttp_find_header(&queryValues, "url");
		if(!url || !*url || !Common::isValidUtf8String(reinterpret_cast<const uint8_t *>(url), strlen(url))) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Check if padding is provided
		int padding;
		const char *paddingParameter = evhttp_find_header(&queryValues, "padding");
		if(paddingParameter) {
		
			// Check if padding parameter is true
			if(!strcasecmp(paddingParameter, "true")) {
			
				// Set padding to default QR code padding
				padding = DEFAULT_QR_CODE_PADDING;
			}
			
			// Otherwise check if padding parameter is false
			else if(!strcasecmp(paddingParameter, "false")) {
			
				// Set padding to zero
				padding = 0;
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
		
			// Set padding to default QR code padding
			padding = DEFAULT_QR_CODE_PADDING;
		}
		
		// Check if invert is provided
		bool invert;
		const char *invertParameter = evhttp_find_header(&queryValues, "invert");
		if(invertParameter) {
		
			// Check if invert parameter is true
			if(!strcasecmp(invertParameter, "true")) {
			
				// Set invert to true
				invert = true;
			}
			
			// Otherwise check if invert parameter is false
			else if(!strcasecmp(invertParameter, "false")) {
			
				// Set invert to false
				invert = false;
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
		
			// Set invert to false
			invert = false;
		}
		
		// Check if payment has a price
		string data;
		if(get<1>(paymentInfo).has_value()) {
		
			// Set data
			data = "{\"Recipient Address\":\"" + Common::jsonEscape(url) + "\",\"Amount\":\"" + Common::getNumberInNumberBase(get<1>(paymentInfo).value(), Consensus::NUMBER_BASE) + "\"}";
		}
		
		// Otherwise
		else {
		
			// Set data
			data = "{\"Recipient Address\":\"" + Common::jsonEscape(url) + "\"}";
		}
		
		// Check if data's capacity is too small
		if(data.capacity() < qrcodegen_BUFFER_LEN_MAX) {
		
			// Increase data's capacity
			data.reserve(qrcodegen_BUFFER_LEN_MAX);
		}
		
		// Check if creating QR code failed
		uint8_t qrCode[qrcodegen_BUFFER_LEN_MAX];
		if(!qrcodegen_encodeBinary(reinterpret_cast<uint8_t *>(data.data()), data.size(), qrCode, qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, false)) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Get QR code size
		const int size = qrcodegen_getSize(qrCode);
		
		// Check if creating PNG failed
		png_infop info = nullptr;
		const auto pngDestructor = [&info](png_structp png) {
		
			// Destroy png
			png_destroy_write_struct(&png, &info);
		};
		
		const unique_ptr<png_struct, decltype(pngDestructor)> png(png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr), pngDestructor);
		if(!png) {

			// Reply with internal server error response to request
			evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Check if creating PNG's info failed
		info = png_create_info_struct(png.get());
		if(!info) {

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
		
		// Set PNG error handler
		if(setjmp(png_jmpbuf(png.get()))) {

			// Reply with internal server error response to request
			evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Set PNG write function
		png_set_write_fn(png.get(), buffer.get(), [](const png_structp png, const png_bytep data, const png_size_t length) {
		
			// Get buffer
			evbuffer *buffer = reinterpret_cast<evbuffer *>(png_get_io_ptr(png));
			
			// Check if adding data to buffer failed
			if(evbuffer_add(buffer, data, length)) {
			
				// Trigger PNG error
				png_error(png, nullptr);
			}
			
		}, nullptr);
		
		// Set PNG image details
		png_set_IHDR(png.get(), info, size + padding * 2, size + padding * 2, 1, PNG_COLOR_TYPE_GRAY, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
		
		// Write PNG info
		png_write_info(png.get(), info);
		
		// Supply each PNG pixel as a byte
		png_set_packing(png.get());
		
		// Check if not inverting
		if(!invert) {
		
			// Invert PNG
			png_set_invert_mono(png.get());
		}
		
		// Go through all rows in the QR code
		for(int y = -padding; y < size + padding; ++y) {
		
			// Go through all padding and modules in the row
			png_byte pixels[size + padding * 2];
			for(int x = -padding; x < size + padding; ++x) {
			
				// Set pixel to padding or module
				pixels[x + padding] = (y < 0 || y >= size || x < 0 || x >= size) ? 0 : qrcodegen_getModule(qrCode, x, y);
			}
			
			// Write pixels to png
			png_write_row(png.get(), pixels);
		}

		// Write PNG end
		png_write_end(png.get(), nullptr);
		
		// Check if setting request's response's content type header failed
		if(evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "image/png")) {
		
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
	
	// Otherwise
	else {

		// Check if request doesn't have a URI
		const evhttp_uri *uri = evhttp_request_get_evhttp_uri(request);
		if(!uri) {
		
			// Reply with not found response to request
			evhttp_send_reply(request, HTTP_NOTFOUND, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Check if URI path is invalid
		const char *path = evhttp_uri_get_path(uri);
		if(!path || strlen(path) != sizeof('/') + Payments::URL_SIZE + sizeof("/v2/foreign") - sizeof('\0') || path[0] != '/' || strcasecmp(&path[sizeof('/') + Payments::URL_SIZE], "/v2/foreign")) {
		
			// Reply with not found response to request
			evhttp_send_reply(request, HTTP_NOTFOUND, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Get payment URL from the URI path
		char paymentUrl[Payments::URL_SIZE + sizeof('\0')];
		memcpy(paymentUrl, &path[sizeof('/')], Payments::URL_SIZE);
		paymentUrl[Payments::URL_SIZE] = '\0';
		
		// Lock payments
		unique_lock lockPayments(payments.getLock());
		
		// Check if payment doesn't exist, it was already received, or it is expired
		tuple paymentInfo = payments.getReceivingPaymentForUrl(paymentUrl);
		if(!get<0>(paymentInfo)) {
		
			// Reply with not found response to request
			evhttp_send_reply(request, HTTP_NOTFOUND, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Check if request doesn't contain headers
		const evkeyvalq *headers = evhttp_request_get_input_headers(request);
		if(!headers) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Check if request's content type is invalid
		const char *contentType = evhttp_find_header(headers, "Content-Type");
		if(!contentType || strncasecmp(contentType, "application/json", sizeof("application/json") - sizeof('\0')) || (contentType[sizeof("application/json") - sizeof('\0')] && contentType[sizeof("application/json") - sizeof('\0')] != ';')) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Check if content type's character set is invalid
		const char *characterSet = strcasestr(contentType, "charset=");
		if(characterSet && ((*(characterSet - sizeof(';')) != ';' && *(characterSet - sizeof(' ')) != ' ') || strncasecmp(characterSet + sizeof("charset=") - sizeof('\0'), "utf8", sizeof("utf8") - sizeof('\0')) || (*(characterSet + sizeof("charset=utf8") - sizeof('\0')) && *(characterSet + sizeof("charset=utf8") - sizeof('\0')) != ';'))) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Initialize compress
		bool compress = false;
		
		// Check if request contains an accept encoding
		const char *acceptEncoding = evhttp_find_header(headers, "Accept-Encoding");
		if(acceptEncoding) {
		
			// Check if gzip encoding is an accepted encoding
			const char *gzipEncoding = strcasestr(acceptEncoding, "gzip");
			if(gzipEncoding && (gzipEncoding == acceptEncoding || *(gzipEncoding - sizeof(',')) == ',' || *(gzipEncoding - sizeof(' ')) == ' ') && (!*(acceptEncoding + sizeof("gzip") - sizeof('\0')) || *(acceptEncoding + sizeof("gzip") - sizeof('\0')) == ',' || *(acceptEncoding + sizeof("gzip") - sizeof('\0')) == ';')) {
			
				// Set compress to true
				compress = true;
			}
		}
		
		// Check if request doesn't contain POST data
		evbuffer *postDataBuffer = evhttp_request_get_input_buffer(request);
		if(!postDataBuffer || !evbuffer_get_length(postDataBuffer)) {
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Check if getting POST data failed
		const unsigned char *postData = evbuffer_pullup(postDataBuffer, evbuffer_get_length(postDataBuffer));
		if(!postData) {
		
			// Reply with internal server error response to request
			evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
			
			// Return
			return;
		}
		
		// Try
		try {
		
			// Parse POST data as JSON
			simdjson::dom::parser parser;
			const simdjson::dom::element json = parser.parse(postData, evbuffer_get_length(postDataBuffer), true);
			
			// Check if JSON isn't a JSON-RPC request
			if(!json.is_object() || strcmp(json["jsonrpc"].get_c_str(), "2.0") || !json["id"].is_uint64() || !json["method"].is_string() || json["params"].error() != simdjson::SUCCESS) {
			
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
			
			// Check if setting request's response's content type header failed
			if(evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "application/json; charset=utf-8")) {
			
				// Remove request's response's content type header
				evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
			
				// Reply with internal server error response to request
				evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
				
				// Return
				return;
			}
			
			// Check if request is to check version
			if(!strcmp(json["method"].get_c_str(), "check_version")) {
			
				// Unlock payments
				lockPayments.unlock();
			
				// Check if parameters aren't provided
				if(!json["params"].is_array()) {
				
					// Check if adding invalid request JSON-RPC error to buffer failed
					if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"}}", json["id"].get_uint64().value()) == -1) {
					
						// Remove request's response's content type header
						evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
						
						// Reply with internal server error response to request
						evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
						
						// Return
						return;
					}
				}
				
				// Otherwise check if parameters are invalid
				else if(json["params"].get_array().size()) {
				
					// Check if adding invalid parameters JSON-RPC error to buffer failed
					if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32602,\"message\":\"Invalid parameters\"}}", json["id"].get_uint64().value()) == -1) {
					
						// Remove request's response's content type header
						evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
						
						// Reply with internal server error response to request
						evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
						
						// Return
						return;
					}
				}
			
				// Otherwise check if adding JSON-RPC result to buffer failed
				else if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"result\":{\"Ok\":{\"foreign_api_version\":2,\"supported_slate_versions\":[\"SP\"]}}}", json["id"].get_uint64().value()) == -1) {
				
					// Remove request's response's content type header
					evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
					
					// Reply with internal server error response to request
					evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
					
					// Return
					return;
				}
			}
			
			// Otherwise check if request is to get proof address
			else if(!strcmp(json["method"].get_c_str(), "get_proof_address")) {
			
				// Unlock payments
				lockPayments.unlock();
			
				// Check if parameters aren't provided
				if(!json["params"].is_array()) {
				
					// Check if adding invalid request JSON-RPC error to buffer failed
					if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"}}", json["id"].get_uint64().value()) == -1) {
					
						// Remove request's response's content type header
						evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
						
						// Reply with internal server error response to request
						evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
						
						// Return
						return;
					}
				}
				
				// Otherwise check if parameters are invalid
				else if(json["params"].get_array().size()) {
				
					// Check if adding invalid parameters JSON-RPC error to buffer failed
					if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32602,\"message\":\"Invalid parameters\"}}", json["id"].get_uint64().value()) == -1) {
					
						// Remove request's response's content type header
						evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
						
						// Reply with internal server error response to request
						evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
						
						// Return
						return;
					}
				}
				
				// Otherwise
				else {
				
					// Get payment proof index from payment's unique number
					const uint64_t &paymentProofIndex = get<0>(paymentInfo);
					
					// Initialize error occurred
					bool errorOccurred = false;
				
					// Try
					string paymentProofAddress;
					try {
					
						// Get wallet's Tor payment proof address at the payment proof index
						paymentProofAddress = wallet.getTorPaymentProofAddress(paymentProofIndex);
					}
					
					// Catch errors
					catch(...) {
					
						// Set error occurred
						errorOccurred = true;
					
						// Check if adding internal error JSON-RPC error to buffer failed
						if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
						
							// Remove request's response's content type header
							evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
							
							// Reply with internal server error response to request
							evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
							
							// Return
							return;
						}
					}
					
					// Check if an error didn't occur
					if(!errorOccurred) {
					
						// Check if adding JSON-RPC result to buffer failed
						if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"result\":{\"Ok\":\"%s\"}}", json["id"].get_uint64().value(), paymentProofAddress.c_str()) == -1) {
						
							// Remove request's response's content type header
							evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
							
							// Reply with internal server error response to request
							evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
							
							// Return
							return;
						}
					}
				}
			}
			
			// Otherwise check if request is to receive transaction
			else if(!strcmp(json["method"].get_c_str(), "receive_tx")) {
			
				// Check if parameters aren't provided
				if(!json["params"].is_array()) {
				
					// Check if adding invalid request JSON-RPC error to buffer failed
					if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"}}", json["id"].get_uint64().value()) == -1) {
					
						// Remove request's response's content type header
						evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
						
						// Reply with internal server error response to request
						evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
						
						// Return
						return;
					}
				}
				
				// Otherwise check if parameters are invalid
				else if(json["params"].get_array().size() != 3 || !json["params"].at(0).is_string() || (!json["params"].at(1).is_null() && !json["params"].at(1).is_string()) || (!json["params"].at(2).is_null() && !json["params"].at(2).is_string())) {
				
					// Check if adding invalid parameters JSON-RPC error to buffer failed
					if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32602,\"message\":\"Invalid parameters\"}}", json["id"].get_uint64().value()) == -1) {
					
						// Remove request's response's content type header
						evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
						
						// Reply with internal server error response to request
						evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
						
						// Return
						return;
					}
				}
				
				// Otherwise
				else {
				
					// Try
					try {
				
						// Get payment proof index from payment's unique number
						const uint64_t &paymentProofIndex = get<0>(paymentInfo);
						
						// Decode parameter as a Slatepack
						const pair slateData = Slatepack::decode(json["params"].at(0).get_c_str(), wallet, paymentProofIndex);
						
						// Parse slate data
						Slate slate(slateData.first.data(), slateData.first.size());
						
						// Get price from payment's price
						const uint64_t price = get<2>(paymentInfo).has_value() ? get<2>(paymentInfo).value() : 0;
						
						// Check if price exists and slate's amount doesn't match the price
						if(price && slate.getAmount() != price) {
						
							// Check if adding invalid parameters JSON-RPC error to buffer failed
							if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32602,\"message\":\"The amount must be exactly %s\"}}", json["id"].get_uint64().value(), Common::getNumberInNumberBase(price, Consensus::NUMBER_BASE).c_str()) == -1) {
							
								// Remove request's response's content type header
								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
								
								// Reply with internal server error response to request
								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
								
								// Return
								return;
							}
						}
						
						// Otherwise check if slate doesn't have a payment proof
						else if(slate.getSenderPaymentProofAddressPublicKey().empty()) {
						
							// Check if adding invalid parameters JSON-RPC error to buffer failed
							if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32602,\"message\":\"A payment proof is required\"}}", json["id"].get_uint64().value()) == -1) {
							
								// Remove request's response's content type header
								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
								
								// Reply with internal server error response to request
								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
								
								// Return
								return;
							}
						}
						
						// Otherwise check if slate's kernel features isn't plain
						else if(slate.getKernelFeatures() != Slate::KernelFeatures::PLAIN) {
						
							// Check if adding invalid parameters JSON-RPC error to buffer failed
							if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32602,\"message\":\"Invalid parameters\"}}", json["id"].get_uint64().value()) == -1) {
							
								// Remove request's response's content type header
								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
								
								// Reply with internal server error response to request
								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
								
								// Return
								return;
							}
						}
						
						// Otherwise
						else {
						
							// Try
							try {
						
								// Check if getting wallet's Tor payment proof address public key at the payment proof index failed
								uint8_t paymentProofAddressPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE];
								if(!wallet.getTorPaymentProofAddressPublicKey(paymentProofAddressPublicKey, paymentProofIndex)) {
								
									// Check if adding internal error JSON-RPC error to buffer failed
									if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
									
										// Remove request's response's content type header
										evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
										
										// Reply with internal server error response to request
										evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
										
										// Return
										return;
									}
								}
								
								// Otherwise
								else {
								
									// Check if slate's sender and recipient payment proof address public keys are the same
									if(slate.getSenderPaymentProofAddressPublicKey() == slate.getRecipientPaymentProofAddressPublicKey()) {
									
										// Set slate's recipient payment proof address public key to the wallet's payment proof address public key
										slate.setRecipientPaymentProofAddressPublicKey(paymentProofAddressPublicKey, sizeof(paymentProofAddressPublicKey));
									}
									
									// Check if slate's recipient payment proof address public key isn't correct
									if(slate.getRecipientPaymentProofAddressPublicKey().size() != sizeof(paymentProofAddressPublicKey) || memcmp(slate.getRecipientPaymentProofAddressPublicKey().data(), paymentProofAddressPublicKey, sizeof(paymentProofAddressPublicKey))) {
									
										// Check if adding invalid parameters JSON-RPC error to buffer failed
										if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32602,\"message\":\"Invalid parameters\"}}", json["id"].get_uint64().value()) == -1) {
										
											// Remove request's response's content type header
											evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
											
											// Reply with internal server error response to request
											evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
											
											// Return
											return;
										}
									}
									
									// Get identifer path from payment's unique number
									const uint64_t &identifierPath = get<0>(paymentInfo);
									
									// Check if getting wallet's commitment and proof at the identifier path for the slate's amount failed
									uint8_t commitment[Crypto::COMMITMENT_SIZE];
									uint8_t proof[Crypto::BULLETPROOF_SIZE];
									if(!wallet.getCommitment(commitment, identifierPath, slate.getAmount()) || !wallet.getBulletproof(proof, identifierPath, slate.getAmount())) {
									
										// Check if adding internal error JSON-RPC error to buffer failed
										if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
										
											// Remove request's response's content type header
											evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
											
											// Reply with internal server error response to request
											evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
											
											// Return
											return;
										}
									}
									
									// Otherwise
									else {
									
										// Set slate's output
										slate.setOutput(SlateOutput(commitment, proof));
										
										// Check if getting wallet's blinding factor at the identifier path for the slate's amount failed
										uint8_t blindingFactor[Crypto::BLINDING_FACTOR_SIZE];
										if(!wallet.getBlindingFactor(blindingFactor, identifierPath, slate.getAmount())) {
										
											// Check if adding internal error JSON-RPC error to buffer failed
											if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
											
												// Remove request's response's content type header
												evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
												
												// Reply with internal server error response to request
												evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
												
												// Return
												return;
											}
										}
										
										// Otherwise check if creating random slate offset failed
										else if(!slate.createRandomOffset(blindingFactor)) {
										
											// Securely clear blinding factor
											explicit_bzero(blindingFactor, sizeof(blindingFactor));
											
											// Check if adding internal error JSON-RPC error to buffer failed
											if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
											
												// Remove request's response's content type header
												evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
												
												// Reply with internal server error response to request
												evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
												
												// Return
												return;
											}
										}
										
										// Otherwise
										else {
										
											// Try
											try {
											
												// Check if applying slate's offset to the blinding factor failed
												const uint8_t *blinds[] = {
												
													// Blinding factor
													blindingFactor,
													
													// Slate's offset
													slate.getOffset()
												};
												
												if(!secp256k1_pedersen_blind_sum(secp256k1_context_no_precomp, blindingFactor, blinds, sizeof(blinds) / sizeof(blinds[0]), 1) || !Crypto::isValidSecp256k1PrivateKey(blindingFactor, sizeof(blindingFactor))) {
												
													// Securely clear blinding factor
													explicit_bzero(blindingFactor, sizeof(blindingFactor));
													
													// Check if adding internal error JSON-RPC error to buffer failed
													if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
													
														// Remove request's response's content type header
														evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
														
														// Reply with internal server error response to request
														evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
														
														// Return
														return;
													}
												}
												
												// Otherwise
												else {
												
													// Check if creating private nonce failed
													uint8_t privateNonce[Crypto::SCALAR_SIZE];
													if(!Crypto::createPrivateNonce(privateNonce)) {
													
														// Securely clear blinding factor
														explicit_bzero(blindingFactor, sizeof(blindingFactor));
														
														// Check if adding internal error JSON-RPC error to buffer failed
														if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
														
															// Remove request's response's content type header
															evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
															
															// Reply with internal server error response to request
															evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
															
															// Return
															return;
														}
													}
													
													// Otherwise
													else {
													
														// Try
														try {
														
															// Check if getting public blind excess from the blinding factor or public nonce from the private nonce failed
															uint8_t publicBlindExcess[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
															uint8_t publicNonce[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
															if(!Crypto::getSecp256k1PublicKey(publicBlindExcess, blindingFactor) || !Crypto::getSecp256k1PublicKey(publicNonce, privateNonce)) {
															
																// Securely clear private nonce
																explicit_bzero(privateNonce, sizeof(privateNonce));
																
																// Securely clear blinding factor
																explicit_bzero(blindingFactor, sizeof(blindingFactor));
																
																// Check if adding internal error JSON-RPC error to buffer failed
																if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
																
																	// Remove request's response's content type header
																	evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																	
																	// Reply with internal server error response to request
																	evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																	
																	// Return
																	return;
																}
															}
															
															// Otherwise
															else {
															
																// Add participant to the slate
																slate.addParticipant(SlateParticipant(publicBlindExcess, publicNonce));
																
																// Check if getting slate's public blind excess sum or public nonce sum failed
																uint8_t publicBlindExcessSum[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
																uint8_t publicNonceSum[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
																if(!slate.getPublicBlindExcessSum(publicBlindExcessSum) || !slate.getPublicNonceSum(publicNonceSum)) {
																
																	// Securely clear private nonce
																	explicit_bzero(privateNonce, sizeof(privateNonce));
																	
																	// Securely clear blinding factor
																	explicit_bzero(blindingFactor, sizeof(blindingFactor));
																	
																	// Check if adding internal error JSON-RPC error to buffer failed
																	if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
																	
																		// Remove request's response's content type header
																		evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																		
																		// Reply with internal server error response to request
																		evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																		
																		// Return
																		return;
																	}
																}
																
																// Otherwise
																else {
																
																	// Check if creating partial signature failed
																	uint8_t partialSignature[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE];
																	const vector kernelData = slate.getKernelData();
																	if(!Crypto::getSecp256k1PartialSingleSignerSignature(partialSignature, blindingFactor, kernelData.data(), kernelData.size(), privateNonce, publicBlindExcessSum, publicNonceSum)) {
																	
																		// Securely clear private nonce
																		explicit_bzero(privateNonce, sizeof(privateNonce));
																		
																		// Securely clear blinding factor
																		explicit_bzero(blindingFactor, sizeof(blindingFactor));
																		
																		// Check if adding internal error JSON-RPC error to buffer failed
																		if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
																		
																			// Remove request's response's content type header
																			evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																			
																			// Reply with internal server error response to request
																			evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																			
																			// Return
																			return;
																		}
																	}
																	
																	// Otherwise
																	else {
																	
																		// Securely clear private nonce
																		explicit_bzero(privateNonce, sizeof(privateNonce));
																		
																		// Securely clear blinding factor
																		explicit_bzero(blindingFactor, sizeof(blindingFactor));
																		
																		// Set slate participant's partial signature
																		slate.setParticipantsPartialSignature(partialSignature);
																		
																		// Check if slate's sender payment proof address public key is a secp256k1 public key
																		string senderPaymentProofAddress;
																		if(slate.getSenderPaymentProofAddressPublicKey().size() == Crypto::SECP256K1_PUBLIC_KEY_SIZE) {
																		
																			// Set sender payment proof address to the slate's sender payment proof address public key as an MQS address
																			senderPaymentProofAddress = Mqs::secp256k1PublicKeyToAddress(slate.getSenderPaymentProofAddressPublicKey().data());
																		}
																		
																		// Otherwise
																		else {
																		
																			// Set sender payment proof address to the slate's sender payment proof address public key as a Tor address
																			senderPaymentProofAddress = Tor::ed25519PublicKeyToAddress(slate.getSenderPaymentProofAddressPublicKey().data());
																		}
																		
																		// Check if getting slate's excess failed
																		uint8_t excess[Crypto::COMMITMENT_SIZE];
																		if(!slate.getExcess(excess)) {
																		
																			// Check if adding internal error JSON-RPC error to buffer failed
																			if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
																			
																				// Remove request's response's content type header
																				evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																				
																				// Reply with internal server error response to request
																				evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																				
																				// Return
																				return;
																			}
																		}
																		
																		// Otherwise
																		else {
																		
																			// Check if getting recipient payment proof signature failed
																			uint8_t recipientPaymentProofSignature[Crypto::ED25519_SIGNATURE_SIZE];
																			if(!wallet.getTorPaymentProofSignature(recipientPaymentProofSignature, paymentProofIndex, excess, senderPaymentProofAddress.c_str(), slate.getAmount())) {
																			
																				// Check if adding internal error JSON-RPC error to buffer failed
																				if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
																				
																					// Remove request's response's content type header
																					evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																					
																					// Reply with internal server error response to request
																					evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																					
																					// Return
																					return;
																				}
																			}
																			
																			// Otherwise
																			else {
																			
																				// Set slate's recipient payment proof signature
																				slate.setRecipientPaymentProofSignature(recipientPaymentProofSignature, sizeof(recipientPaymentProofSignature));
																				
																				// Serialize the slate
																				const vector serializedSlate = slate.serialize();
																				
																				// Check if adding JSON-RPC result to buffer failed
																				if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"result\":{\"Ok\":\"%s\"}}", json["id"].get_uint64().value(), Slatepack::encode(serializedSlate.data(), serializedSlate.size(), slateData.second.has_value() ? slateData.second.value().data() : nullptr, wallet, paymentProofIndex).c_str()) == -1) {
																				
																					// Remove request's response's content type header
																					evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																					
																					// Reply with internal server error response to request
																					evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																					
																					// Return
																					return;
																				}
																				
																				// Initialize error occurred
																				bool errorOccurred = false;
																				
																				// Check if compressing
																				if(compress) {
																				
																					// Check if getting buffer's uncompressed data failed
																					const unsigned char *uncompressedData = evbuffer_pullup(buffer.get(), evbuffer_get_length(buffer.get()));
																					if(!uncompressedData) {
																					
																						// Remove request's response's content type header
																						evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																						
																						// Reply with internal server error response to request
																						evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																						
																						// Return
																						return;
																					}
																					
																					// Try
																					vector<uint8_t> compressedData;
																					try {
																				
																						// Compress uncompressed data
																						compressedData = Gzip::compress(uncompressedData, evbuffer_get_length(buffer.get()));
																					}
																					
																					// Catch errors
																					catch(...) {
																					
																						// Set error occurred
																						errorOccurred = true;
																						
																						// Check if clearing buffer failed
																						if(evbuffer_drain(buffer.get(), evbuffer_get_length(buffer.get()))) {
																						
																							// Remove request's response's content type header
																							evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																							
																							// Reply with internal server error response to request
																							evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																							
																							// Return
																							return;
																						}
																						
																						// Check if adding internal error JSON-RPC error to buffer failed
																						if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
																						
																							// Remove request's response's content type header
																							evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																							
																							// Reply with internal server error response to request
																							evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																							
																							// Return
																							return;
																						}
																					}
																					
																					// Check if an error didn't occur
																					if(!errorOccurred) {
																					
																						// Check if clearing buffer and setting it to the compressed data failed
																						if(evbuffer_drain(buffer.get(), evbuffer_get_length(buffer.get())) || evbuffer_add(buffer.get(), compressedData.data(), compressedData.size())) {
																						
																							// Remove request's response's content type header
																							evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																							
																							// Reply with internal server error response to request
																							evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																							
																							// Return
																							return;
																						}
																						
																						// Check if setting request's response's content encoding and vary headers failed
																						if(evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Encoding", "gzip") || evhttp_add_header(evhttp_request_get_output_headers(request), "Vary", "Accept-Encoding")) {
																						
																							// Remove request's response's content encoding and vary headers
																							evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Encoding");
																							evhttp_remove_header(evhttp_request_get_output_headers(request), "Vary");
																							
																							// Remove request's response's content type header
																							evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																							
																							// Reply with internal server error response to request
																							evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																							
																							// Return
																							return;
																						}
																					}
																				}
																				
																				// Check if an error didn't occur
																				if(!errorOccurred) {
																				
																					// Get payment ID
																					const uint64_t &paymentId = get<1>(paymentInfo);
																				
																					// Check if payment has a received callback
																					if(get<3>(paymentInfo).has_value()) {
																					
																						// Try
																						try {
																						
																							// Get payment's received callback
																							string &paymentReceivedCallback = get<3>(paymentInfo).value();
																							
																							// Apply substitutions to payment's received callback
																							Common::applySubstitutions(paymentReceivedCallback, {
																							
																								// ID
																								{"__id__", to_string(paymentId)},
																								
																								// Price
																								{"__price__", Common::getNumberInNumberBase(slate.getAmount(), Consensus::NUMBER_BASE)},
																								
																								// Sender payment proof address
																								{"__sender_payment_proof_address__", senderPaymentProofAddress},
																								
																								// Kernel commitment
																								{"__kernel_commitment__", Common::toHexString(excess, sizeof(excess))},
																								
																								// Recipient payment proof signature
																								{"__recipient_payment_proof_signature__", Common::toHexString(recipientPaymentProofSignature, sizeof(recipientPaymentProofSignature))}
																							});
																					
																							// Check if sending HTTP request to the payment's received callback failed
																							if(!Common::sendHttpRequest(paymentReceivedCallback.c_str())) {
																							
																								// Throw exception
																								throw runtime_error("Sending HTTP request to the payment's received callback failed");
																							}
																						}
																						
																						// Catch errors
																						catch(...) {
																						
																							// Set error occurred
																							errorOccurred = true;
																							
																							// Check if compressing and removing request's response's content encoding and vary headers failed
																							if(compress && (evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Encoding") || evhttp_remove_header(evhttp_request_get_output_headers(request), "Vary"))) {
																							
																								// Remove request's response's content encoding and vary headers
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Encoding");
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Vary");
																								
																								// Remove request's response's content type header
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																								
																								// Reply with internal server error response to request
																								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																								
																								// Return
																								return;
																							}
																							
																							// Check if clearing buffer failed
																							if(evbuffer_drain(buffer.get(), evbuffer_get_length(buffer.get()))) {
																							
																								// Remove request's response's content type header
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																								
																								// Reply with internal server error response to request
																								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																								
																								// Return
																								return;
																							}
																							
																							// Check if adding internal error JSON-RPC error to buffer failed
																							if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
																							
																								// Remove request's response's content type header
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																								
																								// Reply with internal server error response to request
																								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																								
																								// Return
																								return;
																							}
																						}
																					}
																					
																					// Check if an error didn't occur
																					if(!errorOccurred) {
																				
																						// Check if setting that payment is received failed
																						if(!payments.setPaymentReceived(paymentId, slate.getAmount(), senderPaymentProofAddress.c_str(), excess, slate.getParticipants().front().getPublicBlindExcess(), partialSignature, publicNonceSum, kernelData.data(), kernelData.size())) {
																						
																							// Check if compressing and removing request's response's content encoding and vary headers failed
																							if(compress && (evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Encoding") || evhttp_remove_header(evhttp_request_get_output_headers(request), "Vary"))) {
																							
																								// Remove request's response's content encoding and vary headers
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Encoding");
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Vary");
																								
																								// Remove request's response's content type header
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																								
																								// Reply with internal server error response to request
																								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																								
																								// Return
																								return;
																							}
																							
																							// Check if clearing buffer failed
																							if(evbuffer_drain(buffer.get(), evbuffer_get_length(buffer.get()))) {
																							
																								// Remove request's response's content type header
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																								
																								// Reply with internal server error response to request
																								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																								
																								// Return
																								return;
																							}
																							
																							// Check if adding internal error JSON-RPC error to buffer failed
																							if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
																							
																								// Remove request's response's content type header
																								evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
																								
																								// Reply with internal server error response to request
																								evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
																								
																								// Return
																								return;
																							}
																						}
																						
																						// Otherwise
																						else {
																						
																							// Display message
																							osyncstream(cout) << "Received payment " << paymentId << endl;
																						}
																					}
																				}
																			}
																		}
																	}
																}
															}
														}
														
														// Catch errors
														catch(...) {
														
															// Securely clear private nonce
															explicit_bzero(privateNonce, sizeof(privateNonce));
														
															// Throw
															throw;
														}
													}
												}
											}
											
											// Catch errors
											catch(...) {
											
												// Securely clear blinding factor
												explicit_bzero(blindingFactor, sizeof(blindingFactor));
											
												// Throw
												throw;
											}
										}
									}
								}
							}
							
							// Catch errors
							catch(...) {
							
								// Check if adding internal error JSON-RPC error to buffer failed
								if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}", json["id"].get_uint64().value()) == -1) {
								
									// Remove request's response's content type header
									evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
									
									// Reply with internal server error response to request
									evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
									
									// Return
									return;
								}
							}
						}
					}
					
					// Catch errors
					catch(...) {
					
						// Check if adding invalid parameters JSON-RPC error to buffer failed
						if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32602,\"message\":\"Invalid parameters\"}}", json["id"].get_uint64().value()) == -1) {
						
							// Remove request's response's content type header
							evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
							
							// Reply with internal server error response to request
							evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
							
							// Return
							return;
						}
					}
				}
			}
			
			// Otherwise
			else {
			
				// Unlock payments
				lockPayments.unlock();
			
				// Check if adding method not found JSON-RPC error to buffer failed
				if(evbuffer_add_printf(buffer.get(), "{\"jsonrpc\":\"2.0\",\"id\":%" PRIu64 ",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}", json["id"].get_uint64().value()) == -1) {
				
					// Remove request's response's content type header
					evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
					
					// Reply with internal server error response to request
					evhttp_send_reply(request, HTTP_INTERNAL, nullptr, nullptr);
					
					// Return
					return;
				}
			}
			
			// Reply with ok response to request
			evhttp_send_reply(request, HTTP_OK, nullptr, buffer.get());
		}
		
		// Catch errors
		catch(...) {
		
			// Remove request's response's content type header
			evhttp_remove_header(evhttp_request_get_output_headers(request), "Content-Type");
		
			// Reply with bad request response to request
			evhttp_send_reply(request, HTTP_BADREQUEST, nullptr, nullptr);
		}
	}
}
