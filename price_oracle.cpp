// Header files
#include "./common.h"
#include "event2/buffer.h"
#include "event2/bufferevent_ssl.h"
#include "./price_oracle.h"

using namespace std;


// Constants

// Minimum TLS version
static const int MINIMUM_TLS_VERSION = TLS1_VERSION;

// Read timeout
static const time_t READ_TIMEOUT = 50;

// Write timeout
static const time_t WRITE_TIMEOUT = 50;


// Supporting function implementation

// Constructor
PriceOracle::PriceOracle(const TorProxy &torProxy) :

	// Set Tor proxy
	torProxy(torProxy),
	
	// Get TLS method
	tlsMethod(TLS_client_method()),
	
	// Create TLS context
	tlsContext(SSL_CTX_new_ex(nullptr, nullptr, tlsMethod), SSL_CTX_free),
	
	// Create event base
	eventBase(event_base_new(), event_base_free),
	
	// Set previous timestamp
	previousTimestamp(chrono::seconds(0)),
	
	// Set previous price
	previousPrice("0")
{

	// Check if getting TLS method failed
	if(!tlsMethod) {
	
		// Throw exception
		throw runtime_error("Getting TLS method failed");
	}
	
	// Check if creating TLS context failed
	if(!tlsContext) {
	
		// Throw exception
		throw runtime_error("Creating TLS context failed");
	}
	
	// Check if creating event base failed
	if(!eventBase) {
	
		// Throw exception
		throw runtime_error("Creating event base failed");
	}
	
	// Check if setting TLS context's minimum TLS version failed
	if(!SSL_CTX_set_min_proto_version(tlsContext.get(), MINIMUM_TLS_VERSION)) {
	
		// Throw exception
		throw runtime_error("Setting TLS context's minimum TLS version failed");
	}
	
	// Check if using the default verify paths for the TLS context failed
	if(!SSL_CTX_set_default_verify_paths(tlsContext.get())) {
	
		// Throw exception
		throw runtime_error("Using the default verify paths for the TLS context failed");
	}
	
	// Set TLS context to verify server certificate
	SSL_CTX_set_verify(tlsContext.get(), SSL_VERIFY_PEER, nullptr);
}

// Get price
pair<chrono::time_point<chrono::system_clock>, string> PriceOracle::getPrice() const {

	// Try
	try {
	
		// Check if floonet
		#ifdef FLOONET
		
			// Get new price
			const pair<chrono::time_point<chrono::system_clock>, string> newPrice(chrono::system_clock::now(), "0");
			
		// Otherwise
		#else
		
			// Get new price
			const pair newPrice = getNewPrice();
			
			// Check if price is zero
			if(newPrice.second == "0") {
			
				// Return previous timestamp and price
				return {previousTimestamp, previousPrice};
			}
		#endif
		
		// Update previous timestamp
		previousTimestamp = newPrice.first;
		
		// Update previous price
		previousPrice = newPrice.second;
		
		// Return new price
		return newPrice;
	}
	
	// Catch errors
	catch(...) {
	
		// Return previous timestamp and price
		return {previousTimestamp, previousPrice};
	}
}

// Create request
unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)> PriceOracle::createRequest(const char *host, const uint16_t port, const char *path, vector<uint8_t> &response) const {

	// Check if creating TLS connection from the TLS context failed
	unique_ptr<SSL, decltype(&SSL_free)> tlsConnection(SSL_new(tlsContext.get()), SSL_free);
	if(!tlsConnection) {
	
		// Return nothing
		return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
	}
	
	// Check if enabling the TLS connection's hostname checking failed
	if(!SSL_set1_host(tlsConnection.get(), host)) {
	
		// Return nothing
		return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
	}
	
	// Check if setting the TLS connection's server name indication failed
	if(!SSL_set_tlsext_host_name(tlsConnection.get(), host)) {
	
		// Return nothing
		return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
	}
	
	// Check if Tor is enabled
	#ifdef TOR_ENABLE
	
		// Check if creating SOCKS buffer failed
		const unique_ptr<bufferevent, decltype(&bufferevent_free)> socksBuffer(bufferevent_socket_new(eventBase.get(), -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS), bufferevent_free);
		if(!socksBuffer) {
		
			// Return nothing
			return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
		}
		
		// Set read timeout
		const timeval readTimeout = {

			// Seconds
			.tv_sec = READ_TIMEOUT
		};

		// Set write timeout
		const timeval writeTimeout = {

			// Seconds
			.tv_sec = WRITE_TIMEOUT
		};

		// Set SOCKS buffer's read and write timeout
		bufferevent_set_timeouts(socksBuffer.get(), &readTimeout, &writeTimeout);
		
		// Initialize authenticated
		bool authenticated = false;
		
		// Initialize connected
		bool connected = false;
		
		// Set arguments
		const void *arguments[] = {
		
			// Authenticated
			&authenticated,
			
			// Connected
			&connected,
			
			// Host
			host,
			
			// Port
			&port
		};
		
		// Set SOCKS buffer callbacks
		bufferevent_setcb(socksBuffer.get(), [](bufferevent *buffer, void *argument) {
		
			// Get authenticated from argument
			bool *authenticated = reinterpret_cast<bool *>(reinterpret_cast<void **>(argument)[0]);
			
			// Get connected from argument
			bool *connected = reinterpret_cast<bool *>(reinterpret_cast<void **>(argument)[1]);
			
			// Get host from argument
			const char *host = reinterpret_cast<const char *>(reinterpret_cast<void **>(argument)[2]);
			
			// Get port from argument
			const uint16_t *port = reinterpret_cast<const uint16_t *>(reinterpret_cast<void **>(argument)[3]);
			
			// Check if getting input from the buffer failed
			evbuffer *input = bufferevent_get_input(buffer);
			if(!input) {
			
				// Disable reading from buffer
				bufferevent_disable(buffer, EV_READ);
			}
			
			// Otherwise
			else {
			
				// Get input's length
				const size_t length = evbuffer_get_length(input);
				
				// Check if not authenticated
				if(!*authenticated) {
				
					// Check if length is invalid
					if(length != sizeof("\x05\x00") - sizeof('\0')) {
					
						// Disable reading from buffer
						bufferevent_disable(buffer, EV_READ);
						
						// Return
						return;
					}
				}
				
				// Otherwise
				else {
				
					// Check if length is invalid
					if(length != sizeof("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") - sizeof('\0') && length != sizeof("\x05\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - sizeof('\0')) {
					
						// Disable reading from buffer
						bufferevent_disable(buffer, EV_READ);
						
						// Return
						return;
					}
				}
				
				// Check if getting data from input failed
				const unsigned char *data = evbuffer_pullup(input, length);
				if(!data) {
				
					// Disable reading from buffer
					bufferevent_disable(buffer, EV_READ);
				}
				
				// Otherwise check if data indicates failure
				else if(data[1]) {
				
					// Disable reading from buffer
					bufferevent_disable(buffer, EV_READ);
				}
				
				// Otherwise check if removing data from input failed
				else if(evbuffer_drain(input, length)) {
				
					// Disable reading from buffer
					bufferevent_disable(buffer, EV_READ);
				}
				
				// Otherwise
				else {
				
					// Check if not authenticated
					if(!*authenticated) {
					
						// Set authenticated
						*authenticated = true;
						
						// Create connection request
						const uint8_t hostLength = strlen(host);
						const uint16_t networkPort = htons(*port);
						uint8_t connectionRequest[sizeof("\x05\x01\x00\x03") - sizeof('\0') + sizeof(hostLength) + hostLength + sizeof(networkPort)];
						memcpy(connectionRequest, "\x05\x01\x00\x03", sizeof("\x05\x01\x00\x03") - sizeof('\0'));
						connectionRequest[sizeof("\x05\x01\x00\x03") - sizeof('\0')] = hostLength;
						memcpy(&connectionRequest[sizeof("\x05\x01\x00\x03") - sizeof('\0') + sizeof(hostLength)], host, hostLength);
						memcpy(&connectionRequest[sizeof("\x05\x01\x00\x03") - sizeof('\0') + sizeof(hostLength) + hostLength], &networkPort, sizeof(networkPort));
						
						// Check if writing connection request to buffer failed
						if(bufferevent_write(buffer, connectionRequest, sizeof(connectionRequest))) {
						
							// Disable reading from buffer
							bufferevent_disable(buffer, EV_READ);
						}
					}
					
					// Otherwise
					else {
					
						// Set connected
						*connected = true;
						
						// Disable reading from buffer
						bufferevent_disable(buffer, EV_READ);
					}
				}
			}
			
		}, nullptr, [](bufferevent *buffer, short event, void *argument) {
		
			// Check if connected
			if(event & BEV_EVENT_CONNECTED) {
			
				// Check if enabling reading from buffer was successful
				if(!bufferevent_enable(buffer, EV_READ)) {
				
					// Check if writing authentication request to buffer failed
					if(bufferevent_write(buffer, "\x05\x01\x00", sizeof("\x05\x01\x00") - sizeof('\0'))) {
					
						// Disable reading from buffer
						bufferevent_disable(buffer, EV_READ);
					}
				}
			}
			
		}, arguments);
		
		// Check if connecting to Tor SOCKS proxy failed
		if(bufferevent_socket_connect_hostname(socksBuffer.get(), nullptr, AF_UNSPEC, torProxy.getSocksAddress().c_str(), stoull(torProxy.getSocksPort()))) {
		
			// Return nothing
			return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
		}
		
		// Check if running event loop failed
		if(event_base_dispatch(eventBase.get()) == -1) {
		
			// Return nothing
			return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
		}
		
		// Check if not connected
		if(!connected) {
		
			// Return nothing
			return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
		}
	
		// Check if creating TLS buffer from TLS connection failed
		unique_ptr<bufferevent, decltype(&bufferevent_free)> tlsBuffer(bufferevent_openssl_socket_new(eventBase.get(), bufferevent_getfd(socksBuffer.get()), tlsConnection.get(), BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS), bufferevent_free);
		if(!tlsBuffer) {
		
			// Return nothing
			return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
		}
		
		// Remove SOCKS buffer's file descriptor
		bufferevent_setfd(socksBuffer.get(), -1);
	
	// Otherwise
	#else
	
		// Check if creating TLS buffer from TLS connection failed
		unique_ptr<bufferevent, decltype(&bufferevent_free)> tlsBuffer(bufferevent_openssl_socket_new(eventBase.get(), -1, tlsConnection.get(), BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS), bufferevent_free);
		if(!tlsBuffer) {
		
			// Return nothing
			return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
		}
	#endif
	
	// Release TLS connection
	tlsConnection.release();
	
	// Check if allow dirty shutdown for the TLS buffer failed
	if(bufferevent_ssl_set_flags(tlsBuffer.get(), BUFFEREVENT_SSL_DIRTY_SHUTDOWN) == EV_UINT64_MAX) {
	
		// Return nothing
		return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
	}
	
	// Check if Tor is enabled
	#ifdef TOR_ENABLE
	
		// Check if creating connection from TLS buffer failed
		unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)> connection(evhttp_connection_base_bufferevent_new(eventBase.get(), nullptr, tlsBuffer.get(), torProxy.getSocksAddress().c_str(), stoull(torProxy.getSocksPort())), evhttp_connection_free);
		if(!connection) {
		
			// Return nothing
			return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
		}
	
	// Otherwise
	#else
	
		// Check if creating connection from TLS buffer failed
		unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)> connection(evhttp_connection_base_bufferevent_new(eventBase.get(), nullptr, tlsBuffer.get(), host, port), evhttp_connection_free);
		if(!connection) {
		
			// Return nothing
			return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
		}
	#endif
	
	// Release TLS buffer
	tlsBuffer.release();
	
	// Set connection close callback
	evhttp_connection_set_closecb(connection.get(), [](evhttp_connection *connection, void *argument) {
	
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
	
	// Check if creating request failed
	unique_ptr<evhttp_request, decltype(&evhttp_request_free)> request(evhttp_request_new([](evhttp_request *request, void *argument) {
	
		// Get response from argument
		vector<uint8_t> *response = reinterpret_cast<vector<uint8_t> *>(argument);
		
		// Check if request was successful
		if(request && evhttp_request_get_response_code(request) == HTTP_OK) {
		
			// Check if response exists
			evbuffer *buffer = evhttp_request_get_input_buffer(request);
			if(buffer && evbuffer_get_length(buffer)) {
			
				// Check if getting response failed
				response->resize(evbuffer_get_length(buffer));
				if(evbuffer_copyout(buffer, response->data(), response->size()) != static_cast<ssize_t>(response->size())) {
				
					// Clear response
					response->clear();
				}
			}
			
			// Otherwise
			else {
			
				// Clear response
				response->clear();
			}
			
		}
		
		// Otherwise
		else {
		
			// Clear response
			response->clear();
		}
		
	}, &response), evhttp_request_free);
	
	if(!request) {
	
		// Return nothing
		return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
	}
	
	// Check if setting request's host and connection headers failed
	if(!evhttp_request_get_output_headers(request.get()) || evhttp_add_header(evhttp_request_get_output_headers(request.get()), "Host", (host + ((port != Common::HTTPS_PORT) ? ':' + to_string(port) : "")).c_str()) || evhttp_add_header(evhttp_request_get_output_headers(request.get()), "Connection", "close")) {
	
		// Return nothing
		return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
	}
	
	// Check if making request failed
	if(evhttp_make_request(connection.get(), request.get(), EVHTTP_REQ_GET, path)) {
	
		// Release request
		request.release();
		
		// Return nothing
		return unique_ptr<evhttp_connection, decltype(&evhttp_connection_free)>(nullptr, evhttp_connection_free);
	}
	
	// Release request
	request.release();
	
	// Return connection
	return connection;
}

// Perform requests
bool PriceOracle::performRequests() const {

	// Return if running event loop was successful
	return event_base_dispatch(eventBase.get()) != -1;
}
