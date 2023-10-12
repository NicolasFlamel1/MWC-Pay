// Header files
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <stdexcept>
#include <syncstream>
#include <unistd.h>
#include "./common.h"
#include "openssl/rand.h"
#include "./tor_proxy.h"

using namespace std;


// Constants

// Check if tor is enabled
#ifdef TOR_ENABLE

	// Data directory size
	static const size_t DATA_DIRECTORY_SIZE = 20;

	// Default tor SOCKS proxy port
	static const char *DEFAULT_TOR_SOCKS_PROXY_PORT = "9050";
#endif


// Supporting function implementation

// Constructor
TorProxy::TorProxy(const unordered_map<char, const char *> &providedOptions) :

	// Set started
	started(false),
	
	// Set failed
	failed(false),
	
	// Create configuration
	configuration(tor_main_configuration_new(), tor_main_configuration_free)
{

	// Check if tor is enabled
	#ifdef TOR_ENABLE
	
		// Display message
		osyncstream(cout) << "Starting tor proxy" << endl;
		
		// Check if a tor SOCKS proxy port is provided but not a tor SOCKS proxy address
		if(providedOptions.contains('x') && !providedOptions.contains('s')) {
		
			// Throw exception
			throw runtime_error("No address provided for the tor SOCKS proxy port");
		}
		
		// Check if tor bridge is provided and so is a SOCKS proxy address
		if(providedOptions.contains('b') && providedOptions.contains('s')) {
		
			// Throw exception
			throw runtime_error("Tor bridge can't be used with an external tor SOCKS proxy");
		}
		
		// Check if a tor transport plugin is provided but not a tor bridge
		if(providedOptions.contains('g') && !providedOptions.contains('b')) {
		
			// Throw exception
			throw runtime_error("No bridge provided for the tor transport plugin");
		}
		
		// Check if tor transport plugin is provided and so is a SOCKS proxy address
		if(providedOptions.contains('g') && providedOptions.contains('s')) {
		
			// Throw exception
			throw runtime_error("Tor transport plugin can't be used with an external tor SOCKS proxy");
		}
		
		// Check if a tor SOCKS proxy address is provided
		if(providedOptions.contains('s')) {
			
			// Get tor SOCKS proxy address from provided options
			const char *torSocksProxyAddress = providedOptions.at('s');
			
			// Display message
			osyncstream(cout) << "Using provided tor SOCKS proxy address: " << torSocksProxyAddress << endl;
			
			// Get tor SOCKS proxy port from provided options
			const char *torSocksProxyPort = providedOptions.contains('x') ? providedOptions.at('x') : DEFAULT_TOR_SOCKS_PROXY_PORT;
			
			// Check if a tor SOCKS proxy port is provided
			if(providedOptions.contains('x')) {
			
				// Display message
				osyncstream(cout) << "Using provided tor SOCKS proxy port: " << torSocksProxyPort << endl;
			}
			
			// Display message
			osyncstream(cout) << "Connecting to the tor SOCKS proxy" << endl;
			
			// Set hints
			const addrinfo hints = {
			
				// Port provided
				.ai_flags = AI_NUMERICSERV,
			
				// IPv4 or IPv6
				.ai_family = AF_UNSPEC,
				
				// TCP
				.ai_socktype = SOCK_STREAM,
			};
			
			// Check if getting address info for the tor SOCKS proxy failed
			addrinfo *addressInfo;
			if(getaddrinfo(torSocksProxyAddress, torSocksProxyPort, &hints, &addressInfo)) {
			
				// Throw exception
				throw runtime_error("Getting address info for the tor SOCKS proxy failed");
			}
			
			// Automatically free address info when done
			const unique_ptr<addrinfo, decltype(&freeaddrinfo)> addressInfoUniquePointer(addressInfo, freeaddrinfo);
			
			// Go through all servers in the address info
			bool connected = false;
			for(const addrinfo *server = addressInfo; server; server = server->ai_next) {
			
				// Check if creating socket descriptor for the server was successful
				const int socketDescriptor = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
				if(socketDescriptor != -1) {
				
					// Check if connecting to the socket descriptor was successful
					if(!connect(socketDescriptor, server->ai_addr, server->ai_addrlen)) {
					
						// Shutdown socket descriptor receive and send
						shutdown(socketDescriptor, SHUT_RDWR);
						
						// Check if closing socket descriptor failed
						if(close(socketDescriptor)) {
						
							// Throw exception
							throw runtime_error("Closing socket descriptor failed");
						}
						
						// Set connected
						connected = true;
						
						// Break
						break;
					}
					
					// Otherwise
					else {
					
						// Shutdown socket descriptor receive and send
						shutdown(socketDescriptor, SHUT_RDWR);
						
						// Check if closing socket descriptor failed
						if(close(socketDescriptor)) {
					
							// Throw exception
							throw runtime_error("Closing socket descriptor failed");
						}
					}
				}
			}
			
			// Check if connecting to the tor SOCKS proxy failed
			if(!connected) {
			
				// Throw exception
				throw runtime_error("Connecting to the tor SOCKS proxy failed");
			}
			
			// Set SOCKS address and port
			socksAddress = torSocksProxyAddress;
			socksPort = torSocksProxyPort;
			
			// Display message
			osyncstream(cout) << "Connected to the tor SOCKS proxy" << endl;
			
			// Display message
			osyncstream(cout) << "Tor proxy started" << endl;
		}
		
		// Otherwise
		else {
		
			// Check if creating configuration failed
			if(!configuration) {
			
				// Throw exception
				throw runtime_error("Creating tor proxy configuration failed");
			}
			
			// Check if creating random data directory bytes failed
			uint8_t dataDirectoryBytes[DATA_DIRECTORY_SIZE / Common::HEX_CHARACTER_SIZE];
			if(RAND_bytes_ex(nullptr, dataDirectoryBytes, sizeof(dataDirectoryBytes), RAND_DRBG_STRENGTH) != 1) {
			
				// Throw exception
				throw runtime_error("Creating random tor proxy data directory bytes failed");
			}
			
			// Try
			try {
			
				// Set data directory
				dataDirectory = filesystem::temp_directory_path() / Common::toHexString(dataDirectoryBytes, sizeof(dataDirectoryBytes));
			
				// Check if creating data directory failed
				if(!filesystem::create_directory(dataDirectory)) {
				
					// Throw exception
					throw runtime_error("Creating tor proxy data directory failed");
				}
			}
			
			// Catch errors
			catch(...) {
			
				// Throw exception
				throw runtime_error("Creating tor proxy data directory failed");
			}
			
			// Get tor bridge from provided options
			const char *torBridge = providedOptions.contains('b') ? providedOptions.at('b') : nullptr;
			
			// Get tor transport plugin from provided options
			const char *torTransportPlugin = providedOptions.contains('g') ? providedOptions.at('g') : nullptr;
			
			// Try
			try {
			
				// Set arguments
				arguments = {
				
					// Program name
					"",
					
					// Quiet
					"--quiet",
					
					// Automatic SOCKS port
					"--SocksPort", "auto",
					
					// SOCKS policy to prevent non-localhost from connecting
					"--SocksPolicy", "accept 127.0.0.1, reject *4, accept6 [::1], reject6 *6, reject *:*",
					
					// Disable Geo IPv4
					"--GeoIPFile", "",
					
					// Disable Geo IPv6
					"--GeoIPv6File", "",
					
					// Disable configuration file
					"--torrc-file", "",
					
					// Ignore missing configuration file
					"--ignore-missing-torrc",
					
					// Data directory
					"--DataDirectory", dataDirectory.c_str(),
					
					// Disable signal handlers
					"__DisableSignalHandlers", "1"
				};
				
				// Check if a tor bridge is provided
				if(torBridge) {
				
					// Display message
					osyncstream(cout) << "Using provided tor bridge: " << torBridge << endl;
					
					// Add use bridge and bridge arguments to arguments
					arguments.push_back("UseBridges");
					arguments.push_back("1");
					arguments.push_back("Bridge");
					arguments.push_back(torBridge);
				}
				
				// Check if a tor transport plugin is provided
				if(torTransportPlugin) {
				
					// Display message
					osyncstream(cout) << "Using provided tor transport plugin: " << torTransportPlugin << endl;
					
					// Add client transport plugin arguments to arguments
					arguments.push_back("ClientTransportPlugin");
					arguments.push_back(torTransportPlugin);
				}
				
				// Add end of arguments to arguments
				arguments.push_back(nullptr);
			}
			
			// Catch errors
			catch(...) {
			
				// Remove data directory
				filesystem::remove(dataDirectory);
				
				// Throw exception
				throw runtime_error("Setting tor proxy arguments failed");
			}
			
			// Check if applying arguments failed
			if(tor_main_configuration_set_command_line(configuration.get(), arguments.size() - 1, const_cast<char **>(arguments.data()))) {
			
				// Remove data directory
				filesystem::remove(dataDirectory);
				
				// Throw exception
				throw runtime_error("Applying tor proxy arguments failed");
			}
			
			// Check if getting control socket failed
			controlSocket = tor_main_configuration_setup_control_socket(configuration.get());
			if(controlSocket == INVALID_TOR_CONTROL_SOCKET) {
			
				// Remove data directory
				filesystem::remove(dataDirectory);
				
				// Throw exception
				throw runtime_error("Getting tor proxy control socket failed");
			}
			
			// Try
			try {
			
				// Create main thread
				mainThread = thread(&TorProxy::run, this);
			}
			
			// Catch errors
			catch(...) {
			
				// Close control socket
				close(controlSocket);
				
				// Remove data directory
				filesystem::remove(dataDirectory);
				
				// Throw exception
				throw runtime_error("Creating tor proxy main thread failed");
			}
			
			// Check if main thread is invalid
			if(!mainThread.joinable()) {
			
				// Display message
				osyncstream(cout) << "Tor proxy main thread is invalid" << endl;
				
				// Close control socket
				close(controlSocket);
				
				// Try
				try {
			
					// Remove data directory
					filesystem::remove_all(dataDirectory);
				}
				
				// Catch errors
				catch(...) {
				
				}
				
				// Exit failure
				exit(EXIT_FAILURE);
			}
			
			// Check if a signal was received or sending authenticate request failed
			if(!Common::allowSignals() || Common::getSignalReceived() || write(controlSocket, "AUTHENTICATE \"\"\r\n", sizeof("AUTHENTICATE \"\"\r\n") - sizeof('\0')) != sizeof("AUTHENTICATE \"\"\r\n") - sizeof('\0')) {
			
				// Block signals
				Common::blockSignals();
				
				// Display message
				osyncstream(cout) << "Sending authenticate request to tor proxy failed" << endl;
				
				// Check if closing control socket was successful
				if(!close(controlSocket)) {
				
					// Try
					try {
					
						// Wait for main thread to finish
						mainThread.join();
					}
					
					// Catch errors
					catch(...) {
					
					}
				}
				
				// Try
				try {
			
					// Remove data directory
					filesystem::remove_all(dataDirectory);
				}
				
				// Catch errors
				catch(...) {
				
				}
				
				// Exit failure
				exit(EXIT_FAILURE);
			}
			
			// Check if a signal was received or authenticating failed
			uint8_t authenticateResponse[sizeof("250 OK\r\n") - sizeof('\0')];
			if(Common::getSignalReceived() || read(controlSocket, authenticateResponse, sizeof(authenticateResponse)) != sizeof(authenticateResponse) || memcmp(authenticateResponse, "250 OK\r\n", sizeof("250 OK\r\n") - sizeof('\0'))) {
			
				// Block signals
				Common::blockSignals();
				
				// Display message
				osyncstream(cout) << "Authenticating with tor proxy failed" << endl;
				
				// Check if closing control socket was successful
				if(!close(controlSocket)) {
				
					// Try
					try {
					
						// Wait for main thread to finish
						mainThread.join();
					}
					
					// Catch errors
					catch(...) {
					
					}
				}
				
				// Try
				try {
			
					// Remove data directory
					filesystem::remove_all(dataDirectory);
				}
				
				// Catch errors
				catch(...) {
				
				}
				
				// Exit failure
				exit(EXIT_FAILURE);
			}
			
			// Check if a signal was received or sending get SOCKS info request failed
			if(Common::getSignalReceived() || write(controlSocket, "GETINFO net/listeners/socks\r\n", sizeof("GETINFO net/listeners/socks\r\n") - sizeof('\0')) != sizeof("GETINFO net/listeners/socks\r\n") - sizeof('\0')) {
			
				// Block signals
				Common::blockSignals();
				
				// Display message
				osyncstream(cout) << "Sending get SOCKS info request to tor proxy failed" << endl;
				
				// Check if closing control socket was successful
				if(!close(controlSocket)) {
				
					// Try
					try {
					
						// Wait for main thread to finish
						mainThread.join();
					}
					
					// Catch errors
					catch(...) {
					
					}
				}
				
				// Try
				try {
			
					// Remove data directory
					filesystem::remove_all(dataDirectory);
				}
				
				// Catch errors
				catch(...) {
				
				}
				
				// Exit failure
				exit(EXIT_FAILURE);
			}
			
			// Check if a signal was received or getting SOCKS info failed
			uint8_t getSocksInfoResponse[sizeof("250-net/listeners/socks=\"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:65535\"\r\n250 OK\r\n") - sizeof('\0')];
			ssize_t getSocksInfoResponseLength;
			if(Common::getSignalReceived() || (getSocksInfoResponseLength = read(controlSocket, getSocksInfoResponse, sizeof(getSocksInfoResponse))) <= static_cast<ssize_t>(sizeof("250-net/listeners/socks=\"\"\r\n250 OK\r\n") - sizeof('\0')) || memcmp(getSocksInfoResponse, "250-net/listeners/socks=\"", sizeof("250-net/listeners/socks=\"") - sizeof('\0')) || memcmp(&getSocksInfoResponse[getSocksInfoResponseLength - (sizeof("\"\r\n250 OK\r\n") - sizeof('\0'))], "\"\r\n250 OK\r\n", sizeof("\"\r\n250 OK\r\n") - sizeof('\0'))) {
			
				// Block signals
				Common::blockSignals();
				
				// Display message
				osyncstream(cout) << "Getting SOCKS info from tor proxy failed" << endl;
				
				// Check if closing control socket was successful
				if(!close(controlSocket)) {
				
					// Try
					try {
					
						// Wait for main thread to finish
						mainThread.join();
					}
					
					// Catch errors
					catch(...) {
					
					}
				}
				
				// Try
				try {
			
					// Remove data directory
					filesystem::remove_all(dataDirectory);
				}
				
				// Catch errors
				catch(...) {
				
				}
				
				// Exit failure
				exit(EXIT_FAILURE);
			}
			
			// Check if getting port index in SOCKS info failed
			const uint8_t *portIndex = reinterpret_cast<const uint8_t *>(memrchr(getSocksInfoResponse + (sizeof("250-net/listeners/socks=\"") - sizeof('\0')), ':', getSocksInfoResponseLength - (sizeof("250-net/listeners/socks=\"\"\r\n250 OK\r\n") - sizeof('\0'))));
			if(!portIndex) {
			
				// Block signals
				Common::blockSignals();
				
				// Display message
				osyncstream(cout) << "Getting SOCKS info from tor proxy failed" << endl;
				
				// Check if closing control socket was successful
				if(!close(controlSocket)) {
				
					// Try
					try {
					
						// Wait for main thread to finish
						mainThread.join();
					}
					
					// Catch errors
					catch(...) {
					
					}
				}
				
				// Try
				try {
			
					// Remove data directory
					filesystem::remove_all(dataDirectory);
				}
				
				// Catch errors
				catch(...) {
				
				}
				
				// Exit failure
				exit(EXIT_FAILURE);
			}
			
			// Set SOCKS address and port
			socksAddress = string(reinterpret_cast<const uint8_t *>(getSocksInfoResponse) + (sizeof("250-net/listeners/socks=\"") - sizeof('\0')), portIndex);
			socksPort = string(portIndex + sizeof(':'), reinterpret_cast<const uint8_t *>(getSocksInfoResponse) + getSocksInfoResponseLength - (sizeof("\"\r\n250 OK\r\n") - sizeof('\0')));
			
			// Check if SOCKS address is enclosed in brackets
			if(socksAddress.front() == '[' && socksAddress.back() == ']') {
			
				// Remove enclosing brackets from SOCKS address
				socksAddress = socksAddress.substr(sizeof('['), socksAddress.size() - sizeof('[') - sizeof(']'));
			}
			
			// Display message
			osyncstream(cout) << "Connecting to the tor network" << flush;
			
			// While not connected
			for(int i = 0;; ++i) {
			
				// Check if a signal was received or sending get connection info request failed
				if(Common::getSignalReceived() || write(controlSocket, "GETINFO status/circuit-established\r\n", sizeof("GETINFO status/circuit-established\r\n") - sizeof('\0')) != sizeof("GETINFO status/circuit-established\r\n") - sizeof('\0')) {
				
					// Block signals
					Common::blockSignals();
					
					// Display message
					osyncstream(cout) << endl << "Sending get connection info request to tor proxy failed" << endl;
					
					// Check if closing control socket was successful
					if(!close(controlSocket)) {
					
						// Try
						try {
						
							// Wait for main thread to finish
							mainThread.join();
						}
						
						// Catch errors
						catch(...) {
						
						}
					}
					
					// Try
					try {
				
						// Remove data directory
						filesystem::remove_all(dataDirectory);
					}
					
					// Catch errors
					catch(...) {
					
					}
					
					// Exit failure
					exit(EXIT_FAILURE);
				}
				
				// Check if a signal was received or getting connection info failed
				uint8_t getConnectionInfoResponse[sizeof("250-status/circuit-established=0\r\n250 OK\r\n") - sizeof('\0')];
				if(Common::getSignalReceived() || read(controlSocket, getConnectionInfoResponse, sizeof(getConnectionInfoResponse)) != sizeof(getConnectionInfoResponse) || (memcmp(getConnectionInfoResponse, "250-status/circuit-established=0\r\n250 OK\r\n", sizeof("250-status/circuit-established=0\r\n250 OK\r\n") - sizeof('\0')) && memcmp(getConnectionInfoResponse, "250-status/circuit-established=1\r\n250 OK\r\n", sizeof("250-status/circuit-established=1\r\n250 OK\r\n") - sizeof('\0')))) {
				
					// Block signals
					Common::blockSignals();
					
					// Display message
					osyncstream(cout) << endl << "Getting connection info from tor proxy failed" << endl;
					
					// Check if closing control socket was successful
					if(!close(controlSocket)) {
					
						// Try
						try {
						
							// Wait for main thread to finish
							mainThread.join();
						}
						
						// Catch errors
						catch(...) {
						
						}
					}
					
					// Try
					try {
				
						// Remove data directory
						filesystem::remove_all(dataDirectory);
					}
					
					// Catch errors
					catch(...) {
					
					}
					
					// Exit failure
					exit(EXIT_FAILURE);
				}
				
				// Check if connected
				if(!memcmp(getConnectionInfoResponse, "250-status/circuit-established=1\r\n250 OK\r\n", sizeof("250-status/circuit-established=1\r\n250 OK\r\n") - sizeof('\0'))) {
				
					// Break
					break;
				}
				
				// Check if time to show progress
				if(i && i % 3 == 0) {
				
					// Display message
					osyncstream(cout) << '.' << flush;
				}
				
				// Sleep
				sleep(1);
			}
			
			// Display message
			osyncstream(cout) << endl << "Connected to the tor network" << endl;
			
			// Try
			try {
			
				// Lock started
				lock_guard guard(startedLock);
				
				// Set started
				started = true;
				
				// Check if a signal was received or failed
				if(!Common::blockSignals() || Common::getSignalReceived() || failed.load()) {
				
					// Block signals
					Common::blockSignals();
					
					// Display message
					osyncstream(cout) << "Starting tor proxy failed" << endl;
					
					// Check if closing control socket was successful
					if(!close(controlSocket)) {
					
						// Try
						try {
						
							// Wait for main thread to finish
							mainThread.join();
						}
						
						// Catch errors
						catch(...) {
						
						}
					}
					
					// Try
					try {
				
						// Remove data directory
						filesystem::remove_all(dataDirectory);
					}
					
					// Catch errors
					catch(...) {
					
					}
					
					// Exit failure
					exit(EXIT_FAILURE);
				}
				
				// Display message
				osyncstream(cout) << "Tor proxy started" << endl;
			}
			
			// Catch errors
			catch(...) {
			
				// Block signals
				Common::blockSignals();
				
				// Display message
				osyncstream(cout) << "Starting tor proxy failed" << endl;
				
				// Check if closing control socket was successful
				if(!close(controlSocket)) {
				
					// Try
					try {
					
						// Wait for main thread to finish
						mainThread.join();
					}
					
					// Catch errors
					catch(...) {
					
					}
				}
				
				// Try
				try {
			
					// Remove data directory
					filesystem::remove_all(dataDirectory);
				}
				
				// Catch errors
				catch(...) {
				
				}
				
				// Exit failure
				exit(EXIT_FAILURE);
			}
		}
	#endif
}

// Destructor
TorProxy::~TorProxy() {

	// Check if tor is enabled
	#ifdef TOR_ENABLE
	
		// Display message
		osyncstream(cout) << "Closing tor proxy" << endl;
		
		// Initialize error occurred
		bool errorOccurred = false;
		
		// Check if started
		if(started) {

			// Check if not failed
			if(!failed.load()) {
			
				// Check if sending quit request failed
				if(write(controlSocket, "QUIT\r\n", sizeof("QUIT\r\n") - sizeof('\0')) != sizeof("QUIT\r\n") - sizeof('\0')) {
				
					// Display message
					osyncstream(cout) << "Sending quit request to tor proxy failed" << endl;
					
					// Check if closing control socket was successful
					if(!close(controlSocket)) {
					
						// Try
						try {
						
							// Wait for main thread to finish
							mainThread.join();
						}
						
						// Catch errors
						catch(...) {
						
						}
					}
					
					// Try
					try {

						// Remove data directory
						filesystem::remove_all(dataDirectory);
					}
					
					// Catch errors
					catch(...) {
					
					}
					
					// Exit failure
					exit(EXIT_FAILURE);
				}
				
				// Check if not failed
				if(!failed.load()) {
				
					// Check if quit failed
					uint8_t quitResponse[sizeof("250 closing connection\r\n") - sizeof('\0')];
					if(read(controlSocket, quitResponse, sizeof(quitResponse)) != sizeof(quitResponse) || memcmp(quitResponse, "250 closing connection\r\n", sizeof("250 closing connection\r\n") - sizeof('\0'))) {
					
						// Display message
						osyncstream(cout) << "Quitting tor proxy failed" << endl;
						
						// Check if closing control socket was successful
						if(!close(controlSocket)) {
						
							// Try
							try {
							
								// Wait for main thread to finish
								mainThread.join();
							}
							
							// Catch errors
							catch(...) {
							
							}
						}
						
						// Try
						try {

							// Remove data directory
							filesystem::remove_all(dataDirectory);
						}
						
						// Catch errors
						catch(...) {
						
						}
						
						// Exit failure
						exit(EXIT_FAILURE);
					}
				}
			}
			
			// Try
			try {

				// Wait for main thread to finish
				mainThread.join();
			}

			// Catch errors
			catch(...) {
			
				// Display message
				osyncstream(cout) << "Waiting for tor proxy to finish failed" << endl;
				
				// Close control socket
				close(controlSocket);
				
				// Try
				try {

					// Remove data directory
					filesystem::remove_all(dataDirectory);
				}
				
				// Catch errors
				catch(...) {
				
				}
				
				// Exit failure
				exit(EXIT_FAILURE);
			}
			
			// Check if closing control socket failed
			if(close(controlSocket)) {
			
				// Display message
				osyncstream(cout) << "Closing tor proxy control socket failed" << endl;
				
				// Set error occurred
				errorOccurred = true;
				
				// Set error occurred
				Common::setErrorOccurred();
			}
			
			// Try
			try {

				// Remove data directory
				filesystem::remove_all(dataDirectory);
			}
			
			// Catch errors
			catch(...) {
			
				// Display message
				osyncstream(cout) << "Removing tor proxy data directory failed" << endl;
				
				// Set error occurred
				errorOccurred = true;
				
				// Set error occurred
				Common::setErrorOccurred();
			}
		}
		
		// Check if an error didn't occur
		if(!errorOccurred) {
		
			// Display message
			osyncstream(cout) << "Tor proxy closed" << endl;
		}
	#endif
}

// Get SOCKS address
const string &TorProxy::getSocksAddress() const {

	// Return SOCKS address
	return socksAddress;
}

// Get SOCKS port
const string &TorProxy::getSocksPort() const {

	// Return SOCKS port
	return socksPort;
}

// Get options
vector<option> TorProxy::getOptions() {

	// Return options
	return {
	
		// Check if tor is enabled
		#ifdef TOR_ENABLE
		
			// Tor SOCKS proxy address
			{"tor_socks_proxy_address", required_argument, nullptr, 's'},
			
			// Tor SOCKS proxy port
			{"tor_socks_proxy_port", required_argument, nullptr, 'x'},
			
			// Tor bridge
			{"tor_bridge", required_argument, nullptr, 'b'},
			
			// Tor transport plugin
			{"tor_transport_plugin", required_argument, nullptr, 'g'}
		#endif
	};
}

// Display options help
void TorProxy::displayOptionsHelp() {

	// Check if tor is enabled
	#ifdef TOR_ENABLE
	
		// Display message
		cout << "\t-s, --tor_socks_proxy_address\tSets the external tor SOCKS proxy address to use instead of the built-in one (example: localhost)" << endl;
		cout << "\t-x, --tor_socks_proxy_port\tSets the port to use for the external tor SOCKS proxy address (default: " << DEFAULT_TOR_SOCKS_PROXY_PORT << ')' << endl;
		cout << "\t-b, --tor_bridge\t\tSets the bridge to use for relaying into the tor network (example: obfs4 1.2.3.4:12345)" << endl;
		cout << "\t-g, --tor_transport_plugin\tSets the transport plugin to use to forward traffic to the bridge (example: obfs4 exec /usr/bin/obfs4proxy)" << endl;
	#endif
}

// Validate option
bool TorProxy::validateOption(const char option, const char *value, char *argv[]) {

	// Check if tor is enabled
	#ifdef TOR_ENABLE
	
		// Check option
		switch(option) {
		
			// Tor SOCKS proxy address
			case 's':
			
				// Check if tor SOCKS proxy address is invalid
				if(!value || !strlen(value)) {
				
					// Display message
					cout << argv[0] << ": invalid tor SOCKS proxy address -- '" << (value ? value : "") << '\'' << endl;
			
					// Return false
					return false;
				}
				
				// Break
				break;
			
			// Tor SOCKS proxy port
			case 'x': {
			
				// Check if tor SOCKS proxy port is invalid
				char *end;
				errno = 0;
				const unsigned long port = value ? strtoul(value, &end, Common::DECIMAL_NUMBER_BASE) : 0;
				if(!value || end == value || *end || !isdigit(value[0]) || (value[0] == '0' && isdigit(value[1])) || errno || !port || port > numeric_limits<uint16_t>::max()) {
				
					// Display message
					cout << argv[0] << ": invalid tor SOCKS proxy port -- '" << (value ? value : "") << '\'' << endl;
			
					// Return false
					return false;
				}
				
				// Break
				break;
			}
			
			// Tor bridge
			case 'b':
			
				// Check if tor bridge is invalid
				if(!value || !strlen(value)) {
				
					// Display message
					cout << argv[0] << ": invalid tor bridge -- '" << (value ? value : "") << '\'' << endl;
			
					// Return false
					return false;
				}
				
				// Break
				break;
			
			// Tor transport plugin
			case 'g':
			
				// Check if tor transport plugin is invalid
				if(!value || !strlen(value)) {
				
					// Display message
					cout << argv[0] << ": invalid tor transport plugin -- '" << (value ? value : "") << '\'' << endl;
			
					// Return false
					return false;
				}
				
				// Break
				break;
		}
	#endif
	
	// Return true
	return true;
}

// Run
void TorProxy::run() {

	// Check if running tor failed
	if(tor_run_main(configuration.get())) {
	
		// Try
		try {
	
			// Lock started
			lock_guard guard(startedLock);
			
			// Set failed
			failed.store(true);
			
			// Check if started
			if(started) {
			
				// Display message
				osyncstream(cout) << "Tor proxy failed for unknown reason" << endl;
			
				// Set error occurred
				Common::setErrorOccurred();
			}
				
			// Raise interrupt signal
			kill(getpid(), SIGINT);
		}
		
		// Catch errors
		catch(...) {
		
			// Set failed
			failed.store(true);
			
			// Display message
			osyncstream(cout) << "Tor proxy failed for unknown reason" << endl;
		
			// Set error occurred
			Common::setErrorOccurred();
				
			// Raise interrupt signal
			kill(getpid(), SIGINT);
		}
	}
}
