// Header files
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <stdexcept>
#include <syncstream>
#include <unistd.h>
#include "./common.h"
#include "openssl/rand.h"
#include "./public_server.h"
#include "./tor_proxy.h"

using namespace std;


// Constants

// Check if Tor is enabled
#ifdef ENABLE_TOR

	// Data directory size
	static const size_t DATA_DIRECTORY_SIZE = 20;

	// Default Tor SOCKS proxy port
	static const char *DEFAULT_TOR_SOCKS_PROXY_PORT = "9050";
#endif


// Supporting function implementation

// Constructor
TorProxy::TorProxy(const unordered_map<char, const char *> &providedOptions, const Wallet &wallet) :

	// Set started
	started(false),
	
	// Set failed
	failed(false),
	
	// Create configuration
	configuration(tor_main_configuration_new(), tor_main_configuration_free)
{

	// Check if Tor is enabled
	#ifdef ENABLE_TOR
	
		// Display message
		osyncstream(cout) << "Starting Tor proxy" << endl;
		
		// Check if a Tor SOCKS proxy port is provided but not a Tor SOCKS proxy address
		if(providedOptions.contains('x') && !providedOptions.contains('s')) {
		
			// Throw exception
			throw runtime_error("No address provided for the Tor SOCKS proxy port");
		}
		
		// Check if Tor bridge is provided and so is a SOCKS proxy address
		if(providedOptions.contains('b') && providedOptions.contains('s')) {
		
			// Throw exception
			throw runtime_error("Tor bridge can't be used with an external Tor SOCKS proxy");
		}
		
		// Check if a Tor transport plugin is provided but not a Tor bridge
		if(providedOptions.contains('g') && !providedOptions.contains('b')) {
		
			// Throw exception
			throw runtime_error("No bridge provided for the Tor transport plugin");
		}
		
		// Check if Tor transport plugin is provided and so is a SOCKS proxy address
		if(providedOptions.contains('g') && providedOptions.contains('s')) {
		
			// Throw exception
			throw runtime_error("Tor transport plugin can't be used with an external Tor SOCKS proxy");
		}
		
		// Check if creating Onion Service and a SOCKS proxy address is provided
		if(providedOptions.contains('z') && providedOptions.contains('s')) {
		
			// Throw exception
			throw runtime_error("Onion Service can't be created when using an external Tor SOCKS proxy");
		}
		
		// Check if creating Onion Service and a public server certificate or key is provided
		if(providedOptions.contains('z') && (providedOptions.contains('t') || providedOptions.contains('y'))) {
		
			// Throw exception
			throw runtime_error("Onion Service can't be created when using a public server certificate or key");
		}
		
		// Check if a Tor SOCKS proxy address is provided
		if(providedOptions.contains('s')) {
			
			// Get Tor SOCKS proxy address from provided options
			const char *torSocksProxyAddress = providedOptions.at('s');
			
			// Display message
			osyncstream(cout) << "Using provided Tor SOCKS proxy address: " << torSocksProxyAddress << endl;
			
			// Get Tor SOCKS proxy port from provided options
			const char *torSocksProxyPort = providedOptions.contains('x') ? providedOptions.at('x') : DEFAULT_TOR_SOCKS_PROXY_PORT;
			
			// Check if a Tor SOCKS proxy port is provided
			if(providedOptions.contains('x')) {
			
				// Display message
				osyncstream(cout) << "Using provided Tor SOCKS proxy port: " << torSocksProxyPort << endl;
			}
			
			// Display message
			osyncstream(cout) << "Connecting to the Tor SOCKS proxy" << endl;
			
			// Set hints
			const addrinfo hints = {
			
				// Port provided
				.ai_flags = AI_NUMERICSERV,
			
				// IPv4 or IPv6
				.ai_family = AF_UNSPEC,
				
				// TCP
				.ai_socktype = SOCK_STREAM,
			};
			
			// Check if getting address info for the Tor SOCKS proxy failed
			addrinfo *addressInfo;
			if(getaddrinfo(torSocksProxyAddress, torSocksProxyPort, &hints, &addressInfo)) {
			
				// Throw exception
				throw runtime_error("Getting address info for the Tor SOCKS proxy failed");
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
			
			// Check if connecting to the Tor SOCKS proxy failed
			if(!connected) {
			
				// Throw exception
				throw runtime_error("Connecting to the Tor SOCKS proxy failed");
			}
			
			// Set SOCKS address and port
			socksAddress = torSocksProxyAddress;
			socksPort = torSocksProxyPort;
			
			// Display message
			osyncstream(cout) << "Connected to the Tor SOCKS proxy" << endl;
			
			// Display message
			osyncstream(cout) << "Tor proxy started" << endl;
		}
		
		// Otherwise
		else {
		
			// Check if creating configuration failed
			if(!configuration) {
			
				// Throw exception
				throw runtime_error("Creating Tor proxy configuration failed");
			}
			
			// Check if creating random data directory bytes failed
			uint8_t dataDirectoryBytes[DATA_DIRECTORY_SIZE / Common::HEX_CHARACTER_SIZE];
			if(RAND_bytes_ex(nullptr, dataDirectoryBytes, sizeof(dataDirectoryBytes), RAND_DRBG_STRENGTH) != 1) {
			
				// Throw exception
				throw runtime_error("Creating random Tor proxy data directory bytes failed");
			}
			
			// Try
			try {
			
				// Set data directory
				dataDirectory = filesystem::temp_directory_path() / Common::toHexString(dataDirectoryBytes, sizeof(dataDirectoryBytes));
			
				// Check if creating data directory failed
				if(!filesystem::create_directory(dataDirectory)) {
				
					// Throw exception
					throw runtime_error("Creating Tor proxy data directory failed");
				}
			}
			
			// Catch errors
			catch(...) {
			
				// Throw exception
				throw runtime_error("Creating Tor proxy data directory failed");
			}
			
			// Get Tor bridge from provided options
			const char *torBridge = providedOptions.contains('b') ? providedOptions.at('b') : nullptr;
			
			// Get Tor transport plugin from provided options
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
				
				// Check if a Tor bridge is provided
				if(torBridge) {
				
					// Display message
					osyncstream(cout) << "Using provided Tor bridge: " << torBridge << endl;
					
					// Add use bridge and bridge arguments to arguments
					arguments.push_back("UseBridges");
					arguments.push_back("1");
					arguments.push_back("Bridge");
					arguments.push_back(torBridge);
				}
				
				// Check if a Tor transport plugin is provided
				if(torTransportPlugin) {
				
					// Display message
					osyncstream(cout) << "Using provided Tor transport plugin: " << torTransportPlugin << endl;
					
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
				throw runtime_error("Setting Tor proxy arguments failed");
			}
			
			// Check if applying arguments failed
			if(tor_main_configuration_set_command_line(configuration.get(), arguments.size() - 1, const_cast<char **>(arguments.data()))) {
			
				// Remove data directory
				filesystem::remove(dataDirectory);
				
				// Throw exception
				throw runtime_error("Applying Tor proxy arguments failed");
			}
			
			// Check if getting control socket failed
			controlSocket = tor_main_configuration_setup_control_socket(configuration.get());
			if(controlSocket == INVALID_TOR_CONTROL_SOCKET) {
			
				// Remove data directory
				filesystem::remove(dataDirectory);
				
				// Throw exception
				throw runtime_error("Getting Tor proxy control socket failed");
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
				throw runtime_error("Creating Tor proxy main thread failed");
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
				osyncstream(cout) << "Sending authenticate request to Tor proxy failed" << endl;
				
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
				osyncstream(cout) << "Authenticating with Tor proxy failed" << endl;
				
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
				osyncstream(cout) << "Sending get SOCKS info request to Tor proxy failed" << endl;
				
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
				osyncstream(cout) << "Getting SOCKS info from Tor proxy failed" << endl;
				
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
				osyncstream(cout) << "Getting SOCKS info from Tor proxy failed" << endl;
				
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
			osyncstream(cout) << "Connecting to the Tor network" << flush;
			
			// While not connected
			for(int i = 0;; ++i) {
			
				// Check if a signal was received or sending get connection info request failed
				if(Common::getSignalReceived() || write(controlSocket, "GETINFO status/circuit-established\r\n", sizeof("GETINFO status/circuit-established\r\n") - sizeof('\0')) != sizeof("GETINFO status/circuit-established\r\n") - sizeof('\0')) {
				
					// Block signals
					Common::blockSignals();
					
					// Display message
					osyncstream(cout) << endl << "Sending get connection info request to Tor proxy failed" << endl;
					
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
					osyncstream(cout) << endl << "Getting connection info from Tor proxy failed" << endl;
					
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
			osyncstream(cout) << endl << "Connected to the Tor network" << endl;
			
			// Check if a creating an Onion Service
			if(providedOptions.contains('z')) {
			
				// Display message
				osyncstream(cout) << "Creating Onion Service" << endl;
				
				// Try
				string onionServicePrivateKey;
				string portMap;
				try {
				
					// Get wallet's Onion Service private key
					onionServicePrivateKey = wallet.getOnionServicePrivateKey();
					
					// Get public server address from provided options
					string publicServerAddress = providedOptions.contains('e') ? providedOptions.at('e') : PublicServer::DEFAULT_ADDRESS;
					
					// Check if public server address is an IPv6 address
					char temp[sizeof(in6_addr)];
					const bool isIpv6 = inet_pton(AF_INET6, publicServerAddress.c_str(), temp) == 1;
					if(isIpv6) {
					
						// Enclose public server address in brackets
						publicServerAddress = '[' + publicServerAddress + ']';
					}
					
					// Check if public server address is invalid
					if(!Common::isValidUtf8String(reinterpret_cast<const uint8_t *>(publicServerAddress.data()), publicServerAddress.size()) || strpbrk(publicServerAddress.c_str(), "=, \r\n") || (!isIpv6 && strchr(publicServerAddress.c_str(), ':'))) {
					
						// Securely clear Onion Service private key
						explicit_bzero(onionServicePrivateKey.data(), onionServicePrivateKey.capacity());
						
						// Block signals
						Common::blockSignals();
						
						// Display message
						osyncstream(cout) << "Creating Onion Service failed" << endl;
						
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
					
					// Get public server port from provided options
					const uint16_t publicServerPort = providedOptions.contains('o') ? strtoul(providedOptions.at('o'), nullptr, Common::DECIMAL_NUMBER_BASE) : PublicServer::DEFAULT_PORT;
					
					// Get port map for public server's port
					portMap = " Port=" + to_string(Common::HTTP_PORT) + ',' + publicServerAddress + ':' + to_string(publicServerPort) + "\r\n";
				}
				
				// Catch errors
				catch(...) {
				
					// Securely clear Onion Service private key
					explicit_bzero(onionServicePrivateKey.data(), onionServicePrivateKey.capacity());
					
					// Block signals
					Common::blockSignals();
					
					// Display message
					osyncstream(cout) << "Getting wallet's Onion Service private key failed" << endl;
					
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
				
				// Check if a signal was received or sending add Onion Service request failed
				if(Common::getSignalReceived() || write(controlSocket, "ADD_ONION ED25519-V3:", sizeof("ADD_ONION ED25519-V3:") - sizeof('\0')) != sizeof("ADD_ONION ED25519-V3:") - sizeof('\0') || write(controlSocket, onionServicePrivateKey.data(), onionServicePrivateKey.size()) != static_cast<ssize_t>(onionServicePrivateKey.size()) || write(controlSocket, portMap.data(), portMap.size()) != static_cast<ssize_t>(portMap.size())) {
				
					// Securely clear Onion Service private key
					explicit_bzero(onionServicePrivateKey.data(), onionServicePrivateKey.capacity());
					
					// Block signals
					Common::blockSignals();
					
					// Display message
					osyncstream(cout) << "Sending add Onion Service request to Tor proxy failed" << endl;
					
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
				
				// Securely clear Onion Service private key
				explicit_bzero(onionServicePrivateKey.data(), onionServicePrivateKey.capacity());
				
				// Try
				string onionServiceAddress;
				string expectedAddOnionServiceResponse;
				try {
				
					// Get wallet's Onion Service address
					onionServiceAddress = wallet.getOnionServiceAddress();
					
					// Set expected add Onion Service response failed
					expectedAddOnionServiceResponse = "250-ServiceID=" + onionServiceAddress + "\r\n250 OK\r\n";
				}
				
				// Catch errors
				catch(...) {
				
					// Block signals
					Common::blockSignals();
					
					// Display message
					osyncstream(cout) << "Getting wallet's Onion Service address failed" << endl;
					
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
				
				// Check if a signal was received or adding Onion Service failed
				uint8_t addOnionServiceResponse[expectedAddOnionServiceResponse.size()];
				if(Common::getSignalReceived() || read(controlSocket, addOnionServiceResponse, sizeof(addOnionServiceResponse)) != static_cast<ssize_t>(sizeof(addOnionServiceResponse)) || memcmp(addOnionServiceResponse, expectedAddOnionServiceResponse.data(), sizeof(addOnionServiceResponse))) {
				
					// Block signals
					Common::blockSignals();
					
					// Display message
					osyncstream(cout) << "Creating Onion Service failed" << endl;
					
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
				osyncstream(cout) << "Created Onion Service: http://" << onionServiceAddress << ".onion" << endl;
			}
			
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
					osyncstream(cout) << "Starting Tor proxy failed" << endl;
					
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
				osyncstream(cout) << "Starting Tor proxy failed" << endl;
				
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

	// Check if Tor is enabled
	#ifdef ENABLE_TOR
	
		// Display message
		osyncstream(cout) << "Closing Tor proxy" << endl;
		
		// Initialize error occurred
		bool errorOccurred = false;
		
		// Check if started
		if(started) {

			// Check if not failed
			if(!failed.load()) {
			
				// Check if sending quit request failed
				if(write(controlSocket, "QUIT\r\n", sizeof("QUIT\r\n") - sizeof('\0')) != sizeof("QUIT\r\n") - sizeof('\0')) {
				
					// Display message
					osyncstream(cout) << "Sending quit request to Tor proxy failed" << endl;
					
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
						osyncstream(cout) << "Quitting Tor proxy failed" << endl;
						
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
				osyncstream(cout) << "Waiting for Tor proxy to finish failed" << endl;
				
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
				osyncstream(cout) << "Closing Tor proxy control socket failed" << endl;
				
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
				osyncstream(cout) << "Removing Tor proxy data directory failed" << endl;
				
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
	
		// Check if Tor is enabled
		#ifdef ENABLE_TOR
		
			// Tor SOCKS proxy address
			{"tor_socks_proxy_address", required_argument, nullptr, 's'},
			
			// Tor SOCKS proxy port
			{"tor_socks_proxy_port", required_argument, nullptr, 'x'},
			
			// Tor bridge
			{"tor_bridge", required_argument, nullptr, 'b'},
			
			// Tor transport plugin
			{"tor_transport_plugin", required_argument, nullptr, 'g'},
			
			// Tor create Onion Service
			{"tor_create_onion_service", no_argument, nullptr, 'z'}
		#endif
	};
}

// Display options help
void TorProxy::displayOptionsHelp() {

	// Check if Tor is enabled
	#ifdef ENABLE_TOR
	
		// Display message
		cout << "\t-s, --tor_socks_proxy_address\tSets the external Tor SOCKS proxy address to use instead of the built-in one (example: localhost)" << endl;
		cout << "\t-x, --tor_socks_proxy_port\tSets the port to use for the external Tor SOCKS proxy address (default: " << DEFAULT_TOR_SOCKS_PROXY_PORT << ')' << endl;
		cout << "\t-b, --tor_bridge\t\tSets the bridge to use for relaying into the Tor network (example: obfs4 1.2.3.4:12345)" << endl;
		cout << "\t-g, --tor_transport_plugin\tSets the transport plugin to use to forward traffic to the bridge (example: obfs4 exec /usr/bin/obfs4proxy)" << endl;
		cout << "\t-z, --tor_create_onion_service\tCreates an Onion Service that provides access to the public server API" << endl;
	#endif
}

// Validate option
bool TorProxy::validateOption(const char option, const char *value, char *argv[]) {

	// Check if Tor is enabled
	#ifdef ENABLE_TOR
	
		// Check option
		switch(option) {
		
			// Tor SOCKS proxy address
			case 's':
			
				// Check if Tor SOCKS proxy address is invalid
				if(!value || !strlen(value)) {
				
					// Display message
					cout << argv[0] << ": invalid Tor SOCKS proxy address -- '" << (value ? value : "") << '\'' << endl;
			
					// Return false
					return false;
				}
				
				// Break
				break;
			
			// Tor SOCKS proxy port
			case 'x': {
			
				// Check if Tor SOCKS proxy port is invalid
				char *end;
				errno = 0;
				const unsigned long port = value ? strtoul(value, &end, Common::DECIMAL_NUMBER_BASE) : 0;
				if(!value || end == value || *end || !isdigit(value[0]) || (value[0] == '0' && isdigit(value[1])) || errno || !port || port > numeric_limits<uint16_t>::max()) {
				
					// Display message
					cout << argv[0] << ": invalid Tor SOCKS proxy port -- '" << (value ? value : "") << '\'' << endl;
			
					// Return false
					return false;
				}
				
				// Break
				break;
			}
			
			// Tor bridge
			case 'b':
			
				// Check if Tor bridge is invalid
				if(!value || !strlen(value)) {
				
					// Display message
					cout << argv[0] << ": invalid Tor bridge -- '" << (value ? value : "") << '\'' << endl;
			
					// Return false
					return false;
				}
				
				// Break
				break;
			
			// Tor transport plugin
			case 'g':
			
				// Check if Tor transport plugin is invalid
				if(!value || !strlen(value)) {
				
					// Display message
					cout << argv[0] << ": invalid Tor transport plugin -- '" << (value ? value : "") << '\'' << endl;
			
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

	// Check if running Tor failed
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
