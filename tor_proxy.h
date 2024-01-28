// Header guard
#ifndef TOR_PROXY_H
#define TOR_PROXY_H


// Header files
#include <atomic>
#include <filesystem>
#include <getopt.h>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>
#include "./wallet.h"

// Extern C
extern "C" {

	// Header files
	#include "tor_api.h"
}

using namespace std;


// Classes

// Tor proxy class
class TorProxy final {

	// Public
	public:
	
		// Constructor
		explicit TorProxy(const unordered_map<char, const char *> &providedOptions, const Wallet &wallet);
		
		// Destructr
		~TorProxy();
		
		// Get SOCKS address
		const string &getSocksAddress() const;
		
		// Get SOCKS port
		const string &getSocksPort() const;
		
		// Get options
		static vector<option> getOptions();
		
		// Display options help
		static void displayOptionsHelp();
		
		// Validate option
		static bool validateOption(const char option, const char *value, char *argv[]);
	
	// Private
	private:
	
		// Run
		void run();
		
		// Started
		bool started;
		
		// Started lock
		mutex startedLock;
		
		// Failed
		atomic_bool failed;
		
		// Configuration
		const unique_ptr<tor_main_configuration_t, decltype(&tor_main_configuration_free)> configuration;
		
		// Data directory
		filesystem::path dataDirectory;
		
		// Arguments
		vector<const char *> arguments;
		
		// Control socket
		tor_control_socket_t controlSocket;
		
		// SOCKS address
		string socksAddress;
		
		// SOCKS port
		string socksPort;
		
		// Main thread
		thread mainThread;
};


#endif
