// Header files
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <getopt.h>
#include <iostream>
#include <memory>
#include <pwd.h>
#include <signal.h>
#include <syncstream>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include "./common.h"
#include "event2/event.h"
#include "./expired_monitor.h"
#include "./node.h"
#include "./payments.h"
#include "./price.h"
#include "./private_server.h"
#include "./public_server.h"
#include "sqlite3.h"
#include "./tor_proxy.h"
#include "./wallet.h"

using namespace std;


// Definitions

// To string
#undef STRINGIFY
#undef TOSTRING
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)


// Constants

// Default application directory
static const char *DEFAULT_APPLICATION_DIRECTORY = ".mwc_pay";

// Database file
static const char *DATABASE_FILE = "database.db";

// Lock file
static const char *LOCK_FILE = "directory.lock";


// Classes

// Clear argv class
class ClearArgv {

	// Public
	public:

		// Constructor
		explicit ClearArgv(const int argc, char *argv[]);
		
		// Destructor
		~ClearArgv();
	
	// Private
	private:
	
		// Argc
		const int argc;
		
		// Argv
		char **argv;
};


// Function prototypes

// Display options help
static void displayOptionsHelp(char *argv[]);

// Go to application directory
static bool goToApplicationDirectory(const unordered_map<char, const char *> &providedOptions);

// Exit handler
static void exitHandler(const evutil_socket_t fileDescriptor, const short signal, void *argument);


// Main function
int main(int argc, char *argv[]) {

	// Display message
	cout << TOSTRING(PROGRAM_NAME) << " v" << TOSTRING(PROGRAM_VERSION) << endl;
	
	// Try
	try {
	
		// Automatically clear argv
		static const ClearArgv clearArgv(argc, argv);
		
		// Set options
		vector<option> options({
		
			// Version
			{"version", no_argument, nullptr, 'v'},
			
			// Directory
			{"directory", required_argument, nullptr, 'd'},
			
			// Password
			{"password", required_argument, nullptr, 'w'},
			
			// "Recovery passphrase
			{"recovery_passphrase", no_argument, nullptr, 'r'},
			
			// Root public key
			{"root_public_key", no_argument, nullptr, 'u'},
			
			// Show completed payments
			{"show_completed_payments", no_argument, nullptr, 'l'},
			
			// Show payment
			{"show_payment", required_argument, nullptr, 'i'},
			
			// Help
			{"help", no_argument, nullptr, 'h'},
			
			// End
			{}
		});
		
		// Add Tor proxy options to list
		const vector torProxyOptions = TorProxy::getOptions();
		options.insert(options.begin(), torProxyOptions.begin(), torProxyOptions.end());
		
		// Add price options to list
		const vector priceOptions = Price::getOptions();
		options.insert(options.begin(), priceOptions.begin(), priceOptions.end());
		
		// Add node options to list
		const vector nodeOptions = Node::getOptions();
		options.insert(options.begin(), nodeOptions.begin(), nodeOptions.end());
		
		// Add private server options to list
		const vector privateServerOptions = PrivateServer::getOptions();
		options.insert(options.begin(), privateServerOptions.begin(), privateServerOptions.end());
		
		// Add public server options to list
		const vector publicServerOptions = PublicServer::getOptions();
		options.insert(options.begin(), publicServerOptions.begin(), publicServerOptions.end());
		
		// Go through all options
		string optionsString;
		for(const option &option : options) {
		
			// Check if option exists
			if(option.val) {
		
				// Add option to options string
				optionsString.push_back(option.val);
				
				// Check if option has argument
				if(option.has_arg) {
				
					// Add has argument to options string
					optionsString.push_back(':');
				}
			}
		}
		
		// Initialize provided options
		static unordered_map<char, const char *> providedOptions;
		
		// Go through all options
		int option;
		while((option = getopt_long(argc, const_cast<char **>(argv), optionsString.c_str(), options.data(), nullptr)) != -1) {
		
			// Check option
			switch(option) {
			
				// Version
				case 'v':
				
					// Return success
					return EXIT_SUCCESS;
				
				// Help
				case 'h':
				
					// Display options help
					displayOptionsHelp(argv);
				
					// Return success
					return EXIT_SUCCESS;
					
				// Invalid
				case '?':
				case ':':
				
					// Display options help
					displayOptionsHelp(argv);
				
					// Return failure
					return EXIT_FAILURE;
				
				// Default
				default:
				
					// Check option
					switch(option) {
					
						// Directory
						case 'd':
						
							// Check if directory is invalid
							if(!optarg || !strlen(optarg)) {
							
								// Display message
								cout << argv[0] << ": invalid directory -- '" << (optarg ? optarg : "") << '\'' << endl;
						
								// Display options help
								displayOptionsHelp(argv);
							
								// Return failure
								return EXIT_FAILURE;
							}
							
							// Break
							break;
						
						// Password
						case 'w':
						
							// Check if password is invalid
							if(!optarg) {
							
								// Display message
								cout << argv[0] << ": invalid password -- ''" << endl;
						
								// Display options help
								displayOptionsHelp(argv);
							
								// Return failure
								return EXIT_FAILURE;
							}
							
							// Break
							break;
						
						// Show payment
						case 'i':
						
							// Check if payment ID is invalid
							char *end;
							errno = 0;
							const unsigned long long paymentId = optarg ? strtoull(optarg, &end, Common::DECIMAL_NUMBER_BASE) : 0;
							if(!optarg || end == optarg || *end || !isdigit(optarg[0]) || (optarg[0] == '0' && isdigit(optarg[1])) || errno || paymentId > numeric_limits<uint64_t>::max()) {
							
								// Display message
								cout << argv[0] << ": invalid payment ID -- '" << (optarg ? optarg : "") << '\'' << endl;
						
								// Return false
								return false;
							}
							
							// Break
							break;
					}
					
					// Check if validating Tor proxy option failed
					if(!TorProxy::validateOption(option, optarg, argv)) {
					
						// Display options help
						displayOptionsHelp(argv);
					
						// Return failure
						return EXIT_FAILURE;
					}
					
					// Check if validating price option failed
					if(!Price::validateOption(option, optarg, argv)) {
					
						// Display options help
						displayOptionsHelp(argv);
					
						// Return failure
						return EXIT_FAILURE;
					}
					
					// Check if validating node option failed
					if(!Node::validateOption(option, optarg, argv)) {
					
						// Display options help
						displayOptionsHelp(argv);
					
						// Return failure
						return EXIT_FAILURE;
					}
					
					// Check if validating private server option failed
					if(!PrivateServer::validateOption(option, optarg, argv)) {
					
						// Display options help
						displayOptionsHelp(argv);
					
						// Return failure
						return EXIT_FAILURE;
					}
					
					// Check if validating public server option failed
					if(!PublicServer::validateOption(option, optarg, argv)) {
					
						// Display options help
						displayOptionsHelp(argv);
					
						// Return failure
						return EXIT_FAILURE;
					}
					
					// Add option to provided options
					providedOptions.emplace(option, optarg);
					
					// Break
					break;
			}
		}
		
		// Check if blocking signals failed
		if(!Common::blockSignals()) {
		
			// Display message
			cout << "Blocking signals failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Initialize signal action to fail syscalls when interrupted
		struct sigaction signalAction = {};
		signalAction.sa_handler = [](const int signal) {
		
			// Check if signal is an interrupt or terminate signal
			if(signal == SIGINT || signal == SIGTERM) {
		
				// Ignore further interrupt and terminate signals
				struct sigaction ignoreAction = {};
				ignoreAction.sa_handler = SIG_IGN;
				sigaction(SIGINT, &ignoreAction, nullptr);
				sigaction(SIGTERM, &ignoreAction, nullptr);
				
				// Set signal received
				Common::setSignalReceived();
			}
		};
		
		// Check if setting signal action failed
		if(sigaction(SIGUSR1, &signalAction, nullptr) || sigaction(SIGINT, &signalAction, nullptr) || sigaction(SIGTERM, &signalAction, nullptr)) {
		
			// Display message
			cout << "Setting signal action failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if floonet
		#ifdef FLOONET
		
			// Display message
			cout << "Network type: floonet" << endl;
		
		// Otherwise
		#else
		
			// Display message
			cout << "Network type: mainnet" << endl;
		#endif
	
		// Save current directory
		static const filesystem::path currentDirectory = filesystem::current_path();
		
		// Check if going to application directory failed
		if(!goToApplicationDirectory(providedOptions)) {
		
			// Display message
			cout << "Going to application directory failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if connecting to database failed
		static sqlite3 *databaseConnection;
		if(sqlite3_open_v2(DATABASE_FILE, &databaseConnection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
		
			// Check if database connection exists
			if(databaseConnection) {
			
				// Close database connection
				sqlite3_close(databaseConnection);
			}
			
			// Display message
			cout << "Connecting to database failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Automatically close database connection
		static const unique_ptr<sqlite3, decltype(&sqlite3_close)> databaseConnectionUniquePointer(databaseConnection, sqlite3_close);
		
		// Get provided password
		const char *providedPassword = providedOptions.contains('w') ? providedOptions.at('w') : nullptr;
		
		// Check if using provided password
		if(providedPassword) {
		
			// Display message
			cout << "Using provided password" << endl;
		}
		
		// Get show recovery passphrase from provided options
		const bool showRecoveryPassphrase = providedOptions.contains('r');
		
		// Check if showing recovery passphrase
		if(showRecoveryPassphrase) {
		
			// Display message
			cout << "Displaying wallet's recovery passphrase" << endl;
		}
		
		// Check if opening wallet failed
		static Wallet wallet;
		if(!wallet.open(databaseConnection, providedPassword, showRecoveryPassphrase)) {
		
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if showing recovery passphrase
		if(showRecoveryPassphrase) {
		
			// Return success
			return EXIT_SUCCESS;
		}
		
		// Get show root public key from provided options
		const bool showRootPublicKey = providedOptions.contains('u');
		
		// Check if showing root public key
		if(showRootPublicKey) {
		
			// Display message
			cout << "Displaying wallet's root public key" << endl;
			
			// Display wallet's root public key
			wallet.displayRootPublicKey();
			
			// Return success
			return EXIT_SUCCESS;
		}
		
		// Create payments
		static Payments payments(databaseConnection);
		
		// Get show completed payments from provided options
		const bool showCompletedPayments = providedOptions.contains('l');
		
		// Check if showing completed payments
		if(showCompletedPayments) {
		
			// Display message
			cout << "Displaying completed payments" << endl;
			
			// Display completed payments
			payments.displayCompletedPayments(wallet);
			
			// Return success
			return EXIT_SUCCESS;
		}
		
		// Get show payment from provided options
		const bool showPayment = providedOptions.contains('i');
		
		// Check if showing payment
		if(showPayment) {
		
			// Display message
			cout << "Displaying payment" << endl;
			
			// Get payment ID from provided arguments
			const uint64_t paymentId = strtoull(providedOptions.at('i'), nullptr, Common::DECIMAL_NUMBER_BASE);
			
			// Display completed payments
			payments.displayPayment(paymentId, wallet);
			
			// Return success
			return EXIT_SUCCESS;
		}
		
		// Check if opening lock file failed
		const int lockFile = open(LOCK_FILE, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(lockFile == -1) {
		
			// Display message
			cout << "Opening lock file failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if locking lock file failed
		const flock lock = {
		
			// Type
			.l_type = F_WRLCK
		};
		
		if(fcntl(lockFile, F_SETLK, &lock)) {
		
			// Check if lock file is already locked
			if(errno == EACCES || errno == EAGAIN) {
			
				// Display message
				cout << "Application directory is already in use" << endl;
				
				// Close lock file
				close(lockFile);
				
				// Return failure
				return EXIT_FAILURE;
			}
			
			// Otherwise
			else {
			
				// Display message
				cout << "Locking lock file failed" << endl;
				
				// Close lock file
				close(lockFile);
				
				// Return failure
				return EXIT_FAILURE;
			}
		}
		
		// Create expired monitor
		static const ExpiredMonitor expiredMonitor(payments);
		
		// Create Tor proxy
		static const TorProxy torProxy(providedOptions, wallet);
		
		// Create price
		static const Price price(providedOptions, torProxy);
		
		// Create node
		static const Node node(providedOptions, torProxy, payments);
		
		// Create private server
		static const PrivateServer privateServer(providedOptions, currentDirectory, wallet, payments, price);
		
		// Create public server
		static const PublicServer publicServer(providedOptions, currentDirectory, wallet, payments);
		
		// Check if creating event base failed
		const unique_ptr<event_base, decltype(&event_base_free)> eventBase(event_base_new(), event_base_free);
		if(!eventBase) {
		
			// Display message
			osyncstream(cout) << "Creating event base failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if creating interrupt signal event failed
		const unique_ptr<event, decltype(&event_free)> interruptSignalEvent(evsignal_new(eventBase.get(), SIGINT, exitHandler, eventBase.get()), event_free);
		if(!interruptSignalEvent) {
		
			// Display message
			osyncstream(cout) << "Creating interrupt signal event failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if adding interrupt signal event failed
		if(event_add(interruptSignalEvent.get(), nullptr)) {
		
			// Display message
			osyncstream(cout) << "Adding interrupt signal event failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if creating terminate signal event failed
		const unique_ptr<event, decltype(&event_free)> terminateSignalEvent(evsignal_new(eventBase.get(), SIGTERM, exitHandler, eventBase.get()), event_free);
		if(!terminateSignalEvent) {
		
			// Display message
			osyncstream(cout) << "Creating terminate signal event failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if adding terminate signal event failed
		if(event_add(terminateSignalEvent.get(), nullptr)) {
		
			// Display message
			osyncstream(cout) << "Adding terminate signal event failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if running event loop failed
		if(event_base_dispatch(eventBase.get()) == -1) {
		
			// Display message
			osyncstream(cout) << "Running event loop failed" << endl;
			
			// Return failure
			return EXIT_FAILURE;
		}
	}
	
	// Catch runtime errors
	catch(const runtime_error &error) {
	
		// Display message
		cout << error.what() << endl;
		
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Catch errors
	catch(...) {
	
		// Display message
		cout << "Failed for unknown reason" << endl;
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Check if an error occurred
	if(Common::getErrorOccurred()) {
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Return success
	return EXIT_SUCCESS;
}


// Supporting function implementation

// Clear argv constructor
ClearArgv::ClearArgv(const int argc, char *argv[]) :

	// Set argc
	argc(argc),
	
	// Set argv
	argv(argv)
{
}

// Clear argv destructor
ClearArgv::~ClearArgv() {

	// Go through all arguments
	for(int i = 0; i < argc; ++i) {
	
		// Securely clear argument
		explicit_bzero(argv[i], strlen(argv[i]));
	}
}

// Display options help
void displayOptionsHelp(char *argv[]) {

	// Display message
	cout << endl << "Usage:" << endl << '\t' << argv[0] << " [options]" << endl << endl;
	cout << "Options:" << endl;
	cout << "\t-v, --version\t\t\tDisplays version information" << endl;
	cout << "\t-d, --directory\t\t\tSets the directory to store application files (default: $HOME/" << DEFAULT_APPLICATION_DIRECTORY << ')' << endl;
	cout << "\t-w, --password\t\t\tSets password to use for the wallet instead of being prompted for one" << endl;
	cout << "\t-r, --recovery_passphrase\tDisplays wallet's recovery passphrase" << endl;
	cout << "\t-u, --root_public_key\t\tDisplays wallet's root public key" << endl;
	cout << "\t-l, --show_completed_payments\tDisplays all completed payments" << endl;
	cout << "\t-i, --show_payment\t\tDisplays the payment with a specified ID" << endl;
	
	// Display Tor proxy options help
	TorProxy::displayOptionsHelp();
	
	// Display price options help
	Price::displayOptionsHelp();
	
	// Display node options help
	Node::displayOptionsHelp();
	
	// Display private server options help
	PrivateServer::displayOptionsHelp();
	
	// Display public server options help
	PublicServer::displayOptionsHelp();
	
	// Display message
	cout << "\t-h, --help\t\t\tDisplays help information" << endl;
}

// Go to application directory
bool goToApplicationDirectory(const unordered_map<char, const char *> &providedOptions) {

	// Try
	try {
	
		// Initialize application directory
		filesystem::path applicationDirectory;

		// Check if directory option is provided
		if(providedOptions.contains('d')) {
		
			// Display message
			cout << "Using provided directory: " << providedOptions.at('d') << endl;
		
			// Set application directory from provided options
			applicationDirectory = filesystem::path(providedOptions.at('d'));
		}
		
		// Otherwise
		else {

			// Check if getting home environmental variable failed
			const char *homeDirectory = getenv("HOME");
			if(!homeDirectory) {
			
				// Check if getting user info failed or user info doesn't have a home directory
				const passwd *userInfo = getpwuid(getuid());
				if(!userInfo || !userInfo->pw_dir) {
				
					// Return false
					return false;
				}
				
				// Set home directory to user info's home directory
				homeDirectory = userInfo->pw_dir;
			}
			
			// Set application directory from home directory
			applicationDirectory = filesystem::path(homeDirectory) / DEFAULT_APPLICATION_DIRECTORY;
		}
	
		// Create application directory
		filesystem::create_directory(applicationDirectory);
		
		// Check if floonet
		#ifdef FLOONET
		
			// Create network directory in the application directory
			filesystem::create_directory(applicationDirectory / "floonet");
			
			// Set current path to network directory
			filesystem::current_path(applicationDirectory / "floonet");
		
		// Otherwise
		#else
		
			// Create network directory in the application directory
			filesystem::create_directory(applicationDirectory / "mainnet");
			
			// Set current path to network directory
			filesystem::current_path(applicationDirectory / "mainnet");
		#endif
	}
	
	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Exit handler
void exitHandler(const evutil_socket_t fileDescriptor, const short signal, void *argument) {

	// Get event base from argument
	event_base *eventBase = reinterpret_cast<event_base *>(argument);
	
	// Check if exiting event loop failed
	if(event_base_loopexit(eventBase, nullptr)) {
	
		// Display message
		osyncstream(cout) << "Exiting event loop failed" << endl;
	
		// Exit failure
		exit(EXIT_FAILURE);
	}
}
