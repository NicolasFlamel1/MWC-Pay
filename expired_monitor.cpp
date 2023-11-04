// Header files
#include <iostream>
#include <syncstream>
#include "./common.h"
#include "./expired_monitor.h"

using namespace std;


// Constants

// Check interval seconds
static const unsigned int CHECK_INTERVAL_SECONDS = 1;


// Supporting function implementation

// Constructor
ExpiredMonitor::ExpiredMonitor(Payments &payments) :

	// Set quit
	quit(false),
	
	// Set payments
	payments(payments)
{

	// Display message
	osyncstream(cout) << "Starting expired monitor" << endl;
	
	// Try
	try {
	
		// Create main thread
		mainThread = thread(&ExpiredMonitor::run, this);
	}
	
	// Catch errors
	catch(...) {
	
		// Throw exception
		throw runtime_error("Creating expired monitor main thread failed");
	}
	
	// Check if main thread is invalid
	if(!mainThread.joinable()) {
	
		// Display message
		osyncstream(cout) << "Expired monitor main thread is invalid" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Display message
	osyncstream(cout) << "Expired monitor started" << endl;
}

// Destructor
ExpiredMonitor::~ExpiredMonitor() {

	// Display message
	osyncstream(cout) << "Closing expired monitor" << endl;
	
	// Set quit
	quit.store(true);
	
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
		osyncstream(cout) << "Waiting for expired monitor to finish failed" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Display message
	osyncstream(cout) << "Expired monitor closed" << endl;
}

// Run
void ExpiredMonitor::run() {

	// Try
	try {
	
		// While not quitting
		while(!quit.load()) {
		
			// Run unsuccessful expired payment callbacks
			payments.runUnsuccessfulExpiredPaymentCallbacks();
			
			// Sleep
			sleep(CHECK_INTERVAL_SECONDS);
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Display message
		osyncstream(cout) << "Expired monitor failed for unknown reason" << endl;
	
		// Set error occurred
		Common::setErrorOccurred();
			
		// Raise interrupt signal
		kill(getpid(), SIGINT);
	}
}
