// Header guard
#ifndef EXPIRED_MONITOR_H
#define EXPIRED_MONITOR_H


// Header files
#include <atomic>
#include <thread>
#include "./payments.h"

using namespace std;


// Classes

// Expired monitor class
class ExpiredMonitor final {

	// Public
	public:
	
		// Constructor
		explicit ExpiredMonitor(Payments &payments);
		
		// Destructor
		~ExpiredMonitor();
	
	// Private
	private:
	
		// Run
		void run();
		
		// Quit
		atomic_bool quit;
		
		// Payments
		Payments &payments;
		
		// Main thread
		thread mainThread;
};


#endif
