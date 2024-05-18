// Header files
#include "./consensus.h"

using namespace std;


// Constants

// Number base
const int Consensus::NUMBER_BASE = 1E9;

// Check if floonet
#ifdef FLOONET

	// Kernel commitment explorer URL
	const char *Consensus::KERNEL_COMMITMENT_EXPLORER_URL = "https://explorer.floonet.mwc.mw/#k";

	// Output commitment explorer URL
	const char *Consensus::OUTPUT_COMMITMENT_EXPLORER_URL = "https://explorer.floonet.mwc.mw/#o";
	
	// Currency abbreviation
	const char *Consensus::CURRENCY_ABBREVIATION = "Floonet MWC";
	
// Otherwise
#else

	// Kernel commitment explorer URL
	const char *Consensus::KERNEL_COMMITMENT_EXPLORER_URL = "https://explorer.mwc.mw/#k";

	// Output commitment explorer URL
	const char *Consensus::OUTPUT_COMMITMENT_EXPLORER_URL = "https://explorer.mwc.mw/#o";
	
	// Currency abbreviation
	const char *Consensus::CURRENCY_ABBREVIATION = "MWC";
#endif
