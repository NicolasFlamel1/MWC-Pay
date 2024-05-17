// Header guard
#ifndef NODE_H
#define NODE_H


// Header files
#include <atomic>
#include <getopt.h>
#include <mutex>
#include <unordered_map>
#include <vector>
#include "./node/mwc_validation_node.h"
#include "./payments.h"
#include "./tor_proxy.h"

using namespace std;


// Classes

// Node class
class Node final {

	// Public
	public:
	
		// Constructor
		explicit Node(const unordered_map<char, const char *> &providedOptions, const TorProxy &torProxy, Payments &payments);
		
		// Destructr
		~Node();
		
		// Get options
		static vector<option> getOptions();
		
		// Display options help
		static void displayOptionsHelp();
		
		// Validate option
		static bool validateOption(const char option, const char *value, char *argv[]);
	
	// Private
	private:
	
		// Restore state
		bool restoreState();
		
		// Save state
		bool saveState() const;
		
		// Node failed
		void nodeFailed();
		
		// Transaction hash set occurred
		bool transactionHashSetOccurred(const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Header> &headers, const MwcValidationNode::Header &transactionHashSetArchiveHeader, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Kernel> &kernels);
		
		// Block occurred
		bool blockOccurred(const MwcValidationNode::Header &header, const MwcValidationNode::Block &block);
		
		// Started
		atomic_bool started;
		
		// Started lock
		mutex startedLock;
		
		// Failed
		atomic_bool failed;
		
		// Payments
		Payments &payments;
		
		// Node
		MwcValidationNode::Node node;
};


#endif
