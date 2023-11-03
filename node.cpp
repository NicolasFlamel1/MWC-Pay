// Header files
#include <filesystem>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <syncstream>
#include "./common.h"
#include "./node.h"
#include "./node/peer.h"

using namespace std;


// Constants

// State file
static const char *STATE_FILE = "node_state.bin";

// Check if floonet
#ifdef FLOONET

	// Default node DNS seed port
	static const char *DEFAULT_NODE_DNS_SEED_PORT = "13414";

// Otherwise
#else

	// Default node DNS seed port
	static const char *DEFAULT_NODE_DNS_SEED_PORT = "3414";
#endif


// Supporting function implementation

// Constructor
Node::Node(const unordered_map<char, const char *> &providedOptions, const TorProxy &torProxy, Payments &payments) :

	// Set started
	started(false),
	
	// Set failed
	failed(false),
	
	// Set payments
	payments(payments),
	
	// Set node
	node(torProxy.getSocksAddress(), torProxy.getSocksPort())
{

	// Display message
	osyncstream(cout) << "Starting node" << endl;
	
	// Check if a node DNS seed port is provided but not a node DNS seed address
	if(providedOptions.contains('m') && !providedOptions.contains('n')) {
	
		// Throw exception
		throw runtime_error("No address provided for the node DNS seed port");
	}
	
	// Check if state file exists
	if(filesystem::exists(STATE_FILE)) {
	
		// Display message
		osyncstream(cout) << "Restoring node state" << endl;
		
		// Check if a signal was received
		if(!Common::allowSignals() || Common::getSignalReceived()) {
		
			// Block signals
			Common::blockSignals();
			
			// Throw exception
			throw runtime_error("Restoring node state failed");
		}
		
		// Check if restoring state failed
		if(!restoreState()) {
		
			// Block signals
			Common::blockSignals();
			
			// Throw exception
			throw runtime_error("Restoring node state failed");
		}
		
		// Check if a signal was received
		if(!Common::blockSignals() || Common::getSignalReceived()) {
		
			// Block signals
			Common::blockSignals();
			
			// Throw exception
			throw runtime_error("Restoring node state failed");
		}
		
		// Display message
		osyncstream(cout) << "Node state restored" << endl;
	}
	
	// Set node's on synced callback
	atomic_bool isSynced(false);
	node.setOnSyncedCallback([&isSynced]() {
	
		// Set is synced
		isSynced.store(true);
	});
	
	// Set node's on error callback
	node.setOnErrorCallback([this]() {
	
		// Run node failed
		nodeFailed();
	});
	
	// Set node's on transaction hash set callback
	node.setOnTransactionHashSetCallback([this](const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Header> &headers, const MwcValidationNode::Header &transactionHashSetArchiveHeader, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Kernel> &kernels, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Output> &outputs, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Rangeproof> &rangeproofs) -> bool{
	
		// Try
		try {
		
			// Return if running transaction hash set occurred was successful
			return transactionHashSetOccurred(headers, transactionHashSetArchiveHeader, kernels);
		}
		
		// Catch errors
		catch(...) {
		
			// Return false
			return false;
		}
	});
	
	// Set node's on block callback
	node.setOnBlockCallback([this](const MwcValidationNode::Header &header, const MwcValidationNode::Block &block) -> bool {
	
		// Try
		try {
		
			// Return if running block occurred was succesful
			return blockOccurred(header, block);
		}
		
		// Catch errors
		catch(...) {
		
			// Return false
			return false;
		}
	});
	
	// Initialize node DNS seed
	string nodeDnsSeed;
	
	// Check if a node DNS seed address is provided
	if(providedOptions.contains('n')) {
	
		// Get node DNS seed address from provided arguments
		const char *nodeDnsSeedAddress = providedOptions.at('n');
		
		// Display message
		osyncstream(cout) << "Using provided node DNS seed address: " << nodeDnsSeedAddress << endl;
		
		// Get node DNS seed port from provided arguments
		const char *nodeDnsSeedPort = providedOptions.contains('m') ? providedOptions.at('m') : DEFAULT_NODE_DNS_SEED_PORT;
		
		// Check if a node DNS seed port is provided
		if(providedOptions.contains('m')) {
		
			// Display message
			osyncstream(cout) << "Using provided node DNS seed port: " << nodeDnsSeedPort << endl;
		}
		
		// Check if node DNS seed address is an IPv6 address
		char temp[sizeof(in6_addr)];
		if(inet_pton(AF_INET6, nodeDnsSeedAddress, temp) == 1) {
		
			// Set node DNS seed
			nodeDnsSeed = '[' + string(nodeDnsSeedAddress) + "]:" + nodeDnsSeedPort;
		}
		
		// Otherwise
		else {
		
			// Set node DNS seed
			nodeDnsSeed = string(nodeDnsSeedAddress) + ':' + nodeDnsSeedPort;
		}
	}
	
	// Try
	try {
	
		// Start node
		node.start(nodeDnsSeed.empty() ? nullptr : nodeDnsSeed.c_str());
	}
	
	// Catch errors
	catch(...) {
	
		// Throw exception
		throw runtime_error("Creating node main thread failed");
	}
	
	// Check if node's thread is invalid
	if(!node.getThread().joinable()) {
	
		// Display message
		osyncstream(cout) << "Node main thread is invalid" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Display message
	osyncstream(cout) << "Syncing node" << flush;
	
	// Check if a signal was received
	if(!Common::allowSignals() || Common::getSignalReceived()) {
	
		// Block signals
		Common::blockSignals();
		
		// Display message
		osyncstream(cout) << endl << "Waiting for node to sync failed" << endl;
		
		// Stop node
		node.stop();
		
		// Initialize error occurred
		bool errorOccurred = false;
		
		// Try
		try {

			// Wait for node's thread to finish
			node.getThread().join();
		}

		// Catch errors
		catch(...) {
		
			// Set error occurred
			errorOccurred = true;
		}
		
		// Check if an error didn't occur
		if(!errorOccurred) {
		
			// Go through all of the node's peers
			for(list<MwcValidationNode::Peer>::iterator i = node.getPeers().begin(); i != node.getPeers().end(); ++i) {
			
				// Stop peer
				i->stop();
				
				// Check if peer's thread is running
				if(i->getThread().joinable()) {
				
					// Send signal to peer to fail syscalls
					pthread_kill(i->getThread().native_handle(), SIGUSR1);
					
					// Try
					try {
					
						// Wait for peer to finish
						i->getThread().join();
					}
					
					// Catch errors
					catch(...) {
					
						// Set error occurred
						errorOccurred = true;
					}
				}
				
				// Check if peer's worker operation is running
				if(i->isWorkerOperationRunning()) {
				
					// Set error occurred
					errorOccurred = true;
				}
			}
		}
		
		// Check if an error didn't occur
		if(!errorOccurred) {
		
			// Disconnect node
			node.disconnect();
		
			// Save state
			saveState();
		}
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// While not synced
	for(int i = 0;; ++i) {
	
		// Check if a signal was received
		if(Common::getSignalReceived()) {
		
			// Block signals
			Common::blockSignals();
			
			// Display message
			osyncstream(cout) << endl << "Waiting for node to sync failed" << endl;
			
			// Stop node
			node.stop();
			
			// Initialize error occurred
			bool errorOccurred = false;
			
			// Try
			try {

				// Wait for node's thread to finish
				node.getThread().join();
			}

			// Catch errors
			catch(...) {
			
				// Set error occurred
				errorOccurred = true;
			}
			
			// Check if an error didn't occur
			if(!errorOccurred) {
			
				// Go through all of the node's peers
				for(list<MwcValidationNode::Peer>::iterator j = node.getPeers().begin(); j != node.getPeers().end(); ++j) {
				
					// Stop peer
					j->stop();
					
					// Check if peer's thread is running
					if(j->getThread().joinable()) {
					
						// Send signal to peer to fail syscalls
						pthread_kill(j->getThread().native_handle(), SIGUSR1);
						
						// Try
						try {
						
							// Wait for peer to finish
							j->getThread().join();
						}
						
						// Catch errors
						catch(...) {
						
							// Set error occurred
							errorOccurred = true;
						}
					}
					
					// Check if peer's worker operation is running
					if(j->isWorkerOperationRunning()) {
					
						// Set error occurred
						errorOccurred = true;
					}
				}
			}
			
			// Check if an error didn't occur
			if(!errorOccurred) {
			
				// Disconnect node
				node.disconnect();
				
				// Save state
				saveState();
			}
			
			// Exit failure
			exit(EXIT_FAILURE);
		}
		
		// Check if synced
		if(isSynced.load()) {
		
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
	osyncstream(cout) << endl << "Node synced" << endl;
	
	// Try
	try {
	
		// Lock started
		lock_guard guard(startedLock);
		
		// Set started
		started.store(true);
		
		// Check if a signal was received or failed
		if(!Common::blockSignals() || Common::getSignalReceived() || failed.load()) {
		
			// Block signals
			Common::blockSignals();
			
			// Display message
			osyncstream(cout) << "Starting node failed" << endl;
			
			// Stop node
			node.stop();
			
			// Initialize error occurred
			bool errorOccurred = false;
			
			// Try
			try {

				// Wait for node's thread to finish
				node.getThread().join();
			}

			// Catch errors
			catch(...) {
			
				// Set error occurred
				errorOccurred = true;
			}
			
			// Check if an error didn't occur
			if(!errorOccurred) {
			
				// Go through all of the node's peers
				for(list<MwcValidationNode::Peer>::iterator i = node.getPeers().begin(); i != node.getPeers().end(); ++i) {
				
					// Stop peer
					i->stop();
					
					// Check if peer's thread is running
					if(i->getThread().joinable()) {
					
						// Send signal to peer to fail syscalls
						pthread_kill(i->getThread().native_handle(), SIGUSR1);
						
						// Try
						try {
						
							// Wait for peer to finish
							i->getThread().join();
						}
						
						// Catch errors
						catch(...) {
						
							// Set error occurred
							errorOccurred = true;
						}
					}
					
					// Check if peer's worker operation is running
					if(i->isWorkerOperationRunning()) {
					
						// Set error occurred
						errorOccurred = true;
					}
				}
			}
			
			// Check if an error didn't occur
			if(!errorOccurred) {
			
				// Disconnect node
				node.disconnect();
				
				// Save state
				saveState();
			}
			
			// Exit failure
			exit(EXIT_FAILURE);
		}
	
		// Display message
		osyncstream(cout) << "Node started" << endl;
	}
	
	// Catch errors
	catch(...) {
	
		// Block signals
		Common::blockSignals();
		
		// Display message
		osyncstream(cout) << "Starting node failed" << endl;
		
		// Stop node
		node.stop();
		
		// Initialize error occurred
		bool errorOccurred = false;
		
		// Try
		try {

			// Wait for node's thread to finish
			node.getThread().join();
		}

		// Catch errors
		catch(...) {
		
			// Set error occurred
			errorOccurred = true;
		}
		
		// Check if an error didn't occur
		if(!errorOccurred) {
		
			// Go through all of the node's peers
			for(list<MwcValidationNode::Peer>::iterator i = node.getPeers().begin(); i != node.getPeers().end(); ++i) {
			
				// Stop peer
				i->stop();
				
				// Check if peer's thread is running
				if(i->getThread().joinable()) {
				
					// Send signal to peer to fail syscalls
					pthread_kill(i->getThread().native_handle(), SIGUSR1);
					
					// Try
					try {
					
						// Wait for peer to finish
						i->getThread().join();
					}
					
					// Catch errors
					catch(...) {
					
						// Set error occurred
						errorOccurred = true;
					}
				}
				
				// Check if peer's worker operation is running
				if(i->isWorkerOperationRunning()) {
				
					// Set error occurred
					errorOccurred = true;
				}
			}
		}
		
		// Check if an error didn't occur
		if(!errorOccurred) {
		
			// Disconnect node
			node.disconnect();
			
			// Save state
			saveState();
		}
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
}

// Destructor
Node::~Node() {

	// Display message
	osyncstream(cout) << "Closing node" << endl;
	
	// Stop node
	node.stop();
	
	// Try
	try {

		// Wait for node's thread to finish
		node.getThread().join();
	}

	// Catch errors
	catch(...) {
	
		// Display message
		osyncstream(cout) << "Waiting for node to finish failed" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Display message
	osyncstream(cout) << "Disconnecting from node peers" << endl;
	
	// Initialize error occurred
	bool errorOccurred = false;
	
	// Go through all of the node's peers
	for(list<MwcValidationNode::Peer>::iterator i = node.getPeers().begin(); i != node.getPeers().end(); ++i) {
	
		// Stop peer
		i->stop();
		
		// Check if peer's thread is running
		if(i->getThread().joinable()) {
		
			// Send signal to peer to fail syscalls
			pthread_kill(i->getThread().native_handle(), SIGUSR1);
			
			// Try
			try {
			
				// Wait for peer to finish
				i->getThread().join();
			}
			
			// Catch errors
			catch(...) {
			
				// Set error occurred
				errorOccurred = true;
			}
		}
		
		// Check if peer's worker operation is running
		if(i->isWorkerOperationRunning()) {
		
			// Set error occurred
			errorOccurred = true;
		}
	}
	
	// Check if an error occurred
	if(errorOccurred) {
	
		// Display message
		osyncstream(cout) << "Waiting for node peers to finish failed" << endl;
		
		// Exit failure
		exit(EXIT_FAILURE);
	}
	
	// Disconnect node
	node.disconnect();
	
	// Display message
	osyncstream(cout) << "Disconnected from node peers" << endl;
	
	// Check if saving state failed
	if(!saveState()) {
		
		// Set error occurred
		Common::setErrorOccurred();
		
		// Return
		return;
	}
	
	// Display message
	osyncstream(cout) << "Node closed" << endl;
}

// Get options
vector<option> Node::getOptions() {

	// Return options
	return {
	
		// Node DNS seed address
		{"node_dns_seed_address", required_argument, nullptr, 'n'},
		
		// Node DNS seed port
		{"node_dns_seed_port", required_argument, nullptr, 'm'}
	};
}

// Display options help
void Node::displayOptionsHelp() {

	// Check if floonet
	#ifdef FLOONET
	
		// Display message
		cout << "\t-n, --node_dns_seed_address\tSets the node DNS seed address to use instead of the default ones (example: seed1.mwc.mw)" << endl;
	
	// Otherwise
	#else
	
		// Display message
		cout << "\t-n, --node_dns_seed_address\tSets the node DNS seed address to use instead of the default ones (example: mainnet.seed1.mwc.mw)" << endl;
	#endif
	
	// Display message
	cout << "\t-m, --node_dns_seed_port\tSets the port to use for the node DNS seed address (default: " << DEFAULT_NODE_DNS_SEED_PORT << ')' << endl;
}

// Validate option
bool Node::validateOption(const char option, const char *value, char *argv[]) {

	// Check option
	switch(option) {
	
		// Node DNS seed address
		case 'n':
		
			// Check if node DNS seed address is invalid
			if(!value || !strlen(value)) {
			
				// Display message
				cout << argv[0] << ": invalid node DNS seed address -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		
		// Node DNS seed port
		case 'm': {
		
			// Check if node DNS seed port is invalid
			char *end;
			errno = 0;
			const unsigned long port = value ? strtoul(value, &end, Common::DECIMAL_NUMBER_BASE) : 0;
			if(!value || end == value || *end || !isdigit(value[0]) || (value[0] == '0' && isdigit(value[1])) || errno || !port || port > numeric_limits<uint16_t>::max()) {
			
				// Display message
				cout << argv[0] << ": invalid node DNS seed port -- '" << (value ? value : "") << '\'' << endl;
		
				// Return false
				return false;
			}
			
			// Break
			break;
		}
	}
	
	// Return true
	return true;
}

// Restore state
bool Node::restoreState() {
	
	// Try
	try {
	
		// Set state file to throw exception on error
		ifstream stateFile;
		stateFile.exceptions(ios::badbit | ios::failbit);
		
		// Open state file
		stateFile.open(STATE_FILE, ios::binary);
		
		// Restore node from state file
		node.restore(stateFile);
		
		// Close state file
		stateFile.close();
	}
	
	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Save state
bool Node::saveState() const {

	// Display message
	osyncstream(cout) << "Saving node state" << endl;
	
	// Set temporary state file name
	const string temporaryStateFileName = string(STATE_FILE) + ".tmp";

	// Try
	try {
	
		// Set temporary state file to throw exception on error
		ofstream temporaryStateFile;
		temporaryStateFile.exceptions(ios::badbit | ios::failbit);
		
		// Open temporary state file
		temporaryStateFile.open(temporaryStateFileName, ios::binary | ios::trunc);
		
		// Save node to temporary state file
		node.save(temporaryStateFile);
		
		// Close temporary state file
		temporaryStateFile.close();
		
		// Replace state file with temporary state file
		filesystem::rename(temporaryStateFileName, STATE_FILE);
	}
	
	// Catch errors
	catch(...) {
	
		// Display message
		osyncstream(cout) << "Saving node state failed" << endl;
		
		// Try
		try {
	
			// Remove temporary state file
			filesystem::remove(temporaryStateFileName);
		}
		
		// Catch errors
		catch(...) {
		
		}
		
		// Return false
		return false;
	}
	
	// Display message
	osyncstream(cout) << "Node state saved" << endl;
	
	// Return true
	return true;
}

// Node failed
void Node::nodeFailed() {

	// Try
	try {

		// Lock started
		lock_guard guard(startedLock);
		
		// Check if not failed
		if(!failed.load()) {
		
			// Set failed
			failed.store(true);
			
			// Check if started
			if(started.load()) {
			
				// Display message
				osyncstream(cout) << "Node failed for unknown reason" << endl;
			
				// Set error occurred
				Common::setErrorOccurred();
			}
				
			// Raise interrupt signal
			kill(getpid(), SIGINT);
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Check if not failed
		if(!failed.load()) {
		
			// Set failed
			failed.store(true);
			
			// Display message
			osyncstream(cout) << "Node failed for unknown reason" << endl;
		
			// Set error occurred
			Common::setErrorOccurred();
				
			// Raise interrupt signal
			kill(getpid(), SIGINT);
		}
	}
}

// Transaction hash set occurred
bool Node::transactionHashSetOccurred(const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Header> &headers, const MwcValidationNode::Header &transactionHashSetArchiveHeader, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Kernel> &kernels) {

	// Initialize completed payments
	list<uint64_t> completedPayments;
	
	// Initialize error occurred
	bool errorOccurred = false;
	
	{
		// Lock payments
		lock_guard guard(payments.getLock());
		
		// Check if beginning payments transaction failed
		if(!payments.beginTransaction()) {
		
			// Return false
			return false;
		}
		
		// Try
		try {
		
			// Go through all incomplete payments
			for(const tuple<uint64_t, uint64_t, vector<uint8_t>, optional<uint64_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>> &paymentInfo : payments.getIncompletePayments()) {
			
				// Check if payment isn't confirmed or was potentially reorged
				const optional<uint64_t> &paymentConfirmedHeight = get<3>(paymentInfo);
				if(!paymentConfirmedHeight.has_value() || paymentConfirmedHeight.value() >= headers.front().getHeight()) {
				
					// Check if a kernel exists with the payment kernel commitment
					const vector<uint8_t> &paymentKernelCommitment = get<2>(paymentInfo);
					if(kernels.leafWithLookupValueExists(paymentKernelCommitment)) {
					
						// Initialize payment confirmed
						bool paymentConfirmed = false;
						
						// Initialize kernel leaf index
						uint64_t kernelLeafIndex;
						
						// Go through all kernels with the payment kernel commitment
						for(const uint64_t leafIndex : kernels.getLeafIndicesByLookupValue(paymentKernelCommitment)) {
						
							// Get kernel
							const MwcValidationNode::Kernel *kernel = kernels.getLeaf(leafIndex);
							
							// Check if kernel is for the payment
							const vector<uint8_t> &senderPublicBlindExcess = get<4>(paymentInfo);
							const vector<uint8_t> &recipientPartialSignature = get<5>(paymentInfo);
							const vector<uint8_t> &publicNonceSum = get<6>(paymentInfo);
							const vector<uint8_t> &kernelData = get<7>(paymentInfo);
							if(Crypto::verifySecp256k1CompleteSingleSignerSignatures(senderPublicBlindExcess.data(), publicNonceSum.data(), kernel->getExcess(), kernel->getSignature(), recipientPartialSignature.data(), kernelData.data(), kernelData.size())) {
							
								// Set payment confirmed
								paymentConfirmed = true;
								
								// Set kernel leaf index
								kernelLeafIndex = leafIndex;
								
								// Break
								break;
							}
						}
						
						// Check if payment is confirmed
						if(paymentConfirmed) {
						
							// Get minimum kernel's size at kernel
							const uint64_t minimumKernelsSizeAtKernel = MwcValidationNode::MerkleMountainRange<MwcValidationNode::Kernel>::getSizeAtNumberOfLeaves(kernelLeafIndex + 1);
							
							// Get header for the block that contains the kernel
							const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Header>::const_iterator headerForKernelBlock = lower_bound(headers.cbegin(), headers.cend(), minimumKernelsSizeAtKernel, [](const pair<const uint64_t, MwcValidationNode::Header> &header, const uint64_t minimumKernelsSizeAtKernel) -> bool {
							
								// Return if header's kernel Merkle mountain range size is less than the minimum kernel's size at kernel
								return header.second.getKernelMerkleMountainRangeSize() < minimumKernelsSizeAtKernel;
							});
							
							// Check if header exists and is at a verified height
							if(headerForKernelBlock != headers.cend() && headerForKernelBlock->second.getHeight() <= transactionHashSetArchiveHeader.getHeight()) {
							
								// Set confirmed height to the header's height
								const uint64_t &confirmedHeight = headerForKernelBlock->second.getHeight();
							
								// Check if setting that payment is confirmed failed
								const uint64_t &paymentId = get<0>(paymentInfo);
								const uint64_t confirmations = transactionHashSetArchiveHeader.getHeight() - confirmedHeight + 1;
								if(!payments.setPaymentConfirmed(paymentId, min(confirmations, static_cast<uint64_t>(numeric_limits<uint32_t>::max())), confirmedHeight)) {
								
									// Throw exception
									throw runtime_error("Setting that payment is confirmed failed");
								}
								
								// Check if payment has the required number of confirmations
								const uint64_t &paymentRequiredConfirmation = get<1>(paymentInfo);
								if(confirmations >= paymentRequiredConfirmation) {
								
									// Add payment to list of completed payments
									completedPayments.emplace_back(paymentId);
								}
							}
							
							// Otherwise check if payment was confirmed
							else if(paymentConfirmedHeight.has_value()) {
							
								// Check if setting that payment is unconfirmed failed
								const uint64_t &paymentId = get<0>(paymentInfo);
								if(!payments.setPaymentConfirmed(paymentId, 0, 0)) {
								
									// Throw exception
									throw runtime_error("Setting that payment is unconfirmed failed");
								}
							}
						}
						
						// Otherwise check if payment was confirmed
						else if(paymentConfirmedHeight.has_value()) {
						
							// Check if setting that payment is unconfirmed failed
							const uint64_t &paymentId = get<0>(paymentInfo);
							if(!payments.setPaymentConfirmed(paymentId, 0, 0)) {
							
								// Throw exception
								throw runtime_error("Setting that payment is unconfirmed failed");
							}
						}
					}
					
					// Otherwise check if payment was confirmed
					else if(paymentConfirmedHeight.has_value()) {
					
						// Check if setting that payment is unconfirmed failed
						const uint64_t &paymentId = get<0>(paymentInfo);
						if(!payments.setPaymentConfirmed(paymentId, 0, 0)) {
						
							// Throw exception
							throw runtime_error("Setting that payment is unconfirmed failed");
						}
					}
				}
				
				// Otherwise
				else {
				
					// Check if setting that payment is confirmed failed
					const uint64_t &paymentId = get<0>(paymentInfo);
					const uint64_t confirmations = transactionHashSetArchiveHeader.getHeight() - paymentConfirmedHeight.value() + 1;
					if(!payments.setPaymentConfirmed(paymentId, min(confirmations, static_cast<uint64_t>(numeric_limits<uint32_t>::max())), paymentConfirmedHeight.value())) {
					
						// Throw exception
						throw runtime_error("Setting that payment is confirmed failed");
					}
					
					// Check if payment has the required number of confirmations
					const uint64_t &paymentRequiredConfirmation = get<1>(paymentInfo);
					if(confirmations >= paymentRequiredConfirmation) {
					
						// Add payment to list of completed payments
						completedPayments.emplace_back(paymentId);
					}
				}
			}
			
			// Check if committing payments transaction failed
			if(!payments.commitTransaction()) {
			
				// Throw exception
				throw runtime_error("Committing payments transaction failed");
			}
		}
		
		// Catch errors
		catch(...) {
		
			// Check if rolling back payments transaction failed
			if(!payments.rollbackTransaction()) {
			
				// Set error occurred
				errorOccurred = true;
			}
			
			// Otherwise
			else {
			
				// Return false
				return false;
			}
		}
	}
	
	// Check if an error occurred
	if(errorOccurred) {
	
		// Try
		try {

			// Lock started
			lock_guard guard(startedLock);
			
			// Check if not failed
			if(!failed.load()) {
			
				// Set failed
				failed.store(true);
				
				// Check if started
				if(started.load()) {
				
					// Display message
					osyncstream(cout) << "Node failed for unknown reason" << endl;
				
					// Set error occurred
					Common::setErrorOccurred();
				}
					
				// Raise interrupt signal
				kill(getpid(), SIGINT);
			}
		}
		
		// Catch errors
		catch(...) {
		
			// Check if not failed
			if(!failed.load()) {
			
				// Set failed
				failed.store(true);
				
				// Display message
				osyncstream(cout) << "Node failed for unknown reason" << endl;
			
				// Set error occurred
				Common::setErrorOccurred();
					
				// Raise interrupt signal
				kill(getpid(), SIGINT);
			}
		}
		
		// Return false
		return false;
	}
	
	// Go through all completed payments
	for(const uint64_t completedPaymentId : completedPayments) {
	
		// Display message
		osyncstream(cout) << "Completed payment " << completedPaymentId << endl;
	}
	
	// Check if started
	if(started.load()) {
	
		// Run pending confirmed payment callbacks
		payments.runPendingConfirmedPaymentCallbacks();
		
		// Run unsuccessful completed payment callbacks
		payments.runUnsuccessfulCompletedPaymentCallbacks();
	}
	
	// Return true
	return true;
}

// Block occurred
bool Node::blockOccurred(const MwcValidationNode::Header &header, const MwcValidationNode::Block &block) {

	// Initialize completed payments
	list<uint64_t> completedPayments;
	
	// Initialize error occurred
	bool errorOccurred = false;
	
	{
		// Lock payments
		lock_guard guard(payments.getLock());

		// Check if beginning payments transaction failed
		if(!payments.beginTransaction()) {
		
			// Return false
			return false;
		}
		
		// Try
		try {
		
			// Check if updating payments with reorg failed
			if(!payments.updatePaymentsWithReorg(header.getHeight())) {
			
				// Throw exception
				throw runtime_error("Updating payments with reorg failed");
			}
			
			// Go through all confirming payments
			for(const tuple<uint64_t, uint64_t, uint64_t> &paymentInfo : payments.getConfirmingPayments()) {
			
				// Check if setting that payment is confirmed failed
				const uint64_t &paymentId = get<0>(paymentInfo);
				const uint64_t &paymentConfirmedHeight = get<2>(paymentInfo);
				const uint64_t confirmations = header.getHeight() - paymentConfirmedHeight + 1;
				if(!payments.setPaymentConfirmed(paymentId, min(confirmations, static_cast<uint64_t>(numeric_limits<uint32_t>::max())), paymentConfirmedHeight)) {
				
					// Throw exception
					throw runtime_error("Setting that payment is confirmed failed");
				}
				
				// Check if payment has the required number of confirmations
				const uint64_t &paymentRequiredConfirmation = get<1>(paymentInfo);
				if(confirmations >= paymentRequiredConfirmation) {
				
					// Add payment to list of completed payments
					completedPayments.emplace_back(paymentId);
				}
			}
			
			// Go through all kernels in the block
			for(const MwcValidationNode::Kernel &kernel : block.getKernels()) {
			
				// Check if serializing kernel's excess failed
				uint8_t kernelCommitment[Crypto::COMMITMENT_SIZE];
				if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, kernelCommitment, &kernel.getExcess())) {
				
					// Throw exception
					throw runtime_error("Serializing kernel's excess failed");
				}
				
				// Check if kernel is for an unconfirmed payment
				const tuple paymentInfo = payments.getUnconfirmedPayment(kernelCommitment);
				if(get<0>(paymentInfo)) {
				
					// Check if kernel is for the payment
					const vector<uint8_t> &senderPublicBlindExcess = get<3>(paymentInfo);
					const vector<uint8_t> &recipientPartialSignature = get<4>(paymentInfo);
					const vector<uint8_t> &publicNonceSum = get<5>(paymentInfo);
					const vector<uint8_t> &kernelData = get<6>(paymentInfo);
					if(Crypto::verifySecp256k1CompleteSingleSignerSignatures(senderPublicBlindExcess.data(), publicNonceSum.data(), kernel.getExcess(), kernel.getSignature(), recipientPartialSignature.data(), kernelData.data(), kernelData.size())) {
					
						// Check if setting that payment is confirmed failed
						const uint64_t &paymentId = get<1>(paymentInfo);
						if(!payments.setPaymentConfirmed(paymentId, 1, header.getHeight())) {
						
							// Throw exception
							throw runtime_error("Setting that payment is confirmed failed");
						}
						
						// Check if payment has the required number of confirmations
						const uint64_t &paymentRequiredConfirmations = get<2>(paymentInfo);
						if(paymentRequiredConfirmations == 1) {
						
							// Add payment to list of completed payments
							completedPayments.emplace_back(paymentId);
						}
					}
				}
			}
			
			// Check if committing payments transaction failed
			if(!payments.commitTransaction()) {
			
				// Throw exception
				throw runtime_error("Committing payments transaction failed");
			}
		}
		
		// Catch errors
		catch(...) {
		
			// Check if rolling back payments transaction failed
			if(!payments.rollbackTransaction()) {
			
				// Set error occurred
				errorOccurred = true;
			}
			
			// Otherwise
			else {
			
				// Return false
				return false;
			}
		}
	}
	
	// Check if an error occurred
	if(errorOccurred) {
	
		// Try
		try {

			// Lock started
			lock_guard guard(startedLock);
			
			// Check if not failed
			if(!failed.load()) {
			
				// Set failed
				failed.store(true);
				
				// Check if started
				if(started.load()) {
				
					// Display message
					osyncstream(cout) << "Node failed for unknown reason" << endl;
				
					// Set error occurred
					Common::setErrorOccurred();
				}
					
				// Raise interrupt signal
				kill(getpid(), SIGINT);
			}
		}
		
		// Catch errors
		catch(...) {
		
			// Check if not failed
			if(!failed.load()) {
			
				// Set failed
				failed.store(true);
				
				// Display message
				osyncstream(cout) << "Node failed for unknown reason" << endl;
			
				// Set error occurred
				Common::setErrorOccurred();
					
				// Raise interrupt signal
				kill(getpid(), SIGINT);
			}
		}
		
		// Return false
		return false;
	}
	
	// Go through all completed payments
	for(const uint64_t completedPaymentId : completedPayments) {
	
		// Display message
		osyncstream(cout) << "Completed payment " << completedPaymentId << endl;
	}
	
	// Check if started
	if(started.load()) {
	
		// Run pending confirmed payment callbacks
		payments.runPendingConfirmedPaymentCallbacks();
		
		// Run unsuccessful completed payment callbacks
		payments.runUnsuccessfulCompletedPaymentCallbacks();
	}
	
	// Return true
	return true;
}
