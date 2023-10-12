// Header guard
#ifndef PAYMENTS_H
#define PAYMENTS_H


// Header files
#include <list>
#include <mutex>
#include <optional>
#include "./crypto.h"
#include "sqlite3.h"
#include "./wallet.h"

using namespace std;


// Classes

// Payments class
class Payments final {

	// Public
	public:
	
		// Constructor
		explicit Payments(sqlite3 *databaseConnection);
		
		// Destructor
		~Payments();
		
		// URL size
		static const size_t URL_SIZE;
		
		// URL characters
		static const inline char URL_CHARACTERS[] = "abcdefghijkmnpqrstuvwxyz23456789";
		
		// Any price
		static const uint64_t ANY_PRICE;
		
		// Confirmed when on-chain
		static const uint32_t CONFIRMED_WHEN_ON_CHAIN;

		// No timeout
		static const uint32_t NO_TIMEOUT;
		
		// Maximum completed callback size
		static const size_t MAXIMUM_COMPLETED_CALLBACK_SIZE;
		
		// Create payment
		bool createPayment(const uint64_t id, const char *url, const uint64_t price, const uint32_t requiredConfirmations, const uint32_t timeout, const char *completedCallback);
		
		// Get payment info
		tuple<uint64_t, string, optional<uint64_t>, uint64_t, bool, uint64_t, optional<uint64_t>, string> getPaymentInfo(const uint64_t id);
		
		// Get receiving payment for URL
		tuple<uint64_t, uint64_t, optional<uint64_t>> getReceivingPaymentForUrl(const char *url);
		
		// Display completed payments
		void displayCompletedPayments(const Wallet &wallet);
		
		// Display payment
		void displayPayment(const uint64_t id, const Wallet &wallet);
		
		// Get unconfirmed payment
		tuple<uint64_t, uint64_t, uint64_t, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>> getUnconfirmedPayment(const uint8_t kernelCommitment[Crypto::COMMITMENT_SIZE]);
		
		// Get incomplete payments
		list<tuple<uint64_t, uint64_t, vector<uint8_t>, optional<uint64_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>>> getIncompletePayments();
		
		// Get confirming payments
		list<tuple<uint64_t, uint64_t, uint64_t>> getConfirmingPayments();
		
		// Set payment received
		bool setPaymentReceived(const uint64_t id, const uint64_t price, const char *senderPaymentProofAddress, const uint8_t kernelCommitment[Crypto::COMMITMENT_SIZE], const uint8_t senderPublicBlindExcess[Crypto::SECP256K1_PUBLIC_KEY_SIZE], const uint8_t recipientPartialSignature[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t publicNonceSum[Crypto::SECP256K1_PUBLIC_KEY_SIZE], const uint8_t *kernelData, const size_t kernelDataLength);
		
		// Update payments with reorg
		bool updatePaymentsWithReorg(const uint64_t reorgHeight);
		
		// Set payment confirmed
		bool setPaymentConfirmed(const uint64_t id, const uint32_t confirmations, const uint64_t confirmedHeight);
		
		// Get lock
		mutex &getLock();
		
		// Begin transaction
		bool beginTransaction();
		
		// Commit transaction
		bool commitTransaction();
		
		// Rollback transaction
		bool rollbackTransaction();
		
		// Run unsuccessful completed payment callbacks
		void runUnsuccessfulCompletedPaymentCallbacks();
		
	// Private
	private:
	
		// Get unsuccessful completed callback payments
		list<tuple<uint64_t, string>> getUnsuccessfulCompletedCallbackPayments();
		
		// Set payment successful completed callback
		bool setPaymentSuccessfulCompletedCallback(const uint64_t id);
		
		// Database connection
		sqlite3 *databaseConnection;
		
		// Create payment statement
		sqlite3_stmt *createPaymentStatement;
		
		// Create payment with expiration statement
		sqlite3_stmt *createPaymentWithExpirationStatement;
		
		// Get payment info statement
		sqlite3_stmt *getPaymentInfoStatement;
		
		// Get receiving payment for URL statement
		sqlite3_stmt *getReceivingPaymentForUrlStatement;
		
		// Get completed payments statement
		sqlite3_stmt *getCompletedPaymentsStatement;
		
		// Get payment statement
		sqlite3_stmt *getPaymentStatement;
		
		// Get unconfirmed payment statement
		sqlite3_stmt *getUnconfirmedPaymentStatement;
		
		// Get incomplete payments statement
		sqlite3_stmt *getIncompletePaymentsStatement;
		
		// Get confirming payments statement
		sqlite3_stmt *getConfirmingPaymentsStatement;
		
		// Get unsuccessful completed callback payments statement
		sqlite3_stmt *getUnsuccessfulCompletedCallbackPaymentsStatement;
		
		// Set payment received statement
		sqlite3_stmt *setPaymentReceivedStatement;
		
		// Reorg incomplete payments statement
		sqlite3_stmt *reorgIncompletePaymentsStatement;
		
		// Set payment confirmations statement
		sqlite3_stmt *setPaymentConfirmationsStatement;
		
		// Set payment successful completed callback statement
		sqlite3_stmt *setPaymentSuccessfulCompletedCallbackStatement;
		
		// Begin transaction statement
		sqlite3_stmt *beginTransactionStatement;
		
		// Commit transaction statement
		sqlite3_stmt *commitTransactionStatement;
		
		// Rollback transaction statement
		sqlite3_stmt *rollbackTransactionStatement;
		
		// Lock
		mutex lock;
};


#endif
