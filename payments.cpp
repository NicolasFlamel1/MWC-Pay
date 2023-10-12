// Header files
#include <iomanip>
#include <iostream>
#include <memory>
#include "./common.h"
#include "./consensus.h"
#include "./payments.h"

using namespace std;


// Constants

// URL size
const size_t Payments::URL_SIZE = 20;

// Any price
const uint64_t Payments::ANY_PRICE = 0;

// Confirmed when on-chain
const uint32_t Payments::CONFIRMED_WHEN_ON_CHAIN = 1;

// No timeout
const uint32_t Payments::NO_TIMEOUT = 0;

// Maximum completed callback size
const size_t Payments::MAXIMUM_COMPLETED_CALLBACK_SIZE = 1 * Common::BYTES_IN_A_KILOBYTE;


// Supporting function implementation

// Constructor
Payments::Payments(sqlite3 *databaseConnection) :

	// Set database connection
	databaseConnection(databaseConnection)
{

	// Check if creating payments table in the database failed
	if(sqlite3_exec(databaseConnection, ("CREATE TABLE IF NOT EXISTS \"Payments\" ("
	
		// Unique number (Used for identifier path and payment proof index)
		"\"Unique Number\" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT CHECK(\"Unique Number\" > 0),"
	
		// ID (Used to lookup payment)
		"\"ID\" INTEGER NOT NULL UNIQUE,"
		
		// URL (URL that listens for payment)
		"\"URL\" TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK(\"URL\" != ''),"
		
		// Created (Timestamp when payment was created
		"\"Created\" INTEGER NOT NULL DEFAULT(UNIXEPOCH('now')) CHECK(\"Created\" >= 0),"
		
		// Completed (Timestamp when payment has been confirmed the required number of times)
		"\"Completed\" INTEGER NULL DEFAULT(NULL) CHECK((\"Completed\" IS NULL AND \"Confirmations\" != \"Required Confirmations\") OR (\"Completed\" IS NOT NULL AND \"Received\" IS NOT NULL AND \"Completed\" >= \"Received\" AND \"Confirmations\" = \"Required Confirmations\")),"
		
		// Price (Optional required price for the payment)
		"\"Price\" INTEGER NULL CHECK((\"Price\" IS NULL AND \"Received\" IS NULL) OR (\"Price\" IS NOT NULL AND \"Price\" != 0)),"
		
		// Required confirmations (Required confirmations for the payment)
		"\"Required Confirmations\" INTEGER NOT NULL CHECK(\"Required Confirmations\" > 0),"
		
		// Expires (Optional timestamp for when the payment expires if it hasn't been received)
		"\"Expires\" INTEGER NULL DEFAULT(NULL) CHECK(\"Expires\" IS NULL OR \"Expires\" > \"Created\"),"
		
		// Received (Timestamp when payment was received)
		"\"Received\" INTEGER NULL DEFAULT(NULL) CHECK((\"Received\" IS NULL AND \"Confirmations\" = 0 AND \"Completed\" IS NULL) OR (\"Received\" IS NOT NULL AND \"Received\" >= \"Created\" AND \"Price\" IS NOT NULL)),"
		
		// Confirmations (Number of confirmations that the payment has received)
		"\"Confirmations\" INTEGER NOT NULL DEFAULT(0) CHECK((\"Confirmations\" = 0 AND \"Received\" IS NULL AND \"Completed\" IS NULL) OR (\"Confirmations\" BETWEEN 0 AND \"Required Confirmations\" - 1 AND \"Received\" IS NOT NULL AND \"Completed\" IS NULL) OR (\"Confirmations\" = \"Required Confirmations\" AND \"Received\" IS NOT NULL AND \"Completed\" IS NOT NULL)),"
		
		// Completed callback (Request to perform when payment is completed)
		"\"Completed Callback\" TEXT NOT NULL CHECK (\"Completed Callback\" LIKE 'http://%' OR \"Completed Callback\" LIKE 'https://%'),"
		
		// Completed callback successful (If a response to the completed callback request was successful)
		"\"Completed Callback Successful\" INTEGER NOT NULL DEFAULT(FALSE) CHECK(\"Completed Callback Successful\" = FALSE OR (\"Completed Callback Successful\" = TRUE AND \"Completed\" IS NOT NULL)),"
		
		// Sender payment proof address (Payment proof address of the sender)
		"\"Sender Payment Proof Address\" TEXT NULL DEFAULT(NULL) CHECK((\"Sender Payment Proof Address\" IS NULL AND \"Received\" IS NULL) OR (\"Sender Payment Proof Address\" IS NOT NULL AND \"Sender Payment Proof Address\" != '' AND \"Received\" IS NOT NULL)),"
		
		// Kernel commitment (Kernel commitment of the payment)
		"\"Kernel Commitment\" BLOB NULL UNIQUE DEFAULT(NULL) CHECK((\"Kernel Commitment\" IS NULL AND \"Received\" IS NULL) OR (\"Kernel Commitment\" IS NOT NULL AND LENGTH(\"Kernel Commitment\") = " + to_string(Crypto::COMMITMENT_SIZE) + " AND \"Received\" IS NOT NULL)),"
		
		// Confirmed height (Height that the payment was confirmed on-chain)
		"\"Confirmed Height\" INTEGER NULL DEFAULT(NULL) CHECK((\"Confirmed Height\" IS NULL AND \"Confirmations\" == 0) OR (\"Confirmed Height\" IS NOT NULL AND \"Confirmed Height\" >= 0 AND \"Confirmations\" != 0)),"
		
		// Sender public blind excess
		"\"Sender Public Blind Excess\" BLOB NULL DEFAULT(NULL) CHECK((\"Sender Public Blind Excess\" IS NULL AND \"Received\" IS NULL) OR (\"Sender Public Blind Excess\" IS NOT NULL AND LENGTH(\"Sender Public Blind Excess\") = " + to_string(Crypto::SECP256K1_PUBLIC_KEY_SIZE) + " AND \"Received\" IS NOT NULL)),"
		
		// Recipient partial signature
		"\"Recipient Partial Signature\" BLOB NULL DEFAULT(NULL) CHECK((\"Recipient Partial Signature\" IS NULL AND \"Received\" IS NULL) OR (\"Recipient Partial Signature\" IS NOT NULL AND LENGTH(\"Recipient Partial Signature\") = " + to_string(Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE) + " AND \"Received\" IS NOT NULL)),"
		
		// Public nonce sum
		"\"Public Nonce Sum\" BLOB NULL DEFAULT(NULL) CHECK((\"Public Nonce Sum\" IS NULL AND \"Received\" IS NULL) OR (\"Public Nonce Sum\" IS NOT NULL AND LENGTH(\"Public Nonce Sum\") = " + to_string(Crypto::SECP256K1_PUBLIC_KEY_SIZE) + " AND \"Received\" IS NOT NULL)),"
		
		// Kernel data
		"\"Kernel Data\" BLOB NULL DEFAULT(NULL) CHECK((\"Kernel Data\" IS NULL AND \"Received\" IS NULL) OR (\"Kernel Data\" IS NOT NULL AND LENGTH(\"Kernel Data\") != 0 AND \"Received\" IS NOT NULL))"
		
	") STRICT;").c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Creating payments table in the database failed");
	}
	
	// Check if creating triggers in the database failed
	if(sqlite3_exec(databaseConnection, ""
	
		// Require defaults trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Require Defaults Trigger\" BEFORE INSERT ON \"Payments\" FOR EACH ROW WHEN NEW.\"Created\" != UNIXEPOCH('now') OR NEW.\"Completed\" IS NOT NULL OR NEW.\"Received\" IS NOT NULL OR NEW.\"Confirmations\" != 0 OR NEW.\"Completed Callback Successful\" != FALSE OR NEW.\"Sender Payment Proof Address\" IS NOT NULL OR NEW.\"Kernel Commitment\" IS NOT NULL OR NEW.\"Confirmed Height\" IS NOT NULL OR NEW.\"Sender Public Blind Excess\" IS NOT NULL OR NEW.\"Recipient Partial Signature\" IS NOT NULL OR NEW.\"Public Nonce Sum\" IS NOT NULL OR NEW.\"Kernel Data\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'defaults are required');"
		"END;"
		
		// Read-only columns trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Read-only Columns Trigger\" BEFORE UPDATE OF \"Unique Number\", \"ID\", \"URL\", \"Created\", \"Required Confirmations\", \"Expires\", \"Completed Callback\" ON \"Payments\" BEGIN "
			"SELECT RAISE(ABORT, 'column is read-only');"
		"END;"
		
		// Persistent rows trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Persistent Rows Trigger\" BEFORE DELETE ON \"Payments\" BEGIN "
			"SELECT RAISE(ABORT, 'row is persistent');"
		"END;"
		
		// Keep completed trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Completed Trigger\" BEFORE UPDATE OF \"Completed\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Completed\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'completed can''t change');"
		"END;"
		
		// Keep price trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Price Trigger\" BEFORE UPDATE OF \"Price\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Price\" IS NOT NULL AND NEW.\"Price\" != OLD.\"Price\" BEGIN "
			"SELECT RAISE(ABORT, 'price can''t change');"
		"END;"
		
		// Keep received trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Received Trigger\" BEFORE UPDATE OF \"Received\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Received\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'received can''t change');"
		"END;"
		
		// Keep completed callback successful trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Completed Callback Successful Trigger\" BEFORE UPDATE OF \"Completed Callback Successful\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Completed Callback Successful\" = TRUE BEGIN "
			"SELECT RAISE(ABORT, 'completed callback successful can''t change');"
		"END;"
		
		// Keep sender payment proof address trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Sender Payment Proof Address Trigger\" BEFORE UPDATE OF \"Sender Payment Proof Address\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Sender Payment Proof Address\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'sender payment proof address can''t change');"
		"END;"
		
		// Keep kernel commitment trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Kernel Commitment Trigger\" BEFORE UPDATE OF \"Kernel Commitment\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Kernel Commitment\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'kernel commitment can''t change');"
		"END;"
		
		// Keep confirmed height trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Confirmed Height Trigger\" BEFORE UPDATE OF \"Confirmed Height\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Completed\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'confirmed height can''t change');"
		"END;"
		
		// Keep sender public blind excess trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Sender Public Blind Excess Trigger\" BEFORE UPDATE OF \"Sender Public Blind Excess\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Sender Public Blind Excess\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'sender public blind excess can''t change');"
		"END;"
		
		// Keep recipient partial signature trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Recipient Partial Signature Trigger\" BEFORE UPDATE OF \"Recipient Partial Signature\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Recipient Partial Signature\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'recipient partial signature can''t change');"
		"END;"
		
		// Keep public nonce sum trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Public Nonce Sum Trigger\" BEFORE UPDATE OF \"Public Nonce Sum\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Public Nonce Sum\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'public nonce sum can''t change');"
		"END;"
		
		// Keep kernel data trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Kernel Data Trigger\" BEFORE UPDATE OF \"Kernel Data\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Kernel Data\" IS NOT NULL BEGIN "
			"SELECT RAISE(ABORT, 'kernel data can''t change');"
		"END;"
	
	"", nullptr, nullptr, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Creating payments triggers in the database failed");
	}
	
	// Check if creating indices in the database failed
	if(sqlite3_exec(databaseConnection, ""
	
		// Completed index
		"CREATE INDEX IF NOT EXISTS \"Payments Completed Index\" ON \"Payments\" (\"Completed\") WHERE \"Completed\" IS NOT NULL;"
		
		// Incomplete index
		"CREATE INDEX IF NOT EXISTS \"Payments Incomplete Index\" ON \"Payments\" (\"Completed\", \"Received\") WHERE \"Completed\" IS NULL AND \"Received\" IS NOT NULL;"
		
		// Confirming index
		"CREATE INDEX IF NOT EXISTS \"Payments Confirming Index\" ON \"Payments\" (\"Completed\", \"Confirmed Height\") WHERE \"Completed\" IS NULL AND \"Confirmed Height\" IS NOT NULL;"
		
		// Unsuccessful completed callback index
		"CREATE INDEX IF NOT EXISTS \"Payments Unsuccessful Completed Callback Index\" ON \"Payments\" (\"Completed\", \"Completed Callback Successful\") WHERE \"Completed\" IS NOT NULL AND \"Completed Callback Successful\" = FALSE;"
	
	"", nullptr, nullptr, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Creating payments indices in the database failed");
	}
	
	// Check if preparing create payment statement failed
	if(sqlite3_prepare_v3(databaseConnection, "INSERT INTO \"Payments\" (\"ID\", \"URL\", \"Price\", \"Required Confirmations\", \"Completed Callback\") VALUES (?, ?, ?, ?, ?);", -1, SQLITE_PREPARE_PERSISTENT, &createPaymentStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing create payment statement failed");
	}
	
	// Automatically free create payment statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> createPaymentStatementUniquePointer(createPaymentStatement, sqlite3_finalize);
	
	// Check if preparing create payment with expiration statement failed
	if(sqlite3_prepare_v3(databaseConnection, "INSERT INTO \"Payments\" (\"ID\", \"URL\", \"Price\", \"Required Confirmations\", \"Expires\", \"Completed Callback\") VALUES (?, ?, ?, ?, UNIXEPOCH('now') + ?, ?);", -1, SQLITE_PREPARE_PERSISTENT, &createPaymentWithExpirationStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing create payment with expiration statement failed");
	}
	
	// Automatically free create payment with expiration statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> createPaymentWithExpirationStatementUniquePointer(createPaymentWithExpirationStatement, sqlite3_finalize);
	
	// Check if preparing get payment info statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Unique Number\", \"URL\", \"Price\", \"Required Confirmations\", \"Received\", \"Confirmations\", IIF(\"Expires\" IS NULL, NULL, MAX(\"Expires\" - UNIXEPOCH('now'), 0)) AS \"Time Remaining\", IIF(\"Received\" IS NULL AND \"Expires\" IS NOT NULL AND UNIXEPOCH('now') >= \"Expires\", 'Expired', IIF(\"Received\" IS NULL, 'Not received', IIF(\"Confirmations\" = 0, 'Received', IIF(\"Completed\" IS NULL, 'Confirmed', 'Completed')))) AS \"Status\" FROM \"Payments\" WHERE \"ID\" = ?;", -1, SQLITE_PREPARE_PERSISTENT, &getPaymentInfoStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get payment info statement failed");
	}
	
	// Automatically free get payment info statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getPaymentInfoStatementUniquePointer(getPaymentInfoStatement, sqlite3_finalize);
	
	// Check if preparing get receiving payment for URL statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Unique Number\", \"ID\", \"Price\" FROM \"Payments\" WHERE \"URL\" = ? AND \"Received\" IS NULL AND (\"Expires\" IS NULL OR UNIXEPOCH('now') < \"Expires\");", -1, SQLITE_PREPARE_PERSISTENT, &getReceivingPaymentForUrlStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get receiving payment for URL statement failed");
	}
	
	// Automatically free get receiving payment for URL statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getReceivingPaymentForUrlStatementUniquePointer(getReceivingPaymentForUrlStatement, sqlite3_finalize);
	
	// Check if preparing get completed payments statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Unique Number\", \"ID\", \"URL\", \"Created\", \"Completed\", \"Price\", \"Required Confirmations\", \"Received\", \"Completed Callback\", \"Completed Callback Successful\", \"Sender Payment Proof Address\", \"Kernel Commitment\", \"Confirmed Height\" FROM \"Payments\" WHERE \"Completed\" IS NOT NULL ORDER BY \"Completed\" ASC;", -1, 0, &getCompletedPaymentsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get completed payments statement failed");
	}
	
	// Automatically free get completed payments statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getCompletedPaymentsStatementUniquePointer(getCompletedPaymentsStatement, sqlite3_finalize);
	
	// Check if preparing get payment statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Unique Number\", \"URL\", \"Created\", \"Completed\", \"Price\", \"Required Confirmations\", \"Received\", \"Completed Callback\", \"Completed Callback Successful\", \"Sender Payment Proof Address\", \"Kernel Commitment\", \"Confirmed Height\", IIF(\"Received\" IS NULL AND \"Expires\" IS NOT NULL AND UNIXEPOCH('now') >= \"Expires\", 'Expired', IIF(\"Received\" IS NULL, 'Not received', IIF(\"Confirmations\" = 0, 'Received', IIF(\"Completed\" IS NULL, 'Confirmed', 'Completed')))) AS \"Status\" FROM \"Payments\" WHERE \"ID\" = ?;", -1, 0, &getPaymentStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get payment statement failed");
	}
	
	// Automatically free get payment statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getPaymentStatementUniquePointer(getPaymentStatement, sqlite3_finalize);
	
	// Check if preparing get unconfirmed payment statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Unique Number\", \"ID\", \"Required Confirmations\", \"Sender Public Blind Excess\", \"Recipient Partial Signature\", \"Public Nonce Sum\", \"Kernel Data\" FROM \"Payments\" WHERE \"Kernel Commitment\" = ? AND \"Confirmed Height\" IS NULL;", -1, SQLITE_PREPARE_PERSISTENT, &getUnconfirmedPaymentStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get unconfirmed payment statement failed");
	}
	
	// Automatically free get unconfirmed payment statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getUnconfirmedPaymentStatementUniquePointer(getUnconfirmedPaymentStatement, sqlite3_finalize);
	
	// Check if preparing get incomplete payments statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"ID\", \"Required Confirmations\", \"Kernel Commitment\", \"Confirmed Height\", \"Sender Public Blind Excess\", \"Recipient Partial Signature\", \"Public Nonce Sum\", \"Kernel Data\" FROM \"Payments\" WHERE \"Completed\" IS NULL AND \"Received\" IS NOT NULL;", -1, SQLITE_PREPARE_PERSISTENT, &getIncompletePaymentsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get incomplete payments statement failed");
	}
	
	// Automatically free get incomplete payments statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getIncompletePaymentsStatementUniquePointer(getIncompletePaymentsStatement, sqlite3_finalize);
	
	// Check if preparing get confirming payments statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"ID\", \"Required Confirmations\", \"Confirmed Height\" FROM \"Payments\" WHERE \"Completed\" IS NULL AND \"Confirmed Height\" IS NOT NULL;", -1, SQLITE_PREPARE_PERSISTENT, &getConfirmingPaymentsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get confirming payments statement failed");
	}
	
	// Automatically free get confirming payments statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getConfirmingPaymentsStatementUniquePointer(getConfirmingPaymentsStatement, sqlite3_finalize);
	
	// Check if preparing get unsuccessful completed callback payments statement
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"ID\", \"Completed Callback\" FROM \"Payments\" WHERE \"Completed\" IS NOT NULL AND \"Completed Callback Successful\" = FALSE;", -1, SQLITE_PREPARE_PERSISTENT, &getUnsuccessfulCompletedCallbackPaymentsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get unsuccessful completed callback payments statement failed");
	}
	
	// Automatically free get unsuccessful completed callback payments statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getUnsuccessfulCompletedCallbackPaymentsStatementUniquePointer(getUnsuccessfulCompletedCallbackPaymentsStatement, sqlite3_finalize);
	
	// Check if preparing set payment received statement failed
	if(sqlite3_prepare_v3(databaseConnection, "UPDATE \"Payments\" SET \"Price\" = ?, \"Received\" = UNIXEPOCH('now'), \"Sender Payment Proof Address\" = ?, \"Kernel Commitment\" = ?, \"Sender Public Blind Excess\" = ?, \"Recipient Partial Signature\" = ?, \"Public Nonce Sum\" = ?, \"Kernel Data\" = ? WHERE \"ID\" = ?;", -1, SQLITE_PREPARE_PERSISTENT, &setPaymentReceivedStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing set payment received statement failed");
	}
	
	// Automatically free set payment received statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> setPaymentReceivedStatementUniquePointer(setPaymentReceivedStatement, sqlite3_finalize);
	
	// Check if preparing reorg incomplete payments statement failed
	if(sqlite3_prepare_v3(databaseConnection, "UPDATE \"Payments\" SET \"Confirmations\" = 0, \"Confirmed Height\" = NULL WHERE \"Completed\" IS NULL AND \"Confirmed Height\" IS NOT NULL AND \"Confirmed Height\" >= ?;", -1, SQLITE_PREPARE_PERSISTENT, &reorgIncompletePaymentsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing reorg incomplete payments statement failed");
	}
	
	// Automatically free reorg incomplete payments statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> reorgIncompletePaymentsStatementUniquePointer(reorgIncompletePaymentsStatement, sqlite3_finalize);
	
	// Check if preparing set payment confirmations statement failed
	if(sqlite3_prepare_v3(databaseConnection, "UPDATE \"Payments\" SET \"Confirmations\" = MIN(?, \"Required Confirmations\"), \"Completed\" = IIF(?1 >= \"Required Confirmations\", UNIXEPOCH('now'), NULL), \"Confirmed Height\" = IIF(?1 > 0, ?, NULL) WHERE \"ID\" = ?;", -1, SQLITE_PREPARE_PERSISTENT, &setPaymentConfirmationsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing set payment confirmations statement failed");
	}
	
	// Automatically free set payment confirmations statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> setPaymentConfirmationsStatementUniquePointer(setPaymentConfirmationsStatement, sqlite3_finalize);
	
	// Check if preparing set payment successful completed callback statement failed
	if(sqlite3_prepare_v3(databaseConnection, "UPDATE \"Payments\" SET \"Completed Callback Successful\" = TRUE WHERE \"ID\" = ?;", -1, SQLITE_PREPARE_PERSISTENT, &setPaymentSuccessfulCompletedCallbackStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing set payment successful completed callback statement failed");
	}
	
	// Automatically free set payment successful completed callback statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> setPaymentSuccessfulCompletedCallbackStatementUniquePointer(setPaymentSuccessfulCompletedCallbackStatement, sqlite3_finalize);
	
	// Check if preparing begin transaction statement failed
	if(sqlite3_prepare_v3(databaseConnection, "BEGIN;", -1, SQLITE_PREPARE_PERSISTENT, &beginTransactionStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing begin transaction statement failed");
	}
	
	// Automatically free begin transaction statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> beginTransactionStatementUniquePointer(beginTransactionStatement, sqlite3_finalize);
	
	// Check if preparing commit transaction statement failed
	if(sqlite3_prepare_v3(databaseConnection, "COMMIT;", -1, SQLITE_PREPARE_PERSISTENT, &commitTransactionStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing commit transaction statement failed");
	}
	
	// Automatically free commit transaction statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> commitTransactionStatementUniquePointer(commitTransactionStatement, sqlite3_finalize);
	
	// Check if preparing rollback transaction statement failed
	if(sqlite3_prepare_v3(databaseConnection, "ROLLBACK;", -1, SQLITE_PREPARE_PERSISTENT, &rollbackTransactionStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing rollback transaction statement failed");
	}
	
	// Automatically free rollback transaction statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> rollbackTransactionStatementUniquePointer(rollbackTransactionStatement, sqlite3_finalize);
	
	// Release create payment statement unique pointer
	createPaymentStatementUniquePointer.release();
	
	// Release create payment with expiration statement unique pointer
	createPaymentWithExpirationStatementUniquePointer.release();
	
	// Release get payment info statement unique pointer
	getPaymentInfoStatementUniquePointer.release();
	
	// Release get receiving payment for URL statement unique pointer
	getReceivingPaymentForUrlStatementUniquePointer.release();
	
	// Release get completed payments statement unique pointer
	getCompletedPaymentsStatementUniquePointer.release();
	
	// Release get payment statement unique pointer
	getPaymentStatementUniquePointer.release();
	
	// Release get unconfirmed payment statement unique pointer
	getUnconfirmedPaymentStatementUniquePointer.release();
	
	// Release get incomplete payments statement unique pointer
	getIncompletePaymentsStatementUniquePointer.release();
	
	// Release get confirming payments statement unique pointer
	getConfirmingPaymentsStatementUniquePointer.release();
	
	// Release get unsuccessful completed callback payments statement unique pointer
	getUnsuccessfulCompletedCallbackPaymentsStatementUniquePointer.release();
	
	// Release set payment received statement unique pointer
	setPaymentReceivedStatementUniquePointer.release();
	
	// Release reorg incomplete payments statement unique pointer
	reorgIncompletePaymentsStatementUniquePointer.release();
	
	// Release set payment confirmations statement unique pointer
	setPaymentConfirmationsStatementUniquePointer.release();
	
	// Release set payment successful completed callback statement unique pointer
	setPaymentSuccessfulCompletedCallbackStatementUniquePointer.release();
	
	// Release begin transaction statement unique pointer
	beginTransactionStatementUniquePointer.release();
	
	// Release commit transaction statement unique pointer
	commitTransactionStatementUniquePointer.release();
	
	// Release rollback transaction statement unique pointer
	rollbackTransactionStatementUniquePointer.release();
}

// Destructor
Payments::~Payments() {

	// Check if freeing create payment statement failed
	if(sqlite3_finalize(createPaymentStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing create payment statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing create payment with expiration statement failed
	if(sqlite3_finalize(createPaymentWithExpirationStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing create payment with expiration statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing get payment info statement failed
	if(sqlite3_finalize(getPaymentInfoStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get payment info statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing get receiving payment for URL statement failed
	if(sqlite3_finalize(getReceivingPaymentForUrlStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get receiving payment for URL statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing get completed payments statement failed
	if(sqlite3_finalize(getCompletedPaymentsStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get completed payments statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing get payment statement failed
	if(sqlite3_finalize(getPaymentStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get payment statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing get unconfirmed payment statement failed
	if(sqlite3_finalize(getUnconfirmedPaymentStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get unconfirmed payment statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing get incomplete payments statement failed
	if(sqlite3_finalize(getIncompletePaymentsStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get incomplete payments statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing get confirming payments statement failed
	if(sqlite3_finalize(getConfirmingPaymentsStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get confirming payments statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing set payment received statement failed
	if(sqlite3_finalize(setPaymentReceivedStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing set payment received statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing reorg incomplete payments statement failed
	if(sqlite3_finalize(reorgIncompletePaymentsStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing reorg incomplete payments statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing set payment confirmations statement failed
	if(sqlite3_finalize(setPaymentConfirmationsStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing set payment confirmations statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing set payment successful completed callback statement failed
	if(sqlite3_finalize(setPaymentSuccessfulCompletedCallbackStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing set payment successful completed callback statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing begin transaction statement failed
	if(sqlite3_finalize(beginTransactionStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing begin transaction statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing commit transaction statement failed
	if(sqlite3_finalize(commitTransactionStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing commit transaction statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing rollback transaction statement failed
	if(sqlite3_finalize(rollbackTransactionStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing rollback transaction statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
}

// Create payment
bool Payments::createPayment(const uint64_t id, const char *url, const uint64_t price, const uint32_t requiredConfirmations, const uint32_t timeout, const char *completedCallback) {

	// Try
	try {
	
		// Lock
		lock_guard guard(lock);
		
		// Check if a timeout exists
		if(timeout) {
		
			// Check if resetting and clearing create payment with expiration statement failed
			if(sqlite3_reset(createPaymentWithExpirationStatement) != SQLITE_OK || sqlite3_clear_bindings(createPaymentWithExpirationStatement) != SQLITE_OK) {
			
				// Return false
				return false;
			}
		
			// Check if binding create payment with expiration statement's values failed
			if(sqlite3_bind_int64(createPaymentWithExpirationStatement, 1, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK || sqlite3_bind_text(createPaymentWithExpirationStatement, 2, url, -1, SQLITE_STATIC) != SQLITE_OK || (price ? sqlite3_bind_int64(createPaymentWithExpirationStatement, 3, *reinterpret_cast<const int64_t *>(&price)) : sqlite3_bind_null(createPaymentWithExpirationStatement, 3)) != SQLITE_OK || sqlite3_bind_int64(createPaymentWithExpirationStatement, 4, requiredConfirmations) != SQLITE_OK || sqlite3_bind_int64(createPaymentWithExpirationStatement, 5, timeout) != SQLITE_OK || sqlite3_bind_text(createPaymentWithExpirationStatement, 6, completedCallback, -1, SQLITE_STATIC) != SQLITE_OK) {
			
				// Return false
				return false;
			}
			
			// Check if running create payment with expiration statement failed
			if(sqlite3_step(createPaymentWithExpirationStatement) != SQLITE_DONE) {
			
				// Reset create payment with expiration statement
				sqlite3_reset(createPaymentWithExpirationStatement);
				
				// Return false
				return false;
			}
		}
		
		// Otherwise
		else {
		
			// Check if resetting and clearing create payment statement failed
			if(sqlite3_reset(createPaymentStatement) != SQLITE_OK || sqlite3_clear_bindings(createPaymentStatement) != SQLITE_OK) {
			
				// Return false
				return false;
			}
			
			// Check if binding create payment statement's values failed
			if(sqlite3_bind_int64(createPaymentStatement, 1, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK || sqlite3_bind_text(createPaymentStatement, 2, url, -1, SQLITE_STATIC) != SQLITE_OK || (price ? sqlite3_bind_int64(createPaymentStatement, 3, *reinterpret_cast<const int64_t *>(&price)) : sqlite3_bind_null(createPaymentStatement, 3)) != SQLITE_OK || sqlite3_bind_int64(createPaymentStatement, 4, requiredConfirmations) != SQLITE_OK || sqlite3_bind_text(createPaymentStatement, 5, completedCallback, -1, SQLITE_STATIC) != SQLITE_OK) {
			
				// Return false
				return false;
			}
			
			// Check if running create payment statement failed
			if(sqlite3_step(createPaymentStatement) != SQLITE_DONE) {
			
				// Reset create payment statement
				sqlite3_reset(createPaymentStatement);
				
				// Return false
				return false;
			}
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get payment info
tuple<uint64_t, string, optional<uint64_t>, uint64_t, bool, uint64_t, optional<uint64_t>, string> Payments::getPaymentInfo(const uint64_t id) {

	// Lock
	lock_guard guard(lock);
	
	// Check if resetting and clearing get payment info statement failed
	if(sqlite3_reset(getPaymentInfoStatement) != SQLITE_OK || sqlite3_clear_bindings(getPaymentInfoStatement) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Resetting and clearing get payment info statement failed");
	}

	// Check if binding get payment info statement's values failed
	if(sqlite3_bind_int64(getPaymentInfoStatement, 1, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Binding get payment info statement's values failed");
	}
	
	// Check if running get payment info statement failed
	const int sqlResult = sqlite3_step(getPaymentInfoStatement);
	if(sqlResult != SQLITE_ROW && sqlResult != SQLITE_DONE) {
	
		// Reset get payment info statement
		sqlite3_reset(getPaymentInfoStatement);
		
		// Throw exception
		throw runtime_error("Running get payment info statement failed");
	}
	
	// Check if payment was found
	if(sqlResult == SQLITE_ROW) {
		
		// Create result from payment's info
		const int64_t priceStorage = (sqlite3_column_type(getPaymentInfoStatement, 2) == SQLITE_NULL) ? 0 : sqlite3_column_int64(getPaymentInfoStatement, 2);
		const tuple<uint64_t, string, optional<uint64_t>, uint64_t, bool, uint64_t, optional<uint64_t>, string> result(
		
			// Unique number
			sqlite3_column_int64(getPaymentInfoStatement, 0),
			
			// URL
			reinterpret_cast<const char *>(sqlite3_column_text(getPaymentInfoStatement, 1)),
			
			// Price
			(sqlite3_column_type(getPaymentInfoStatement, 2) == SQLITE_NULL) ? nullopt : optional<uint64_t>(*reinterpret_cast<const uint64_t *>(&priceStorage)),
			
			// Required confirmations
			sqlite3_column_int64(getPaymentInfoStatement, 3),
			
			// Received
			sqlite3_column_type(getPaymentInfoStatement, 4) != SQLITE_NULL,
			
			// Confirmations
			sqlite3_column_int64(getPaymentInfoStatement, 5),
			
			// Time remaining
			(sqlite3_column_type(getPaymentInfoStatement, 6) == SQLITE_NULL) ? nullopt : optional<uint64_t>(sqlite3_column_int64(getPaymentInfoStatement, 6)),
			
			// Status
			reinterpret_cast<const char *>(sqlite3_column_text(getPaymentInfoStatement, 7))
		);
	
		// Check if running get payment info statement failed
		if(sqlite3_step(getPaymentInfoStatement) != SQLITE_DONE) {
		
			// Reset get payment info statement
			sqlite3_reset(getPaymentInfoStatement);
			
			// Throw exception
			throw runtime_error("Running get payment info statement failed");
		}
		
		// Return result
		return result;
	}
	
	// Return nothing
	return {};
}

// Get receiving payment for URL
tuple<uint64_t, uint64_t, optional<uint64_t>> Payments::getReceivingPaymentForUrl(const char *url) {

	// Check if resetting and clearing get receiving payment for URL statement failed
	if(sqlite3_reset(getReceivingPaymentForUrlStatement) != SQLITE_OK || sqlite3_clear_bindings(getReceivingPaymentForUrlStatement) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Resetting and clearing get receiving payment for URL statement failed");
	}

	// Check if binding get receiving payment for URL statement's values failed
	if(sqlite3_bind_text(getReceivingPaymentForUrlStatement, 1, url, -1, SQLITE_STATIC) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Binding get receiving payment for URL statement's values failed");
	}
	
	// Check if running get receiving payment for URL statement failed
	const int sqlResult = sqlite3_step(getReceivingPaymentForUrlStatement);
	if(sqlResult != SQLITE_ROW && sqlResult != SQLITE_DONE) {
	
		// Reset get receiving payment for URL statement
		sqlite3_reset(getReceivingPaymentForUrlStatement);
		
		// Throw exception
		throw runtime_error("Running get receiving payment for URL statement failed");
	}
	
	// Check if payment was found
	if(sqlResult == SQLITE_ROW) {
		
		// Create result from payment's info
		const int64_t idStorage = sqlite3_column_int64(getReceivingPaymentForUrlStatement, 1);
		const int64_t priceStorage = (sqlite3_column_type(getReceivingPaymentForUrlStatement, 2) == SQLITE_NULL) ? 0 : sqlite3_column_int64(getReceivingPaymentForUrlStatement, 2);
		const tuple<uint64_t, uint64_t, optional<uint64_t>> result(
		
			// Unique number
			sqlite3_column_int64(getReceivingPaymentForUrlStatement, 0),
			
			// ID
			*reinterpret_cast<const uint64_t *>(&idStorage),
			
			// Price
			(sqlite3_column_type(getReceivingPaymentForUrlStatement, 2) == SQLITE_NULL) ? nullopt : optional<uint64_t>(*reinterpret_cast<const uint64_t *>(&priceStorage))
		);
	
		// Check if running get receiving payment for URL statement failed
		if(sqlite3_step(getReceivingPaymentForUrlStatement) != SQLITE_DONE) {
		
			// Reset get receiving payment for URL statement
			sqlite3_reset(getReceivingPaymentForUrlStatement);
			
			// Throw exception
			throw runtime_error("Running get receiving payment for URL statement failed");
		}
		
		// Return result
		return result;
	}
	
	// Return nothing
	return {};
}

// Display completed payments
void Payments::displayCompletedPayments(const Wallet &wallet) {

	// Try
	try {
	
		// Initialize completed payment exists
		bool completedPaymentExists = false;
		
		// Go through all completed payments
		int sqlResult;
		while((sqlResult = sqlite3_step(getCompletedPaymentsStatement)) != SQLITE_DONE) {
		
			// Check if running get completed payments statement failed
			if(sqlResult != SQLITE_ROW) {
				
				// Throw exception
				throw runtime_error("Running get completed payments statement failed");
			}
			
			// Check if a signal was received
			if(!Common::allowSignals() || !Common::blockSignals() || Common::getSignalReceived()) {
			
				// Block signals
				Common::blockSignals();
				
				// Throw exception
				throw runtime_error("Getting completed payment failed");
			}
			
			// Display payment's ID
			const int64_t idStorage = sqlite3_column_int64(getCompletedPaymentsStatement, 1);
			cout << "Payment " << *reinterpret_cast<const uint64_t *>(&idStorage) << ':' << endl;
			
			// Display payment's status
			cout << "\tStatus: Completed" << endl;
			
			// Display payment's URL
			cout << "\tURL path: " << sqlite3_column_text(getCompletedPaymentsStatement, 2) << endl;
			
			// Display payment's created at
			time_t time = sqlite3_column_int64(getCompletedPaymentsStatement, 3);
			cout << "\tCreated at: " << put_time(gmtime(&time), "%c %Z") << endl;
			
			// Display payment's received at
			time = sqlite3_column_int64(getCompletedPaymentsStatement, 7);
			cout << "\tReceived at: " << put_time(gmtime(&time), "%c %Z") << endl;
			
			// Display payment's completed at
			time = sqlite3_column_int64(getCompletedPaymentsStatement, 4);
			cout << "\tCompleted at: " << put_time(gmtime(&time), "%c %Z") << endl;
			
			// Display payment's price
			const int64_t priceStorage = sqlite3_column_int64(getCompletedPaymentsStatement, 5);
			const uint64_t price = *reinterpret_cast<const uint64_t *>(&priceStorage);
			cout << "\tPrice: " << Common::getNumberInNumberBase(price, Consensus::NUMBER_BASE) << endl;
			
			// Display payment's required confirmations
			cout << "\tRequired confirmations: " << sqlite3_column_int64(getCompletedPaymentsStatement, 6) << endl;
			
			// Display payment's confirmed height
			cout << "\tConfirmed height: " << sqlite3_column_int64(getCompletedPaymentsStatement, 12) << endl;
			
			// Check if getting commitment failed
			uint8_t commitment[Crypto::COMMITMENT_SIZE];
			const uint64_t identifierPath = sqlite3_column_int64(getCompletedPaymentsStatement, 0);
			if(!wallet.getCommitment(commitment, identifierPath, price)) {
			
				// Throw exception
				throw runtime_error("Getting commitment failed");
			}
			
			// Display payment's output commitment
			cout << "\tOutput commitment: " << Common::toHexString(commitment, sizeof(commitment)) << " (" << Consensus::OUTPUT_COMMITMENT_EXPLORER_URL << Common::toHexString(commitment, sizeof(commitment)) << ')' << endl;
			
			// Display payment's kernel commitment
			const uint8_t *kernelCommitment = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getCompletedPaymentsStatement, 11));
			cout << "\tKernel excess: " << Common::toHexString(kernelCommitment, sqlite3_column_bytes(getCompletedPaymentsStatement, 11)) << " (" << Consensus::KERNEL_COMMITMENT_EXPLORER_URL << Common::toHexString(kernelCommitment, sqlite3_column_bytes(getCompletedPaymentsStatement, 11)) << ')' << endl;
			
			// Display payment's payment proof addresses
			const char *senderPaymentProofAddress = reinterpret_cast<const char *>(sqlite3_column_text(getCompletedPaymentsStatement, 10));
			cout << "\tSender payment proof address: " << senderPaymentProofAddress << endl;
			const uint64_t &paymentProofIndex = identifierPath;
			cout << "\tRecipient payment proof address: " << wallet.getTorPaymentProofAddress(paymentProofIndex) << endl;
			
			// Check if getting recipient payment proof signature failed
			uint8_t recipientPaymentProofSignature[Crypto::ED25519_SIGNATURE_SIZE];
			if(!wallet.getTorPaymentProofSignature(recipientPaymentProofSignature, paymentProofIndex, kernelCommitment, senderPaymentProofAddress, price)) {
			
				// Throw exception
				throw runtime_error("Getting recipient payment proof signature failed");
			}
			
			// Display payment's payment proof signature
			cout << "\tRecipient payment proof signature: " << Common::toHexString(recipientPaymentProofSignature, sizeof(recipientPaymentProofSignature)) << endl;
			
			// Display payment's completed callback
			cout << "\tCompleted callback: " << sqlite3_column_text(getCompletedPaymentsStatement, 8) << endl;
			
			// Display payment's completed successful callback
			cout << "\tCompleted callback was successful: " << (sqlite3_column_int64(getCompletedPaymentsStatement, 9) ? "True" : "False") << endl;
			
			// Set completed payment exists
			completedPaymentExists = true;
		}
		
		// Check if no completed payments exist
		if(!completedPaymentExists) {
		
			// Display message
			cout << "No completed payments exist" << endl;
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Reset get completed payments statement
		sqlite3_reset(getCompletedPaymentsStatement);
		
		// Throw
		throw;
	}
}

// Display payment
void Payments::displayPayment(const uint64_t id, const Wallet &wallet) {

	// Check if binding get payment statement's values failed
	if(sqlite3_bind_int64(getPaymentStatement, 1, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Binding get payment statement's values failed");
	}
	
	// Check if running get payment statement failed
	const int sqlResult = sqlite3_step(getPaymentStatement);
	if(sqlResult != SQLITE_ROW && sqlResult != SQLITE_DONE) {
	
		// Reset get payment statement
		sqlite3_reset(getPaymentStatement);
		
		// Throw exception
		throw runtime_error("Running get payment statement failed");
	}
	
	// Check if payment was found
	if(sqlResult == SQLITE_ROW) {
		
		// Try
		try {
		
			// Display payment's ID
			cout << "Payment " << id << ':' << endl;
			
			// Display payment's status
			cout << "\tStatus: " << sqlite3_column_text(getPaymentStatement, 12) << endl;
			
			// Display payment's URL
			cout << "\tURL path: " << sqlite3_column_text(getPaymentStatement, 1) << endl;
			
			// Display payment's created at
			time_t time = sqlite3_column_int64(getPaymentStatement, 2);
			cout << "\tCreated at: " << put_time(gmtime(&time), "%c %Z") << endl;
			
			// check if payment hasn't been received
			if(sqlite3_column_type(getPaymentStatement, 6) == SQLITE_NULL) {
			
				// Display payment's received at
				cout << "\tReceived at: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's received at
				time = sqlite3_column_int64(getPaymentStatement, 6);
				cout << "\tReceived at: " << put_time(gmtime(&time), "%c %Z") << endl;
			}
			
			// check if payment hasn't been completed
			if(sqlite3_column_type(getPaymentStatement, 3) == SQLITE_NULL) {
			
				// Display payment's completed at
				cout << "\tCompleted at: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's completed at
				time = sqlite3_column_int64(getPaymentStatement, 3);
				cout << "\tCompleted at: " << put_time(gmtime(&time), "%c %Z") << endl;
			}
			
			// check if payment doesn't have a price
			uint64_t price = 0;
			if(sqlite3_column_type(getPaymentStatement, 4) == SQLITE_NULL) {
			
				// Display payment's price
				cout << "\tPrice: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's price
				const int64_t priceStorage = sqlite3_column_int64(getPaymentStatement, 4);
				price = *reinterpret_cast<const uint64_t *>(&priceStorage);
				cout << "\tPrice: " << Common::getNumberInNumberBase(price, Consensus::NUMBER_BASE) << endl;
			}
			
			// Display payment's required confirmations
			cout << "\tRequired confirmations: " << sqlite3_column_int64(getPaymentStatement, 5) << endl;
			
			// check if payment hasn't been confirmed
			if(sqlite3_column_type(getPaymentStatement, 11) == SQLITE_NULL) {
			
				// Display payment's confirmed height
				cout << "\tConfirmed height: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's confirmed height
				cout << "\tConfirmed height: " << sqlite3_column_int64(getPaymentStatement, 11) << endl;
			}
			
			// check if payment hasn't been received
			const uint64_t identifierPath = sqlite3_column_int64(getPaymentStatement, 0);
			const uint64_t &paymentProofIndex = identifierPath;
			if(sqlite3_column_type(getPaymentStatement, 6) == SQLITE_NULL) {
			
				// Display payment's output commitment
				cout << "\tOutput commitment: N/A" << endl;
				
				// Display payment's kernel commitment
				cout << "\tKernel excess: N/A" << endl;
				
				// Display payment's sender payment proof addresses
				cout << "\tSender payment proof address: N/A" << endl;
				
				// Display payment's payment proof signature
				cout << "\tRecipient payment proof signature: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Check if getting commitment failed
				uint8_t commitment[Crypto::COMMITMENT_SIZE];
				if(!wallet.getCommitment(commitment, identifierPath, price)) {
				
					// Throw exception
					throw runtime_error("Getting commitment failed");
				}
				
				// Display payment's output commitment
				cout << "\tOutput commitment: " << Common::toHexString(commitment, sizeof(commitment)) << " (" << Consensus::OUTPUT_COMMITMENT_EXPLORER_URL << Common::toHexString(commitment, sizeof(commitment)) << ')' << endl;
				
				// Display payment's kernel commitment
				const uint8_t *kernelCommitment = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getPaymentStatement, 10));
				cout << "\tKernel excess: " << Common::toHexString(kernelCommitment, sqlite3_column_bytes(getPaymentStatement, 10)) << " (" << Consensus::KERNEL_COMMITMENT_EXPLORER_URL << Common::toHexString(kernelCommitment, sqlite3_column_bytes(getPaymentStatement, 10)) << ')' << endl;
				
				// Display payment's sender payment proof addresses
				const char *senderPaymentProofAddress = reinterpret_cast<const char *>(sqlite3_column_text(getPaymentStatement, 9));
				cout << "\tSender payment proof address: " << senderPaymentProofAddress << endl;
				
				// Check if getting recipient payment proof signature failed
				uint8_t recipientPaymentProofSignature[Crypto::ED25519_SIGNATURE_SIZE];
				if(!wallet.getTorPaymentProofSignature(recipientPaymentProofSignature, paymentProofIndex, kernelCommitment, senderPaymentProofAddress, price)) {
				
					// Throw exception
					throw runtime_error("Getting recipient payment proof signature failed");
				}
				
				// Display payment's payment proof signature
				cout << "\tRecipient payment proof signature: " << Common::toHexString(recipientPaymentProofSignature, sizeof(recipientPaymentProofSignature)) << endl;
			}
			
			// Display payment's recipient payment proof addresses
			cout << "\tRecipient payment proof address: " << wallet.getTorPaymentProofAddress(paymentProofIndex) << endl;
			
			// Display payment's completed callback
			cout << "\tCompleted callback: " << sqlite3_column_text(getPaymentStatement, 7) << endl;
			
			// Display payment's completed successful callback
			cout << "\tCompleted callback was successful: " << (sqlite3_column_int64(getPaymentStatement, 8) ? "True" : "False") << endl;
			
			// Check if running get payment statement failed
			if(sqlite3_step(getPaymentStatement) != SQLITE_DONE) {
			
				// Reset get payment statement
				sqlite3_reset(getPaymentStatement);
			}
		}
	
		// Catch errors
		catch(...) {
		
			// Reset get payment statement
			sqlite3_reset(getPaymentStatement);
			
			// Throw
			throw;
		}
	}
	
	// Otherwise
	else {
	
		// Display message
		cout << "Payment doesn't exist" << endl;
	}
}

// Get unconfirmed payment
tuple<uint64_t, uint64_t, uint64_t, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>> Payments::getUnconfirmedPayment(const uint8_t kernelCommitment[Crypto::COMMITMENT_SIZE]) {

	// Check if resetting and clearing get unconfirmed payment statement failed
	if(sqlite3_reset(getUnconfirmedPaymentStatement) != SQLITE_OK || sqlite3_clear_bindings(getUnconfirmedPaymentStatement) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Resetting and clearing get unconfirmed payment statement failed");
	}

	// Check if binding get unconfirmed payment statement's values failed
	if(sqlite3_bind_blob(getUnconfirmedPaymentStatement, 1, kernelCommitment, Crypto::COMMITMENT_SIZE, SQLITE_STATIC) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Binding get unconfirmed payment statement's values failed");
	}
	
	// Check if running get unconfirmed payment statement failed
	const int sqlResult = sqlite3_step(getUnconfirmedPaymentStatement);
	if(sqlResult != SQLITE_ROW && sqlResult != SQLITE_DONE) {
	
		// Reset get unconfirmed payment statement
		sqlite3_reset(getUnconfirmedPaymentStatement);
		
		// Throw exception
		throw runtime_error("Running get unconfirmed payment statement failed");
	}
	
	// Check if payment was found
	if(sqlResult == SQLITE_ROW) {
	
		// Create result from payment's info
		const int64_t idStorage = sqlite3_column_int64(getUnconfirmedPaymentStatement, 1);
		const uint8_t *senderPublicBlindExcess = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getUnconfirmedPaymentStatement, 3));
		const uint8_t *recipientPartialSignature = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getUnconfirmedPaymentStatement, 4));
		const uint8_t *publicNonceSum = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getUnconfirmedPaymentStatement, 5));
		const uint8_t *kernelData = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getUnconfirmedPaymentStatement, 6));
		const tuple<uint64_t, uint64_t, uint64_t, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>> result(
		
			// Unique number
			sqlite3_column_int64(getUnconfirmedPaymentStatement, 0),
			
			// ID
			*reinterpret_cast<const uint64_t *>(&idStorage),
			
			// Required confirmations
			sqlite3_column_int64(getUnconfirmedPaymentStatement, 2),
			
			// Sender public blind excess
			vector<uint8_t>(senderPublicBlindExcess, senderPublicBlindExcess + sqlite3_column_bytes(getUnconfirmedPaymentStatement, 3)),
			
			// Recipient partial signature
			vector<uint8_t>(recipientPartialSignature, recipientPartialSignature + sqlite3_column_bytes(getUnconfirmedPaymentStatement, 4)),
			
			// Public nonce sum
			vector<uint8_t>(publicNonceSum, publicNonceSum + sqlite3_column_bytes(getUnconfirmedPaymentStatement, 5)),
			
			// Kernel data
			vector<uint8_t>(kernelData, kernelData + sqlite3_column_bytes(getUnconfirmedPaymentStatement, 6))
		);
	
		// Check if running get unconfirmed payment statement failed
		if(sqlite3_step(getUnconfirmedPaymentStatement) != SQLITE_DONE) {
		
			// Reset get unconfirmed payment statement
			sqlite3_reset(getUnconfirmedPaymentStatement);
			
			// Throw exception
			throw runtime_error("Running get unconfirmed payment statement failed");
		}
		
		// Return result
		return result;
	}
	
	// Return nothing
	return {};
}

// Get incomplete payments
list<tuple<uint64_t, uint64_t, vector<uint8_t>, optional<uint64_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>>> Payments::getIncompletePayments() {

	// Check if resetting get incomplete payments statement failed
	if(sqlite3_reset(getIncompletePaymentsStatement) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Resetting get incomplete payments statement failed");
	}
	
	// Initialize result
	list<tuple<uint64_t, uint64_t, vector<uint8_t>, optional<uint64_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>, vector<uint8_t>>> result;
	
	// Go through all incomplete payments
	int sqlResult;
	while((sqlResult = sqlite3_step(getIncompletePaymentsStatement)) != SQLITE_DONE) {
	
		// Check if running get incomplete payments statement failed
		if(sqlResult != SQLITE_ROW) {
		
			// Reset get incomplete payments statement
			sqlite3_reset(getIncompletePaymentsStatement);
			
			// Throw exception
			throw runtime_error("Running get incomplete payments statement failed");
		}
		
		// Add payment's info to result
		const int64_t idStorage = sqlite3_column_int64(getIncompletePaymentsStatement, 0);
		const uint8_t *kernelCommitment = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getIncompletePaymentsStatement, 2));
		const uint8_t *senderPublicBlindExcess = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getIncompletePaymentsStatement, 4));
		const uint8_t *recipientPartialSignature = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getIncompletePaymentsStatement, 5));
		const uint8_t *publicNonceSum = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getIncompletePaymentsStatement, 6));
		const uint8_t *kernelData = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getIncompletePaymentsStatement, 7));
		result.emplace_back( 
		
			// ID
			*reinterpret_cast<const uint64_t *>(&idStorage),
			
			// Required confirmations
			sqlite3_column_int64(getIncompletePaymentsStatement, 1),
			
			// Kernel commitment
			vector<uint8_t>(kernelCommitment, kernelCommitment + sqlite3_column_bytes(getIncompletePaymentsStatement, 2)),
			
			// Confirmed height
			(sqlite3_column_type(getIncompletePaymentsStatement, 3) == SQLITE_NULL) ? nullopt : optional<uint64_t>(sqlite3_column_int64(getIncompletePaymentsStatement, 3)),
			
			// Sender public blind excess
			vector<uint8_t>(senderPublicBlindExcess, senderPublicBlindExcess + sqlite3_column_bytes(getIncompletePaymentsStatement, 4)),
			
			// Recipient partial signature
			vector<uint8_t>(recipientPartialSignature, recipientPartialSignature + sqlite3_column_bytes(getIncompletePaymentsStatement, 5)),
			
			// Public nonce sum
			vector<uint8_t>(publicNonceSum, publicNonceSum + sqlite3_column_bytes(getIncompletePaymentsStatement, 6)),
			
			// Kernel data
			vector<uint8_t>(kernelData, kernelData + sqlite3_column_bytes(getIncompletePaymentsStatement, 7))
		);
	}
	
	// Return result
	return result;
}

// Get confirming payments
list<tuple<uint64_t, uint64_t, uint64_t>> Payments::getConfirmingPayments() {

	// Check if resetting get confirming payments statement failed
	if(sqlite3_reset(getConfirmingPaymentsStatement) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Resetting get confirming payments statement failed");
	}
	
	// Initialize result
	list<tuple<uint64_t, uint64_t, uint64_t>> result;
	
	// Go through all confirming payments
	int sqlResult;
	while((sqlResult = sqlite3_step(getConfirmingPaymentsStatement)) != SQLITE_DONE) {
	
		// Check if running get confirming payments statement failed
		if(sqlResult != SQLITE_ROW) {
		
			// Reset get confirming payments statement
			sqlite3_reset(getConfirmingPaymentsStatement);
			
			// Throw exception
			throw runtime_error("Running get confirming payments statement failed");
		}
		
		// Add payment's info to result
		const int64_t idStorage = sqlite3_column_int64(getConfirmingPaymentsStatement, 0);
		result.emplace_back( 
		
			// ID
			*reinterpret_cast<const uint64_t *>(&idStorage),
			
			// Required confirmations
			sqlite3_column_int64(getConfirmingPaymentsStatement, 1),
			
			// Confirmed height
			sqlite3_column_int64(getConfirmingPaymentsStatement, 2)
		);
	}
	
	// Return result
	return result;
}

// Set payment received
bool Payments::setPaymentReceived(const uint64_t id, const uint64_t price, const char *senderPaymentProofAddress, const uint8_t kernelCommitment[Crypto::COMMITMENT_SIZE], const uint8_t senderPublicBlindExcess[Crypto::SECP256K1_PUBLIC_KEY_SIZE], const uint8_t recipientPartialSignature[Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE], const uint8_t publicNonceSum[Crypto::SECP256K1_PUBLIC_KEY_SIZE], const uint8_t *kernelData, const size_t kernelDataLength) {

	// Check if resetting and clearing set payment received statement failed
	if(sqlite3_reset(setPaymentReceivedStatement) != SQLITE_OK || sqlite3_clear_bindings(setPaymentReceivedStatement) != SQLITE_OK) {
	
		// Return false
		return false;
	}
	
	// Check if binding set payment received statement's values failed
	if(sqlite3_bind_int64(setPaymentReceivedStatement, 1, *reinterpret_cast<const int64_t *>(&price)) != SQLITE_OK || sqlite3_bind_text(setPaymentReceivedStatement, 2, senderPaymentProofAddress, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_blob(setPaymentReceivedStatement, 3, kernelCommitment, Crypto::COMMITMENT_SIZE, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_blob(setPaymentReceivedStatement, 4, senderPublicBlindExcess, Crypto::SECP256K1_PUBLIC_KEY_SIZE, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_blob(setPaymentReceivedStatement, 5, recipientPartialSignature, Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_blob(setPaymentReceivedStatement, 6, publicNonceSum, Crypto::SECP256K1_PUBLIC_KEY_SIZE, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_blob(setPaymentReceivedStatement, 7, kernelData, kernelDataLength, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_int64(setPaymentReceivedStatement, 8, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK) {
	
		// Return false
		return false;
	}
	
	// Check if running set payment received statement failed
	if(sqlite3_step(setPaymentReceivedStatement) != SQLITE_DONE) {
	
		// Reset set payment received statement
		sqlite3_reset(setPaymentReceivedStatement);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Update payments with reorg
bool Payments::updatePaymentsWithReorg(const uint64_t reorgHeight) {

	// Try
	try {
	
		// Check if resetting and clearing reorg incomplete payments statement failed
		if(sqlite3_reset(reorgIncompletePaymentsStatement) != SQLITE_OK || sqlite3_clear_bindings(reorgIncompletePaymentsStatement) != SQLITE_OK) {
		
			// Return false
			return false;
		}
		
		// Check if binding reorg incomplete payments statement's values failed
		if(sqlite3_bind_int64(reorgIncompletePaymentsStatement, 1, reorgHeight) != SQLITE_OK) {
		
			// Return false
			return false;
		}
		
		// Check if running reorg incomplete payments statement failed
		if(sqlite3_step(reorgIncompletePaymentsStatement) != SQLITE_DONE) {
		
			// Reset reorg incomplete payments statement
			sqlite3_reset(reorgIncompletePaymentsStatement);
			
			// Return false
			return false;
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Set payment confirmed
bool Payments::setPaymentConfirmed(const uint64_t id, const uint32_t confirmations, const uint64_t confirmedHeight) {

	// Check if resetting and clearing set payment confirmed statement failed
	if(sqlite3_reset(setPaymentConfirmationsStatement) != SQLITE_OK || sqlite3_clear_bindings(setPaymentConfirmationsStatement) != SQLITE_OK) {
	
		// Return false
		return false;
	}
	
	// Check if binding set payment confirmed statement's values failed
	if(sqlite3_bind_int64(setPaymentConfirmationsStatement, 1, confirmations) != SQLITE_OK || sqlite3_bind_int64(setPaymentConfirmationsStatement, 2, confirmedHeight) != SQLITE_OK || sqlite3_bind_int64(setPaymentConfirmationsStatement, 3, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK) {
	
		// Return false
		return false;
	}
	
	// Check if running set payment confirmed statement failed
	if(sqlite3_step(setPaymentConfirmationsStatement) != SQLITE_DONE) {
	
		// Reset set payment confirmed statement
		sqlite3_reset(setPaymentConfirmationsStatement);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Get lock
mutex &Payments::getLock() {

	// Return lock
	return lock;
}

// Begin transaction
bool Payments::beginTransaction() {

	// Check if resetting begin transaction statement failed
	if(sqlite3_reset(beginTransactionStatement) != SQLITE_OK) {
	
		// Return false
		return false;
	}
	
	// Check if running begin transaction statement failed
	if(sqlite3_step(beginTransactionStatement) != SQLITE_DONE) {
	
		// Reset begin transaction statement
		sqlite3_reset(beginTransactionStatement);
		
		// Return false
		return false;
	}
	
	// Check if database is in autocommit mode
	if(sqlite3_get_autocommit(databaseConnection)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Commit transaction
bool Payments::commitTransaction() {

	// Check if database is in autocommit mode
	if(sqlite3_get_autocommit(databaseConnection)) {
	
		// Return false
		return false;
	}
	
	// Check if resetting commit transaction statement failed
	if(sqlite3_reset(commitTransactionStatement) != SQLITE_OK) {
	
		// Return false
		return false;
	}
	
	// Check if running commit transaction statement failed
	if(sqlite3_step(commitTransactionStatement) != SQLITE_DONE) {
	
		// Reset commit transaction statement
		sqlite3_reset(commitTransactionStatement);
		
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Rollback transaction
bool Payments::rollbackTransaction() {

	// Check if database isn't in autocommit mode
	if(!sqlite3_get_autocommit(databaseConnection)) {
	
		// Check if resetting rollback transaction statement failed
		if(sqlite3_reset(rollbackTransactionStatement) != SQLITE_OK) {
		
			// Return false
			return false;
		}
		
		// Check if running rollback transaction statement failed
		if(sqlite3_step(rollbackTransactionStatement) != SQLITE_DONE) {
		
			// Reset rollback transaction statement
			sqlite3_reset(rollbackTransactionStatement);
			
			// Return false
			return false;
		}
	}
	
	// Return true
	return true;
}

// Run unsuccessful completed payment callbacks
void Payments::runUnsuccessfulCompletedPaymentCallbacks() {

	// Try
	try {

		// Go through all unsuccessful completed callback payments
		for(const tuple<uint64_t, string> &paymentInfo : getUnsuccessfulCompletedCallbackPayments()) {
		
			// Try
			try {
		
				// Check if sending HTTP request to the payment's completed callback was successful
				const string &paymentCompletedCallback = get<1>(paymentInfo);
				if(Common::sendHttpRequest(paymentCompletedCallback.c_str())) {
				
					// Set that payment's completed callback was successful
					const uint64_t &paymentId = get<0>(paymentInfo);
					setPaymentSuccessfulCompletedCallback(paymentId);
				}
			}
			
			// Catch errors
			catch(...) {
			
			}
		}
	}
	
	// Catch errors
	catch(...) {
	
	}
}

// Get unsuccessful completed callback payments
list<tuple<uint64_t, string>> Payments::getUnsuccessfulCompletedCallbackPayments() {

	// Lock
	lock_guard guard(lock);
	
	// Check if resetting get unsuccessful completed callback payments statement failed
	if(sqlite3_reset(getUnsuccessfulCompletedCallbackPaymentsStatement) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Resetting get unsuccessful completed callback payments statement failed");
	}
	
	// Initialize result
	list<tuple<uint64_t, string>> result;
	
	// Go through all unsuccessful completed callback payments
	int sqlResult;
	while((sqlResult = sqlite3_step(getUnsuccessfulCompletedCallbackPaymentsStatement)) != SQLITE_DONE) {
	
		// Check if running get unsuccessful completed callback payments statement failed
		if(sqlResult != SQLITE_ROW) {
		
			// Reset get unsuccessful completed callback payments statement
			sqlite3_reset(getUnsuccessfulCompletedCallbackPaymentsStatement);
			
			// Throw exception
			throw runtime_error("Running get unsuccessful completed callback payments statement failed");
		}
		
		// Add payment's info to result
		const int64_t idStorage = sqlite3_column_int64(getUnsuccessfulCompletedCallbackPaymentsStatement, 0);
		result.emplace_back( 
		
			// ID
			*reinterpret_cast<const uint64_t *>(&idStorage),
			
			// Completed callback
			reinterpret_cast<const char *>(sqlite3_column_text(getUnsuccessfulCompletedCallbackPaymentsStatement, 1))
		);
	}
	
	// Return result
	return result;
}

// Set payment successful completed callback
bool Payments::setPaymentSuccessfulCompletedCallback(const uint64_t id) {

	// Try
	try {
	
		// Lock
		lock_guard guard(lock);
		
		// Check if resetting and clearing set payment successful completed callback statement failed
		if(sqlite3_reset(setPaymentSuccessfulCompletedCallbackStatement) != SQLITE_OK || sqlite3_clear_bindings(setPaymentSuccessfulCompletedCallbackStatement) != SQLITE_OK) {
		
			// Return false
			return false;
		}
		
		// Check if binding set payment successful completed callback statement's values failed
		if(sqlite3_bind_int64(setPaymentSuccessfulCompletedCallbackStatement, 1, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK) {
		
			// Return false
			return false;
		}
		
		// Check if running set payment successful completed callback statement failed
		if(sqlite3_step(setPaymentSuccessfulCompletedCallbackStatement) != SQLITE_DONE) {
		
			// Reset set payment successful completed callback statement
			sqlite3_reset(setPaymentSuccessfulCompletedCallbackStatement);
			
			// Return false
			return false;
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}
