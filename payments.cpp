// Header files
#include <cstring>
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

// Maximum received callback size
const size_t Payments::MAXIMUM_RECEIVED_CALLBACK_SIZE = Payments::MAXIMUM_COMPLETED_CALLBACK_SIZE;

// No received callback
const char *Payments::NO_RECEIVED_CALLBACK = nullptr;

// Maximum confirmed callback size
const size_t Payments::MAXIMUM_CONFIRMED_CALLBACK_SIZE = Payments::MAXIMUM_COMPLETED_CALLBACK_SIZE;

// No confirmed callback
const char *Payments::NO_CONFIRMED_CALLBACK = nullptr;

// Maximum expired callback size
const size_t Payments::MAXIMUM_EXPIRED_CALLBACK_SIZE = Payments::MAXIMUM_COMPLETED_CALLBACK_SIZE;

// No expired callback
const char *Payments::NO_EXPIRED_CALLBACK = nullptr;


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
		
		// Sender public blind excess (Sender public blind excess of the payment)
		"\"Sender Public Blind Excess\" BLOB NULL DEFAULT(NULL) CHECK((\"Sender Public Blind Excess\" IS NULL AND \"Received\" IS NULL) OR (\"Sender Public Blind Excess\" IS NOT NULL AND LENGTH(\"Sender Public Blind Excess\") = " + to_string(Crypto::SECP256K1_PUBLIC_KEY_SIZE) + " AND \"Received\" IS NOT NULL)),"
		
		// Recipient partial signature (Recipient partial signature of the payment)
		"\"Recipient Partial Signature\" BLOB NULL DEFAULT(NULL) CHECK((\"Recipient Partial Signature\" IS NULL AND \"Received\" IS NULL) OR (\"Recipient Partial Signature\" IS NOT NULL AND LENGTH(\"Recipient Partial Signature\") = " + to_string(Crypto::SECP256K1_SINGLE_SIGNER_SIGNATURE_SIZE) + " AND \"Received\" IS NOT NULL)),"
		
		// Public nonce sum (Public nonce sum of the payment)
		"\"Public Nonce Sum\" BLOB NULL DEFAULT(NULL) CHECK((\"Public Nonce Sum\" IS NULL AND \"Received\" IS NULL) OR (\"Public Nonce Sum\" IS NOT NULL AND LENGTH(\"Public Nonce Sum\") = " + to_string(Crypto::SECP256K1_PUBLIC_KEY_SIZE) + " AND \"Received\" IS NOT NULL)),"
		
		// Kernel data (Kernel data of the payment)
		"\"Kernel Data\" BLOB NULL DEFAULT(NULL) CHECK((\"Kernel Data\" IS NULL AND \"Received\" IS NULL) OR (\"Kernel Data\" IS NOT NULL AND LENGTH(\"Kernel Data\") != 0 AND \"Received\" IS NOT NULL)),"
		
		// Received callback (Request to perform when payment is received)
		"\"Received Callback\" TEXT NULL DEFAULT(NULL) CHECK(\"Received Callback\" IS NULL OR \"Received Callback\" LIKE 'http://%' OR \"Received Callback\" LIKE 'https://%'),"
		
		// Confirmed callback (Request to perform when the payments number of confirmations changes and it's not completed)
		"\"Confirmed Callback\" TEXT NULL DEFAULT(NULL) CHECK(\"Confirmed Callback\" IS NULL OR \"Confirmed Callback\" LIKE 'http://%' OR \"Confirmed Callback\" LIKE 'https://%'),"
		
		// Confirmations changed (If the payment's number of confirmations changed)
		"\"Confirmations Changed\" INTEGER NOT NULL DEFAULT(FALSE) CHECK(\"Confirmations Changed\" = FALSE OR (\"Confirmations Changed\" = TRUE AND \"Received\" IS NOT NULL AND \"Completed\" IS NULL)),"
		
		// Expired callback (Request to perform when the payment expires)
		"\"Expired Callback\" TEXT NULL DEFAULT(NULL) CHECK(\"Expired Callback\" IS NULL OR ((\"Expired Callback\" LIKE 'http://%' OR \"Expired Callback\" LIKE 'https://%') AND \"Expires\" IS NOT NULL)),"
		
		// Expired callback successful (If a response to the expired callback request was successful)
		"\"Expired Callback Successful\" INTEGER NOT NULL DEFAULT(FALSE) CHECK(\"Expired Callback Successful\" = FALSE OR (\"Expired Callback Successful\" = TRUE AND \"Received\" IS NULL AND \"Expired Callback\" IS NOT NULL AND \"Expires\" IS NOT NULL))"
		
	") STRICT;").c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Creating payments table in the database failed");
	}
	
	// Check if getting if received callback column exists in the payments table in the database failed
	bool receivedCallbackColumnExists;
	if(sqlite3_exec(databaseConnection, "SELECT COUNT() > 0 FROM pragma_table_info(\"Payments\") WHERE \"name\"='Received Callback';", [](void *argument, int numberOfRows, char **rows, char **columnNames) -> int {
	
		// Get received callback column exists from argument
		bool *receivedCallbackColumnExists = reinterpret_cast<bool *>(argument);
		
		// Set received callback column exists
		*receivedCallbackColumnExists = numberOfRows && !strcmp(rows[0], "1");
		
		// Return success
		return 0;
		
	}, &receivedCallbackColumnExists, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Getting if received callback column exists in the payments table in the database failed");
	}
	
	// Check if received callback column doesn't exist
	if(!receivedCallbackColumnExists) {
	
		// Check if adding received callback column to payments table in the database failed
		if(sqlite3_exec(databaseConnection, "ALTER TABLE \"Payments\" ADD COLUMN \"Received Callback\" TEXT NULL DEFAULT(NULL) CHECK(\"Received Callback\" IS NULL OR \"Received Callback\" LIKE 'http://%' OR \"Received Callback\" LIKE 'https://%');", nullptr, nullptr, nullptr) != SQLITE_OK) {
		
			// Throw exception
			throw runtime_error("Adding received callback column to payments table in the database failed");
		}
	}
	
	// Check if getting if confirmed callback column exists in the payments table in the database failed
	bool confirmedCallbackColumnExists;
	if(sqlite3_exec(databaseConnection, "SELECT COUNT() > 0 FROM pragma_table_info(\"Payments\") WHERE \"name\"='Confirmed Callback';", [](void *argument, int numberOfRows, char **rows, char **columnNames) -> int {
	
		// Get confirmed callback column exists from argument
		bool *confirmedCallbackColumnExists = reinterpret_cast<bool *>(argument);
		
		// Set confirmed callback column exists
		*confirmedCallbackColumnExists = numberOfRows && !strcmp(rows[0], "1");
		
		// Return success
		return 0;
		
	}, &confirmedCallbackColumnExists, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Getting if confirmed callback column exists in the payments table in the database failed");
	}
	
	// Check if confirmed callback column doesn't exist
	if(!confirmedCallbackColumnExists) {
	
		// Check if adding confirmed callback column to payments table in the database failed
		if(sqlite3_exec(databaseConnection, "ALTER TABLE \"Payments\" ADD COLUMN \"Confirmed Callback\" TEXT NULL DEFAULT(NULL) CHECK(\"Confirmed Callback\" IS NULL OR \"Confirmed Callback\" LIKE 'http://%' OR \"Confirmed Callback\" LIKE 'https://%');", nullptr, nullptr, nullptr) != SQLITE_OK) {
		
			// Throw exception
			throw runtime_error("Adding confirmed callback column to payments table in the database failed");
		}
	}
	
	// Check if getting if confirmations changed column exists in the payments table in the database failed
	bool confirmationsChangedColumnExists;
	if(sqlite3_exec(databaseConnection, "SELECT COUNT() > 0 FROM pragma_table_info(\"Payments\") WHERE \"name\"='Confirmations Changed';", [](void *argument, int numberOfRows, char **rows, char **columnNames) -> int {
	
		// Get confirmations changed column exists from argument
		bool *confirmationsChangedColumnExists = reinterpret_cast<bool *>(argument);
		
		// Set confirmations changed column exists
		*confirmationsChangedColumnExists = numberOfRows && !strcmp(rows[0], "1");
		
		// Return success
		return 0;
		
	}, &confirmationsChangedColumnExists, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Getting if confirmations changed column exists in the payments table in the database failed");
	}
	
	// Check if confirmations changed column doesn't exist
	if(!confirmationsChangedColumnExists) {
	
		// Check if adding confirmations changed column to payments table in the database failed
		if(sqlite3_exec(databaseConnection, "ALTER TABLE \"Payments\" ADD COLUMN \"Confirmations Changed\" INTEGER NOT NULL DEFAULT(FALSE) CHECK(\"Confirmations Changed\" = FALSE OR (\"Confirmations Changed\" = TRUE AND \"Received\" IS NOT NULL AND \"Completed\" IS NULL));", nullptr, nullptr, nullptr) != SQLITE_OK) {
		
			// Throw exception
			throw runtime_error("Adding confirmations changed column to payments table in the database failed");
		}
	}
	
	// Check if getting if expired callback column exists in the payments table in the database failed
	bool expiredCallbackColumnExists;
	if(sqlite3_exec(databaseConnection, "SELECT COUNT() > 0 FROM pragma_table_info(\"Payments\") WHERE \"name\"='Expired Callback';", [](void *argument, int numberOfRows, char **rows, char **columnNames) -> int {
	
		// Get expired callback column exists from argument
		bool *expiredCallbackColumnExists = reinterpret_cast<bool *>(argument);
		
		// Set expired callback column exists
		*expiredCallbackColumnExists = numberOfRows && !strcmp(rows[0], "1");
		
		// Return success
		return 0;
		
	}, &expiredCallbackColumnExists, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Getting if expired callback column exists in the payments table in the database failed");
	}
	
	// Check if expired callback column doesn't exist
	if(!expiredCallbackColumnExists) {
	
		// Check if adding expired callback column to payments table in the database failed
		if(sqlite3_exec(databaseConnection, "ALTER TABLE \"Payments\" ADD COLUMN \"Expired Callback\" TEXT NULL DEFAULT(NULL) CHECK(\"Expired Callback\" IS NULL OR ((\"Expired Callback\" LIKE 'http://%' OR \"Expired Callback\" LIKE 'https://%') AND \"Expires\" IS NOT NULL));", nullptr, nullptr, nullptr) != SQLITE_OK) {
		
			// Throw exception
			throw runtime_error("Adding expired callback column to payments table in the database failed");
		}
	}
	
	// Check if getting if expired callback successful column exists in the payments table in the database failed
	bool expiredCallbackSuccessfulColumnExists;
	if(sqlite3_exec(databaseConnection, "SELECT COUNT() > 0 FROM pragma_table_info(\"Payments\") WHERE \"name\"='Expired Callback Successful';", [](void *argument, int numberOfRows, char **rows, char **columnNames) -> int {
	
		// Get expired callback successful column exists from argument
		bool *expiredCallbackSuccessfulColumnExists = reinterpret_cast<bool *>(argument);
		
		// Set confirmations changed column exists
		*expiredCallbackSuccessfulColumnExists = numberOfRows && !strcmp(rows[0], "1");
		
		// Return success
		return 0;
		
	}, &expiredCallbackSuccessfulColumnExists, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Getting if expired callback successful column exists in the payments table in the database failed");
	}
	
	// Check if expired callback successful column doesn't exist
	if(!expiredCallbackSuccessfulColumnExists) {
	
		// Check if adding expired callback successful column to payments table in the database failed
		if(sqlite3_exec(databaseConnection, "ALTER TABLE \"Payments\" ADD COLUMN \"Expired Callback Successful\" INTEGER NOT NULL DEFAULT(FALSE) CHECK(\"Expired Callback Successful\" = FALSE OR (\"Expired Callback Successful\" = TRUE AND \"Received\" IS NULL AND \"Expired Callback\" IS NOT NULL AND \"Expires\" IS NOT NULL));", nullptr, nullptr, nullptr) != SQLITE_OK) {
		
			// Throw exception
			throw runtime_error("Adding expired callback successful column to payments table in the database failed");
		}
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
		
		// Keep received callback
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Received Callback\" BEFORE UPDATE OF \"Received Callback\" ON \"Payments\" BEGIN "
			"SELECT RAISE(ABORT, 'received callback can''t change');"
		"END;"
		
		// Keep confirmed callback
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Confirmed Callback\" BEFORE UPDATE OF \"Confirmed Callback\" ON \"Payments\" BEGIN "
			"SELECT RAISE(ABORT, 'confirmed callback can''t change');"
		"END;"
		
		// Require default confirmations changed trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Require Default Confirmations Changed Trigger\" BEFORE INSERT ON \"Payments\" FOR EACH ROW WHEN NEW.\"Confirmations Changed\" != FALSE BEGIN "
			"SELECT RAISE(ABORT, 'default confirmations changed is required');"
		"END;"
		
		// Keep expired callback
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Expired Callback\" BEFORE UPDATE OF \"Expired Callback\" ON \"Payments\" BEGIN "
			"SELECT RAISE(ABORT, 'received callback can''t change');"
		"END;"
		
		// Require default expired callback successful trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Require Default Expired Callback Successful Trigger\" BEFORE INSERT ON \"Payments\" FOR EACH ROW WHEN NEW.\"Expired Callback Successful\" != FALSE BEGIN "
			"SELECT RAISE(ABORT, 'default expired callback successful is required');"
		"END;"
		
		// Keep expired callback successful trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Keep Expired Callback Successful Trigger\" BEFORE UPDATE OF \"Expired Callback Successful\" ON \"Payments\" FOR EACH ROW WHEN OLD.\"Expired Callback Successful\" = TRUE BEGIN "
			"SELECT RAISE(ABORT, 'expired callback successful can''t change');"
		"END;"
		
		// Check expired callback successful trigger
		"CREATE TRIGGER IF NOT EXISTS \"Payments Check Expired Callback Successful Trigger\" BEFORE UPDATE OF \"Expired Callback Successful\" ON \"Payments\" FOR EACH ROW WHEN NEW.\"Expired Callback Successful\" = TRUE AND OLD.\"Expires\" IS NOT NULL AND OLD.\"Expires\" > UNIXEPOCH('now') BEGIN "
			"SELECT RAISE(ABORT, 'expired callback successful is invalid');"
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
		
		// Pending confirmed callback index
		"CREATE INDEX IF NOT EXISTS \"Payments Pending Confirmed Callback Index\" ON \"Payments\" (\"Confirmed Callback\", \"Confirmations Changed\") WHERE \"Confirmed Callback\" IS NOT NULL AND \"Confirmations Changed\" = TRUE;"
		
		// Unsuccessful expired callback index
		"CREATE INDEX IF NOT EXISTS \"Payments Unsuccessful Expired Callback Index\" ON \"Payments\" (\"Received\", \"Expired Callback\", \"Expired Callback Successful\", \"Expires\") WHERE \"Received\" IS NULL AND \"Expired Callback\" IS NOT NULL AND \"Expired Callback Successful\" = FALSE AND \"Expires\" IS NOT NULL;"
	
	"", nullptr, nullptr, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Creating payments indices in the database failed");
	}
	
	// Check if preparing create payment statement failed
	if(sqlite3_prepare_v3(databaseConnection, "INSERT INTO \"Payments\" (\"ID\", \"URL\", \"Price\", \"Required Confirmations\", \"Completed Callback\", \"Received Callback\", \"Confirmed Callback\") VALUES (?, ?, ?, ?, ?, ?, ?);", -1, SQLITE_PREPARE_PERSISTENT, &createPaymentStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing create payment statement failed");
	}
	
	// Automatically free create payment statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> createPaymentStatementUniquePointer(createPaymentStatement, sqlite3_finalize);
	
	// Check if preparing create payment with expiration statement failed
	if(sqlite3_prepare_v3(databaseConnection, "INSERT INTO \"Payments\" (\"ID\", \"URL\", \"Price\", \"Required Confirmations\", \"Expires\", \"Completed Callback\", \"Received Callback\", \"Confirmed Callback\", \"Expired Callback\") VALUES (?, ?, ?, ?, UNIXEPOCH('now') + ?, ?, ?, ?, ?);", -1, SQLITE_PREPARE_PERSISTENT, &createPaymentWithExpirationStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing create payment with expiration statement failed");
	}
	
	// Automatically free create payment with expiration statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> createPaymentWithExpirationStatementUniquePointer(createPaymentWithExpirationStatement, sqlite3_finalize);
	
	// Check if preparing get payment info statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Unique Number\", \"URL\", \"Price\", \"Required Confirmations\", \"Received\", \"Confirmations\", IIF(\"Expires\" IS NULL, NULL, MAX(\"Expires\" - UNIXEPOCH('now'), 0)) AS \"Time Remaining\", IIF(\"Received\" IS NULL AND \"Expires\" IS NOT NULL AND \"Expires\" <= UNIXEPOCH('now'), 'Expired', IIF(\"Received\" IS NULL, 'Not received', IIF(\"Confirmations\" = 0, 'Received', IIF(\"Completed\" IS NULL, 'Confirmed', 'Completed')))) AS \"Status\" FROM \"Payments\" WHERE \"ID\" = ?;", -1, SQLITE_PREPARE_PERSISTENT, &getPaymentInfoStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get payment info statement failed");
	}
	
	// Automatically free get payment info statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getPaymentInfoStatementUniquePointer(getPaymentInfoStatement, sqlite3_finalize);
	
	// Check if preparing get receiving payment for URL statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Unique Number\", \"ID\", \"Price\", \"Received Callback\" FROM \"Payments\" WHERE \"URL\" = ? AND \"Received\" IS NULL AND (\"Expires\" IS NULL OR \"Expires\" > UNIXEPOCH('now'));", -1, SQLITE_PREPARE_PERSISTENT, &getReceivingPaymentForUrlStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get receiving payment for URL statement failed");
	}
	
	// Automatically free get receiving payment for URL statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getReceivingPaymentForUrlStatementUniquePointer(getReceivingPaymentForUrlStatement, sqlite3_finalize);
	
	// Check if preparing get completed payments statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Unique Number\", \"ID\", \"URL\", \"Created\", \"Completed\", \"Price\", \"Required Confirmations\", \"Expires\", \"Received\", \"Completed Callback\", \"Completed Callback Successful\", \"Sender Payment Proof Address\", \"Kernel Commitment\", \"Confirmed Height\", \"Received Callback\", \"Confirmed Callback\", \"Expired Callback\", \"Expired Callback Successful\" FROM \"Payments\" WHERE \"Completed\" IS NOT NULL ORDER BY \"Completed\" ASC;", -1, 0, &getCompletedPaymentsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get completed payments statement failed");
	}
	
	// Automatically free get completed payments statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getCompletedPaymentsStatementUniquePointer(getCompletedPaymentsStatement, sqlite3_finalize);
	
	// Check if preparing get payment statement failed
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Unique Number\", \"URL\", \"Created\", \"Completed\", \"Price\", \"Required Confirmations\", \"Expires\", \"Received\", \"Completed Callback\", \"Completed Callback Successful\", \"Sender Payment Proof Address\", \"Kernel Commitment\", \"Confirmed Height\", \"Received Callback\", \"Confirmed Callback\", \"Expired Callback\", \"Expired Callback Successful\", IIF(\"Received\" IS NULL AND \"Expires\" IS NOT NULL AND \"Expires\" <= UNIXEPOCH('now'), 'Expired', IIF(\"Received\" IS NULL, 'Not received', IIF(\"Confirmations\" = 0, 'Received', IIF(\"Completed\" IS NULL, 'Confirmed', 'Completed')))) AS \"Status\" FROM \"Payments\" WHERE \"ID\" = ?;", -1, 0, &getPaymentStatement, nullptr) != SQLITE_OK) {
	
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
	
	// Check if preparing get pending confirmed callback payments statement
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"ID\", \"Confirmations\", \"Confirmed Callback\" FROM \"Payments\" WHERE \"Confirmed Callback\" IS NOT NULL AND \"Confirmations Changed\" = TRUE;", -1, SQLITE_PREPARE_PERSISTENT, &getPendingConfirmedCallbackPaymentsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get pending confirmed callback payments statement failed");
	}
	
	// Automatically free get pending confirmed callback payments statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getPendingConfirmedCallbackPaymentsStatementUniquePointer(getPendingConfirmedCallbackPaymentsStatement, sqlite3_finalize);
	
	// Check if preparing get unsuccessful expired callback payments statement
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"ID\", \"Expired Callback\" FROM \"Payments\" WHERE \"Received\" IS NULL AND \"Expired Callback\" IS NOT NULL AND \"Expired Callback Successful\" = FALSE AND \"Expires\" IS NOT NULL AND \"Expires\" <= UNIXEPOCH('now');", -1, SQLITE_PREPARE_PERSISTENT, &getUnsuccessfulExpiredCallbackPaymentsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get unsuccessful expired callback payments statement failed");
	}
	
	// Automatically free get unsuccessful expired callback payments statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getUnsuccessfulExpiredCallbackPaymentsStatementUniquePointer(getUnsuccessfulExpiredCallbackPaymentsStatement, sqlite3_finalize);
	
	// Check if preparing set payment received statement failed
	if(sqlite3_prepare_v3(databaseConnection, "UPDATE \"Payments\" SET \"Price\" = ?, \"Received\" = UNIXEPOCH('now'), \"Sender Payment Proof Address\" = ?, \"Kernel Commitment\" = ?, \"Sender Public Blind Excess\" = ?, \"Recipient Partial Signature\" = ?, \"Public Nonce Sum\" = ?, \"Kernel Data\" = ? WHERE \"ID\" = ?;", -1, SQLITE_PREPARE_PERSISTENT, &setPaymentReceivedStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing set payment received statement failed");
	}
	
	// Automatically free set payment received statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> setPaymentReceivedStatementUniquePointer(setPaymentReceivedStatement, sqlite3_finalize);
	
	// Check if preparing reorg incomplete payments statement failed
	if(sqlite3_prepare_v3(databaseConnection, "UPDATE \"Payments\" SET \"Confirmations\" = 0, \"Confirmed Height\" = NULL, \"Confirmations Changed\" = TRUE WHERE \"Completed\" IS NULL AND \"Confirmed Height\" IS NOT NULL AND \"Confirmed Height\" >= ?;", -1, SQLITE_PREPARE_PERSISTENT, &reorgIncompletePaymentsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing reorg incomplete payments statement failed");
	}
	
	// Automatically free reorg incomplete payments statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> reorgIncompletePaymentsStatementUniquePointer(reorgIncompletePaymentsStatement, sqlite3_finalize);
	
	// Check if preparing set payment confirmations statement failed
	if(sqlite3_prepare_v3(databaseConnection, "UPDATE \"Payments\" SET \"Confirmations\" = MIN(?, \"Required Confirmations\"), \"Completed\" = IIF(?1 >= \"Required Confirmations\", UNIXEPOCH('now'), NULL), \"Confirmed Height\" = IIF(?1 > 0, ?, NULL), \"Confirmations Changed\" = IIF(?1 >= \"Required Confirmations\", FALSE, TRUE) WHERE \"ID\" = ?;", -1, SQLITE_PREPARE_PERSISTENT, &setPaymentConfirmationsStatement, nullptr) != SQLITE_OK) {
	
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
	
	// Check if preparing set payment acknowledged confirmed callback statement failed
	if(sqlite3_prepare_v3(databaseConnection, "UPDATE \"Payments\" SET \"Confirmations Changed\" = FALSE WHERE \"ID\" = ?;", -1, SQLITE_PREPARE_PERSISTENT, &setPaymentAcknowledgedConfirmedCallbackStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing set payment acknowledged confirmed callback statement failed");
	}
	
	// Automatically free set payment acknowledged confirmed callback statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> setPaymentAcknowledgedConfirmedCallbackStatementUniquePointer(setPaymentAcknowledgedConfirmedCallbackStatement, sqlite3_finalize);
	
	// Check if preparing set payment successful expired callback statement failed
	if(sqlite3_prepare_v3(databaseConnection, "UPDATE \"Payments\" SET \"Expired Callback Successful\" = TRUE WHERE \"ID\" = ?;", -1, SQLITE_PREPARE_PERSISTENT, &setPaymentSuccessfulExpiredCallbackStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing set payment successful expired callback statement failed");
	}
	
	// Automatically free set payment successful expired callback statement
	unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> setPaymentSuccessfulExpiredCallbackStatementUniquePointer(setPaymentSuccessfulExpiredCallbackStatement, sqlite3_finalize);
	
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
	
	// Release get pending confirmed callback payments statement unique pointer
	getPendingConfirmedCallbackPaymentsStatementUniquePointer.release();
	
	// Release get unsuccessful expired callback payments statement unique pointer
	getUnsuccessfulExpiredCallbackPaymentsStatementUniquePointer.release();
	
	// Release set payment received statement unique pointer
	setPaymentReceivedStatementUniquePointer.release();
	
	// Release reorg incomplete payments statement unique pointer
	reorgIncompletePaymentsStatementUniquePointer.release();
	
	// Release set payment confirmations statement unique pointer
	setPaymentConfirmationsStatementUniquePointer.release();
	
	// Release set payment successful completed callback statement unique pointer
	setPaymentSuccessfulCompletedCallbackStatementUniquePointer.release();
	
	// Release set payment acknowledged confirmed callback statement unique pointer
	setPaymentAcknowledgedConfirmedCallbackStatementUniquePointer.release();
	
	// Release set payment successful expired callback statement unique pointer
	setPaymentSuccessfulExpiredCallbackStatementUniquePointer.release();
	
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
	
	// Check if freeing get unsuccessful completed callback payments statement failed
	if(sqlite3_finalize(getUnsuccessfulCompletedCallbackPaymentsStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get unsuccessful completed callback payments statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing get pending confirmed callback payments statement failed
	if(sqlite3_finalize(getPendingConfirmedCallbackPaymentsStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get pending confirmed callback payments statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing get unsuccessful expired callback payments statement failed
	if(sqlite3_finalize(getUnsuccessfulExpiredCallbackPaymentsStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing get unsuccessful expired callback payments statement failed" << endl;
		
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
	
	// Check if freeing set payment acknowledged confirmed callback statement failed
	if(sqlite3_finalize(setPaymentAcknowledgedConfirmedCallbackStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing set payment acknowledged confirmed callback statement failed" << endl;
		
		// Set error occurred
		Common::setErrorOccurred();
	}
	
	// Check if freeing set payment successful expired callback statement failed
	if(sqlite3_finalize(setPaymentSuccessfulExpiredCallbackStatement) != SQLITE_OK) {
	
		// Display message
		cout << "Freeing set payment successful expired callback statement failed" << endl;
		
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
uint64_t Payments::createPayment(const uint64_t id, const char *url, const uint64_t price, const uint32_t requiredConfirmations, const uint32_t timeout, const char *completedCallback, const char *receivedCallback, const char *confirmedCallback, const char *expiredCallback) {

	// Initialize result
	uint64_t result;
	
	// Try
	try {
	
		// Lock
		lock_guard guard(lock);
		
		// Check if a timeout exists
		if(timeout) {
		
			// Check if resetting and clearing create payment with expiration statement failed
			if(sqlite3_reset(createPaymentWithExpirationStatement) != SQLITE_OK || sqlite3_clear_bindings(createPaymentWithExpirationStatement) != SQLITE_OK) {
			
				// Return zero
				return 0;
			}
		
			// Check if binding create payment with expiration statement's values failed
			if(sqlite3_bind_int64(createPaymentWithExpirationStatement, 1, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK || sqlite3_bind_text(createPaymentWithExpirationStatement, 2, url, -1, SQLITE_STATIC) != SQLITE_OK || (price ? sqlite3_bind_int64(createPaymentWithExpirationStatement, 3, *reinterpret_cast<const int64_t *>(&price)) : sqlite3_bind_null(createPaymentWithExpirationStatement, 3)) != SQLITE_OK || sqlite3_bind_int64(createPaymentWithExpirationStatement, 4, requiredConfirmations) != SQLITE_OK || sqlite3_bind_int64(createPaymentWithExpirationStatement, 5, timeout) != SQLITE_OK || sqlite3_bind_text(createPaymentWithExpirationStatement, 6, completedCallback, -1, SQLITE_STATIC) != SQLITE_OK || (receivedCallback ? sqlite3_bind_text(createPaymentWithExpirationStatement, 7, receivedCallback, -1, SQLITE_STATIC) : sqlite3_bind_null(createPaymentWithExpirationStatement, 7)) != SQLITE_OK || (confirmedCallback ? sqlite3_bind_text(createPaymentWithExpirationStatement, 8, confirmedCallback, -1, SQLITE_STATIC) : sqlite3_bind_null(createPaymentWithExpirationStatement, 8)) != SQLITE_OK || (expiredCallback ? sqlite3_bind_text(createPaymentWithExpirationStatement, 9, expiredCallback, -1, SQLITE_STATIC) : sqlite3_bind_null(createPaymentWithExpirationStatement, 9)) != SQLITE_OK) {
			
				// Return zero
				return 0;
			}
			
			// Check if running create payment with expiration statement failed
			if(sqlite3_step(createPaymentWithExpirationStatement) != SQLITE_DONE) {
			
				// Reset create payment with expiration statement
				sqlite3_reset(createPaymentWithExpirationStatement);
				
				// Return zero
				return 0;
			}
		}
		
		// Otherwise
		else {
		
			// Check if resetting and clearing create payment statement failed
			if(sqlite3_reset(createPaymentStatement) != SQLITE_OK || sqlite3_clear_bindings(createPaymentStatement) != SQLITE_OK) {
			
				// Return zero
				return 0;
			}
			
			// Check if binding create payment statement's values failed
			if(sqlite3_bind_int64(createPaymentStatement, 1, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK || sqlite3_bind_text(createPaymentStatement, 2, url, -1, SQLITE_STATIC) != SQLITE_OK || (price ? sqlite3_bind_int64(createPaymentStatement, 3, *reinterpret_cast<const int64_t *>(&price)) : sqlite3_bind_null(createPaymentStatement, 3)) != SQLITE_OK || sqlite3_bind_int64(createPaymentStatement, 4, requiredConfirmations) != SQLITE_OK || sqlite3_bind_text(createPaymentStatement, 5, completedCallback, -1, SQLITE_STATIC) != SQLITE_OK || (receivedCallback ? sqlite3_bind_text(createPaymentStatement, 6, receivedCallback, -1, SQLITE_STATIC) : sqlite3_bind_null(createPaymentStatement, 6)) != SQLITE_OK || (confirmedCallback ? sqlite3_bind_text(createPaymentStatement, 7, confirmedCallback, -1, SQLITE_STATIC) : sqlite3_bind_null(createPaymentStatement, 7)) != SQLITE_OK) {
			
				// Return zero
				return 0;
			}
			
			// Check if running create payment statement failed
			if(sqlite3_step(createPaymentStatement) != SQLITE_DONE) {
			
				// Reset create payment statement
				sqlite3_reset(createPaymentStatement);
				
				// Return zero
				return 0;
			}
		}
		
		// Set result to payment's unique number
		result = sqlite3_last_insert_rowid(databaseConnection);
	}
	
	// Catch errors
	catch(...) {
	
		// Return zero
		return 0;
	}
	
	// Return result
	return result;
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
tuple<uint64_t, uint64_t, optional<uint64_t>, optional<string>> Payments::getReceivingPaymentForUrl(const char *url) {

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
		const tuple<uint64_t, uint64_t, optional<uint64_t>, optional<string>> result(
		
			// Unique number
			sqlite3_column_int64(getReceivingPaymentForUrlStatement, 0),
			
			// ID
			*reinterpret_cast<const uint64_t *>(&idStorage),
			
			// Price
			(sqlite3_column_type(getReceivingPaymentForUrlStatement, 2) == SQLITE_NULL) ? nullopt : optional<uint64_t>(*reinterpret_cast<const uint64_t *>(&priceStorage)),
			
			// Received callback
			(sqlite3_column_type(getReceivingPaymentForUrlStatement, 3) == SQLITE_NULL) ? nullopt : optional<string>(reinterpret_cast<const char *>(sqlite3_column_text(getReceivingPaymentForUrlStatement, 3)))
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
			
			// check if payment can't expire
			if(sqlite3_column_type(getCompletedPaymentsStatement, 7) == SQLITE_NULL) {
			
				// Display payment's expires at
				cout << "\tExpires at: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's expires at
				time = sqlite3_column_int64(getCompletedPaymentsStatement, 7);
				cout << "\tExpires at: " << put_time(gmtime(&time), "%c %Z") << endl;
			}
			
			// Display payment's received at
			time = sqlite3_column_int64(getCompletedPaymentsStatement, 8);
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
			cout << "\tConfirmed height: " << sqlite3_column_int64(getCompletedPaymentsStatement, 13) << endl;
			
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
			const uint8_t *kernelCommitment = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getCompletedPaymentsStatement, 12));
			cout << "\tKernel excess: " << Common::toHexString(kernelCommitment, sqlite3_column_bytes(getCompletedPaymentsStatement, 12)) << " (" << Consensus::KERNEL_COMMITMENT_EXPLORER_URL << Common::toHexString(kernelCommitment, sqlite3_column_bytes(getCompletedPaymentsStatement, 12)) << ')' << endl;
			
			// Display payment's payment proof addresses
			const char *senderPaymentProofAddress = reinterpret_cast<const char *>(sqlite3_column_text(getCompletedPaymentsStatement, 11));
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
			
			// check if payment doesn't have a received callback
			if(sqlite3_column_type(getCompletedPaymentsStatement, 14) == SQLITE_NULL) {
			
				// Display payment's received callback
				cout << "\tReceived callback: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's received callback
				cout << "\tReceived callback: " << sqlite3_column_text(getCompletedPaymentsStatement, 14) << endl;
			}
			
			// check if payment doesn't have a confirmed callback
			if(sqlite3_column_type(getCompletedPaymentsStatement, 15) == SQLITE_NULL) {
			
				// Display payment's confirmed callback
				cout << "\tConfirmed callback: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's confirmed callback
				cout << "\tConfirmed callback: " << sqlite3_column_text(getCompletedPaymentsStatement, 15) << endl;
			}
			
			// check if payment doesn't have a expired callback
			if(sqlite3_column_type(getCompletedPaymentsStatement, 16) == SQLITE_NULL) {
			
				// Display payment's expired callback
				cout << "\tExpired callback: N/A" << endl;
				
				// Display payment's expired successful callback
				cout << "\tExpired callback was successful: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's expired callback
				cout << "\tExpired callback: " << sqlite3_column_text(getCompletedPaymentsStatement, 16) << endl;
				
				// Display payment's expired successful callback
				cout << "\tExpired callback was successful: " << (sqlite3_column_int64(getCompletedPaymentsStatement, 17) ? "True" : "False") << endl;
			}
			
			// Display payment's completed callback
			cout << "\tCompleted callback: " << sqlite3_column_text(getCompletedPaymentsStatement, 9) << endl;
			
			// Display payment's completed successful callback
			cout << "\tCompleted callback was successful: " << (sqlite3_column_int64(getCompletedPaymentsStatement, 10) ? "True" : "False") << endl;
			
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
			cout << "\tStatus: " << sqlite3_column_text(getPaymentStatement, 17) << endl;
			
			// Display payment's URL
			cout << "\tURL path: " << sqlite3_column_text(getPaymentStatement, 1) << endl;
			
			// Display payment's created at
			time_t time = sqlite3_column_int64(getPaymentStatement, 2);
			cout << "\tCreated at: " << put_time(gmtime(&time), "%c %Z") << endl;
			
			// check if payment can't expire
			if(sqlite3_column_type(getPaymentStatement, 6) == SQLITE_NULL) {
			
				// Display payment's expires at
				cout << "\tExpires at: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's expires at
				time = sqlite3_column_int64(getPaymentStatement, 6);
				cout << "\tExpires at: " << put_time(gmtime(&time), "%c %Z") << endl;
			}
			
			// check if payment hasn't been received
			if(sqlite3_column_type(getPaymentStatement, 7) == SQLITE_NULL) {
			
				// Display payment's received at
				cout << "\tReceived at: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's received at
				time = sqlite3_column_int64(getPaymentStatement, 7);
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
			if(sqlite3_column_type(getPaymentStatement, 12) == SQLITE_NULL) {
			
				// Display payment's confirmed height
				cout << "\tConfirmed height: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's confirmed height
				cout << "\tConfirmed height: " << sqlite3_column_int64(getPaymentStatement, 12) << endl;
			}
			
			// check if payment hasn't been received
			const uint64_t identifierPath = sqlite3_column_int64(getPaymentStatement, 0);
			const uint64_t &paymentProofIndex = identifierPath;
			if(sqlite3_column_type(getPaymentStatement, 7) == SQLITE_NULL) {
			
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
				const uint8_t *kernelCommitment = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getPaymentStatement, 11));
				cout << "\tKernel excess: " << Common::toHexString(kernelCommitment, sqlite3_column_bytes(getPaymentStatement, 11)) << " (" << Consensus::KERNEL_COMMITMENT_EXPLORER_URL << Common::toHexString(kernelCommitment, sqlite3_column_bytes(getPaymentStatement, 11)) << ')' << endl;
				
				// Display payment's sender payment proof addresses
				const char *senderPaymentProofAddress = reinterpret_cast<const char *>(sqlite3_column_text(getPaymentStatement, 10));
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
			
			// check if payment doesn't have a received callback
			if(sqlite3_column_type(getPaymentStatement, 13) == SQLITE_NULL) {
			
				// Display payment's received callback
				cout << "\tReceived callback: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's received callback
				cout << "\tReceived callback: " << sqlite3_column_text(getPaymentStatement, 13) << endl;
			}
			
			// check if payment doesn't have a confirmed callback
			if(sqlite3_column_type(getPaymentStatement, 14) == SQLITE_NULL) {
			
				// Display payment's confirmed callback
				cout << "\tConfirmed callback: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's confirmed callback
				cout << "\tConfirmed callback: " << sqlite3_column_text(getPaymentStatement, 14) << endl;
			}
			
			// check if payment doesn't have a expired callback
			if(sqlite3_column_type(getPaymentStatement, 15) == SQLITE_NULL) {
			
				// Display payment's expired callback
				cout << "\tExpired callback: N/A" << endl;
				
				// Display payment's expired successful callback
				cout << "\tExpired callback was successful: N/A" << endl;
			}
			
			// Otherwise
			else {
			
				// Display payment's expired callback
				cout << "\tExpired callback: " << sqlite3_column_text(getPaymentStatement, 15) << endl;
				
				// Display payment's expired successful callback
				cout << "\tExpired callback was successful: " << (sqlite3_column_int64(getPaymentStatement, 16) ? "True" : "False") << endl;
			}
			
			// Display payment's completed callback
			cout << "\tCompleted callback: " << sqlite3_column_text(getPaymentStatement, 8) << endl;
			
			// Display payment's completed successful callback
			cout << "\tCompleted callback was successful: " << (sqlite3_column_int64(getPaymentStatement, 9) ? "True" : "False") << endl;
			
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
		for(tuple<uint64_t, string> &paymentInfo : getUnsuccessfulCompletedCallbackPayments()) {
		
			// Try
			try {
			
				// Get payment ID
				const uint64_t &paymentId = get<0>(paymentInfo);
			
				// Get payment's completed callback
				string &paymentCompletedCallback = get<1>(paymentInfo);
				
				// Apply substitutions to payment's completed callback
				Common::applySubstitutions(paymentCompletedCallback, {
				
					// ID
					{"__id__", to_string(paymentId)}
				});
		
				// Check if sending HTTP request to the payment's completed callback was successful
				if(Common::sendHttpRequest(paymentCompletedCallback.c_str())) {
				
					// Set that payment's completed callback was successful
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

// Run pending confirmed payment callbacks
void Payments::runPendingConfirmedPaymentCallbacks() {

	// Try
	try {

		// Go through all pending confirmed callback payments
		for(tuple<uint64_t, uint64_t, string> &paymentInfo : getPendingConfirmedCallbackPayments()) {
		
			// Get payment ID
			const uint64_t &paymentId = get<0>(paymentInfo);
			
			// Try
			try {
			
				// Get payment confirmations
				const uint64_t &paymentConfirmations = get<1>(paymentInfo);
				
				// Get payment's confirmed callback
				string &paymentConfirmedCallback = get<2>(paymentInfo);
				
				// Apply substitutions to payment's confirmed callback
				Common::applySubstitutions(paymentConfirmedCallback, {
				
					// ID
					{"__id__", to_string(paymentId)},
					
					// Confirmations
					{"__confirmations__", to_string(paymentConfirmations)}
				});
		
				// Send HTTP request to the payment's confirmed callback
				Common::sendHttpRequest(paymentConfirmedCallback.c_str());
			}
			
			// Catch errors
			catch(...) {
			
			}
			
			// Set that payment's confirmed callback was acknowledged
			setPaymentAcknowledgedConfirmedCallback(paymentId);
		}
	}
	
	// Catch errors
	catch(...) {
	
	}
}

// Run unsuccessful expired payment callbacks
void Payments::runUnsuccessfulExpiredPaymentCallbacks() {

	// Try
	try {

		// Go through all unsuccessful expired callback payments
		for(tuple<uint64_t, string> &paymentInfo : getUnsuccessfulExpiredCallbackPayments()) {
		
			// Try
			try {
			
				// Get payment ID
				const uint64_t &paymentId = get<0>(paymentInfo);
			
				// Get payment's expired callback
				string &paymentExpiredCallback = get<1>(paymentInfo);
				
				// Apply substitutions to payment's expired callback
				Common::applySubstitutions(paymentExpiredCallback, {
				
					// ID
					{"__id__", to_string(paymentId)}
				});
		
				// Check if sending HTTP request to the payment's expired callback was successful
				if(Common::sendHttpRequest(paymentExpiredCallback.c_str())) {
				
					// Set that payment's expired callback was successful
					setPaymentSuccessfulExpiredCallback(paymentId);
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

// Get pending confirmed callback payments
list<tuple<uint64_t, uint64_t, string>> Payments::getPendingConfirmedCallbackPayments() {

	// Lock
	lock_guard guard(lock);
	
	// Check if resetting get pending confirmed callback payments statement failed
	if(sqlite3_reset(getPendingConfirmedCallbackPaymentsStatement) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Resetting get pending confirmed callback payments statement failed");
	}
	
	// Initialize result
	list<tuple<uint64_t, uint64_t, string>> result;
	
	// Go through all pending confirmed callback payments
	int sqlResult;
	while((sqlResult = sqlite3_step(getPendingConfirmedCallbackPaymentsStatement)) != SQLITE_DONE) {
	
		// Check if running get pending confirmed callback payments statement failed
		if(sqlResult != SQLITE_ROW) {
		
			// Reset get pending confirmed callback payments statement
			sqlite3_reset(getPendingConfirmedCallbackPaymentsStatement);
			
			// Throw exception
			throw runtime_error("Running get pending confirmed callback payments statement failed");
		}
		
		// Add payment's info to result
		const int64_t idStorage = sqlite3_column_int64(getPendingConfirmedCallbackPaymentsStatement, 0);
		result.emplace_back(
		
			// ID
			*reinterpret_cast<const uint64_t *>(&idStorage),
			
			// Confirmations
			sqlite3_column_int64(getPendingConfirmedCallbackPaymentsStatement, 1),
			
			// Confirmed callback
			reinterpret_cast<const char *>(sqlite3_column_text(getPendingConfirmedCallbackPaymentsStatement, 2))
		);
	}
	
	// Return result
	return result;
}

// Set payment acknowledged confirmed callback
bool Payments::setPaymentAcknowledgedConfirmedCallback(const uint64_t id) {

	// Try
	try {
	
		// Lock
		lock_guard guard(lock);
		
		// Check if resetting and clearing set payment acknowledged confirmed callback statement failed
		if(sqlite3_reset(setPaymentAcknowledgedConfirmedCallbackStatement) != SQLITE_OK || sqlite3_clear_bindings(setPaymentAcknowledgedConfirmedCallbackStatement) != SQLITE_OK) {
		
			// Return false
			return false;
		}
		
		// Check if binding set payment acknowledged confirmed callback statement's values failed
		if(sqlite3_bind_int64(setPaymentAcknowledgedConfirmedCallbackStatement, 1, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK) {
		
			// Return false
			return false;
		}
		
		// Check if running set payment acknowledged confirmed callback statement failed
		if(sqlite3_step(setPaymentAcknowledgedConfirmedCallbackStatement) != SQLITE_DONE) {
		
			// Reset set payment acknowledged confirmed callback statement
			sqlite3_reset(setPaymentAcknowledgedConfirmedCallbackStatement);
			
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

// Get unsuccessful expired callback payments
list<tuple<uint64_t, string>> Payments::getUnsuccessfulExpiredCallbackPayments() {

	// Lock
	lock_guard guard(lock);
	
	// Check if resetting get unsuccessful expired callback payments statement failed
	if(sqlite3_reset(getUnsuccessfulExpiredCallbackPaymentsStatement) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Resetting get unsuccessful expired callback payments statement failed");
	}
	
	// Initialize result
	list<tuple<uint64_t, string>> result;
	
	// Go through all unsuccessful expired callback payments
	int sqlResult;
	while((sqlResult = sqlite3_step(getUnsuccessfulExpiredCallbackPaymentsStatement)) != SQLITE_DONE) {
	
		// Check if running get unsuccessful expired callback payments statement failed
		if(sqlResult != SQLITE_ROW) {
		
			// Reset get unsuccessful expired callback payments statement
			sqlite3_reset(getUnsuccessfulExpiredCallbackPaymentsStatement);
			
			// Throw exception
			throw runtime_error("Running get unsuccessful expired callback payments statement failed");
		}
		
		// Add payment's info to result
		const int64_t idStorage = sqlite3_column_int64(getUnsuccessfulExpiredCallbackPaymentsStatement, 0);
		result.emplace_back(
		
			// ID
			*reinterpret_cast<const uint64_t *>(&idStorage),
			
			// Expired callback
			reinterpret_cast<const char *>(sqlite3_column_text(getUnsuccessfulExpiredCallbackPaymentsStatement, 1))
		);
	}
	
	// Return result
	return result;
}

// Set payment successful expired callback
bool Payments::setPaymentSuccessfulExpiredCallback(const uint64_t id) {

	// Try
	try {
	
		// Lock
		lock_guard guard(lock);
		
		// Check if resetting and clearing set payment successful expired callback statement failed
		if(sqlite3_reset(setPaymentSuccessfulExpiredCallbackStatement) != SQLITE_OK || sqlite3_clear_bindings(setPaymentSuccessfulExpiredCallbackStatement) != SQLITE_OK) {
		
			// Return false
			return false;
		}
		
		// Check if binding set payment successful expired callback statement's values failed
		if(sqlite3_bind_int64(setPaymentSuccessfulExpiredCallbackStatement, 1, *reinterpret_cast<const int64_t *>(&id)) != SQLITE_OK) {
		
			// Return false
			return false;
		}
		
		// Check if running set payment successful expired callback statement failed
		if(sqlite3_step(setPaymentSuccessfulExpiredCallbackStatement) != SQLITE_DONE) {
		
			// Reset set payment successful expired callback statement
			sqlite3_reset(setPaymentSuccessfulExpiredCallbackStatement);
			
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
