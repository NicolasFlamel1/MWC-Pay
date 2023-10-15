// Header files
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <sys/random.h>
#include <termios.h>
#include <unistd.h>
#include <vector>
#include "./common.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/kdf.h"
#include "openssl/rand.h"
#include "./mnemonic.h"
#include "./mqs.h"
#include "./tor.h"
#include "./wallet.h"
#include "zlib.h"

using namespace std;


// Constants

// Pepper size
static const size_t PEPPER_SIZE = 256 / numeric_limits<uint8_t>::digits;

// Salt size
static const size_t SALT_SIZE = 256 / numeric_limits<uint8_t>::digits;

// Initialization vector size
static const size_t INITIALIZATION_VECTOR_SIZE = 256 / numeric_limits<uint8_t>::digits;

// Key size
static const size_t KEY_SIZE = 256 / numeric_limits<uint8_t>::digits;

// Key derivation algorithm
static const char *KEY_DERIVATION_ALGORITHM = "PBKDF2";

// Key derivation iterations
static const unsigned int KEY_DERIVATION_ITERATIONS = 210000;

// Key derivation digest
static const char *KEY_DERIVATION_DIGEST = "SHA-512";

// Seed encryption algorithm
static const char *SEED_ENCRYPTION_ALGORITHM = "AES-256-GCM";

// Extended private key MAC algorithm
static const char *EXTENDED_PRIVATE_KEY_MAC_ALGORITHM = "HMAC";

// Extended private key MAC digest
static const char *EXTENDED_PRIVATE_KEY_MAC_DIGEST = "SHA-512";

// Extended private key MAC seed
static const char EXTENDED_PRIVATE_KEY_MAC_SEED[] = "IamVoldemort";

// Bulletproof hash digest algorithm
static const char *BULLETPROOF_HASH_DIGEST_ALGORITHM = "BLAKE2B-512";

// Bulletproof nonce MAC algorithm
static const char *BULLETPROOF_NONCE_MAC_ALGORITHM = "BLAKE2BMAC";

// Address private key committed value
static const uint64_t ADDRESS_PRIVATE_KEY_COMMITTED_VALUE = 713;

// Address private key MAC algorithm
static const char *ADDRESS_PRIVATE_KEY_MAC_ALGORITHM = "HMAC";

// Address private key MAC digest
static const char *ADDRESS_PRIVATE_KEY_MAC_DIGEST = "SHA-512";

// Address private key MAC seed
static const char ADDRESS_PRIVATE_KEY_MAC_SEED[] = "Grinbox_seed";

// Address message encryption algorithm
static const char *ADDRESS_MESSAGE_ENCRYPTION_ALGORITHM = "CHACHA20-POLY1305";

// Switch type
enum class SwitchType {

	// None
	NONE,
	
	// Regular
	REGULAR
};


// Function prototypes

// Is valid seed
static bool isValidSeed(const uint8_t seed[Mnemonic::SEED_SIZE]);


// Supporting function implementation

// Constructor
Wallet::Wallet() :

	// Set opened
	opened(false)
{
}

// Destructor
Wallet::~Wallet() {

	// Check if opened
	if(opened) {
	
		// Display message
		cout << "Closing wallet" << endl;
	}
	
	// Securely clear extended private key
	explicit_bzero(extendedPrivateKey, sizeof(extendedPrivateKey));
	
	// Check if opened
	if(opened) {
	
		// Display message
		cout << "Wallet closed" << endl;
	}
}

// Open
bool Wallet::open(sqlite3 *databaseConnection, const char *providedPassword, const bool showRecoveryPassphrase) {

	// Check if creating wallets table in the database failed
	if(sqlite3_exec(databaseConnection, ("CREATE TABLE IF NOT EXISTS \"Wallets\" ("
	
		// Pepper
		"\"Pepper\" BLOB NOT NULL CHECK(LENGTH(\"Pepper\") = " + to_string(PEPPER_SIZE) + "),"
		
		// Salt
		"\"Salt\" BLOB NOT NULL CHECK(LENGTH(\"Salt\") = " + to_string(SALT_SIZE) + "),"
		
		// Initialization vector
		"\"Initialization Vector\" BLOB NOT NULL CHECK(LENGTH(\"Initialization Vector\") = " + to_string(INITIALIZATION_VECTOR_SIZE) + "),"
		
		// Encrypted seed
		"\"Encrypted Seed\" BLOB NOT NULL CHECK(LENGTH(\"Encrypted Seed\") != 0)"
	
	") STRICT;").c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Creating wallets table in the database failed");
	}
	
	// Check if creating triggers in the database failed
	if(sqlite3_exec(databaseConnection, ""
	
		// Read-only columns trigger
		"CREATE TRIGGER IF NOT EXISTS \"Wallets Read-only Columns Trigger\" BEFORE UPDATE OF \"Pepper\", \"Salt\", \"Initialization Vector\", \"Encrypted Seed\" ON \"Wallets\" BEGIN "
			"SELECT RAISE(ABORT, 'column is read-only');"
		"END;"
		
		// Persistent rows trigger
		"CREATE TRIGGER IF NOT EXISTS \"Wallets Persistent Rows Trigger\" BEFORE DELETE ON \"Wallets\" BEGIN "
			"SELECT RAISE(ABORT, 'row is persistent');"
		"END;"
		
		// Single row trigger
		"CREATE TRIGGER IF NOT EXISTS \"Wallets Single Row Trigger\" BEFORE INSERT ON \"Wallets\" FOR EACH ROW WHEN (SELECT COUNT() FROM \"Wallets\") >= 1 BEGIN "
			"SELECT RAISE(ABORT, 'only one row can exist');"
		"END;"
	
	"", nullptr, nullptr, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Creating wallets triggers in the database failed");
	}
	
	// Check if preparing wallet exists statement failed
	sqlite3_stmt *walletExistsStatement;
	if(sqlite3_prepare_v3(databaseConnection, "SELECT COUNT() > 0 FROM \"Wallets\";", -1, 0, &walletExistsStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing wallet exists statement failed");
	}
	
	// Automatically free wallet exists statement
	const unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> walletExistsStatementUniquePointer(walletExistsStatement, sqlite3_finalize);
	
	// Check if preparing create wallet statement failed
	sqlite3_stmt *createWalletStatement;
	if(sqlite3_prepare_v3(databaseConnection, "INSERT INTO \"Wallets\" (\"Pepper\", \"Salt\", \"Initialization Vector\", \"Encrypted Seed\") VALUES (?, ?, ?, ?);", -1, 0, &createWalletStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing create wallet statement failed");
	}
	
	// Automatically free create wallet statement
	const unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> createWalletStatementUniquePointer(createWalletStatement, sqlite3_finalize);
	
	// Check if preparing get wallet statement failed
	sqlite3_stmt *getWalletStatement;
	if(sqlite3_prepare_v3(databaseConnection, "SELECT \"Pepper\", \"Salt\", \"Initialization Vector\", \"Encrypted Seed\" FROM \"Wallets\";", -1, 0, &getWalletStatement, nullptr) != SQLITE_OK) {
	
		// Throw exception
		throw runtime_error("Preparing get wallet statement failed");
	}
	
	// Automatically free get wallet statement
	const unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> getWalletStatementUniquePointer(getWalletStatement, sqlite3_finalize);
	
	// Check if running wallet exists statement failed
	const int walletExistsResult = sqlite3_step(walletExistsStatement);
	if(walletExistsResult != SQLITE_ROW) {
	
		// Check running wallet exists statement didn't finish
		if(walletExistsResult != SQLITE_DONE) {
		
			// Reset wallet exists statement
			sqlite3_reset(walletExistsStatement);
		}
	
		// Throw exception
		throw runtime_error("Running wallet exists statement failed");
	}
	
	// Set create wallet to if wallet doesn't exist
	const bool createWallet = !sqlite3_column_int64(walletExistsStatement, 0);
	
	// Check if running wallet exists statement failed
	if(sqlite3_step(walletExistsStatement) != SQLITE_DONE) {
	
		// Reset wallet exists statement
		sqlite3_reset(walletExistsStatement);
		
		// Throw exception
		throw runtime_error("Running wallet exists statement failed");
	}
	
	// Initialize seed
	uint8_t seed[Mnemonic::SEED_SIZE];
	
	// Try
	try {

		// Initialize password
		string password;
		
		// Try
		try {
		
			// Check if password isn't provided
			if(!providedPassword) {
		
				// Check if getting input settings failed
				termios savedInputSettings;
				if(tcgetattr(STDIN_FILENO, &savedInputSettings)) {
				
					// Throw exception
					throw runtime_error("Getting input settings failed");
				}
				
				// Try
				try {
				
					// Check if silencing echo in input settings failed
					termios newInputSettings = savedInputSettings;
					newInputSettings.c_lflag &= ~ECHO;
					if(tcsetattr(STDIN_FILENO, TCSANOW, &newInputSettings)) {
					
						// Throw exception
						throw runtime_error("Silencing echo in input settings failed");
					}

					// Check if creating wallet
					if(createWallet) {
					
						// Try
						try {
						
							// Display message
							cout << "Creating new wallet" << endl;
							cout << "Enter password: ";
							
							// Set input to throw exception on error
							cin.exceptions(ios::badbit | ios::failbit);
							
							// Check if a signal was received
							if(!Common::allowSignals() || Common::getSignalReceived()) {
							
								// Block signals
								Common::blockSignals();
								
								// Throw exception
								throw runtime_error("Getting password failed");
							}
						
							// Get password
							getline(cin, password);
							
							// Check if a signal was received
							if(!Common::blockSignals() || Common::getSignalReceived()) {
							
								// Block signals
								Common::blockSignals();
								
								// Throw exception
								throw runtime_error("Getting password failed");
							}
							
							// Display new line
							cout << endl;
						}
						
						// Catch errors
						catch(...) {
						
							// Display new line
							cout << endl;
						
							// Throw exception
							throw runtime_error("Getting password failed");
						}
						
						// Initialize confirm password
						string confirmPassword;
						
						// Try
						try {
						
							// Display message
							cout << "Reenter password: " ;
							
							// Check if a signal was received
							if(!Common::allowSignals() || Common::getSignalReceived()) {
							
								// Block signals
								Common::blockSignals();
								
								// Throw exception
								throw runtime_error("Getting password failed");
							}
							
							// Get confirm password
							getline(cin, confirmPassword);
							
							// Check if a signal was received
							if(!Common::blockSignals() || Common::getSignalReceived()) {
							
								// Block signals
								Common::blockSignals();
								
								// Throw exception
								throw runtime_error("Getting password failed");
							}
							
							// Display new line
							cout << endl;
						}
						
						// Catch errors
						catch(...) {
						
							// Securely clear confirm password
							explicit_bzero(confirmPassword.data(), confirmPassword.capacity());
							
							// Display new line
							cout << endl;
							
							// Throw exception
							throw runtime_error("Getting password failed");
						}
						
						// Check if confirm password isn't the password
						if(confirmPassword != password) {
						
							// Display message
							cout << "Passwords don't match" << endl;
							
							// Securely clear confirm password
							explicit_bzero(confirmPassword.data(), confirmPassword.capacity());
							
							// Restore input settings
							tcsetattr(STDIN_FILENO, TCSANOW, &savedInputSettings);
							
							// Securely clear password
							explicit_bzero(password.data(), password.capacity());
							
							// Return false
							return false;
						}
						
						// Securely clear password
						explicit_bzero(confirmPassword.data(), confirmPassword.capacity());
					}
					
					// Otherwise
					else {
					
						// Try
						try {
					
							// Display message
							cout << "Opening wallet" << endl;
							cout << "Enter password: ";
							
							// Set input to throw exception on error
							cin.exceptions(ios::badbit | ios::failbit);
							
							// Check if a signal was received
							if(!Common::allowSignals() || Common::getSignalReceived()) {
							
								// Block signals
								Common::blockSignals();
								
								// Throw exception
								throw runtime_error("Getting password failed");
							}
							
							// Get password
							getline(cin, password);
							
							// Check if a signal was received
							if(!Common::blockSignals() || Common::getSignalReceived()) {
							
								// Block signals
								Common::blockSignals();
								
								// Throw exception
								throw runtime_error("Getting password failed");
							}
							
							// Display new line
							cout << endl;
						}
						
						// Catch errors
						catch(...) {
						
							// Display new line
							cout << endl;
							
							// Throw exception
							throw runtime_error("Getting password failed");
						}
					}
				}
			
				// Catch errors
				catch(...) {
				
					// Restore input settings
					tcsetattr(STDIN_FILENO, TCSANOW, &savedInputSettings);
					
					// Throw
					throw;
				}
				
				// Check if restoring input settings failed
				if(tcsetattr(STDIN_FILENO, TCSANOW, &savedInputSettings)) {
				
					// Throw exception
					throw runtime_error("Restoring input settings failed");
				}
			}
			
			// Otherwise
			else {
			
				// Check if creating wallet
				if(createWallet) {
				
					// Display message
					cout << "Creating new wallet" << endl;
				}
				
				// Otherwise
				else {
				
					// Display message
					cout << "Opening wallet" << endl;
				}
				
				// Set password to the provided password
				password = providedPassword;
			}
			
			// Check if creating wallet
			uint8_t pepper[PEPPER_SIZE];
			uint8_t salt[SALT_SIZE];
			uint8_t initializationVector[INITIALIZATION_VECTOR_SIZE];
			vector<uint8_t> encryptedSeed;
			if(createWallet) {
				
				// Check if creating random pepper failed
				if(getentropy(pepper, sizeof(pepper))) {
				
					// Throw exception
					throw runtime_error("Creating random pepper failed");
				}
				
				// Check if creating random salt failed
				if(getentropy(salt, sizeof(salt))) {
				
					// Throw exception
					throw runtime_error("Creating random salt failed");
				}
				
				// Check if creating random initialization vector failed
				if(getentropy(initializationVector, sizeof(initializationVector))) {
				
					// Throw exception
					throw runtime_error("Creating initialization vector failed");
				}
			}
			
			// Otherwise
			else {
			
				// Check if running get wallet statement failed
				const int getWalletResult = sqlite3_step(getWalletStatement);
				if(getWalletResult != SQLITE_ROW) {
				
					// Check running get wallet statement didn't finish
					if(getWalletResult != SQLITE_DONE) {
					
						// Reset get wallet statement
						sqlite3_reset(getWalletStatement);
					}
				
					// Throw exception
					throw runtime_error("Running get wallet statement failed");
				}
				
				// Get pepper, salt, initialization vector, and encrypted seed from wallet
				memcpy(pepper, sqlite3_column_blob(getWalletStatement, 0), sizeof(pepper));
				memcpy(salt, sqlite3_column_blob(getWalletStatement, 1), sizeof(salt));
				memcpy(initializationVector, sqlite3_column_blob(getWalletStatement, 2), sizeof(initializationVector));
				encryptedSeed.assign(reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getWalletStatement, 3)), reinterpret_cast<const uint8_t *>(sqlite3_column_blob(getWalletStatement, 3)) + sqlite3_column_bytes(getWalletStatement, 3));
				
				// Check if running get wallet statement failed
				if(sqlite3_step(getWalletStatement) != SQLITE_DONE) {
				
					// Reset get wallet statement
					sqlite3_reset(getWalletStatement);
					
					// Throw exception
					throw runtime_error("Running get wallet statement failed");
				}
			}
			
			// Inialize key
			uint8_t key[KEY_SIZE];
			
			// Try
			try {
			
				// Initialize peppered password
				uint8_t pepperedPassword[password.size() + sizeof(pepper)];
				
				// Try
				try {
				
					// Set peppered password
					memcpy(pepperedPassword, password.data(), password.size());
					memcpy(&pepperedPassword[password.size()], pepper, sizeof(pepper));
					
					// Check if getting key derivation failed
					const unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> keyDerivation(EVP_KDF_fetch(nullptr, KEY_DERIVATION_ALGORITHM, nullptr), EVP_KDF_free);
					if(!keyDerivation) {
					
						// Throw exception
						throw runtime_error("Getting key derivation failed");
					}
					
					// Check if creating key derivation context failed
					const unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> keyDerivationContext(EVP_KDF_CTX_new(keyDerivation.get()), EVP_KDF_CTX_free);
					if(!keyDerivationContext) {
					
						// Throw exception
						throw runtime_error("Creating key derivation context failed");
					}
					
					// Check if deriving key failed
					const OSSL_PARAM parameters[] = {
					
						// Password
						OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, pepperedPassword, sizeof(pepperedPassword)),
						
						// Salt
						OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt)),
						
						// Iterations
						OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, const_cast<unsigned int *>(&KEY_DERIVATION_ITERATIONS)),
						
						// Digest
						OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char *>(KEY_DERIVATION_DIGEST), 0),
						
						// End
						OSSL_PARAM_END
					};
					if(EVP_KDF_derive(keyDerivationContext.get(), key, sizeof(key), parameters) != 1) {
					
						// Throw exception
						throw runtime_error("Deriving key failed");
					}
				}
				
				// Catch errors
				catch(...) {
				
					// Securely clear peppered password
					explicit_bzero(pepperedPassword, sizeof(pepperedPassword));
					
					// Throw
					throw;
				}
				
				// Securely clear peppered password
				explicit_bzero(pepperedPassword, sizeof(pepperedPassword));
				
				// Check if getting cipher failed
				const unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(EVP_CIPHER_fetch(nullptr, SEED_ENCRYPTION_ALGORITHM, nullptr), EVP_CIPHER_free);
				if(!cipher) {
				
					// Throw exception
					throw runtime_error("Getting cipher failed");
				}
				
				// Check if creating cipher context failed
				const unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipherContext(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
				if(!cipherContext) {
				
					// Throw exception
					throw runtime_error("Creating cipher context failed");
				}
				
				// Check if creating wallet
				if(createWallet) {
				
					// Check if initializing cipher context failed
					const size_t initializationVectorLength = sizeof(initializationVector);
					const OSSL_PARAM setInitializationVectorLengthParameters[] = {
					
						// Initialization vector length
						OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, const_cast<size_t *>(&initializationVectorLength)),
						
						// End
						OSSL_PARAM_END
					};
					if(!EVP_EncryptInit_ex2(cipherContext.get(), cipher.get(), nullptr, nullptr, setInitializationVectorLengthParameters) || !EVP_EncryptInit_ex2(cipherContext.get(), nullptr, key, initializationVector, nullptr)) {
					
						// Throw exception
						throw runtime_error("Initializing cipher context failed");
					}
					
					// Check if getting tag length failed
					size_t tagLength;
					OSSL_PARAM getTagLengthParameters[] = {
					
						// Tag length
						OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tagLength),
						
						// End
						OSSL_PARAM_END
					};
					if(!EVP_CIPHER_CTX_get_params(cipherContext.get(), getTagLengthParameters)) {
					
						// Throw exception
						throw runtime_error("Getting tag length failed");
					}
					
					// Loop while seed isn't valid
					do {
					
						// Check if creating random seed failed
						if(getentropy(seed, sizeof(seed))) {
					
							// Throw exception
							throw runtime_error("Creating random seed failed");
						}
						
					} while(!isValidSeed(seed));
					
					// Check if encrypting seed failed
					encryptedSeed.resize(sizeof(seed) + tagLength);
					int encryptedSeedLength;
					if(!EVP_EncryptUpdate(cipherContext.get(), encryptedSeed.data(), &encryptedSeedLength, seed, sizeof(seed)) || static_cast<size_t>(encryptedSeedLength) != sizeof(seed)) {
					
						// Throw exception
						throw runtime_error("Encrypting seed failed");
					}
					
					// Check if finishing encrypting seed failed
					if(!EVP_EncryptFinal_ex(cipherContext.get(), encryptedSeed.data(), &encryptedSeedLength) || encryptedSeedLength) {
					
						// Throw exception
						throw runtime_error("Finishing encrypting seed failed");
					}
					
					// Check if getting tag failed
					OSSL_PARAM getTagParameters[] = {
					
						// Tag
						OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, &encryptedSeed[sizeof(seed)], tagLength),
						
						// End
						OSSL_PARAM_END
					};
					if(!EVP_CIPHER_CTX_get_params(cipherContext.get(), getTagParameters)) {
					
						// Throw exception
						throw runtime_error("Getting tag failed");
					}
					
					// Check if binding create wallet statement's values failed
					if(sqlite3_bind_blob(createWalletStatement, 1, pepper, sizeof(pepper), SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_blob(createWalletStatement, 2, salt, sizeof(salt), SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_blob(createWalletStatement, 3, initializationVector, sizeof(initializationVector), SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_blob(createWalletStatement, 4, encryptedSeed.data(), encryptedSeed.size(), SQLITE_STATIC) != SQLITE_OK) {
					
						// Throw exception
						throw runtime_error("Binding create wallet statement's values failed");
					}
					
					// Check if running create wallet statement failed
					if(sqlite3_step(createWalletStatement) != SQLITE_DONE) {
					
						// Reset create wallet statement
						sqlite3_reset(createWalletStatement);
						
						// Throw exception
						throw runtime_error("Running create wallet statement failed");
					}
				}
				
				// Otherwise
				else {
					
					// Check if initializing cipher context failed
					const size_t initializationVectorLength = sizeof(initializationVector);
					const OSSL_PARAM setInitializationVectorLengthParameters[] = {
					
						// Initialization vector length
						OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, const_cast<size_t *>(&initializationVectorLength)),
						
						// End
						OSSL_PARAM_END
					};
					if(!EVP_DecryptInit_ex2(cipherContext.get(), cipher.get(), nullptr, nullptr, setInitializationVectorLengthParameters) || !EVP_DecryptInit_ex2(cipherContext.get(), nullptr, key, initializationVector, nullptr)) {
					
						// Throw exception
						throw runtime_error("Initializing cipher context failed");
					}
					
					// Check if getting tag length failed
					size_t tagLength;
					OSSL_PARAM getTagLengthParameters[] = {
					
						// Tag length
						OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tagLength),
						
						// end
						OSSL_PARAM_END
					};
					if(!EVP_CIPHER_CTX_get_params(cipherContext.get(), getTagLengthParameters)) {
					
						// Throw exception
						throw runtime_error("Getting tag length failed");
					}
					
					// Check if encrypted seed size is invalid
					if(encryptedSeed.size() != sizeof(seed) + tagLength) {
					
						// Throw exception
						throw runtime_error("Encrypted seed size is invalid");
					}
					
					// Check if decrypting encrypted seed failed
					int seedLength;
					if(!EVP_DecryptUpdate(cipherContext.get(), seed, &seedLength, encryptedSeed.data(), sizeof(seed)) || static_cast<size_t>(seedLength) != sizeof(seed)) {
					
						// Throw exception
						throw runtime_error("Decrypting encrypted seed failed");
					}
					
					// Check if setting tag failed
					const OSSL_PARAM setTagParameters[] = {
					
						// Tag
						OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, &encryptedSeed[sizeof(seed)], tagLength),
						
						// End
						OSSL_PARAM_END
					};
					if(!EVP_CIPHER_CTX_set_params(cipherContext.get(), setTagParameters)) {
					
						// Throw exception
						throw runtime_error("Setting tag failed");
					}
					
					// Check if finishing decrypting encrypted seed failed
					if(!EVP_DecryptFinal_ex(cipherContext.get(), seed, &seedLength) || seedLength) {
					
						// Check if password was incorrect
						if(!seedLength) {
						
							// Display message
							cout << "Incorrect password" << endl;
							
							// Securely clear key
							explicit_bzero(key, sizeof(key));
							
							// Securely clear password
							explicit_bzero(password.data(), password.capacity());
							
							// Securely clear seed
							explicit_bzero(seed, sizeof(seed));
							
							// Return false
							return false;
						}
						
						// Otherwise
						else {
						
							// Throw exception
							throw runtime_error("Finishing decrypting encrypted seed failed");
						}
					}
				}
			}
				
			// Catch errors
			catch(...) {
			
				// Securely clear key
				explicit_bzero(key, sizeof(key));
				
				// Throw
				throw;
			}
			
			// Securely clear key
			explicit_bzero(key, sizeof(key));
		}
		
		// Catch errors
		catch(...) {
		
			// Securely clear password
			explicit_bzero(password.data(), password.capacity());
			
			// Throw
			throw;
		}
		
		// Securely clear password
		explicit_bzero(password.data(), password.capacity());
		
		// Check if getting MAC failed
		const unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(EVP_MAC_fetch(nullptr, EXTENDED_PRIVATE_KEY_MAC_ALGORITHM, nullptr), EVP_MAC_free);
		if(!mac) {
		
			// Throw exception
			throw runtime_error("Getting MAC failed");
		}
		
		// Check if creating MAC context failed
		const unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> macContext(EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free);
		if(!macContext) {
		
			// Throw exception
			throw runtime_error("Creating MAC context failed");
		}
		
		// Check if initializing MAC context failed
		const OSSL_PARAM setDigestParameters[] = {
					
			// Digest
			OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(EXTENDED_PRIVATE_KEY_MAC_DIGEST), 0),
			
			// end
			OSSL_PARAM_END
		};
		if(!EVP_MAC_init(macContext.get(), reinterpret_cast<const unsigned char *>(EXTENDED_PRIVATE_KEY_MAC_SEED), sizeof(EXTENDED_PRIVATE_KEY_MAC_SEED) - sizeof('\0'), setDigestParameters)) {
		
			// Throw exception
			throw runtime_error("Initializing MAC context failed");
		}
		
		// Check if hashing seed failed
		if(!EVP_MAC_update(macContext.get(), seed, sizeof(seed))) {
		
			// Throw exception
			throw runtime_error("Hashing seed failed");
		}
		
		// Check if getting result length failed
		size_t resultLength;
		OSSL_PARAM getResultLengthParameters[] = {
		
			// MAC length
			OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &resultLength),
			
			// End
			OSSL_PARAM_END
		};
		if(!EVP_MAC_CTX_get_params(macContext.get(), getResultLengthParameters)) {
		
			// Throw exception
			throw runtime_error("Getting result length failed");
		}
		
		// Check if result length is invalid
		if(resultLength != sizeof(extendedPrivateKey)) {
		
			// Throw exception
			throw runtime_error("Result length is invalid");
		}
		
		// Check if getting extended private key failed
		size_t extendedPrivateKeyLength;
		if(!EVP_MAC_final(macContext.get(), extendedPrivateKey, &extendedPrivateKeyLength, sizeof(extendedPrivateKey)) || extendedPrivateKeyLength != sizeof(extendedPrivateKey)) {
		
			// Throw exception
			throw runtime_error("Getting extended private key failed");
		}
		
		// Check if extended private key's private key isn't a valid secp256k1 private key
		if(!Crypto::isValidSecp256k1PrivateKey(extendedPrivateKey, Crypto::SECP256K1_PRIVATE_KEY_SIZE)) {
		
			// Throw exception
			throw runtime_error("Extended private key's private key isn't a valid secp256k1 private key");
		}
		
		// Check if creating wallet
		if(createWallet) {
		
			// Display message
			cout << "Wallet created" << endl;
			
			// Set opened
			opened = true;
		
			// Display passphrase for seed
			Mnemonic::displayPassphrase(seed);
			
			// Display root public key
			displayRootPublicKey();
		}
		
		// Otherwise
		else {
		
			// Display message
			cout << "Wallet opened" << endl;
			
			// Set opened
			opened = true;
			
			// Check if showing recovery passphrase
			if(showRecoveryPassphrase) {
			
				// Display passphrase for seed
				Mnemonic::displayPassphrase(seed);
			}
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Securely clear seed
		explicit_bzero(seed, sizeof(seed));
		
		// Throw
		throw;
	}
	
	// Securely clear seed
	explicit_bzero(seed, sizeof(seed));
	
	// Return true
	return true;
}

// Display root public key
void Wallet::displayRootPublicKey() const {

	// Check if getting extended private key's private key's public key failed
	uint8_t rootPublicKey[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
	if(!Crypto::getSecp256k1PublicKey(rootPublicKey, extendedPrivateKey)) {
	
		// Throw exception
		throw runtime_error("Getting extended private key's private key's public key failed");
	}
	
	// Get root public key as a string
	string rootPublicKeyString = Common::toHexString(rootPublicKey, sizeof(rootPublicKey));
	
	// Display root public key string
	cout << "Root public key: " << rootPublicKeyString << endl;
	
	// Securely clear root public key string
	explicit_bzero(rootPublicKeyString.data(), rootPublicKeyString.capacity());
	
	// Securely clear root public key
	explicit_bzero(rootPublicKey, sizeof(rootPublicKey));
}

// Get blinding factor
bool Wallet::getBlindingFactor(uint8_t blindingFactor[Crypto::BLINDING_FACTOR_SIZE], const uint64_t identifierPath, const uint64_t value) const {

	// Set child path to a non-standard path used to allow 2^64 unique identifiers that other wallet software won't use
	const uint32_t childPath[] = {
		static_cast<uint32_t>(identifierPath >> numeric_limits<uint32_t>::digits),
		static_cast<uint32_t>(identifierPath & numeric_limits<uint32_t>::max()),
		0,
		0
	};
	
	// Check if deriving the child extended private key at the child path failed
	uint8_t childExtendedPrivateKey[sizeof(extendedPrivateKey)];
	memcpy(childExtendedPrivateKey, extendedPrivateKey, sizeof(extendedPrivateKey));
	if(!Crypto::deriveChildExtendedPrivateKey(childExtendedPrivateKey, childPath, sizeof(childPath) / sizeof(childPath[0]))) {
	
		// Return false
		return false;
	}
	
	// Check if getting the blinding factor from the child extended private key's private key and value failed
	if(!Crypto::getBlindingFactor(blindingFactor, childExtendedPrivateKey, value)) {
	
		// Securely clear child extended private key
		explicit_bzero(childExtendedPrivateKey, sizeof(childExtendedPrivateKey));
		
		// Return false
		return false;
	}
	
	// Securely clear child extended private key
	explicit_bzero(childExtendedPrivateKey, sizeof(childExtendedPrivateKey));
	
	// Return true
	return true;
}

// Get commitment
bool Wallet::getCommitment(uint8_t commitment[Crypto::COMMITMENT_SIZE], const uint64_t identifierPath, const uint64_t value) const {

	// Set child path to a non-standard path used to allow 2^64 unique identifiers that other wallet software won't use
	const uint32_t childPath[] = {
		static_cast<uint32_t>(identifierPath >> numeric_limits<uint32_t>::digits),
		static_cast<uint32_t>(identifierPath & numeric_limits<uint32_t>::max()),
		0,
		0
	};
	
	// Check if deriving the child extended private key at the child path failed
	uint8_t childExtendedPrivateKey[sizeof(extendedPrivateKey)];
	memcpy(childExtendedPrivateKey, extendedPrivateKey, sizeof(extendedPrivateKey));
	if(!Crypto::deriveChildExtendedPrivateKey(childExtendedPrivateKey, childPath, sizeof(childPath) / sizeof(childPath[0]))) {
	
		// Return false
		return false;
	}
	
	// Check if getting the blinding factor from the child extended private key's private key and value failed
	uint8_t blindingFactor[Crypto::BLINDING_FACTOR_SIZE];
	if(!Crypto::getBlindingFactor(blindingFactor, childExtendedPrivateKey, value)) {
	
		// Securely clear child extended private key
		explicit_bzero(childExtendedPrivateKey, sizeof(childExtendedPrivateKey));
		
		// Return false
		return false;
	}
	
	// Securely clear child extended private key
	explicit_bzero(childExtendedPrivateKey, sizeof(childExtendedPrivateKey));
	
	// Check if getting commitment failed
	if(!Crypto::getCommitment(commitment, blindingFactor, value)) {
	
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Securely clear blinding factor
	explicit_bzero(blindingFactor, sizeof(blindingFactor));
	
	// Return true
	return true;
}

// Get Bulletproof
bool Wallet::getBulletproof(uint8_t bulletproof[Crypto::BULLETPROOF_SIZE], const uint64_t identifierPath, const uint64_t value) const {

	// Set child path to a non-standard path used to allow 2^64 unique identifiers that other wallet software won't use
	uint32_t childPath[] = {
		static_cast<uint32_t>(identifierPath >> numeric_limits<uint32_t>::digits),
		static_cast<uint32_t>(identifierPath & numeric_limits<uint32_t>::max()),
		0,
		0
	};
	
	// Check if deriving the child extended private key at the child path failed
	uint8_t childExtendedPrivateKey[sizeof(extendedPrivateKey)];
	memcpy(childExtendedPrivateKey, extendedPrivateKey, sizeof(extendedPrivateKey));
	if(!Crypto::deriveChildExtendedPrivateKey(childExtendedPrivateKey, childPath, sizeof(childPath) / sizeof(childPath[0]))) {
	
		// Return false
		return false;
	}
	
	// Check if getting the blinding factor from the child extended private key's private key and value failed
	uint8_t blindingFactor[Crypto::BLINDING_FACTOR_SIZE];
	if(!Crypto::getBlindingFactor(blindingFactor, childExtendedPrivateKey, value)) {
	
		// Securely clear child extended private key
		explicit_bzero(childExtendedPrivateKey, sizeof(childExtendedPrivateKey));
		
		// Return false
		return false;
	}
	
	// Securely clear child extended private key
	explicit_bzero(childExtendedPrivateKey, sizeof(childExtendedPrivateKey));
	
	// Check if getting commitment failed
	uint8_t commitment[Crypto::COMMITMENT_SIZE];
	if(!Crypto::getCommitment(commitment, blindingFactor, value)) {
	
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if getting digest failed
	const unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(EVP_MD_fetch(nullptr, BULLETPROOF_HASH_DIGEST_ALGORITHM, nullptr), EVP_MD_free);
	if(!digest) {
	
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if creating digest context failed
	const unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if(!digestContext) {
	
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if initializing digest context failed
	if(!EVP_DigestInit_ex2(digestContext.get(), digest.get(), nullptr)) {
	
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if hashing extended private key's private key failed
	if(!EVP_DigestUpdate(digestContext.get(), extendedPrivateKey, Crypto::SECP256K1_PRIVATE_KEY_SIZE)) {
	
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if getting digest length failed
	size_t digestLength;
	OSSL_PARAM getDigestLengthParameters[] = {
	
		// Digest length
		OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &digestLength),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_MD_get_params(digest.get(), getDigestLengthParameters)) {
	
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if getting private hash failed
	uint8_t privateHash[digestLength];
	unsigned int privateHashLength;
	if(!EVP_DigestFinal_ex(digestContext.get(), privateHash, &privateHashLength) || privateHashLength != sizeof(privateHash)) {
	
		// Securely clear private hash
		explicit_bzero(privateHash, sizeof(privateHash));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if getting MAC failed
	const unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(EVP_MAC_fetch(nullptr, BULLETPROOF_NONCE_MAC_ALGORITHM, nullptr), EVP_MAC_free);
	if(!mac) {
	
		// Securely clear private hash
		explicit_bzero(privateHash, sizeof(privateHash));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if creating MAC context failed
	const unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> macContext(EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free);
	if(!macContext) {
	
		// Securely clear private hash
		explicit_bzero(privateHash, sizeof(privateHash));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if initializing MAC context with the commitment as the key failed
	if(!EVP_MAC_init(macContext.get(), commitment, sizeof(commitment), nullptr)) {
	
		// Securely clear private hash
		explicit_bzero(privateHash, sizeof(privateHash));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if hashing private hash failed
	if(!EVP_MAC_update(macContext.get(), privateHash, sizeof(privateHash))) {
	
		// Securely clear private hash
		explicit_bzero(privateHash, sizeof(privateHash));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Securely clear private hash
	explicit_bzero(privateHash, sizeof(privateHash));
	
	// Check if getting private nonce failed
	uint8_t privateNonce[Crypto::SCALAR_SIZE];
	size_t privateNonceLength;
	if(!EVP_MAC_final(macContext.get(), privateNonce, &privateNonceLength, sizeof(privateNonce)) || privateNonceLength != sizeof(privateNonce)) {
	
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if private nonce isn't a valid secp256k1 private key
	if(!Crypto::isValidSecp256k1PrivateKey(privateNonce, sizeof(privateNonce))) {
	
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if getting extended private key's private key's public key failed
	uint8_t publicKey[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
	if(!Crypto::getSecp256k1PublicKey(publicKey, extendedPrivateKey)) {
	
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if initializing digest context failed
	if(!EVP_DigestInit_ex2(digestContext.get(), digest.get(), nullptr)) {
	
		// Securely clear public key
		explicit_bzero(publicKey, sizeof(publicKey));
		
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if hashing public key failed
	if(!EVP_DigestUpdate(digestContext.get(), publicKey, sizeof(publicKey))) {
	
		// Securely clear public key
		explicit_bzero(publicKey, sizeof(publicKey));
		
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Securely clear public key
	explicit_bzero(publicKey, sizeof(publicKey));
	
	// Check if getting rewind hash failed
	uint8_t rewindHash[digestLength];
	unsigned int rewindHashLength;
	if(!EVP_DigestFinal_ex(digestContext.get(), rewindHash, &rewindHashLength) || rewindHashLength != sizeof(rewindHash)) {
	
		// Securely clear rewind hash
		explicit_bzero(rewindHash, sizeof(rewindHash));
		
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if initializing MAC context with the commitment as the key failed
	if(!EVP_MAC_init(macContext.get(), commitment, sizeof(commitment), nullptr)) {
	
		// Securely clear rewind hash
		explicit_bzero(rewindHash, sizeof(rewindHash));
		
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if hashing rewind hash failed
	if(!EVP_MAC_update(macContext.get(), rewindHash, sizeof(rewindHash))) {
	
		// Securely clear rewind hash
		explicit_bzero(rewindHash, sizeof(rewindHash));
		
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Securely clear rewind hash
	explicit_bzero(rewindHash, sizeof(rewindHash));
	
	// Check if getting rewind nonce failed
	uint8_t rewindNonce[Crypto::SCALAR_SIZE];
	size_t rewindNonceLength;
	if(!EVP_MAC_final(macContext.get(), rewindNonce, &rewindNonceLength, sizeof(rewindNonce)) || rewindNonceLength != sizeof(rewindNonce)) {
	
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if rewind nonce isn't a valid secp256k1 private key
	if(!Crypto::isValidSecp256k1PrivateKey(rewindNonce, sizeof(rewindNonce))) {
	
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Create message
	uint8_t message[Crypto::BULLETPROOF_MESSAGE_SIZE] = {};
	message[Crypto::BULLETPROOF_MESSAGE_SWITCH_TYPE_INDEX] = static_cast<underlying_type<SwitchType>::type>(SwitchType::REGULAR);
	message[Crypto::BULLETPROOF_MESSAGE_PATH_DEPTH_INDEX] = sizeof(childPath) / sizeof(childPath[0]);
	
	// Check if little endian
	#if BYTE_ORDER == LITTLE_ENDIAN
	
		// Make child path big endian
		for(size_t i = 0; i < sizeof(childPath) / sizeof(childPath[0]); ++i) {
	
			childPath[i] = __builtin_bswap32(childPath[i]);
		}
	#endif
	
	// Add child path to message
	memcpy(&message[Crypto::BULLETPROOF_MESSAGE_PATH_INDEX], childPath, sizeof(childPath));
	
	// Check if getting Bulletproof failed
	if(!Crypto::getBulletproof(bulletproof, blindingFactor, value, rewindNonce, privateNonce, message)) {
	
		// Securely clear private nonce
		explicit_bzero(privateNonce, sizeof(privateNonce));
		
		// Securely clear blinding factor
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Securely clear private nonce
	explicit_bzero(privateNonce, sizeof(privateNonce));
	
	// Securely clear blinding factor
	explicit_bzero(blindingFactor, sizeof(blindingFactor));
	
	// Return true
	return true;
}

// Get Tor payment proof address
string Wallet::getTorPaymentProofAddress(const uint64_t index) const {

	// Check if getting address private key at the index failed
	uint8_t addressPrivateKey[Crypto::ED25519_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, index)) {
	
		// Throw exception
		throw runtime_error("Getting address private key at the index failed");
	}
	
	// Check if address private key isn't a valid Ed25519 private key
	if(!Crypto::isValidEd25519PrivateKey(addressPrivateKey, sizeof(addressPrivateKey))) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Address private key isn't a valid Ed25519 private key");
	}
	
	// Check if getting address private key's public key failed
	uint8_t addressPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE];
	if(!Crypto::getEd25519PublicKey(addressPublicKey, addressPrivateKey)) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Getting address private key's public key failed");
	}
	
	// Securely clear address private key
	explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return address public key as a Tor address
	return Tor::ed25519PublicKeyToAddress(addressPublicKey);
}

// Get MQS payment proof address public key
bool Wallet::getTorPaymentProofAddressPublicKey(uint8_t publicKey[Crypto::ED25519_PUBLIC_KEY_SIZE], const uint64_t index) const {

	// Check if getting address private key at the index failed
	uint8_t addressPrivateKey[Crypto::ED25519_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, index)) {
	
		// Return false
		return false;
	}
	
	// Check if address private key isn't a valid Ed25519 private key
	if(!Crypto::isValidEd25519PrivateKey(addressPrivateKey, sizeof(addressPrivateKey))) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}
	
	// Check if getting address private key's public key failed
	if(!Crypto::getEd25519PublicKey(publicKey, addressPrivateKey)) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}
	
	// Securely clear address private key
	explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return true
	return true;
}

// Get Tor payment proof signature
bool Wallet::getTorPaymentProofSignature(uint8_t signature[Crypto::ED25519_SIGNATURE_SIZE], const uint64_t index, const uint8_t kernelCommitment[Crypto::COMMITMENT_SIZE], const char *senderAddress, const uint64_t value) const {

	// Check if getting address private key at the index failed
	uint8_t addressPrivateKey[Crypto::ED25519_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, index)) {
	
		// Return false
		return false;
	}
	
	// Check if address private key isn't a valid Ed25519 private key
	if(!Crypto::isValidEd25519PrivateKey(addressPrivateKey, sizeof(addressPrivateKey))) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}

	// Set data
	const string data = Common::toHexString(kernelCommitment, Crypto::COMMITMENT_SIZE) + senderAddress + to_string(value);
	
	// Check if signing data failed
	if(!Crypto::getEd25519Signature(signature, addressPrivateKey, reinterpret_cast<const uint8_t *>(data.data()), data.size())) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}
	
	// Securely clear address private key
	explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return true
	return true;
}

// Get MQS payment proof address
string Wallet::getMqsPaymentProofAddress(const uint64_t index) const {

	// Check if getting address private key at the index failed
	uint8_t addressPrivateKey[Crypto::SECP256K1_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, index)) {
	
		// Throw exception
		throw runtime_error("Getting address private key at the index failed");
	}
	
	// Check if address private key isn't a valid secp256k1 private key
	if(!Crypto::isValidSecp256k1PrivateKey(addressPrivateKey, sizeof(addressPrivateKey))) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Address private key isn't a valid secp256k1 private key");
	}
	
	// Check if getting address private key's public key failed
	uint8_t addressPublicKey[Crypto::SECP256K1_PUBLIC_KEY_SIZE];
	if(!Crypto::getSecp256k1PublicKey(addressPublicKey, addressPrivateKey)) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Getting address private key's public key failed");
	}
	
	// Securely clear address private key
	explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return address public key as an MQS address
	return Mqs::secp256k1PublicKeyToAddress(addressPublicKey);
}

// Get MQS payment proof address public key
bool Wallet::getMqsPaymentProofAddressPublicKey(uint8_t publicKey[Crypto::SECP256K1_PUBLIC_KEY_SIZE], const uint64_t index) const {

	// Check if getting address private key at the index failed
	uint8_t addressPrivateKey[Crypto::SECP256K1_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, index)) {
	
		// Return false
		return false;
	}
	
	// Check if address private key isn't a valid secp256k1 private key
	if(!Crypto::isValidSecp256k1PrivateKey(addressPrivateKey, sizeof(addressPrivateKey))) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}
	
	// Check if getting address private key's public key failed
	if(!Crypto::getSecp256k1PublicKey(publicKey, addressPrivateKey)) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return false
		return false;
	}
	
	// Securely clear address private key
	explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Return true
	return true;
}

// Get MQS payment proof signature
vector<uint8_t> Wallet::getMqsPaymentProofSignature(const uint64_t index, const uint8_t kernelCommitment[Crypto::COMMITMENT_SIZE], const char *senderAddress, const uint64_t value) const {

	// Check if getting address private key at the index failed
	uint8_t addressPrivateKey[Crypto::SECP256K1_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, index)) {
	
		// Throw exception
		throw runtime_error("Getting address private key at the index failed");
	}
	
	// Check if address private key isn't a valid secp256k1 private key
	if(!Crypto::isValidSecp256k1PrivateKey(addressPrivateKey, sizeof(addressPrivateKey))) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Address private key isn't a valid secp256k1 private key");
	}
	
	// Set data
	const string data = Common::toHexString(kernelCommitment, Crypto::COMMITMENT_SIZE) + senderAddress + to_string(value);
	
	// Try
	try {
	
		// Sign data
		vector signature = Crypto::getSecp256k1EcdsaSignature(addressPrivateKey, reinterpret_cast<const uint8_t *>(data.data()), data.size());
		
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Return signature
		return signature;
	}
	
	// Catch errors
	catch(...) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw
		throw;
	}
}

// Encrypt address message
pair<vector<uint8_t>, array<uint8_t, Crypto::CHACHA20_NONCE_SIZE>> Wallet::encryptAddressMessage(const uint8_t *data, const size_t length, const uint8_t recipientPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE], const uint64_t index, const uint8_t version) const {

	// Check if creating random nonce failed
	array<uint8_t, Crypto::CHACHA20_NONCE_SIZE> nonce;
	if(RAND_bytes_ex(nullptr, nonce.data(), nonce.size(), RAND_DRBG_STRENGTH) != 1) {
	
		// Throw exception
		throw runtime_error("Creating random nonce failed");
	}
	
	// Check if getting address private key at the index failed
	uint8_t addressPrivateKey[Crypto::ED25519_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, index)) {
	
		// Throw exception
		throw runtime_error("Getting address private key at the index failed");
	}
	
	// Check if address private key isn't a valid Ed25519 private key
	if(!Crypto::isValidEd25519PrivateKey(addressPrivateKey, sizeof(addressPrivateKey))) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Address private key isn't a valid Ed25519 private key");
	}
	
	// Check if getting address private key's public key failed
	uint8_t publicKey[Crypto::ED25519_PUBLIC_KEY_SIZE];
	if(!Crypto::getEd25519PublicKey(publicKey, addressPrivateKey)) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Getting address private key's public key failed");
	}
	
	// Check if getting X25519 private key from address private key
	uint8_t x25519PrivateKey[Crypto::X25519_PRIVATE_KEY_SIZE];
	if(!Crypto::getX25519PrivateKey(x25519PrivateKey, addressPrivateKey)) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Getting X25519 private key from address private key");
	}
	
	// Securely clear address private key
	explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Check if getting X25519 public key from recipient public key failed
	uint8_t x25519PublicKey[Crypto::X25519_PUBLIC_KEY_SIZE];
	if(!Crypto::getX25519PublicKey(x25519PublicKey, recipientPublicKey)) {
	
		// Securely clear X25519 private key
		explicit_bzero(x25519PrivateKey, sizeof(x25519PrivateKey));
		
		// Throw exception
		throw runtime_error("Getting X25519 public key from recipient public key failed");	
	}
	
	// Check if getting shared key from X25519 private key and X25519 public key failed
	uint8_t sharedKey[Crypto::SCALAR_SIZE];
	if(!Crypto::getX25519SharedKey(sharedKey, x25519PrivateKey, x25519PublicKey)) {
	
		// Securely clear X25519 private key
		explicit_bzero(x25519PrivateKey, sizeof(x25519PrivateKey));
		
		// Throw exception
		throw runtime_error("Getting shared key from X25519 private key and X25519 public key failed");	
	}
	
	// Securely clear X25519 private key
	explicit_bzero(x25519PrivateKey, sizeof(x25519PrivateKey));
	
	// Check if getting cipher failed
	const unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(EVP_CIPHER_fetch(nullptr, ADDRESS_MESSAGE_ENCRYPTION_ALGORITHM, nullptr), EVP_CIPHER_free);
	if(!cipher) {
	
		// Securely clear shared private key
		explicit_bzero(sharedKey, sizeof(sharedKey));
		
		// Throw exception
		throw runtime_error("Getting cipher failed");
	}

	// Check if creating cipher context failed
	const unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipherContext(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if(!cipherContext) {
	
		// Securely clear shared private key
		explicit_bzero(sharedKey, sizeof(sharedKey));
		
		// Throw exception
		throw runtime_error("Creating cipher context failed");
	}

	// Check if initializing cipher context failed
	if(!EVP_EncryptInit_ex2(cipherContext.get(), cipher.get(), sharedKey, nonce.data(), nullptr)) {
	
		// Securely clear shared private key
		explicit_bzero(sharedKey, sizeof(sharedKey));
		
		// Throw exception
		throw runtime_error("Initializing cipher context failed");
	}
	
	// Securely clear shared private key
	explicit_bzero(sharedKey, sizeof(sharedKey));
	
	// Get checksum
	uint32_t checksum = crc32(0, Z_NULL, 0);
	checksum = crc32_z(checksum, &version, sizeof(version));
	checksum = crc32_z(checksum, publicKey, sizeof(publicKey));
	checksum = crc32_z(checksum, recipientPublicKey, Crypto::ED25519_PUBLIC_KEY_SIZE);
	checksum = crc32_z(checksum, data, length);
	
	// Check if little endian
	#if BYTE_ORDER == LITTLE_ENDIAN
	
		// Make checksum big endian
		checksum = __builtin_bswap32(checksum);
	#endif
	
	// Check if getting tag length failed
	size_t tagLength;
	OSSL_PARAM getTagLengthParameters[] = {
	
		// Tag length
		OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tagLength),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_CIPHER_CTX_get_params(cipherContext.get(), getTagLengthParameters)) {
	
		// Throw exception
		throw runtime_error("Getting tag length failed");
	}
	
	// Check if encrypting data failed
	vector<uint8_t> encryptedData(length + sizeof(checksum) + tagLength);
	int encryptedDataLength;
	if(!EVP_EncryptUpdate(cipherContext.get(), encryptedData.data(), &encryptedDataLength, data, length) || static_cast<size_t>(encryptedDataLength) != length) {
	
		// Throw exception
		throw runtime_error("Encrypting data failed");
	}
	
	// Check if encrypting checksum failed
	if(!EVP_EncryptUpdate(cipherContext.get(), &encryptedData[length], &encryptedDataLength, reinterpret_cast<const uint8_t *>(&checksum), sizeof(checksum)) || static_cast<size_t>(encryptedDataLength) != sizeof(checksum)) {
	
		// Throw exception
		throw runtime_error("Encrypting data failed");
	}
	
	// Check if finishing encrypting data failed
	if(!EVP_EncryptFinal_ex(cipherContext.get(), encryptedData.data(), &encryptedDataLength) || encryptedDataLength) {
	
		// Throw exception
		throw runtime_error("Finishing encrypting data failed");
	}
	
	// Check if getting tag failed
	OSSL_PARAM getTagParameters[] = {
	
		// Tag
		OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, &encryptedData[length + sizeof(checksum)], tagLength),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_CIPHER_CTX_get_params(cipherContext.get(), getTagParameters)) {
	
		// Throw exception
		throw runtime_error("Getting tag failed");
	}
	
	// Return encrypted data and nonce
	return {encryptedData, nonce};
}

// Decrypt address message
vector<uint8_t> Wallet::decryptAddressMessage(const uint8_t *encryptedData, const size_t length, const uint8_t nonce[Crypto::CHACHA20_NONCE_SIZE], const uint8_t senderPublicKey[Crypto::ED25519_PUBLIC_KEY_SIZE], const uint64_t index, const uint8_t version) const {
	
	// Check if getting address private key at the index failed
	uint8_t addressPrivateKey[Crypto::ED25519_PRIVATE_KEY_SIZE];
	if(!getAddressPrivateKey(addressPrivateKey, index)) {
	
		// Throw exception
		throw runtime_error("Getting address private key at the index failed");
	}
	
	// Check if address private key isn't a valid Ed25519 private key
	if(!Crypto::isValidEd25519PrivateKey(addressPrivateKey, sizeof(addressPrivateKey))) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Address private key isn't a valid Ed25519 private key");
	}
	
	// Check if getting address private key's public key failed
	uint8_t publicKey[Crypto::ED25519_PUBLIC_KEY_SIZE];
	if(!Crypto::getEd25519PublicKey(publicKey, addressPrivateKey)) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Getting address private key's public key failed");
	}
	
	// Check if getting X25519 private key from address private key
	uint8_t x25519PrivateKey[Crypto::X25519_PRIVATE_KEY_SIZE];
	if(!Crypto::getX25519PrivateKey(x25519PrivateKey, addressPrivateKey)) {
	
		// Securely clear address private key
		explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
		
		// Throw exception
		throw runtime_error("Getting X25519 private key from address private key");
	}
	
	// Securely clear address private key
	explicit_bzero(addressPrivateKey, sizeof(addressPrivateKey));
	
	// Check if getting X25519 public key from sender public key failed
	uint8_t x25519PublicKey[Crypto::X25519_PUBLIC_KEY_SIZE];
	if(!Crypto::getX25519PublicKey(x25519PublicKey, senderPublicKey)) {
	
		// Securely clear X25519 private key
		explicit_bzero(x25519PrivateKey, sizeof(x25519PrivateKey));
		
		// Throw exception
		throw runtime_error("Getting X25519 public key from sender public key failed");	
	}
	
	// Check if getting shared key from X25519 private key and X25519 public key failed
	uint8_t sharedKey[Crypto::SCALAR_SIZE];
	if(!Crypto::getX25519SharedKey(sharedKey, x25519PrivateKey, x25519PublicKey)) {
	
		// Securely clear X25519 private key
		explicit_bzero(x25519PrivateKey, sizeof(x25519PrivateKey));
		
		// Throw exception
		throw runtime_error("Getting shared key from X25519 private key and X25519 public key failed");	
	}
	
	// Securely clear X25519 private key
	explicit_bzero(x25519PrivateKey, sizeof(x25519PrivateKey));
	
	// Check if getting cipher failed
	const unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(EVP_CIPHER_fetch(nullptr, ADDRESS_MESSAGE_ENCRYPTION_ALGORITHM, nullptr), EVP_CIPHER_free);
	if(!cipher) {
	
		// Securely clear shared private key
		explicit_bzero(sharedKey, sizeof(sharedKey));
		
		// Throw exception
		throw runtime_error("Getting cipher failed");
	}

	// Check if creating cipher context failed
	const unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipherContext(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if(!cipherContext) {
	
		// Securely clear shared private key
		explicit_bzero(sharedKey, sizeof(sharedKey));
		
		// Throw exception
		throw runtime_error("Creating cipher context failed");
	}

	// Check if initializing cipher context failed
	if(!EVP_DecryptInit_ex2(cipherContext.get(), cipher.get(), sharedKey, nonce, nullptr)) {
	
		// Securely clear shared private key
		explicit_bzero(sharedKey, sizeof(sharedKey));
		
		// Throw exception
		throw runtime_error("Initializing cipher context failed");
	}
	
	// Securely clear shared private key
	explicit_bzero(sharedKey, sizeof(sharedKey));
	
	// Check if getting tag length failed
	size_t tagLength;
	OSSL_PARAM getTagLengthParameters[] = {
	
		// Tag length
		OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tagLength),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_CIPHER_CTX_get_params(cipherContext.get(), getTagLengthParameters)) {
	
		// Throw exception
		throw runtime_error("Getting tag length failed");
	}
	
	// Check if encrypted data doesn't contain a tag
	if(length < tagLength) {
	
		// Throw exception
		throw runtime_error("Encrypted data doesn't contain a tag");
	}
	
	// Get encrypted data's tag
	const uint8_t *tag = &encryptedData[length - tagLength];

	// Check if decrypting encrypted data failed
	vector<uint8_t> data(length - tagLength);
	int dataLength;
	if(!EVP_DecryptUpdate(cipherContext.get(), data.data(), &dataLength, encryptedData, data.size()) || static_cast<size_t>(dataLength) != data.size()) {
	
		// Throw exception
		throw runtime_error("Decrypting encrypted data failed");
	}

	// Check if setting tag failed
	const OSSL_PARAM setTagParameters[] = {

		// Tag
		OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, const_cast<uint8_t *>(tag), tagLength),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_CIPHER_CTX_set_params(cipherContext.get(), setTagParameters)) {
	
		// Throw exception
		throw runtime_error("Setting tag failed");
	}

	// Check if finishing decrypting encrypted data failed
	if(!EVP_DecryptFinal_ex(cipherContext.get(), data.data(), &dataLength) || dataLength) {
	
		// Throw exception
		throw runtime_error("Finishing decrypting encrypted data failed");
	}
	
	// Check if data doesn't contain a checksum
	if(data.size() < sizeof(uint32_t)) {
	
		// Throw exception
		throw runtime_error("Data doesn't contain a checksum");
	}
	
	// Get data's checksum
	uint32_t checksum;
	memcpy(&checksum, &data[data.size() - sizeof(checksum)], sizeof(checksum));
	
	// Check if little endian
	#if BYTE_ORDER == LITTLE_ENDIAN
	
		// Make checksum little endian
		checksum = __builtin_bswap32(checksum);
	#endif
	
	// Get expected checksum
	uint32_t expectedChecksum = crc32(0, Z_NULL, 0);
	expectedChecksum = crc32_z(expectedChecksum, &version, sizeof(version));
	expectedChecksum = crc32_z(expectedChecksum, senderPublicKey, Crypto::ED25519_PUBLIC_KEY_SIZE);
	expectedChecksum = crc32_z(expectedChecksum, publicKey, sizeof(publicKey));
	expectedChecksum = crc32_z(expectedChecksum, data.data(), data.size() - sizeof(checksum));
	
	// Check if checksum is invalid
	if(checksum != expectedChecksum) {
	
		// Throw exception
		throw runtime_error("Checksum is invalid");
	}
	
	// Remove checksum from data
	data.resize(data.size() - sizeof(checksum));
	
	// Return data
	return data;
}

// Get address private key
bool Wallet::getAddressPrivateKey(uint8_t addressPrivateKey[Crypto::SECP256K1_PRIVATE_KEY_SIZE], const uint64_t index) const {

	// Check if getting the blinding factor for the extended private key's private key and committed value failed
	uint8_t blindingFactor[Crypto::BLINDING_FACTOR_SIZE];
	if(!Crypto::getBlindingFactor(blindingFactor, extendedPrivateKey, ADDRESS_PRIVATE_KEY_COMMITTED_VALUE)) {
	
		// Return false
		return false;
	}
	
	// Check if getting MAC failed
	const unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(EVP_MAC_fetch(nullptr, ADDRESS_PRIVATE_KEY_MAC_ALGORITHM, nullptr), EVP_MAC_free);
	if(!mac) {
	
		// Securely blinding factor key
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if creating MAC context failed
	const unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> macContext(EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free);
	if(!macContext) {
	
		// Securely blinding factor key
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if initializing MAC context failed
	const OSSL_PARAM setDigestParameters[] = {
				
		// Digest
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(ADDRESS_PRIVATE_KEY_MAC_DIGEST), 0),
		
		// end
		OSSL_PARAM_END
	};
	if(!EVP_MAC_init(macContext.get(), reinterpret_cast<const unsigned char *>(ADDRESS_PRIVATE_KEY_MAC_SEED), sizeof(ADDRESS_PRIVATE_KEY_MAC_SEED) - sizeof('\0'), setDigestParameters)) {
	
		// Securely blinding factor key
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Check if hashing blinding factor failed
	if(!EVP_MAC_update(macContext.get(), blindingFactor, sizeof(blindingFactor))) {
	
		// Securely blinding factor key
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Return false
		return false;
	}
	
	// Securely blinding factor key
	explicit_bzero(blindingFactor, sizeof(blindingFactor));
	
	// Check if getting result length failed
	size_t resultLength;
	OSSL_PARAM getResultLengthParameters[] = {
	
		// MAC length
		OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &resultLength),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_MAC_CTX_get_params(macContext.get(), getResultLengthParameters)) {
	
		// Return false
		return false;
	}
	
	// Check if result length is invalid
	if(resultLength != Crypto::EXTENDED_PRIVATE_KEY_SIZE) {
	
		// Return false
		return false;
	}
	
	// Check if getting master address extended private key failed
	uint8_t masterAddressExtendedPrivateKey[Crypto::EXTENDED_PRIVATE_KEY_SIZE];
	size_t masterAddressExtendedPrivateKeyLength;
	if(!EVP_MAC_final(macContext.get(), masterAddressExtendedPrivateKey, &masterAddressExtendedPrivateKeyLength, sizeof(masterAddressExtendedPrivateKey)) || masterAddressExtendedPrivateKeyLength != sizeof(masterAddressExtendedPrivateKey)) {
	
		// Securely clear master address extended private key
		explicit_bzero(masterAddressExtendedPrivateKey, sizeof(masterAddressExtendedPrivateKey));
		
		// Return false
		return false;
	}
	
	// Check if master extended private key's private key isn't a valid secp256k1 private key
	if(!Crypto::isValidSecp256k1PrivateKey(masterAddressExtendedPrivateKey, Crypto::SECP256K1_PRIVATE_KEY_SIZE)) {
	
		// Securely clear master address extended private key
		explicit_bzero(masterAddressExtendedPrivateKey, sizeof(masterAddressExtendedPrivateKey));
		
		// Return false
		return false;
	}
	
	// Set child path to a non-standard path used to allow 2^64 unique addresses that other wallet software won't use
	const uint32_t childPath[] = {
		static_cast<uint32_t>(index >> numeric_limits<uint32_t>::digits),
		static_cast<uint32_t>(index & numeric_limits<uint32_t>::max())
	};
	
	// Check if deriving master address extended private key's child extended private key at the child path failed
	if(!Crypto::deriveChildExtendedPrivateKey(masterAddressExtendedPrivateKey, childPath, sizeof(childPath) / sizeof(childPath[0]))) {
	
		// Return false
		return false;
	}
	
	// Set address private key to the child address extended private key's private key
	memcpy(addressPrivateKey, masterAddressExtendedPrivateKey, Crypto::SECP256K1_PRIVATE_KEY_SIZE);
	
	// Securely clear master address extended private key
	explicit_bzero(masterAddressExtendedPrivateKey, sizeof(masterAddressExtendedPrivateKey));
	
	// Return true
	return true;
}

// Is valid seed
bool isValidSeed(const uint8_t seed[Mnemonic::SEED_SIZE]) {

	// Check if getting extended private key MAC failed
	const unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> extendedPrivateKeyMac(EVP_MAC_fetch(nullptr, EXTENDED_PRIVATE_KEY_MAC_ALGORITHM, nullptr), EVP_MAC_free);
	if(!extendedPrivateKeyMac) {
	
		// Throw exception
		throw runtime_error("Getting extended private key MAC failed");
	}
	
	// Check if creating extended private key MAC context failed
	const unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> extendedPrivateKeyMacContext(EVP_MAC_CTX_new(extendedPrivateKeyMac.get()), EVP_MAC_CTX_free);
	if(!extendedPrivateKeyMacContext) {
	
		// Throw exception
		throw runtime_error("Creating extended private key MAC context failed");
	}
	
	// Check if initializing extended private key MAC context failed
	const OSSL_PARAM setExtendedPrivateKeyDigestParameters[] = {
				
		// Digest
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(EXTENDED_PRIVATE_KEY_MAC_DIGEST), 0),
		
		// end
		OSSL_PARAM_END
	};
	if(!EVP_MAC_init(extendedPrivateKeyMacContext.get(), reinterpret_cast<const unsigned char *>(EXTENDED_PRIVATE_KEY_MAC_SEED), sizeof(EXTENDED_PRIVATE_KEY_MAC_SEED) - sizeof('\0'), setExtendedPrivateKeyDigestParameters)) {
	
		// Throw exception
		throw runtime_error("Initializing extended private key MAC context failed");
	}
	
	// Check if hashing seed failed
	if(!EVP_MAC_update(extendedPrivateKeyMacContext.get(), seed, Mnemonic::SEED_SIZE)) {
	
		// Throw exception
		throw runtime_error("Hashing seed failed");
	}
	
	// Check if getting extended private key result length failed
	size_t extendedPrivateKeyResultLength;
	OSSL_PARAM getExtendedPrivateKeyResultLengthParameters[] = {
	
		// MAC length
		OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &extendedPrivateKeyResultLength),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_MAC_CTX_get_params(extendedPrivateKeyMacContext.get(), getExtendedPrivateKeyResultLengthParameters)) {
	
		// Throw exception
		throw runtime_error("Getting extended private key result length failed");
	}
	
	// Check if extended private key result length is invalid
	if(extendedPrivateKeyResultLength != Crypto::EXTENDED_PRIVATE_KEY_SIZE) {
	
		// Throw exception
		throw runtime_error("Extended private key result length is invalid");
	}
	
	// Check if getting extended private key failed
	uint8_t extendedPrivateKey[Crypto::EXTENDED_PRIVATE_KEY_SIZE];
	size_t extendedPrivateKeyLength;
	if(!EVP_MAC_final(extendedPrivateKeyMacContext.get(), extendedPrivateKey, &extendedPrivateKeyLength, sizeof(extendedPrivateKey)) || extendedPrivateKeyLength != sizeof(extendedPrivateKey)) {
	
		// Securely clear extended private key
		explicit_bzero(extendedPrivateKey, sizeof(extendedPrivateKey));
		
		// Throw exception
		throw runtime_error("Getting extended private key failed");
	}
	
	// Check if extended private key's private key isn't a valid secp256k1 private key
	if(!Crypto::isValidSecp256k1PrivateKey(extendedPrivateKey, Crypto::SECP256K1_PRIVATE_KEY_SIZE)) {
	
		// Securely clear extended private key
		explicit_bzero(extendedPrivateKey, sizeof(extendedPrivateKey));
		
		// Return false
		return false;
	}
	
	// Check if getting the blinding factor for the extended private key's private key and committed value failed
	uint8_t blindingFactor[Crypto::BLINDING_FACTOR_SIZE];
	if(!Crypto::getBlindingFactor(blindingFactor, extendedPrivateKey, ADDRESS_PRIVATE_KEY_COMMITTED_VALUE)) {
	
		// Securely clear extended private key
		explicit_bzero(extendedPrivateKey, sizeof(extendedPrivateKey));
		
		// Return false
		return false;
	}
	
	// Securely clear extended private key
	explicit_bzero(extendedPrivateKey, sizeof(extendedPrivateKey));
	
	// Check if getting address private key MAC failed
	const unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> addressPrivateKeyMac(EVP_MAC_fetch(nullptr, ADDRESS_PRIVATE_KEY_MAC_ALGORITHM, nullptr), EVP_MAC_free);
	if(!addressPrivateKeyMac) {
	
		// Securely blinding factor key
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Throw exception
		throw runtime_error("Getting address private key MAC failed");
	}
	
	// Check if creating address private key MAC context failed
	const unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> addressPrivateKeyMacContext(EVP_MAC_CTX_new(addressPrivateKeyMac.get()), EVP_MAC_CTX_free);
	if(!addressPrivateKeyMacContext) {
	
		// Securely blinding factor key
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Throw exception
		throw runtime_error("Creating address private key MAC context failed");
	}
	
	// Check if initializing address private key MAC context failed
	const OSSL_PARAM setAddressPrivateKeyDigestParameters[] = {
				
		// Digest
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(ADDRESS_PRIVATE_KEY_MAC_DIGEST), 0),
		
		// end
		OSSL_PARAM_END
	};
	if(!EVP_MAC_init(addressPrivateKeyMacContext.get(), reinterpret_cast<const unsigned char *>(ADDRESS_PRIVATE_KEY_MAC_SEED), sizeof(ADDRESS_PRIVATE_KEY_MAC_SEED) - sizeof('\0'), setAddressPrivateKeyDigestParameters)) {
	
		// Securely blinding factor key
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Throw exception
		throw runtime_error("Initializing address private key MAC context failed");
	}
	
	// Check if hashing blinding factor failed
	if(!EVP_MAC_update(addressPrivateKeyMacContext.get(), blindingFactor, sizeof(blindingFactor))) {
	
		// Securely blinding factor key
		explicit_bzero(blindingFactor, sizeof(blindingFactor));
		
		// Throw exception
		throw runtime_error("Hashing blinding factor failed");
	}
	
	// Securely blinding factor key
	explicit_bzero(blindingFactor, sizeof(blindingFactor));
	
	// Check if getting address private key result length failed
	size_t addressPrivateKeyResultLength;
	OSSL_PARAM getAddressPrivateKeyResultLengthParameters[] = {
	
		// MAC length
		OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &addressPrivateKeyResultLength),
		
		// End
		OSSL_PARAM_END
	};
	if(!EVP_MAC_CTX_get_params(addressPrivateKeyMacContext.get(), getAddressPrivateKeyResultLengthParameters)) {
	
		// Throw exception
		throw runtime_error("Getting address private key result length failed");
	}
	
	// Check if address private key result length is invalid
	if(addressPrivateKeyResultLength != Crypto::EXTENDED_PRIVATE_KEY_SIZE) {
	
		// Throw exception
		throw runtime_error("Address private key result length is invalid");
	}
	
	// Check if getting master address extended private key failed
	uint8_t masterAddressExtendedPrivateKey[Crypto::EXTENDED_PRIVATE_KEY_SIZE];
	size_t masterAddressExtendedPrivateKeyLength;
	if(!EVP_MAC_final(addressPrivateKeyMacContext.get(), masterAddressExtendedPrivateKey, &masterAddressExtendedPrivateKeyLength, sizeof(masterAddressExtendedPrivateKey)) || masterAddressExtendedPrivateKeyLength != sizeof(masterAddressExtendedPrivateKey)) {
	
		// Securely clear master address extended private key
		explicit_bzero(masterAddressExtendedPrivateKey, sizeof(masterAddressExtendedPrivateKey));
		
		// Throw exception
		throw runtime_error("Getting master address extended private key failed");
	}
	
	// Check if master extended private key's private key isn't a valid secp256k1 private key
	if(!Crypto::isValidSecp256k1PrivateKey(masterAddressExtendedPrivateKey, Crypto::SECP256K1_PRIVATE_KEY_SIZE)) {
	
		// Securely clear master address extended private key
		explicit_bzero(masterAddressExtendedPrivateKey, sizeof(masterAddressExtendedPrivateKey));
		
		// Return false
		return false;
	}
	
	// Securely clear master address extended private key
	explicit_bzero(masterAddressExtendedPrivateKey, sizeof(masterAddressExtendedPrivateKey));
	
	// Return true
	return true;
}
