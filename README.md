# MWC Pay

### Description
An all-in-one, self-hosted MimbleWimble Coin payment processor for Linux with an emphasis on privacy.

### Installing
MWC Pay can be built and installed with the following commands which will place a `MWC Pay` executable into your `/usr/local/bin` directory:
```
make dependencies
make
sudo make install
```

The optional argument `FLOONET` can be used when building MWC Pay to compile it for the floonet network. For example:
```
make FLOONET=1
```

### Usage
When MWC Pay starts, it'll prompt you for a password that will be used to create or open a wallet. Then it will connect to the tor network and sync with the MimbleWimble Coin network. After that's completed, it'll start the private and public servers which can then be used for creating and receiving payments. An example of how to interface with the APIs that MWC Pay provides can be found [here](https://github.com/NicolasFlamel1/MWC-Pay/tree/master/example).

MWC Pay consists of the following components:
* Wallet: The wallet that receives payments.
* Tor proxy: The proxy that's used to route all node traffic.
* Validation node: Used to determines when payments are confirmed.
* Private server: Provides the APIs to create payments and check the status of payments.
* Public server: Provides the APIs to received payments.

A high level overview of a payment's life cycle when using MWC Pay consists of the following steps:
1. The merchant sends a request to the private server to create a payment.
2. The merchant gets a URL for the payment by sending a request to the private server.
3. The buyer sends MimbleWimble Coin to that URL.
4. The payment's completed callback is ran once the payment achieves the desired number of on-chain confirmations.

MWC Pay also accepts the following command line arguments:
* `-v, --version`: Displays version information
* `-d, --directory`: Sets the directory to store application files (default: `$HOME/.mwc_pay`)
* `-w, --password`: Sets password to use for the wallet instead of being prompted for one
* `-r, --recovery_passphrase`: Displays wallet's recovery passphrase
* `-u, --root_public_key`: Displays wallet's root public key
* `-l, --show_completed_payments`: Displays all completed payments
* `-i, --show_payment`: Displays the payment with a specified ID
* `-s, --tor_socks_proxy_address`: Sets the external tor SOCKS proxy address to use instead of the built-in one (example: `localhost`)
* `-x, --tor_socks_proxy_port`: Sets the port to use for the external tor SOCKS proxy address (default: `9050`)
* `-b, --tor_bridge`: Sets the bridge to use for relaying into the tor network (example: `obfs4 1.2.3.4:12345`)
* `-g, --tor_transport_plugin`: Sets the transport plugin to use to forward traffic to the bridge (example: `obfs4 exec /usr/bin/obfs4proxy`)
* `-n, --node_dns_seed_address`: Sets the node DNS seed address to use instead of the default ones (example: `mainnet.seed1.mwc.mw`)
* `-m, --node_dns_seed_port`: Sets the port to use for the node DNS seed address (default: `3414`)
* `-a, --private_address`: Sets the address for the private server to listen at (default: `localhost`)
* `-p, --private_port`: Sets the port for the private server to listen at (default: `9010`)
* `-c, --private_certificate`: Sets the TLS certificate file for the private server
* `-k, --private_key`: Sets the TLS private key file for the private server
* `-e, --public_address`: Sets the address for the public server to listen at (default: `0.0.0.0`)
* `-o, --public_port`: Sets the port for the public server to listen at (default: `9011`)
* `-t, --public_certificate`: Sets the TLS certificate file for the public server
* `-y, --public_key`: Sets the TLS private key file for the public server
* `-h, --help`: Displays help information

\* MWC Pay doesn't include the functionality to send MimbleWimble Coin, so it's intended for its users to obtain their wallet's recovery passphrase from MWC Pay and use it in other MimbleWimble Coin wallet software when they want to send it.

\* Since a payment's sender is responsible for broadcasting a payment to the MimbleWimble Coin network, they could purposely delay broadcasting it as a way to short the price of MimbleWimble Coin. As a result, it's recommended to include a timestamp in the private server's `create_payment` API's `completed_callback` parameter that can be used to determine if this happens so that the payment can be refunded instead of the purchased item(s) being sent.

\* Once a payment achieves its specified number of on-chain confirmations it will always be considered completed even if the payment is reorged out of the MimbleWimble Coin blockchain at a later time. As a result, it's recommended to use a large enough value for the private server's `create_payment` API's `required_confirmations` parameter so that it becomes financially difficult for a buyer to remove the transaction from the MimbleWimble Coin blockchain.

### Private Server API
MWC Pay's private server allows for payments to be created, and it provides the following APIs which are accessible via HTTP GET requests with parameters provided in the request's query string:

1. `create_payment(price, required_confirmations, timeout, completed_callback)`: Creates a payment with the provided parameters and returns its ID in a JSON response.

   The provided parameters are the following:
   * `price` (optional): The expected amount for the payment. If not provided then any amount will fulfill the payment.
   * `required_confirmations` (optional): The required number of on-chain confirmations that the payment must have before it's considered complete. If not provided then one required confirmation will be used.
   * `timeout` (optional): The duration in seconds that the payment can be received. If not provided then the payment will never expire.
   * `completed_callback`: The HTTP GET request that will be performed when the payment is complete. If the response status code to this request isn't `HTTP 200 OK`, then the same request will be made at a later time. This request can't follow redirects. This request may happen multiple times despite a previous attempt receiving an `HTTP 200 OK` response status code, so make sure to prepare for this and to respond to all requests with an `HTTP 200 OK` response status code if the request has already happened.

   A response to this request will have one of the following status codes:
   * `HTTP 200 OK`: The payment was successfully created and its ID is included in the response.
   * `HTTP 500 Internal Error`: An error occurred.

   Any other response status codes should be considered the equivalent of an `HTTP 400 Bad Request` status code.

   Example:
   * Request: `http://localhost:9010/create_payment?price=123.456&required_confirmations=5&timeout=600&completed_callback=http%3A%2F%2Fexample.com%2F`
   * Request: `http://localhost:9010/create_payment?completed_callback=http%3A%2F%2Fexample.com%2F`
   * Response: `{"payment_id": "123"}`

2. `get_payment_info(payment_id)`: Returns the URL, price, required confirmations, if received, confirmations, time remaining, status, and payment proof address for a payment with the provided ID.

   The provided parameters are the following:
   * `payment_id`: The payment's ID.

   A response to this request will have one of the following status codes:
   * `HTTP 200 OK`: The payment's info is included in the response.
   * `HTTP 500 Internal Error`: An error occurred.

   Any other response status codes should be considered the equivalent of an `HTTP 400 Bad Request` status code.

   Example:
   * Request: `http://localhost:9010/get_payment_info?payment_id=123`
   * Response: `{"url": "abc", "price": "123.456", "required_confirmations": 5, "received": false, "confirmations": 0, "time_remaining": 600, "status": "Not Received", "payment_proof_address": "52cflcqg7mr2b2mbg6x62huvut3sufz3gthjblo7yn7snfohrv54nxqd"}`
   * Response: `{"url": "abc", "price": null, "required_confirmations": 1, "received": false, "confirmations": 0, "time_remaining": null, "status": "Not Received", "payment_proof_address": "52cflcqg7mr2b2mbg6x62huvut3sufz3gthjblo7yn7snfohrv54nxqd"}`

### Public Server API
MWC Pay's public server allows payments to be received, and it provides the following JSON-RPC methods accessible via the `/v2/foreign` endpoint.

1. `check_version`: Returns the wallet's foreign API version and supported slate versions. Only `SP` slate versions are supported.

   Example:
   * Request: `{"jsonrpc": "2.0", "id": 1, "method": "check_version", "params": []}`
   * Response: `{"jsonrpc": "2.0", "id": 1, "result": {"Ok": {"foreign_api_version": 2, "supported_slate_versions": ["SP"]}}}`

2. `get_proof_address`: Returns the wallet's payment proof address for the payment.

   Example:
   * Request: `{"jsonrpc": "2.0", "id": 1, "method": "get_proof_address", "params": []}`
   * Response: `{"jsonrpc": "2.0", "id": 1, "result": {"Ok": "52cflcqg7mr2b2mbg6x62huvut3sufz3gthjblo7yn7snfohrv54nxqd"}}`

3. `receive_tx`: Returns a provided slate signed by the wallet to receive a payment. Payments must include a payment proof, and payments must have the exact amount if the payment was created with a `price` parameter.

   Example:
   * Request: `{"jsonrpc": "2.0", "id": 1, "method": "receive_tx", "params" :["BEGINSLATEPACK. MHbyiHTkVjFKUbs q6B3xtsgZK142dE g45LJu17rWw3JFi sZw5d3FKmjGAmys S43DoUmK31S8AN1 FuE5ahxuTKTun4L wSd9Xcya4PSAts1 6r8itNdPDfu4C4v sMaSWLcK24rPdbj 2dRnX1vo974gTSy uCjSZb46jmMYUth Ej5ohMCvjH1oYLb EbSCD5X1H7ZaSKK PhgdzC6w9uqejWp ppXRjDwKwFyRnmV hiiBUGPAgAmjRt5 9xnkQhsABebcoxZ ZW7svAQrqMiKSBW mDqbKptL5bmbus7 RXN4NHfCLAfW7Fj bgwpnfzYAW9b5UE Zr9eQoytjafN3bZ e2eRAJDjiwzAVMA iGTaCsh8PU. ENDSLATEPACK.", null, null]}`
   * Response: `{"jsonrpc": "2.0" , "id" : 1, "result": {"Ok": "BEGINSLATEPACK. 4K5tEqYQ3JCUkNH76Wwhb5o65uBfZGTwmyCE75Q9pr1ADHaxbqu53h8r8koEf3uqCNZiKikJYzo9pSwz11LFnvpdeLL2GdJGs2FM47CCYiXEx1tSEZi9BUAuFC9jQgzXcQ1VZ7KxuagksY1HDS1sP14gAMhrzQT9qRiFqKmAisonLMNMvErbGBUz1tLRk3tzC6yeGar7sw43JgBdh2pGXnLJZEW81unR8z1ZwqonvkW7cBPih54bzMgmMKVdCY2Mu77CVAL4kF6QuirgoemdPqcwgNMHyVk6LoE766QDdQ9gTG8iLAWdXjWBidC4V6avsGrLaNQtqmZLpvKogFQi5dV3HUdnGA1cRDNwBpi9bV1DoiCybhtMZYkPrfnZzB27n9VQqGHBykncrd4USxKFSPHczZAbtDihnMjfxemoDAk158365j659Gt6rGnoiGR7VHK9aCca6DxPzCoj9mB3cqQVAQCU3CHHvydN1s4TQquxXzT4Aw1Mt46esRb4uyRowS2pJqrQyaN2BysipoXkWj99aWsqcNakV2aZDCp4MXtaJCtw9MWWiWoQR9pRAJT9qdQY5L9yg4ySsooGn89A3MUwp9Fi3JieNsRqbGLjmoiXrWTSuhJGRttJnBr4hpkuYojZ3VCbTKn8Xn8rf2haHfgX3DVJcYa4tJBAy2s8qMsb8x6ruYJJurKUUdQMUuBpMaXGPfYEvbqx7t9RKw1jkjuk9jpEi2Lx8V9EEcULbK1acvmYFJFQsLpQ3n1AUg317BEC2x5dy1vHDsmccge9qdM9hXGvfjRgYfokN67CN6CQsHbK5YmWjSuANg9kqZcFidb9VT7dtqd8PhZq6ZWvyVLFfwjuNC1r7YcHUBwbAzpPLT63GMMpSPaquEUQU33B7a8TL6ZuG4KN5pEUY6xVWe2QUFSxqkRZLDHhtzgXqmP53dFpwXATrFqLBZKcfYiwrUnb8To93t7DeJXhfntkiuihosmfe564Es4V3c6yfpr6vf1VmrTcp8YKWSMXtunocydV2HRg2tfoB2kzDYv6W158f87uHZUcpsKfnadw1sZbY6eiXT4JC3ngSbMcfgX8C4nYgGF4e4sxoQmfcAcJk1AoDaaB3dd9pnuQQdobpphUGop1x2yeQLtBei9RU3M1Hqd9bdwK2Qad9oVL6jNREyRYYc1APhJKp5hPaaM8twRSFg2ZJXWVhFTCxBir52JHn1NBUiTgxfY6Z5WaLfGDQxBfgcrY2KV62PurPVKHQb8bcqH8fVUjBSCs8CdGKrHiuMKoAHuYn4fPoZE8urEyCPxcK5aHjxEjtCyJHevUop8vL3soVnSyziiiCt7M4f5s787m356fxvktFckWmpCfwoxdTKQG1F3ruavTrXqYwRPAEvQZ97gunDpMWw6nyhgyFTY5qX5fwbQ12a1Df5uzbvkLJTuaD1LoL2jtSNhMJBJMcSQeofdAQRZxsC1WiPnv1hqqzPTX8AirACwxr1GwhWxEzudsaGVNuHYECpHRuPXBcwvXjnESjFLeV4QysnZM8RaYLNFpCWQD52FeYhrjSo946oVDrXUyeY8f7Mv69iDoTp2mnpnumpsCMHNr7RkNr9ucnxJ9DX8LBAQEwvgxxKCC5SjaZ9oozQduWaNxyKz3Wn6paqHXLbmpXVPxECaZnysigpUdxc. ENDSLATEPACK."}}`

HTTP requests sent to the public server's endpoint will receive a response with one of the following status codes:
* `HTTP 200 OK`: A response to the JSON-RPC method is included in the response.
* `HTTP 404 Not Found`: The payment doesn't exist, is expired, or was already received.
* `HTTP 500 Internal Error`: An error occurred.

Any other response status codes should be considered the equivalent of an `HTTP 400 Bad Request` status code.

### Privacy Considerations
The following should be taken into consideration to ensure that one's privacy is preserved when running MWC Pay:
1. Don't use an address for the `-s, --tor_socks_proxy_address` command line argument that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
2. Don't use an address for the `-a, --private_address` command line argument that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
3. Don't use an address for the `-e, --public_address` command line argument that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
4. Don't use an address for the private server's `create_payment` API's `completed_callback` parameter that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
5. If you use a reverse proxy to provided access to the public server API, then set the `-e, --public_address` command line argument to something like `localhost` so that its not listening on a publicly accessible interface.
