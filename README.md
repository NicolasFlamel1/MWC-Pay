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
When MWC Pay starts, it'll prompt you for a password that will be used to create or open a wallet. Then it will connect to the Tor network and sync with the MimbleWimble Coin network. After that's completed, it'll start the private and public servers which can then be used for creating and receiving payments. An example of how to directly interface with the APIs that MWC Pay provides can be found [here](https://github.com/NicolasFlamel1/MWC-Pay/tree/master/example).

There's also an SDK available for [PHP](https://github.com/NicolasFlamel1/MWC-Pay-PHP-SDK) that simplifies communicating with MWC Pay.

MWC Pay consists of the following components:
* Wallet: The wallet that receives payments.
* Expired monitor: Monitors when payments are expired.
* Tor proxy: The proxy that's used to route all node traffic and price requests.
* Price: Used to determine the current price of MimbleWimble Coin.
* Validation node: Used to determines when payments are completed and confirmed.
* Private server: Provides the APIs to create payments, check the status of payments, and get the current price of MimbleWimble Coin.
* Public server: Provides the APIs to received payments.

A high level overview of a payment's life cycle when using MWC Pay consists of the following steps:
1. The merchant sends a request to the private server to create a payment and gets the payment's URL from the response.
2. The buyer sends MimbleWimble Coin to that URL.
3. The merchant can optionally monitor the payment's status via the private server's `get_payment_info` API, the private server's `create_payment` API's `received_callback` parameter, the private server's `create_payment` API's `confirmed_callback` parameter, and/or the private server's `create_payment` API's `expired_callback` parameter.
4. The payment's completed callback is ran once the payment achieves the desired number of on-chain confirmations.

MWC Pay also accepts the following command line arguments:
* `-v, --version`: Displays version information
* `-d, --directory`: Sets the directory to store application files (default: `$HOME/.mwc_pay`)
* `-w, --password`: Sets password to use for the wallet instead of being prompted for one
* `-r, --recovery_passphrase`: Displays wallet's recovery passphrase
* `-u, --root_public_key`: Displays wallet's root public key
* `-l, --show_completed_payments`: Displays all completed payments
* `-i, --show_payment`: Displays the payment with a specified ID
* `-s, --tor_socks_proxy_address`: Sets the external Tor SOCKS proxy address to use instead of the built-in one (example: `localhost`)
* `-x, --tor_socks_proxy_port`: Sets the port to use for the external Tor SOCKS proxy address (default: `9050`)
* `-b, --tor_bridge`: Sets the bridge to use for relaying into the Tor network (example: `obfs4 1.2.3.4:12345`)
* `-g, --tor_transport_plugin`: Sets the transport plugin to use to forward traffic to the bridge (example: `obfs4 exec /usr/bin/obfs4proxy`)
* `-z, --tor_create_onion_service`: Creates an Onion Service that provides access to the public server
* `-f, --price_update_interval`: Sets the interval in seconds for updating the price (default: `3600`)
* `-j, --price_average_length`: Sets the number of previous prices used when determining the average price (default: `168`)
* `-q, --price_disable`: Disables the price API
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

\* Since a payment's sender is responsible for broadcasting a payment to the MimbleWimble Coin network, they could purposely delay broadcasting it as a way to short the price of MimbleWimble Coin. As a result, it's recommended to include a timestamp in the private server's `create_payment` API's `completed_callback` parameter that can be used to determine if this happens so that the payment can be refunded instead of the purchased item(s) being sent. The private server's `create_payment` API's `completed_callback` parameter can automatically include a payment's completed timestamp and received timestamp to assist with this.

\* Once a payment achieves its specified number of on-chain confirmations it will always be considered completed even if the payment is reorged out of the MimbleWimble Coin blockchain at a later time. As a result, it's recommended to use a large enough value for the private server's `create_payment` API's `required_confirmations` parameter so that it becomes financially difficult for a buyer to remove the transaction from the MimbleWimble Coin blockchain.

### Private Server API
MWC Pay's private server allows for payments to be created, and it provides the following APIs which are accessible via HTTP GET requests with parameters provided in the request's query string:

1. `create_payment(price, required_confirmations, timeout, completed_callback, received_callback, confirmed_callback, expired_callback)`: Creates a payment with the provided parameters and returns its ID, URL, and recipient payment proof address in a JSON response.

   The provided parameters are the following:
   * `price` (optional): The expected amount for the payment. If not provided then any amount will fulfill the payment.
   * `required_confirmations` (optional): The required number of on-chain confirmations that the payment must have before it's considered complete. If not provided then one required confirmation will be used.
   * `timeout` (optional): The duration in seconds that the payment can be received. If not provided then the payment will never expire.
   * `completed_callback`: The HTTP GET request that will be performed when the payment is complete. If the response status code to this request isn't `HTTP 200 OK`, then the same request will be made at a later time. This request can't follow redirects. This request may happen multiple times despite a previous attempt receiving an `HTTP 200 OK` response status code, so make sure to prepare for this and to respond to all requests with an `HTTP 200 OK` response status code if the request has already happened. All instances of `__id__`, `__completed__`, and `__received__` are replaced with the payment's ID, completed timestamp, and received timestamp respectively.
   * `received_callback` (optional): The HTTP GET request that will be performed when the payment is received. If the response status code to this request isn't `HTTP 200 OK`, then an `HTTP 500 Internal Error` response will be sent to the payment's sender when they are sending the payment. This request can't follow redirects. This request may happen multiple times despite a previous attempt receiving an `HTTP 200 OK` response status code, so make sure to prepare for this and to respond to all requests with an `HTTP 200 OK` response status code if the request has already happened. All instances of `__id__`, `__price__`, `__sender_payment_proof_address__`, `__kernel_commitment__`, and `__recipient_payment_proof_signature__` are replaced with the payment's ID, price, sender payment proof address, kernel commitment, and recipient payment proof signature respectively. If not provided then no request will be performed when the payment is received.
   * `confirmed_callback` (optional): The HTTP GET request that will be performed when the payment's number of on-chain confirmations changes and the payment isn't completed. The response status code to this request doesn't matter. This request can't follow redirects. All instances of `__id__`, and `__confirmations__` are replaced with the payment's ID and number of on-chain confirmations respectively. If not provided then no request will be performed when the payment's number of on-chain confirmations changes.
   * `expired_callback` (optional): The HTTP GET request that will be performed when the payment is expired. If the response status code to this request isn't `HTTP 200 OK`, then the same request will be made at a later time. This request can't follow redirects. This request may happen multiple times despite a previous attempt receiving an `HTTP 200 OK` response status code, so make sure to prepare for this and to respond to all requests with an `HTTP 200 OK` response status code if the request has already happened. All instances of `__id__` are replaced with the payment's ID. If not provided then no request will be performed when the payment is expired.

   A response to this request will have one of the following status codes:
   * `HTTP 200 OK`: The payment was successfully created and its ID, URL, and recipient payment proof address are included in the response.
   * `HTTP 500 Internal Error`: An error occurred.

   Any other response status codes should be considered the equivalent of an `HTTP 400 Bad Request` status code.

   Example:
   * Request: `http://localhost:9010/create_payment?price=123.456&required_confirmations=5&timeout=600&completed_callback=http%3A%2F%2Fexample.com%2Fcompleted&received_callback=http%3A%2F%2Fexample.com%2Freceived&confirmed_callback=http%3A%2F%2Fexample.com%2Fconfirmed&expired_callback=http%3A%2F%2Fexample.com%2Fexpired`
   * Request: `http://localhost:9010/create_payment?completed_callback=http%3A%2F%2Fexample.com%2Fcompleted`
   * Response: `{"payment_id": "123", "url": "abc", "recipient_payment_proof_address": "52cflcqg7mr2b2mbg6x62huvut3sufz3gthjblo7yn7snfohrv54nxqd"}`

2. `get_payment_info(payment_id)`: Returns the URL, price, required confirmations, if received, confirmations, time remaining, status, and recipient payment proof address for a payment with the provided ID.

   The provided parameters are the following:
   * `payment_id`: The payment's ID.

   A response to this request will have one of the following status codes:
   * `HTTP 200 OK`: The payment's info is included in the response.
   * `HTTP 500 Internal Error`: An error occurred.

   Any other response status codes should be considered the equivalent of an `HTTP 400 Bad Request` status code.

   Example:
   * Request: `http://localhost:9010/get_payment_info?payment_id=123`
   * Response: `{"url": "abc", "price": "123.456", "required_confirmations": 5, "received": false, "confirmations": 0, "time_remaining": 600, "status": "Not Received", "recipient_payment_proof_address": "52cflcqg7mr2b2mbg6x62huvut3sufz3gthjblo7yn7snfohrv54nxqd"}`
   * Response: `{"url": "abc", "price": null, "required_confirmations": 1, "received": false, "confirmations": 0, "time_remaining": null, "status": "Not Received", "recipient_payment_proof_address": "52cflcqg7mr2b2mbg6x62huvut3sufz3gthjblo7yn7snfohrv54nxqd"}`

3. `get_price()`: Returns the current price of MimbleWimble Coin in USDT.

   A response to this request will have one of the following status codes:
   * `HTTP 200 OK`: The price is included in the response.
   * `HTTP 500 Internal Error`: An error occurred.

   Any other response status codes should be considered the equivalent of an `HTTP 400 Bad Request` status code.

   Example:
   * Request: `http://localhost:9010/get_price`
   * Response: `{"price":"0.909238"}`

4. `get_public_server_info()`: Returns the public server's URL and Onion Service address if it has one.

   A response to this request will have one of the following status codes:
   * `HTTP 200 OK`: The public server info is included in the response.
   * `HTTP 500 Internal Error`: An error occurred.

   Any other response status codes should be considered the equivalent of an `HTTP 400 Bad Request` status code.

   Example:
   * Request: `http://localhost:9010/get_public_server_info`
   * Response: `{"url":"http://0.0.0.0:9011","onion_service_address":"http://52cflcqg7mr2b2mbg6x62huvut3sufz3gthjblo7yn7snfohrv54nxqd.onion"}`
   * Response: `{"url":"http://0.0.0.0:9011","onion_service_address":null}`

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

MWC Pay's public server can also generate invoice QR codes for payments as PNG images. These QR codes encode as JSON a provided URL as a recipient address and the payment's price as an amount if it was created with a specified price. These QR codes can be scanned by wallets that support them to automatically fill in the details when sending a payment. It accepts the following parameters in the request's query string:
* `url`: The recipient address for the QR code to include.
* `padding` (optional): `true` for the QR code to have a four unit padding around it as per the QR code specs or `false` to not have any padding. If not provided then the QR code will have padding.
* `invert` (optional): `true` for the QR code to have its colors inverted or `false` to not invert its colors. If not provided then the QR code will not be inverted. 

Example:
* Request: `http://localhost:9011/abc.png?url=http%3A%2F%2Fexample.com&padding=true&invert=false`
* Response: PNG image of the QR code containing the JSON `{"Recipient Address":"http://example.com","Amount":"123.456"}`

### Privacy Considerations
The following should be taken into consideration to ensure that one's privacy is preserved when running MWC Pay:
1. Don't use an address for the `-s, --tor_socks_proxy_address` command line argument that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
2. Don't use an address for the `-a, --private_address` command line argument that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
3. Don't use an address for the `-e, --public_address` command line argument that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
4. Don't use an address for the private server's `create_payment` API's `completed_callback` parameter that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
5. Don't use an address for the private server's `create_payment` API's `received_callback` parameter that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
6. Don't use an address for the private server's `create_payment` API's `confirmed_callback` parameter that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
7. Don't use an address for the private server's `create_payment` API's `expired_callback` parameter that requires performing a DNS request to a third-party DNS server to resolve its IP address or requires sending packets through an unencrypted third-party network to connect to it.
8. If you use a reverse proxy to provided access to the public server API, then set the `-e, --public_address` command line argument to something like `localhost` so that its not listening on a publicly accessible interface.

### Real-World Usage
The following is a list of real-world software that uses MWC Pay to accept MimbleWimble Coin payments.
* MWC Place ([https://mwcplace.com](https://mwcplace.com))
