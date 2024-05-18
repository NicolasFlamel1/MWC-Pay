# Program parameters
NAME = "MWC Pay"
VERSION = "1.1.0"
CC = "g++"
STRIP = "strip"
CFLAGS = -I "./" -I "./gmp/dist/include" -I "./mpfr/dist/include" -I "./openssl/dist/include" -I "./libevent/dist/include" -I "./secp256k1-zkp/dist/include" -I "./sqlite/dist/include" -I "./simdjson/dist/include" -I "./zlib/dist/include" -I "./tor/src/feature/api" -I "./libzip/dist/include" -I "./croaring/dist/include" -I "./qrcodegen/c" -I "./libpng/dist/include" -static-libstdc++ -static-libgcc -O3 -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-clobbered -std=c++23 -finput-charset=UTF-8 -fexec-charset=UTF-8 -funsigned-char -ffunction-sections -fdata-sections -DPROGRAM_NAME=$(NAME) -DPROGRAM_VERSION=$(VERSION) -DDISABLE_SIGNAL_HANDLER -DPRUNE_HEADERS -DPRUNE_KERNELS -DPRUNE_RANGEPROOFS -DTOR_ENABLE
LIBS = -L "./gmp/dist/lib" -L "./mpfr/dist/lib" -L "./openssl/dist/lib" -L "./libevent/dist/lib" -L "./secp256k1-zkp/dist/lib" -L "./sqlite/dist/lib" -L "./simdjson/dist/lib" -L "./zlib/dist/lib" -L "./tor" -L "./libzip/dist/lib" -L "./croaring/dist/lib" -L "./qrcodegen/c" -L "./libpng/dist/lib" -Wl,-Bstatic -lmpfr -lgmp -ltor -lssl -lcrypto -levent -levent_pthreads -levent_openssl -lsecp256k1 -lsqlite3 -lsimdjson -lz -lzip -lroaring -lqrcodegen -lpng -Wl,-Bdynamic -lpthread
SRCS = "./base32.cpp" "./base58.cpp" "./base64.cpp" "./bit_reader.cpp" "./bit_writer.cpp" "./blake2.cpp" "./common.cpp" "./consensus.cpp" "./crypto.cpp" "./expired_monitor.cpp" "./gzip.cpp" "./main.cpp" "./mnemonic.cpp" "./mqs.cpp" "./node.cpp" "./node/block.cpp" "./node/common.cpp" "./node/consensus.cpp" "./node/crypto.cpp" "./node/header.cpp" "./node/input.cpp" "./node/kernel.cpp" "./node/mempool.cpp" "./node/message.cpp" "./node/node.cpp" "./node/output.cpp" "./node/peer.cpp" "./node/proof_of_work.cpp" "./node/rangeproof.cpp" "./node/saturate_math.cpp" "./node/transaction.cpp" "./payments.cpp" "./price.cpp" "./price_oracle.cpp" "./price_oracles/coingecko.cpp" "./price_oracles/tradeogre.cpp" "./price_oracles/whitebit.cpp" "./private_server.cpp" "./public_server.cpp" "./slate.cpp" "./slatepack.cpp" "./slate_output.cpp" "./slate_participant.cpp" "./smaz.cpp" "./tor.cpp" "./tor_proxy.cpp" "./wallet.cpp"
PROGRAM_NAME = $(subst $\",,$(NAME))

# Check if using floonet
ifeq ($(FLOONET),1)

	# Build for floonet
	CFLAGS += -DFLOONET
endif

# Make
all:
	$(CC) $(CFLAGS) -o "./$(PROGRAM_NAME)" $(SRCS) $(LIBS)
	$(STRIP) "./$(PROGRAM_NAME)"

# Make clean
clean:
	rm -rf "./$(PROGRAM_NAME)" "./gmp-6.3.0.tar.xz" "./gmp-6.3.0" "./gmp" "./mpfr-4.2.1.tar.gz" "./mpfr-4.2.1" "./mpfr" "./openssl-3.3.0.tar.gz" "./openssl-3.3.0" "./openssl" "./libevent-2.2.1-alpha-dev.tar.gz" "./libevent-2.2.1-alpha-dev" "./libevent" "./master.zip" "./secp256k1-zkp-master" "./secp256k1-zkp" "./sqlite-autoconf-3450300.tar.gz" "./sqlite-autoconf-3450300" "./sqlite" "./v3.9.2.zip" "./simdjson-3.9.2" "./simdjson" "./zlib-1.3.1.tar.gz" "./zlib-1.3.1" "./zlib" "./tor-tor-0.4.8.11.zip" "./tor-tor-0.4.8.11" "./tor" "./libzip-1.10.1.tar.gz" "./libzip-1.10.1" "./libzip" "./v4.0.0.zip" "./CRoaring-4.0.0" "./croaring" "./MWC-Validation-Node-master" "./node" "./v1.8.0.zip" "./QR-Code-generator-1.8.0" "./qrcodegen" "./libpng-1.6.43.tar.gz" "./libpng-1.6.43" "./libpng"

# Make run
run:
	"./$(PROGRAM_NAME)"

# Make install
install:
	rm -f "/usr/local/bin/$(PROGRAM_NAME)"
	cp "./$(PROGRAM_NAME)" "/usr/local/bin/"
	chown root:root "/usr/local/bin/$(PROGRAM_NAME)"
	chmod 755 "/usr/local/bin/$(PROGRAM_NAME)"

# Make dependencies
dependencies:
	
	# GMP
	wget "https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz"
	tar -xf "./gmp-6.3.0.tar.xz"
	rm "./gmp-6.3.0.tar.xz"
	mv "./gmp-6.3.0" "./gmp"
	cd "./gmp" && "./configure" --prefix="$(CURDIR)/gmp/dist" --disable-shared --build=x86_64-pc-linux-gnu && make && make install
	
	# MPFR
	wget "https://www.mpfr.org/mpfr-current/mpfr-4.2.1.tar.gz"
	tar -xf "./mpfr-4.2.1.tar.gz"
	rm "./mpfr-4.2.1.tar.gz"
	mv "./mpfr-4.2.1" "./mpfr"
	cd "./mpfr" && "./configure" --prefix="$(CURDIR)/mpfr/dist" --disable-shared --with-gmp-include="$(CURDIR)/gmp/dist/include" --with-gmp-lib="$(CURDIR)/gmp/dist/lib" && make && make install
	
	# OpenSSL
	wget "https://github.com/openssl/openssl/releases/download/openssl-3.3.0/openssl-3.3.0.tar.gz"
	tar -xf "./openssl-3.3.0.tar.gz"
	rm "./openssl-3.3.0.tar.gz"
	mv "./openssl-3.3.0" "./openssl"
	cd "./openssl" && "./config" --prefix="$(CURDIR)/openssl/dist" --openssldir=$(shell openssl version -d | awk '{print $$2}') --libdir=lib --release no-shared && make && make install || true
	
	# Libevent
	wget "https://github.com/libevent/libevent/releases/download/release-2.2.1-alpha/libevent-2.2.1-alpha-dev.tar.gz"
	tar -xf "./libevent-2.2.1-alpha-dev.tar.gz"
	rm "./libevent-2.2.1-alpha-dev.tar.gz"
	mv "./libevent-2.2.1-alpha-dev" "./libevent"
	cd "./libevent" && "./autogen.sh" && "./configure" --prefix="$(CURDIR)/libevent/dist" --disable-debug-mode --disable-shared CPPFLAGS="-I../openssl/dist/include" LDFLAGS="-L../openssl/dist/lib" && make && make install
	
	# Secp256k1-zkp
	wget "https://github.com/mimblewimble/secp256k1-zkp/archive/refs/heads/master.zip"
	unzip "./master.zip"
	rm "./master.zip"
	mv "./secp256k1-zkp-master" "./secp256k1-zkp"
	cd "./secp256k1-zkp" && "./autogen.sh" && "./configure" --prefix="$(CURDIR)/secp256k1-zkp/dist" --disable-shared --enable-endomorphism --enable-experimental --enable-module-generator --enable-module-commitment --enable-module-rangeproof --enable-module-bulletproof --enable-module-aggsig --with-bignum=no --disable-benchmark && make && make install
	
	# SQLite
	wget "https://www.sqlite.org/2024/sqlite-autoconf-3450300.tar.gz"
	tar -xf "./sqlite-autoconf-3450300.tar.gz"
	rm "./sqlite-autoconf-3450300.tar.gz"
	mv "./sqlite-autoconf-3450300" "./sqlite"
	cd "./sqlite" && "./configure" --prefix="$(CURDIR)/sqlite/dist" --disable-debug --disable-shared && make && make install
	
	# Simdjson
	wget "https://github.com/simdjson/simdjson/archive/refs/tags/v3.9.2.zip"
	unzip "./v3.9.2.zip"
	rm "./v3.9.2.zip"
	mv "./simdjson-3.9.2" "./simdjson"
	cd "./simdjson" && cmake -DCMAKE_INSTALL_PREFIX="$(CURDIR)/simdjson/dist" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF "./CMakeLists.txt" && make && make install
	
	# Zlib
	wget "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"
	tar -xf "./zlib-1.3.1.tar.gz"
	rm "./zlib-1.3.1.tar.gz"
	mv "./zlib-1.3.1" "./zlib"
	cd "./zlib" && "./configure" --prefix="$(CURDIR)/zlib/dist" --static && make && make install
	
	# Tor
	wget "https://gitlab.torproject.org/tpo/core/tor/-/archive/tor-0.4.8.11/tor-tor-0.4.8.11.zip"
	unzip "./tor-tor-0.4.8.11.zip"
	rm "./tor-tor-0.4.8.11.zip"
	mv "./tor-tor-0.4.8.11" "./tor"
	cd "./tor" && "./autogen.sh" && "./configure" --enable-static-openssl --with-openssl-dir="$(CURDIR)/openssl/dist" --enable-static-libevent --with-libevent-dir="$(CURDIR)/libevent/dist" --enable-static-zlib --with-zlib-dir="$(CURDIR)/zlib/dist" --disable-module-relay --disable-module-dirauth --disable-asciidoc --disable-system-torrc --disable-nss --disable-systemd --disable-lzma --disable-zstd --disable-seccomp --disable-libscrypt && make
	
	# Libzip
	wget "https://github.com/nih-at/libzip/releases/download/v1.10.1/libzip-1.10.1.tar.gz"
	tar -xf "./libzip-1.10.1.tar.gz"
	rm "./libzip-1.10.1.tar.gz"
	mv "./libzip-1.10.1" "./libzip"
	cd "./libzip" && cmake -DCMAKE_INSTALL_PREFIX="$(CURDIR)/libzip/dist" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DZLIB_INCLUDE_DIR="$(CURDIR)/zlib/dist/include" -DZLIB_LIBRARY="$(CURDIR)/zlib/dist/lib/libz.a" -DENABLE_BZIP2=OFF -DENABLE_ZSTD=OFF -DENABLE_LZMA=OFF -DENABLE_OPENSSL=OFF "./CMakeLists.txt" && make && make install
	
	# CRoaring
	wget "https://github.com/RoaringBitmap/CRoaring/archive/refs/tags/v4.0.0.zip"
	unzip "./v4.0.0.zip"
	rm "./v4.0.0.zip"
	mv "./CRoaring-4.0.0" "./croaring"
	cd "./croaring" && cmake -DCMAKE_INSTALL_PREFIX="$(CURDIR)/croaring/dist" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DENABLE_ROARING_TESTS=OFF "./CMakeLists.txt" && make && make install
	
	# MWC Validation Node
	wget "https://github.com/NicolasFlamel1/MWC-Validation-Node/archive/refs/heads/master.zip"
	unzip "./master.zip"
	rm "./master.zip"
	mv "./MWC-Validation-Node-master" "./node"
	
	# QR Code generator
	wget "https://github.com/nayuki/QR-Code-generator/archive/refs/tags/v1.8.0.zip"
	unzip "./v1.8.0.zip"
	rm "./v1.8.0.zip"
	mv "./QR-Code-generator-1.8.0" "./qrcodegen"
	cd "./qrcodegen/c" && make
	
	# Libpng
	wget "http://prdownloads.sourceforge.net/libpng/libpng-1.6.43.tar.gz"
	tar -xf "./libpng-1.6.43.tar.gz"
	rm "./libpng-1.6.43.tar.gz"
	mv "./libpng-1.6.43" "./libpng"
	cd "./libpng" && "./configure" --prefix="$(CURDIR)/libpng/dist" --disable-shared --build=x86_64-pc-linux-gnu --with-zlib-prefix="$(CURDIR)/zlib/dist" && make && make install
