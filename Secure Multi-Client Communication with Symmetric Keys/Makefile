CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

OPENSSL_PREFIX := $(shell brew --prefix openssl@3)

CPPFLAGS = -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -lpthread

TARGETS = server client attacks

COMMON_SOURCES = crypto_utils.cpp protocol_fsm.cpp
SERVER_SOURCES = server.cpp $(COMMON_SOURCES)
CLIENT_SOURCES = client.cpp $(COMMON_SOURCES)
ATTACKS_SOURCES = attacks.cpp $(COMMON_SOURCES)

HEADERS = crypto_utils.h protocol_fsm.h

.PHONY: all clean help

all: $(TARGETS)

server: $(SERVER_SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $(SERVER_SOURCES) $(LDFLAGS)
	@echo "✓ Built server"

client: $(CLIENT_SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $(CLIENT_SOURCES) $(LDFLAGS)
	@echo "✓ Built client"

attacks: $(ATTACKS_SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $(ATTACKS_SOURCES) $(LDFLAGS)
	@echo "✓ Built attacks simulator"

clean:
	rm -f $(TARGETS)
	@echo "✓ Cleaned up"
