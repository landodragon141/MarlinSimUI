# Host-only tests for the WebSocket serial bridge (no SDL, no Marlin build needed).
#   make test    protocol unit tests + live bridge tests (needs python3 and `pip install websockets`)
SRC      := ../../src/MarlinSimulator
CXXFLAGS := -std=c++17 -O1 -g -Wall -Wextra -I$(SRC) -I../../include
LDFLAGS  := -pthread

all: ws_protocol_test echo_marlin

ws_protocol_test: ws_protocol_test.cpp $(SRC)/websocket/ws_protocol.cpp $(SRC)/websocket/ws_protocol.h
	$(CXX) $(CXXFLAGS) -o $@ ws_protocol_test.cpp $(SRC)/websocket/ws_protocol.cpp $(LDFLAGS)

echo_marlin: echo_marlin.cpp $(SRC)/websocket/*.cpp $(SRC)/websocket/*.h
	$(CXX) $(CXXFLAGS) -o $@ echo_marlin.cpp $(SRC)/websocket/ws_protocol.cpp $(SRC)/websocket/websocket_serial.cpp $(LDFLAGS)

test: all
	./ws_protocol_test
	python3 bridge_test.py ./echo_marlin

clean:
	rm -f ws_protocol_test echo_marlin

.PHONY: all test clean
