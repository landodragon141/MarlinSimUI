// Runs WebSocketSerial without the simulator and answers like a minimal
// Marlin: every received line gets "echo:<line>" then "ok". Used by
// bridge_test.py. Build: make -C test/websocket
#include "websocket/websocket_serial.h"

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

static volatile std::sig_atomic_t stop_requested = 0;

int main(int argc, char** argv) {
  const uint16_t port = argc > 1 ? uint16_t(atoi(argv[1])) : 8100;
  std::vector<std::string> origins;
  for (int i = 2; i < argc; ++i) origins.push_back(argv[i]);
  std::signal(SIGTERM, [](int) { stop_requested = 1; });
  std::signal(SIGINT, [](int) { stop_requested = 1; });

  if (!ws_serial.start(port, origins)) return 1;

  std::string line;
  uint8_t buf[1024];
  while (!stop_requested) {
    const auto n = ws_serial.read(buf, sizeof buf);
    for (size_t i = 0; i < n; ++i) {
      if (buf[i] == '\n') {
        const std::string reply = "echo:" + line + "\nok\n";
        ws_serial.write((const uint8_t*)reply.data(), reply.size());
        line.clear();
      }
      else if (buf[i] != '\r') line += char(buf[i]);
    }
    if (!n) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  ws_serial.stop();
  return 0;
}
