#pragma once

/**
 * WebSocket bridge to Marlin's serial stream 3, for web apps.
 *
 * Browsers can't open the raw TCP G-code socket (--serial-port), so this
 * serves the same byte stream over a WebSocket. A page connects to
 * ws://127.0.0.1:<port>/ and gets the bytes Marlin writes to stream 3 as
 * binary messages; any text or binary message it sends is fed to Marlin as
 * serial input. Message boundaries carry no meaning, exactly like a serial
 * port: a web app can use the same line handling for this and Web Serial.
 *
 * - Off unless --ws-port <n> (or MARLIN_SIM_WS_PORT) is given.
 * - Listens on 127.0.0.1 only, since it executes G-code.
 * - Checks the Origin header so an arbitrary web page can't drive the
 *   simulator. Pages on localhost / 127.0.0.1 / [::1] are allowed; add others
 *   with --ws-allow-origin <origin> (repeatable, "*" allows all).
 * - One client at a time. A second connection is refused (409) rather than
 *   silently taking over the first one's session.
 * - Output Marlin produced while no client was connected is discarded on
 *   connect, so a client starts from a clean stream.
 *
 * Like the raw socket, stream 3 is only read by Marlin when a serial port maps
 * to it (#define SERIAL_PORT_2 3 in Configuration.h).
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <cstring>   // RingBuffer.h uses memcpy and numeric_limits without including them
#include <limits>
#include <RingBuffer.h>

class WebSocketSerial {
public:
  static constexpr std::size_t buffer_size = 32768;

  // Starts listening. Non-fatal: returns false (and logs) if the port is busy.
  bool start(uint16_t port, std::vector<std::string> allowed_origins);
  void stop();
  bool connected() const { return client_open.load(); }

  // Simulation thread side.
  void write(const uint8_t* data, std::size_t length);   // Marlin -> client (dropped when no client)
  std::size_t available() { return rx_buffer.available(); }
  std::size_t read(uint8_t* dst, std::size_t length) { return rx_buffer.read(dst, length); }

  ~WebSocketSerial() { stop(); }

private:
  void run();

  std::atomic_bool running{false};
  std::atomic_bool client_open{false};
  std::thread thread;
  intptr_t listener = -1;  // socket handle, platform type hidden in the .cpp
  uint16_t port = 0;
  std::vector<std::string> allowed_origins;

  RingBuffer<uint8_t, buffer_size> rx_buffer;   // client -> Marlin
  RingBuffer<uint8_t, buffer_size> tx_buffer;   // Marlin -> client
};

extern WebSocketSerial ws_serial;
