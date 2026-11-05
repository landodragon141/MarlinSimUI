#pragma once

/**
 * WebSocket protocol pieces (RFC 6455) with no socket code, so they can be
 * unit-tested on their own: the opening handshake, the Origin check, and frame
 * encoding/decoding. websocket_serial.cpp does the networking.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ws {

// SHA-1 of data (used only for the handshake accept key, not for security).
std::array<uint8_t, 20> sha1(const uint8_t* data, std::size_t length);
std::string base64_encode(const uint8_t* data, std::size_t length);

// Sec-WebSocket-Accept value for a client's Sec-WebSocket-Key.
std::string accept_key(const std::string& client_key);

// Parsed opening handshake.
struct HandshakeRequest {
  bool valid = false;        // well-formed WebSocket upgrade request
  std::string error;         // why not, when !valid
  std::string path;
  std::string key;           // Sec-WebSocket-Key
  std::string origin;        // empty if the client sent none (non-browser clients)
};

// Parses an HTTP request head (everything up to and including "\r\n\r\n").
HandshakeRequest parse_handshake(const std::string& head);

// Origin policy. Browsers always send Origin, so this decides which web pages
// may drive the simulator: pages served
// from localhost / 127.0.0.1 / [::1] (http or https, any port) are always
// allowed; configured origins are added to those. An
// entry of "*" allows every origin. A request without Origin (curl, scripts)
// is always allowed: it cannot come from a web page.
bool origin_allowed(const std::string& origin, const std::vector<std::string>& allowed);

std::string handshake_response(const std::string& client_key);
std::string http_error_response(int code, const std::string& reason);

enum class Opcode : uint8_t {
  Continuation = 0x0, Text = 0x1, Binary = 0x2,
  Close = 0x8, Ping = 0x9, Pong = 0xA,
};

// Encodes one unmasked, unfragmented server frame.
std::vector<uint8_t> encode_frame(Opcode opcode, const uint8_t* payload, std::size_t length);

// Incremental decoder for client frames. Feed bytes as they arrive; complete
// events come out of next(). Data messages (text, binary, and their
// continuation fragments) are delivered fragment by fragment, since for a
// serial bridge only the byte stream matters, not message boundaries.
class FrameDecoder {
public:
  static constexpr std::size_t max_frame_payload = 1 << 20;  // 1 MiB per frame

  struct Event {
    enum class Kind { Data, Ping, Pong, Close, Error } kind;
    std::vector<uint8_t> payload;   // Data bytes, Ping/Pong payload, Close body
    uint16_t close_code = 1000;     // Close and Error: code to send back
    std::string error;              // Error: description
  };

  void feed(const uint8_t* data, std::size_t length);
  // Returns false when no complete event is buffered.
  bool next(Event& event);
  bool failed() const { return error_state; }

private:
  std::vector<uint8_t> buffer;
  std::size_t consumed = 0;
  bool error_state = false;
  bool in_fragmented_message = false;
};

} // namespace ws
