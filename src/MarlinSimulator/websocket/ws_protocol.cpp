#include "ws_protocol.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace ws {

namespace {

inline uint32_t rotl(uint32_t value, int bits) { return (value << bits) | (value >> (32 - bits)); }

std::string to_lower(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return char(std::tolower(c)); });
  return text;
}

std::string trim(const std::string& text) {
  const auto first = text.find_first_not_of(" \t");
  if (first == std::string::npos) return "";
  const auto last = text.find_last_not_of(" \t\r");
  return text.substr(first, last - first + 1);
}

// True if a comma-separated header value contains token (case-insensitive).
bool has_token(const std::string& value, const std::string& token) {
  std::size_t start = 0;
  while (start <= value.size()) {
    std::size_t end = value.find(',', start);
    if (end == std::string::npos) end = value.size();
    if (to_lower(trim(value.substr(start, end - start))) == token) return true;
    start = end + 1;
  }
  return false;
}

const char* status_text(int code) {
  switch (code) {
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 426: return "Upgrade Required";
    case 431: return "Request Header Fields Too Large";
    default:  return "Error";
  }
}

} // namespace

std::array<uint8_t, 20> sha1(const uint8_t* data, std::size_t length) {
  uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

  // Pad: 0x80, zeros, then the bit length as a 64-bit big-endian number.
  std::vector<uint8_t> message(data, data + length);
  message.push_back(0x80);
  while (message.size() % 64 != 56) message.push_back(0);
  const uint64_t bit_length = uint64_t(length) * 8;
  for (int i = 7; i >= 0; --i) message.push_back(uint8_t(bit_length >> (i * 8)));

  for (std::size_t chunk = 0; chunk < message.size(); chunk += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
      const uint8_t* p = &message[chunk + i * 4];
      w[i] = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }
    for (int i = 16; i < 80; ++i) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
      uint32_t f, k;
      if (i < 20)      { f = (b & c) | (~b & d);           k = 0x5A827999; }
      else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8F1BBCDC; }
      else             { f = b ^ c ^ d;                    k = 0xCA62C1D6; }
      const uint32_t temp = rotl(a, 5) + f + e + k + w[i];
      e = d; d = c; c = rotl(b, 30); b = a; a = temp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
  }

  std::array<uint8_t, 20> digest{};
  for (int i = 0; i < 5; ++i)
    for (int j = 0; j < 4; ++j) digest[i * 4 + j] = uint8_t(h[i] >> (24 - j * 8));
  return digest;
}

std::string base64_encode(const uint8_t* data, std::size_t length) {
  static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve((length + 2) / 3 * 4);
  for (std::size_t i = 0; i < length; i += 3) {
    const uint32_t n = (uint32_t(data[i]) << 16)
                     | (i + 1 < length ? uint32_t(data[i + 1]) << 8 : 0)
                     | (i + 2 < length ? uint32_t(data[i + 2]) : 0);
    out += alphabet[(n >> 18) & 63];
    out += alphabet[(n >> 12) & 63];
    out += i + 1 < length ? alphabet[(n >> 6) & 63] : '=';
    out += i + 2 < length ? alphabet[n & 63] : '=';
  }
  return out;
}

std::string accept_key(const std::string& client_key) {
  const std::string text = client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const auto digest = sha1((const uint8_t*)text.data(), text.size());
  return base64_encode(digest.data(), digest.size());
}

HandshakeRequest parse_handshake(const std::string& head) {
  HandshakeRequest request;

  std::size_t line_end = head.find("\r\n");
  if (line_end == std::string::npos) { request.error = "no request line"; return request; }

  // Request line: GET <path> HTTP/1.1
  const std::string request_line = head.substr(0, line_end);
  const auto space1 = request_line.find(' ');
  const auto space2 = request_line.find(' ', space1 == std::string::npos ? 0 : space1 + 1);
  if (space1 == std::string::npos || space2 == std::string::npos) { request.error = "malformed request line"; return request; }
  if (request_line.substr(0, space1) != "GET") { request.error = "method must be GET"; return request; }
  request.path = request_line.substr(space1 + 1, space2 - space1 - 1);
  if (request_line.compare(space2 + 1, std::string::npos, "HTTP/1.1") != 0) { request.error = "HTTP/1.1 required"; return request; }

  std::string upgrade, connection, version;
  std::size_t pos = line_end + 2;
  while (pos < head.size()) {
    line_end = head.find("\r\n", pos);
    if (line_end == std::string::npos || line_end == pos) break;  // blank line ends the head
    const std::string line = head.substr(pos, line_end - pos);
    pos = line_end + 2;
    const auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    const std::string name = to_lower(trim(line.substr(0, colon)));
    const std::string value = trim(line.substr(colon + 1));
    if (name == "upgrade") upgrade = value;
    else if (name == "connection") connection = value;
    else if (name == "sec-websocket-version") version = value;
    else if (name == "sec-websocket-key") request.key = value;
    else if (name == "origin") request.origin = value;
  }

  if (!has_token(upgrade, "websocket"))   { request.error = "not a WebSocket upgrade (Upgrade header)"; return request; }
  if (!has_token(connection, "upgrade"))  { request.error = "not a WebSocket upgrade (Connection header)"; return request; }
  if (version != "13")                    { request.error = "Sec-WebSocket-Version 13 required"; return request; }
  if (request.key.size() != 24)           { request.error = "invalid Sec-WebSocket-Key"; return request; }

  request.valid = true;
  return request;
}

bool origin_allowed(const std::string& origin, const std::vector<std::string>& allowed) {
  if (origin.empty()) return true;  // not a browser page

  const std::string normalized = to_lower(origin);
  for (const auto& entry : allowed) {
    if (entry == "*") return true;
    std::string candidate = to_lower(entry);
    while (!candidate.empty() && candidate.back() == '/') candidate.pop_back();
    if (candidate == normalized) return true;
  }

  // Loopback pages: scheme://host[:port] with host localhost, 127.0.0.1 or [::1].
  std::string rest;
  if (normalized.rfind("http://", 0) == 0) rest = normalized.substr(7);
  else if (normalized.rfind("https://", 0) == 0) rest = normalized.substr(8);
  else return false;  // includes "null" (file:// pages, sandboxed frames)

  std::string host = rest;
  if (host.rfind("[::1]", 0) == 0) host = host.substr(5);
  else if (host.rfind("localhost", 0) == 0) host = host.substr(9);
  else if (host.rfind("127.0.0.1", 0) == 0) host = host.substr(9);
  else return false;

  if (host.empty()) return true;
  if (host[0] != ':' || host.size() == 1) return false;
  return std::all_of(host.begin() + 1, host.end(), [](unsigned char c) { return std::isdigit(c); });
}

std::string handshake_response(const std::string& client_key) {
  return "HTTP/1.1 101 Switching Protocols\r\n"
         "Upgrade: websocket\r\n"
         "Connection: Upgrade\r\n"
         "Sec-WebSocket-Accept: " + accept_key(client_key) + "\r\n"
         "\r\n";
}

std::string http_error_response(int code, const std::string& reason) {
  const std::string body = reason + "\n";
  return "HTTP/1.1 " + std::to_string(code) + " " + status_text(code) + "\r\n"
         "Content-Type: text/plain\r\n"
         "Content-Length: " + std::to_string(body.size()) + "\r\n"
         "Sec-WebSocket-Version: 13\r\n"
         "Connection: close\r\n"
         "\r\n" + body;
}

std::vector<uint8_t> encode_frame(Opcode opcode, const uint8_t* payload, std::size_t length) {
  std::vector<uint8_t> frame;
  frame.reserve(length + 10);
  frame.push_back(uint8_t(0x80 | uint8_t(opcode)));  // FIN, no RSV bits
  if (length < 126) {
    frame.push_back(uint8_t(length));
  }
  else if (length <= 0xFFFF) {
    frame.push_back(126);
    frame.push_back(uint8_t(length >> 8));
    frame.push_back(uint8_t(length));
  }
  else {
    frame.push_back(127);
    for (int i = 7; i >= 0; --i) frame.push_back(uint8_t(uint64_t(length) >> (i * 8)));
  }
  frame.insert(frame.end(), payload, payload + length);
  return frame;
}

void FrameDecoder::feed(const uint8_t* data, std::size_t length) {
  if (error_state) return;
  // Drop consumed bytes once they dominate the buffer.
  if (consumed > 0 && consumed >= buffer.size() / 2) {
    buffer.erase(buffer.begin(), buffer.begin() + consumed);
    consumed = 0;
  }
  buffer.insert(buffer.end(), data, data + length);
}

bool FrameDecoder::next(Event& event) {
  if (error_state) return false;

  auto emit = [&](Event::Kind kind, std::vector<uint8_t> payload, uint16_t code = 1000, const char* why = "") {
    event.kind = kind;
    event.payload = std::move(payload);
    event.close_code = code;
    event.error = why;
    return true;
  };
  auto fail = [&](uint16_t code, const char* why) {
    error_state = true;
    return emit(Event::Kind::Error, {}, code, why);
  };

  const std::size_t available = buffer.size() - consumed;
  if (available < 2) return false;
  const uint8_t* p = buffer.data() + consumed;

  const bool fin = p[0] & 0x80;
  const uint8_t rsv = p[0] & 0x70;
  const uint8_t opcode = p[0] & 0x0F;
  const bool masked = p[1] & 0x80;
  uint64_t payload_length = p[1] & 0x7F;

  if (rsv) return fail(1002, "reserved bits set (no extensions negotiated)");
  if (!masked) return fail(1002, "client frames must be masked");

  std::size_t header = 2;
  if (payload_length == 126) {
    if (available < 4) return false;
    payload_length = (uint64_t(p[2]) << 8) | p[3];
    header = 4;
  }
  else if (payload_length == 127) {
    if (available < 10) return false;
    payload_length = 0;
    for (int i = 0; i < 8; ++i) payload_length = (payload_length << 8) | p[2 + i];
    header = 10;
  }

  const bool control = opcode & 0x08;
  if (control && (!fin || payload_length > 125)) return fail(1002, "invalid control frame");
  if (payload_length > max_frame_payload) return fail(1009, "frame too large");

  if (available < header + 4 + payload_length) return false;  // wait for the rest

  const uint8_t* mask = p + header;
  const uint8_t* body = mask + 4;
  std::vector<uint8_t> payload(static_cast<std::size_t>(payload_length));
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = body[i] ^ mask[i & 3];
  consumed += header + 4 + std::size_t(payload_length);

  switch (Opcode(opcode)) {
    case Opcode::Continuation:
      if (!in_fragmented_message) return fail(1002, "continuation without a message");
      if (fin) in_fragmented_message = false;
      return emit(Event::Kind::Data, std::move(payload));

    case Opcode::Text:     // Text is not checked for valid UTF-8: the bridge carries
    case Opcode::Binary:   // serial bytes and Marlin does its own parsing.
      if (in_fragmented_message) return fail(1002, "new message inside a fragmented one");
      in_fragmented_message = !fin;
      return emit(Event::Kind::Data, std::move(payload));

    case Opcode::Ping:
      return emit(Event::Kind::Ping, std::move(payload));

    case Opcode::Pong:
      return emit(Event::Kind::Pong, std::move(payload));

    case Opcode::Close: {
      if (payload.size() == 1) return fail(1002, "invalid close frame");
      uint16_t code = 1000;
      if (payload.size() >= 2) code = uint16_t((payload[0] << 8) | payload[1]);
      return emit(Event::Kind::Close, std::move(payload), code);
    }

    default:
      return fail(1002, "unknown opcode");
  }
}

} // namespace ws
