// Unit tests for src/MarlinSimulator/websocket/ws_protocol.cpp. No sockets.
// Build and run: make -C test/websocket test
#include "websocket/ws_protocol.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { ++failures; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static std::string hex(const uint8_t* d, size_t n) {
  std::string s; char b[3];
  for (size_t i = 0; i < n; ++i) { snprintf(b, sizeof b, "%02x", d[i]); s += b; }
  return s;
}

// Builds a masked client frame.
static std::vector<uint8_t> client_frame(uint8_t first_byte, const std::string& payload, const uint8_t mask[4]) {
  std::vector<uint8_t> f{ first_byte };
  const size_t n = payload.size();
  if (n < 126) f.push_back(uint8_t(0x80 | n));
  else if (n <= 0xFFFF) { f.push_back(0x80 | 126); f.push_back(uint8_t(n >> 8)); f.push_back(uint8_t(n)); }
  else { f.push_back(0x80 | 127); for (int i = 7; i >= 0; --i) f.push_back(uint8_t(uint64_t(n) >> (i * 8))); }
  f.insert(f.end(), mask, mask + 4);
  for (size_t i = 0; i < n; ++i) f.push_back(uint8_t(payload[i]) ^ mask[i & 3]);
  return f;
}

int main() {
  const uint8_t mask[4] = { 0x37, 0xfa, 0x21, 0x3d };

  { // SHA-1 known answers
    const auto d1 = ws::sha1((const uint8_t*)"abc", 3);
    CHECK(hex(d1.data(), 20) == "a9993e364706816aba3e25717850c26c9cd0d89d");
    const auto d0 = ws::sha1(nullptr, 0);
    CHECK(hex(d0.data(), 20) == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    const std::string m(1000, 'a');  // crosses several 64-byte blocks
    const auto dm = ws::sha1((const uint8_t*)m.data(), m.size());
    CHECK(hex(dm.data(), 20) == "291e9a6c66994949b57ba5e650361e98fc36b1ba");
  }

  { // base64 padding cases
    CHECK(ws::base64_encode((const uint8_t*)"", 0) == "");
    CHECK(ws::base64_encode((const uint8_t*)"f", 1) == "Zg==");
    CHECK(ws::base64_encode((const uint8_t*)"fo", 2) == "Zm8=");
    CHECK(ws::base64_encode((const uint8_t*)"foo", 3) == "Zm9v");
  }

  // RFC 6455 section 1.3 example
  CHECK(ws::accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

  { // Handshake parsing
    const std::string good =
      "GET /chat HTTP/1.1\r\nHost: 127.0.0.1:8100\r\nUpgrade: websocket\r\n"
      "Connection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Origin: http://localhost:5173\r\nSec-WebSocket-Version: 13\r\n\r\n";
    const auto r = ws::parse_handshake(good);
    CHECK(r.valid);
    CHECK(r.path == "/chat");
    CHECK(r.origin == "http://localhost:5173");
    CHECK(r.key == "dGhlIHNhbXBsZSBub25jZQ==");

    std::string no_upgrade = good; no_upgrade.replace(no_upgrade.find("Upgrade: websocket"), 18, "Upgrade: h2c");
    CHECK(!ws::parse_handshake(no_upgrade).valid);
    std::string post = good; post.replace(0, 3, "POST");
    CHECK(!ws::parse_handshake(post).valid);
    std::string v8 = good; v8.replace(v8.find("Version: 13"), 11, "Version: 8");
    CHECK(!ws::parse_handshake(v8).valid);
    // Header names are case-insensitive
    std::string lower = good;
    lower.replace(lower.find("Sec-WebSocket-Key"), 17, "sec-websocket-key");
    CHECK(ws::parse_handshake(lower).valid);

    const auto resp = ws::handshake_response(r.key);
    CHECK(resp.find("101 Switching Protocols") != std::string::npos);
    CHECK(resp.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != std::string::npos);
  }

  { // Origin policy
    const std::vector<std::string> none;
    CHECK(ws::origin_allowed("", none));                          // non-browser client
    CHECK(ws::origin_allowed("http://localhost:5173", none));
    CHECK(ws::origin_allowed("http://127.0.0.1", none));
    CHECK(ws::origin_allowed("https://[::1]:8443", none));
    CHECK(ws::origin_allowed("HTTP://LOCALHOST:5173", none));
    CHECK(!ws::origin_allowed("http://localhost.evil.com", none));
    CHECK(!ws::origin_allowed("http://localhost:5173.evil.com", none));
    CHECK(!ws::origin_allowed("http://127.0.0.1.evil.com", none));
    CHECK(!ws::origin_allowed("https://example.com", none));
    CHECK(!ws::origin_allowed("null", none));
    const std::vector<std::string> pages{ "https://dbuezas.github.io/" };
    CHECK(ws::origin_allowed("https://dbuezas.github.io", pages));
    CHECK(!ws::origin_allowed("https://evil.github.io", pages));
    CHECK(ws::origin_allowed("http://localhost:3000", pages));    // localhost still allowed
    CHECK(ws::origin_allowed("https://anything.example", { "*" }));
  }

  { // Server frame encoding: length forms
    const std::string s5 = "Hello";
    auto f = ws::encode_frame(ws::Opcode::Text, (const uint8_t*)s5.data(), s5.size());
    CHECK(hex(f.data(), f.size()) == "810548656c6c6f");  // RFC 6455 section 5.7
    std::vector<uint8_t> big(300, 'x');
    f = ws::encode_frame(ws::Opcode::Binary, big.data(), big.size());
    CHECK(f[0] == 0x82 && f[1] == 126 && f[2] == 0x01 && f[3] == 0x2c && f.size() == 304);
    std::vector<uint8_t> huge(70000, 'y');
    f = ws::encode_frame(ws::Opcode::Binary, huge.data(), huge.size());
    CHECK(f[1] == 127 && f.size() == 70010 && f[7] == 0x01 && f[8] == 0x11 && f[9] == 0x70);
  }

  using Kind = ws::FrameDecoder::Event::Kind;
  ws::FrameDecoder::Event e;

  { // RFC 6455 masked "Hello", fed one byte at a time
    const uint8_t rfc[] = { 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    ws::FrameDecoder d;
    for (size_t i = 0; i < sizeof rfc; ++i) {
      CHECK(!d.next(e));
      d.feed(rfc + i, 1);
    }
    CHECK(d.next(e) && e.kind == Kind::Data && std::string(e.payload.begin(), e.payload.end()) == "Hello");
    CHECK(!d.next(e));
  }

  { // Fragmented message with a ping in the middle, plus 16- and 64-bit lengths
    ws::FrameDecoder d;
    std::vector<uint8_t> all;
    auto add = [&](std::vector<uint8_t> f) { all.insert(all.end(), f.begin(), f.end()); };
    add(client_frame(0x01, "G28 ", mask));          // text, not final
    add(client_frame(0x89, "hb", mask));            // ping between fragments is allowed
    add(client_frame(0x80, "X\n", mask));           // final continuation
    add(client_frame(0x82, std::string(200, 'a'), mask));
    add(client_frame(0x82, std::string(70000, 'b'), mask));
    d.feed(all.data(), all.size());
    CHECK(d.next(e) && e.kind == Kind::Data && std::string(e.payload.begin(), e.payload.end()) == "G28 ");
    CHECK(d.next(e) && e.kind == Kind::Ping && std::string(e.payload.begin(), e.payload.end()) == "hb");
    CHECK(d.next(e) && e.kind == Kind::Data && std::string(e.payload.begin(), e.payload.end()) == "X\n");
    CHECK(d.next(e) && e.kind == Kind::Data && e.payload.size() == 200);
    CHECK(d.next(e) && e.kind == Kind::Data && e.payload.size() == 70000 && e.payload[69999] == 'b');
    CHECK(!d.next(e) && !d.failed());
  }

  { // Close frame with code 1001
    ws::FrameDecoder d;
    auto f = client_frame(0x88, std::string("\x03\xe9", 2), mask);
    d.feed(f.data(), f.size());
    CHECK(d.next(e) && e.kind == Kind::Close && e.close_code == 1001);
  }

  { // Protocol errors
    ws::FrameDecoder d;
    const uint8_t unmasked[] = { 0x81, 0x02, 'o', 'k' };
    d.feed(unmasked, sizeof unmasked);
    CHECK(d.next(e) && e.kind == Kind::Error && e.close_code == 1002);
    CHECK(d.failed() && !d.next(e));

    ws::FrameDecoder d2;
    auto f = client_frame(0x89, std::string(126, 'p'), mask);   // control frame > 125 bytes
    d2.feed(f.data(), f.size());
    CHECK(d2.next(e) && e.kind == Kind::Error && e.close_code == 1002);

    ws::FrameDecoder d3;
    f = client_frame(0x80, "orphan", mask);                     // continuation with no message
    d3.feed(f.data(), f.size());
    CHECK(d3.next(e) && e.kind == Kind::Error);

    ws::FrameDecoder d4;
    const uint8_t too_big[] = { 0x82, 0xFF, 0, 0, 0, 0, 0x10, 0, 0, 0 };  // 256 MiB announced
    d4.feed(too_big, sizeof too_big);
    CHECK(d4.next(e) && e.kind == Kind::Error && e.close_code == 1009);

    ws::FrameDecoder d5;
    f = client_frame(0xC1, "rsv", mask);                        // RSV1 set
    d5.feed(f.data(), f.size());
    CHECK(d5.next(e) && e.kind == Kind::Error);
  }

  printf(failures ? "%d FAILED\n" : "all protocol tests passed\n", failures);
  return failures ? 1 : 0;
}
