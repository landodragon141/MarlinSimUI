#include "websocket_serial.h"
#include "ws_protocol.h"

// BSD sockets, as in agent_server.cpp and webcam.cpp (SDL_net can't bind
// loopback-only). On Windows SDLNet_Init() has already called WSAStartup.
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using socket_t = SOCKET;
  #define CLOSE_SOCKET closesocket
  #define BAD_SOCKET INVALID_SOCKET
  #define SEND_FLAGS 0
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <unistd.h>
  using socket_t = int;
  #define CLOSE_SOCKET ::close
  #define BAD_SOCKET (-1)
  #ifdef MSG_NOSIGNAL
    #define SEND_FLAGS MSG_NOSIGNAL
  #else
    #define SEND_FLAGS 0   // macOS: SO_NOSIGPIPE is set on each socket instead
  #endif
#endif

#include <chrono>
#include <cstdio>
#include <cstring>

WebSocketSerial ws_serial;

namespace {

constexpr std::size_t max_handshake_size = 8192;
constexpr int64_t handshake_timeout_ms = 5000;

inline socket_t to_socket(intptr_t handle) { return socket_t(handle); }

int64_t now_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

bool send_all(socket_t s, const uint8_t* data, std::size_t size) {
  while (size) {
    const auto n = ::send(s, (const char*)data, int(size), SEND_FLAGS);
    if (n <= 0) return false;
    data += n; size -= std::size_t(n);
  }
  return true;
}
bool send_all(socket_t s, const std::string& text) { return send_all(s, (const uint8_t*)text.data(), text.size()); }
bool send_frame(socket_t s, ws::Opcode opcode, const uint8_t* data, std::size_t size) {
  const auto frame = ws::encode_frame(opcode, data, size);
  return send_all(s, frame.data(), frame.size());
}
bool send_close(socket_t s, uint16_t code) {
  const uint8_t body[2] = { uint8_t(code >> 8), uint8_t(code) };
  return send_frame(s, ws::Opcode::Close, body, 2);
}

void configure_client(socket_t s) {
  #ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, (const char*)&one, sizeof(one));
  #endif
  int nodelay = 1;  // G-code replies are small; don't let Nagle add latency to "ok"
  setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
}

void reject(socket_t s, int code, const std::string& reason) {
  send_all(s, ws::http_error_response(code, reason));
  CLOSE_SOCKET(s);
}

} // namespace

bool WebSocketSerial::start(uint16_t listen_port, std::vector<std::string> origins) {
  if (running.load()) return true;

  socket_t l = ::socket(AF_INET, SOCK_STREAM, 0);
  if (l == BAD_SOCKET) { fprintf(stderr, "WebSocketSerial: socket() failed\n"); return false; }
  int reuse = 1;
  setsockopt(l, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_port = htons(listen_port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only, by design
  if (::bind(l, (sockaddr*)&address, sizeof(address)) != 0 || ::listen(l, 4) != 0) {
    fprintf(stderr, "WebSocketSerial: can't listen on 127.0.0.1:%u (in use?)\n", unsigned(listen_port));
    CLOSE_SOCKET(l);
    return false;
  }

  listener = intptr_t(l);
  port = listen_port;
  allowed_origins = std::move(origins);
  running = true;
  thread = std::thread(&WebSocketSerial::run, this);
  printf("WebSocketSerial: ws://127.0.0.1:%u/ (serial stream 3)\n", unsigned(port));
  fflush(stdout);
  return true;
}

void WebSocketSerial::stop() {
  if (!running.exchange(false)) return;
  if (thread.joinable()) thread.join();
  CLOSE_SOCKET(to_socket(listener));
  listener = -1;
}

void WebSocketSerial::write(const uint8_t* data, std::size_t length) {
  if (!client_open.load()) return;  // nobody listening: drop, like a serial line with nothing attached
  tx_buffer.write(data, length);
}

void WebSocketSerial::run() {
  const socket_t l = to_socket(listener);

  enum class State { None, Handshaking, Open } state = State::None;
  socket_t client = BAD_SOCKET;
  std::string handshake;
  int64_t handshake_deadline = 0;
  ws::FrameDecoder decoder;
  static uint8_t chunk[16384];
  static uint8_t outgoing[WebSocketSerial::buffer_size];
  bool warned_rx_overflow = false;

  auto disconnect = [&](const char* why) {
    if (client != BAD_SOCKET) CLOSE_SOCKET(client);
    if (state == State::Open) printf("WebSocketSerial: client disconnected (%s)\n", why);
    client = BAD_SOCKET;
    state = State::None;
    client_open = false;
    handshake.clear();
    fflush(stdout);
  };

  while (running.load()) {
    fd_set set; FD_ZERO(&set);
    FD_SET(l, &set);
    socket_t highest = l;
    if (client != BAD_SOCKET) { FD_SET(client, &set); if (client > highest) highest = client; }

    // A short timeout keeps Marlin's output flowing to the client promptly.
    timeval tv { 0, 1000 };
    const int ready = ::select(int(highest) + 1, &set, nullptr, nullptr, &tv);

    if (ready > 0 && FD_ISSET(l, &set)) {
      socket_t s = ::accept(l, nullptr, nullptr);
      if (s != BAD_SOCKET) {
        configure_client(s);
        if (state != State::None) reject(s, 409, "Another client is already connected to the simulator");
        else {
          client = s;
          state = State::Handshaking;
          handshake.clear();
          handshake_deadline = now_ms() + handshake_timeout_ms;
        }
      }
    }

    if (state == State::Handshaking && now_ms() > handshake_deadline) disconnect("handshake timeout");

    if (ready > 0 && client != BAD_SOCKET && FD_ISSET(client, &set)) {
      const auto n = ::recv(client, (char*)chunk, int(sizeof(chunk)), 0);
      if (n <= 0) { disconnect("connection closed"); continue; }

      if (state == State::Handshaking) {
        handshake.append((const char*)chunk, std::size_t(n));
        const auto end = handshake.find("\r\n\r\n");
        if (end == std::string::npos) {
          if (handshake.size() > max_handshake_size) {
            reject(client, 431, "Request head too large");
            client = BAD_SOCKET; state = State::None;
          }
          continue;
        }

        const auto request = ws::parse_handshake(handshake.substr(0, end + 4));
        if (!request.valid) {
          reject(client, 400, request.error);
          client = BAD_SOCKET; state = State::None;
          continue;
        }
        if (!ws::origin_allowed(request.origin, allowed_origins)) {
          fprintf(stderr, "WebSocketSerial: refused origin '%s' (allow it with --ws-allow-origin)\n", request.origin.c_str());
          reject(client, 403, "Origin not allowed: " + request.origin);
          client = BAD_SOCKET; state = State::None;
          continue;
        }
        if (!send_all(client, ws::handshake_response(request.key))) { disconnect("handshake send failed"); continue; }

        decoder = ws::FrameDecoder();
        tx_buffer.clear();      // start the client on a clean stream
        warned_rx_overflow = false;
        state = State::Open;
        client_open = true;
        printf("WebSocketSerial: client connected%s%s\n", request.origin.empty() ? "" : " from ", request.origin.c_str());
        fflush(stdout);

        // Any bytes after the handshake head are the first frames.
        if (handshake.size() > end + 4)
          decoder.feed((const uint8_t*)handshake.data() + end + 4, handshake.size() - end - 4);
        handshake.clear();
      }
      else {
        decoder.feed(chunk, std::size_t(n));
      }

      ws::FrameDecoder::Event event;
      bool closed = false;
      while (!closed && decoder.next(event)) {
        switch (event.kind) {
          case ws::FrameDecoder::Event::Kind::Data: {
            const auto written = rx_buffer.write(event.payload.data(), event.payload.size());
            if (written < event.payload.size() && !warned_rx_overflow) {
              fprintf(stderr, "WebSocketSerial: input buffer full, %zu bytes dropped (is the client waiting for \"ok\"?)\n",
                      event.payload.size() - written);
              warned_rx_overflow = true;
            }
            break;
          }
          case ws::FrameDecoder::Event::Kind::Ping:
            send_frame(client, ws::Opcode::Pong, event.payload.data(), event.payload.size());
            break;
          case ws::FrameDecoder::Event::Kind::Pong:
            break;
          case ws::FrameDecoder::Event::Kind::Close:
            send_close(client, event.payload.size() >= 2 ? event.close_code : 1000);
            disconnect("closed by client");
            closed = true;
            break;
          case ws::FrameDecoder::Event::Kind::Error:
            fprintf(stderr, "WebSocketSerial: protocol error: %s\n", event.error.c_str());
            send_close(client, event.close_code);
            disconnect("protocol error");
            closed = true;
            break;
        }
      }
      if (closed) continue;
    }

    if (state == State::Open && tx_buffer.available()) {
      const auto count = tx_buffer.read(outgoing, sizeof(outgoing));
      if (!send_frame(client, ws::Opcode::Binary, outgoing, count)) disconnect("send failed");
    }
  }

  if (client != BAD_SOCKET) {
    if (state == State::Open) send_close(client, 1001);  // going away
    CLOSE_SOCKET(client);
  }
  client_open = false;
}
