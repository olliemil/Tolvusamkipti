// tsamgroup21.cpp — TSAM A5 group server (A5 21)
//
// What this does (client↔server protocol only):
//  - Listens on a TCP port (non-blocking) and multiplexes clients with poll()
//  - Commands (newline-terminated):
//      LISTSERVERS                -> "SERVERS,A5 21,127.0.0.1,<port>"
//      SENDMSG,<GROUPID>,<text>   -> "OK" (stores text if GROUPID == MY_GROUP)
//      GETMSG                     -> "MSG,<text>" or "EMPTY"
//  - Per-connection state (Conn): input buffer, output queue, peer string
//  - Robust I/O:
//      * Non-blocking sockets
//      * recv() loops until EAGAIN; partial lines buffered
//      * send() handles partial writes via outq
//
// Notes:
//  - This file is intentionally single-threaded (poll-based).
//  - It’s a clean base to extend with the P2P server-to-server protocol (HELO/SERVERS/KEEPALIVE).
//  - For early-bonus local demo, LISTSERVERS reports 127.0.0.1; replace with public IP when deploying on TSAM if required by spec.

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <unordered_set>

// ---------- Utilities ----------

// Human-readable timestamp "YYYY-MM-DD HH:MM:SS" for logging
static std::string now() {
  using namespace std::chrono;
  auto t = system_clock::to_time_t(system_clock::now());
  char timestampBuffer[32];
  strftime(timestampBuffer, sizeof(timestampBuffer), "%F %T", std::localtime(&t));
  return timestampBuffer;
}

// Put a socket/file descriptor into non-blocking mode (so recv/accept/send never block the event loop)
static int set_nonblock(int socketFileDescriptor) {
  int fl = fcntl(socketFileDescriptor, F_GETFL, 0);
  if (fl < 0) return -1;
  return fcntl(socketFileDescriptor, F_SETFL, fl | O_NONBLOCK);
}

// Per-connection state for client sockets
struct Conn {
  int socketFileDescriptor;       // socket fd
  std::string inbuf;              // bytes accumulated from recv() until newline
  std::deque<std::string> outq;   // lines pending to send (each ends with '\n')
  std::string peer;               // "ip:port" for logs
};

// Whitespace trim (spaces/tabs/CR) – returns a trimmed copy
static inline std::string trim(std::string s) {
  size_t a = 0;
  while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r')) ++a;
  size_t b = s.size();
  while (b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r')) --b;
  return s.substr(a, b - a);
}

// ---------- P2P (server-to-server) framing and peer state ----------

namespace p2p {
  static constexpr uint8_t SOH = 0x01, STX = 0x02, ETX = 0x03;

  // Frame a payload as: SOH | len(16-bit NBO) | STX | payload | ETX
  inline std::string frame(const std::string& payload) {
    uint16_t total = 1 + 2 + 1 + payload.size() + 1;
    uint16_t nbo = htons(total);
    std::string out;
    out.reserve(total);
    out.push_back(char(SOH));
    out.append(reinterpret_cast<const char*>(&nbo), 2);
    out.push_back(char(STX));
    out += payload;
    out.push_back(char(ETX));
    return out;
  }

  // Pop a single framed payload from byte stream; returns true and sets payload if a full frame is available.
  inline bool pop(std::string& frameBuffer, std::string& payload) {
    // resync to SOH
    while (!frameBuffer.empty() && uint8_t(frameBuffer[0]) != SOH) frameBuffer.erase(frameBuffer.begin());
    if (frameBuffer.size() < 4) return false;
    uint16_t nbo;
    memcpy(&nbo, frameBuffer.data()+1, 2);
    uint16_t total = ntohs(nbo);
    if (total < 5) { frameBuffer.erase(frameBuffer.begin()); return false; }
    if (frameBuffer.size() < total) return false;
    if (uint8_t(frameBuffer[3]) != STX || uint8_t(frameBuffer[total-1]) != ETX) { frameBuffer.erase(frameBuffer.begin()); return false; }
    payload.assign(frameBuffer.data()+4, total-5);
    frameBuffer.erase(0, total);
    return true;
  }
}

// A peer connection that uses framed server-to-server protocol.
struct Peer {
  int socketFileDescriptor = -1;
  std::string inbuf;              // raw framed bytes
  std::deque<std::string> outq;  // framed buffers ready to send
  std::string peer;               // ip:port string for logs
  std::string name;               // learned group name from HELO (e.g., "A5 42")
};

int main(int argc, char* argv[]) {
  if (argc != 2) { std::cerr << "Usage: tsamgroup21 <port>\n"; return 1; }
  const char* MY_GROUP = "A5 21";
  int port = std::atoi(argv[1]);

  // Safety limit: drop connections that try to buffer excessively (basic DoS guard)
  const size_t MAX_INBUF = 64 * 1024; // 64 KiB
  // Group label used by SENDMSG matching and LISTSERVERS reply

  // ---------- Create and prepare listening socket ----------
  int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocket < 0) { perror("socket"); return 1; }
  int socketOption = 1; setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &socketOption, sizeof(socketOption));
  if (set_nonblock(listenSocket) < 0) { perror("fcntl"); return 1; }

  sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(port);
  if (bind(listenSocket, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
  if (listen(listenSocket, 16) < 0) { perror("listen"); return 1; }
  std::cout << now() << " SERVER listening on port " << port << "\n";

  // Active client connections indexed by fd
  std::unordered_map<int, Conn> conns;

  // P2P peers (framed protocol) indexed by fd
  std::unordered_map<int, Peer> peers;

  // Public IP to disclose in SERVERS (change to TSAM IP when deployed)
  std::string PUB_IP = "130.208.246.98";

  // Simple FIFO for messages addressed to MY_GROUP (one-node demo "mailbox")
  std::deque<std::string> inbox;

  // Queue a line for sending (appends '\n' so the client receives one line per reply)
  auto enqueue = [&](Conn& connection, const std::string& line) {
    connection.outq.push_back(line + "\n");
  };

  // ---------- Event loop ----------
  while (true) {
    // Build pollfd list: index 0 = listener, then one entry per active client.
    std::vector<pollfd> pfds; pfds.push_back({listenSocket, POLLIN, 0});
    for (auto& [socketFileDescriptor, c] : conns) {
      short ev = POLLIN;
      if (!c.outq.empty()) ev |= POLLOUT;
      pfds.push_back({socketFileDescriptor, ev, 0});
    }
    // Also monitor P2P peer sockets
    for (auto& [peerSocketFileDescriptor, p] : peers) {
      short ev = POLLIN;
      if (!p.outq.empty()) ev |= POLLOUT;
      pfds.push_back({peerSocketFileDescriptor, ev, 0});
    }
    int rc = poll(pfds.data(), pfds.size(), 1000); if (rc < 0) { perror("poll"); break; }

    // New inbound connections ready?
    if (pfds[0].revents & POLLIN) {
      sockaddr_in cli{}; socklen_t clientAddressLength = sizeof(cli);
      // Accept all pending connections (drain the accept queue)
      while (true) {
        int clientSocketFileDescriptor = accept(listenSocket, (sockaddr*)&cli, &clientAddressLength);
        if (clientSocketFileDescriptor < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          perror("accept"); break;
        }
        set_nonblock(clientSocketFileDescriptor);
        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof(ip));
        int cport = ntohs(cli.sin_port);
        Conn c{clientSocketFileDescriptor, {}, {}, std::string(ip) + ":" + std::to_string(cport)};
        conns.emplace(clientSocketFileDescriptor, std::move(c));
        std::cout << now() << " ACCEPT " << ip << ":" << cport << " fd=" << clientSocketFileDescriptor << "\n";
      }
    }

    // Handle readable/writable client sockets
    for (size_t i = 1; i < pfds.size(); ++i) {
      int socketFileDescriptor = pfds[i].fd;
      auto connectionIterator = conns.find(socketFileDescriptor); if (connectionIterator == conns.end()) continue;
      Conn& connection = connectionIterator->second;

      if (pfds[i].revents & (POLLIN | POLLERR | POLLHUP)) {
        char networkBuffer[4096];
        while (true) {
          ssize_t bytesReceived = recv(socketFileDescriptor, networkBuffer, sizeof(networkBuffer), 0);
          if (bytesReceived > 0) {
            // If we don't yet have any buffered data and the first new byte looks like SOH,
            // this is a framed P2P connection: promote this socket from Conn -> Peer.
            if (connection.inbuf.empty() && uint8_t(networkBuffer[0]) == p2p::SOH) {
              Peer p;
              p.socketFileDescriptor   = socketFileDescriptor;
              p.peer = connection.peer;
              p.inbuf.assign(networkBuffer, networkBuffer + bytesReceived);
              peers.emplace(socketFileDescriptor, std::move(p));
              std::cout << now() << " PROMOTE " << connection.peer << " fd=" << socketFileDescriptor << " to P2P\n";
              conns.erase(connectionIterator);
              goto next_fd; // will be handled in the peers section
            } else {
              connection.inbuf.append(networkBuffer, networkBuffer + bytesReceived);
            }
          } else if (bytesReceived == 0) {
            std::cout << now() << " CLOSE " << connection.peer << " fd=" << socketFileDescriptor << "\n";
            close(socketFileDescriptor); conns.erase(connectionIterator); goto next_fd;
          } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            perror("recv"); close(socketFileDescriptor); conns.erase(connectionIterator); goto next_fd;
          }
        }

        // Guard against unbounded input growth (protects server memory)
        if (connection.inbuf.size() > MAX_INBUF) {
          std::cerr << now() << " WARN closing " << connection.peer << " due to oversized input buffer (" << connection.inbuf.size() << " bytes)\n";
          close(socketFileDescriptor); conns.erase(connectionIterator); goto next_fd;
        }

        // Extract complete lines (LF-terminated; strip CR if present)
        size_t newlinePosition;
        while ((newlinePosition = connection.inbuf.find('\n')) != std::string::npos) {
          std::string line = connection.inbuf.substr(0, newlinePosition); connection.inbuf.erase(0, newlinePosition + 1);
          if (!line.empty() && line.back() == '\r') line.pop_back();
          std::cout << now() << " RX " << connection.peer << " \"" << line << "\"\n";

          if (line == "LISTSERVERS") {
            // Early-bonus demo: advertise only this node.
            // NOTE: uses PUB_IP for local testing; replace with the public TSAM IP when required by spec.
            enqueue(connection, std::string("SERVERS,") + MY_GROUP + "," + PUB_IP + "," + std::to_string(port));

          } else if (line.rfind("SENDMSG,", 0) == 0) {
            // SENDMSG,<GROUPID>,<text>
            // Parse two commas after "SENDMSG," then normalize fields (trim spaces/CR and surrounding quotes)
            size_t firstCommaPos = line.find(',', 7);
            if (firstCommaPos != std::string::npos) {
              size_t secondCommaPos = line.find(',', firstCommaPos + 1);
              if (secondCommaPos != std::string::npos) {
                std::string to   = line.substr(firstCommaPos + 1, secondCommaPos - (firstCommaPos + 1));
                std::string text = line.substr(secondCommaPos + 1);

                auto normalize = [](std::string& stringToNormalize){
                  // trim left
                  size_t a = 0; while (a < stringToNormalize.size() && (stringToNormalize[a]==' '||stringToNormalize[a]=='\t'||stringToNormalize[a]=='\r')) ++a;
                  // trim right
                  size_t b = stringToNormalize.size(); while (b > a && (stringToNormalize[b-1]==' '||stringToNormalize[b-1]=='\t'||stringToNormalize[b-1]=='\r')) --b;
                  stringToNormalize = stringToNormalize.substr(a, b - a);
                  // strip matching surrounding quotes (repeat to tolerate doubled quotes)
                  while (stringToNormalize.size() >= 2 && stringToNormalize.front()=='"' && stringToNormalize.back()=='"') {
                    stringToNormalize = stringToNormalize.substr(1, stringToNormalize.size()-2);
                  }
                  // drop a stray trailing quote if present
                  if (!stringToNormalize.empty() && stringToNormalize.back()=='"') stringToNormalize.pop_back();
                };
                normalize(to);
                normalize(text);

                // Debug: show parsed/normalized fields (comment out later if too verbose)
                std::cout << now() << " PARSED to=[" << to << "] text=[" << text << "]\n";

                if (to == MY_GROUP) {
                  inbox.push_back(text);
                }
                enqueue(connection, "OK");
              } else {
                enqueue(connection, "ERR,BADFORMAT");
              }
            } else {
              enqueue(connection, "ERR,BADFORMAT");
            }

          } else if (line == "GETMSG") {
            if (!inbox.empty()) { std::string msg = inbox.front(); inbox.pop_front(); enqueue(connection, std::string("MSG,") + msg); }
            else enqueue(connection, "EMPTY");

          } else {
            enqueue(connection, "ERR,UNKNOWN");
          }
        }
      }

      // Writable: flush as much of the out queue as the kernel will take (handles partial writes)
      if (pfds[i].revents & POLLOUT) {
        while (!connection.outq.empty()) {
          const std::string& front = connection.outq.front();
          ssize_t bytesSent = send(socketFileDescriptor, front.data(), front.size(), 0);
          if (bytesSent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            perror("send"); close(socketFileDescriptor); conns.erase(connectionIterator); goto next_fd;
          }
          // Kernel accepted only part of the buffer; keep the remainder in-place for next POLLOUT
          if ((size_t)bytesSent < front.size()) { connection.outq.front() = front.substr(bytesSent); break; }
          else {
            std::string log = front; if (!log.empty() && log.back() == '\n') log.pop_back();
            std::cout << now() << " TX " << connection.peer << " \"" << log << "\"\n";
            connection.outq.pop_front();
          }
        }
      }
      next_fd: continue;
    }

    // ---------- Handle P2P peers (framed protocol) ----------
    // We iterate a snapshot of current peer fds to avoid iterator invalidation on erase.
    {
      std::vector<int> pfds_peers;
      pfds_peers.reserve(peers.size());
      for (auto& kv : peers) pfds_peers.push_back(kv.first);

      for (int peerSocketFileDescriptor : pfds_peers) {
        // Find this pfd's poll entry
        size_t pidx = 0;
        bool found = false;
        for (size_t k = 0; k < pfds.size(); ++k) { if (pfds[k].fd == peerSocketFileDescriptor) { pidx = k; found = true; break; } }
        if (!found) continue;

        auto peerIterator = peers.find(peerSocketFileDescriptor);
        if (peerIterator == peers.end()) continue;
        Peer& peer = peerIterator->second;

        // Read
        if (pfds[pidx].revents & (POLLIN | POLLERR | POLLHUP)) {
          char peerNetworkBuffer[4096];
          while (true) {
            ssize_t bytesReceived = recv(peerSocketFileDescriptor, peerNetworkBuffer, sizeof(peerNetworkBuffer), 0);
            if (bytesReceived > 0) {
              peer.inbuf.append(peerNetworkBuffer, peerNetworkBuffer + bytesReceived);
            } else if (bytesReceived == 0) {
              std::cout << now() << " PEER-CLOSE " << peer.peer << " fd=" << peerSocketFileDescriptor << "\n";
              close(peerSocketFileDescriptor); peers.erase(peerIterator); goto next_peer;
            } else {
              if (errno == EAGAIN || errno == EWOULDBLOCK) break;
              perror("peer recv"); close(peerSocketFileDescriptor); peers.erase(peerIterator); goto next_peer;
            }
          }

          // Parse all complete frames
          std::string payload;
          while (p2p::pop(peer.inbuf, payload)) {
            std::cout << now() << " P2P-RX " << peer.peer << " \"" << payload << "\"\n";

            // Handle HELO: reply SERVERS with our public reachability
            if (payload.rfind("HELO,", 0) == 0) {
              peer.name = payload.substr(5); // remember their group name
              std::string resp = std::string("SERVERS,") + MY_GROUP + "," + PUB_IP + "," + std::to_string(port);
              peer.outq.push_back(p2p::frame(resp));
            }
            // Handle SENDMSG,<TO>,<FROM>,<Message...>
            else if (payload.rfind("SENDMSG,", 0) == 0) {
              size_t firstCommaPos = payload.find(',', 8);
              size_t secondCommaPos = (firstCommaPos == std::string::npos) ? std::string::npos : payload.find(',', firstCommaPos + 1);
              if (firstCommaPos != std::string::npos && secondCommaPos != std::string::npos) {
                std::string to = trim(payload.substr(8, firstCommaPos - 8));
                std::string from = trim(payload.substr(firstCommaPos + 1, secondCommaPos - (firstCommaPos + 1)));
                std::string body = payload.substr(secondCommaPos + 1);
                if (to == MY_GROUP) {
                  inbox.push_back(body);
                  std::cout << now() << " MSG-ENQUEUE from [" << from << "] -> [" << to << "]: " << body << "\n";
                }
              }
              // No explicit ACK required by spec for SENDMSG
            }
            // Optionally ignore KEEPALIVE, GETMSGS, STATUSREQ here for this step
          }
        }

        // Write any pending framed data
        if (pfds[pidx].revents & POLLOUT) {
          while (!peer.outq.empty()) {
            const std::string& frameBuffer = peer.outq.front();
            ssize_t bytesSent = send(peerSocketFileDescriptor, frameBuffer.data(), frameBuffer.size(), 0);
            if (bytesSent < 0) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) break;
              perror("peer send"); close(peerSocketFileDescriptor); peers.erase(peerIterator); goto next_peer;
            }
            if ((size_t)bytesSent < frameBuffer.size()) {
              peer.outq.front() = frameBuffer.substr(bytesSent); break;
            } else {
              // Pretty log: peel payload for display
              std::string tmp = frameBuffer, pl;
              if (p2p::pop(tmp, pl)) std::cout << now() << " P2P-TX " << peer.peer << " \"" << pl << "\"\n";
              else std::cout << now() << " P2P-TX " << peer.peer << " (" << frameBuffer.size() << " bytes)\n";
              peer.outq.pop_front();
            }
          }
        }
        next_peer: ;
      }
    }
  }
  // (unreachable in this simple loop) — on program exit, OS will close descriptors
}