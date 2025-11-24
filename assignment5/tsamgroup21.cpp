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
#include <tuple>

// ---------- Utilities ----------

// Human-readable timestamp "YYYY-MM-DD HH:MM:SS" for logging
static std::string now() {
  using namespace std::chrono;
  auto t = system_clock::to_time_t(system_clock::now());
  char buf[32];
  strftime(buf, sizeof(buf), "%F %T", std::localtime(&t));
  return buf;
}

// Put a socket/file descriptor into non-blocking mode (so recv/accept/send never block the event loop)
static int set_nonblock(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0) return -1;
  return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

// Per-connection state for client sockets
struct Conn {
  int fd;                         // socket fd
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
  inline bool pop(std::string& buf, std::string& payload) {
    // resync to SOH
    while (!buf.empty() && uint8_t(buf[0]) != SOH) buf.erase(buf.begin());
    if (buf.size() < 4) return false;
    uint16_t nbo;
    memcpy(&nbo, buf.data()+1, 2);
    uint16_t total = ntohs(nbo);
    if (total < 5) { buf.erase(buf.begin()); return false; }
    if (buf.size() < total) return false;
    if (uint8_t(buf[3]) != STX || uint8_t(buf[total-1]) != ETX) { buf.erase(buf.begin()); return false; }
    payload.assign(buf.data()+4, total-5);
    buf.erase(0, total);
    return true;
  }
}

// A peer connection that uses framed server-to-server protocol.
struct Peer {
  int fd = -1;
  std::string inbuf;              // raw framed bytes
  std::deque<std::string> outq;  // framed buffers ready to send
  std::string peer;               // ip:port string for logs
  std::string name;               // learned group name from HELO (e.g., "A5 42")
};

int serverSendMsg(const std::string& to_group, const std::string& from_group, const std::string& text) {
  // this function will be used when we receive a SENDMSG with the format SENDMSG,<TO_GROUP>,<FROM_GROUP>,<text>
  // we will have to take in the message and the group as an input parameter
  // we will have to check if we have any peers connected to the target group, we will do that by iterating through the peers map
  //Send message to another group. The message content may be arbitrary data, but the whole command should not exceed 5000 bytes
  return 0; // return 0 on success, -1 on failure
}

int main(int argc, char* argv[]) {
  if (argc != 2 && argc != 4) { std::cerr << "Usage: tsamgroup21 <port> [seed_host seed_port]\n"; return 1; }
  const char* MY_GROUP = "A5_21";
  int port = std::atoi(argv[1]);
  // Optional seed peer (e.g., instructor server) to proactively connect to.
  const char* seed_host = nullptr; // there is no seed host by default
  int seed_port = 0; // no seed port by default
  if (argc == 4) { seed_host = argv[2]; seed_port = std::atoi(argv[3]); } // 

  // Safety limit: drop connections that try to buffer excessively (basic DoS guard)
  const size_t MAX_INBUF = 64 * 1024; // 64 KiB
  // Group label used by SENDMSG matching and LISTSERVERS reply

  // ---------- Create and prepare listening socket ----------
  int ls = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) { perror("socket"); return 1; }
  int on = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if (set_nonblock(ls) < 0) { perror("fcntl"); return 1; }

  sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(port);
  if (bind(ls, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
  if (listen(ls, 16) < 0) { perror("listen"); return 1; }
  std::cout << now() << " SERVER listening on port " << port << "\n";

  // Active client connections indexed by fd
  std::unordered_map<int, Conn> conns;

  // P2P peers (framed protocol) indexed by fd
  std::unordered_map<int, Peer> peers;
  // Deduplication & rate-limit for outbound peer connections
  static const size_t MAX_PEERS = 12;
  std::unordered_set<std::string> known_endpoints; // "ip:port" we've connected (or tried) recently, we keep it in a set to avoid duplicates
  std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_attempt; // last connect attempt time
  static const std::chrono::seconds CONNECT_BACKOFF(30); // min time between connect attempts to same endpoint

  // Helper to connect to a peer and queue HELO
  auto connect_peer = [&](const std::string& host, int rport) -> int { // this is a lambda function to connect to a peer
    // Connection fan-out guard & dedup
    if (peers.size() >= MAX_PEERS) {
      perror("connect_peer: max peers reached");
      return -1;
    }
    std::string key = host + ":" + std::to_string(rport); // unique key for this endpoint like e.g. 192.168.1.1:12345
    auto now_tp = std::chrono::steady_clock::now(); // current time point
    auto itla = last_attempt.find(key); // find last attempt time
    if (itla != last_attempt.end() && now_tp - itla->second < CONNECT_BACKOFF) { 
      return -1; // too soon to try again
    }
    if (known_endpoints.count(key)) {
      // already connected/attempted recently
      return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket(connect_peer)"); return -1; }
    // We can do blocking connect; set non-block afterwards to keep event loop simple.
    sockaddr_in r{}; r.sin_family = AF_INET; r.sin_port = htons(rport); // the r is for remote
    if (inet_pton(AF_INET, host.c_str(), &r.sin_addr) != 1) { std::cerr << "Bad seed host: " << host << "\n"; close(fd); return -1; }
    if (connect(fd, (sockaddr*)&r, sizeof(r)) < 0) { perror("connect(seed)"); close(fd); return -1; }
    set_nonblock(fd);
    known_endpoints.insert(key); // the connection succeeded (we add it to known endpoints)
    last_attempt[key] = now_tp; // record last attempt time for this endpoint
    char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &r.sin_addr, ip, sizeof(ip));

    Peer p; p.fd = fd; p.peer = std::string(ip) + ":" + std::to_string(rport); // p is for a new instance of Peer
    // Proactively identify ourselves
    p.outq.push_back(p2p::frame(std::string("HELO,") + MY_GROUP));
    // when we connect to a peer, we queue a HELO message to introduce ourselves
    peers.emplace(fd, std::move(p)); 
    std::cout << now() << " OUTBOUND " << host << ":" << rport << " fd=" << fd << " (HELLO queued)\n";
    return fd;
  };

  // Public IP to disclose in SERVERS (change to TSAM IP when deployed)
  std::string PUB_IP = "130.208.246.98";
  using clock = std::chrono::steady_clock;
  auto last_ka = clock::now();
  bool toggle_statusreq = true; // alternate STATUSREQ to reduce noise

  // Simple FIFO for messages addressed to MY_GROUP (one-node demo "mailbox")
  std::deque<std::string> inbox;
  // Messages we hold for other groups: key = TO group, value = deque of (FROM, BODY)
  std::unordered_map<std::string, std::deque<std::tuple<std::string,std::string>>> hold; // this is to hold messages for other groups

  // Queue a line for sending (appends '\n' so the client receives one line per reply)
  auto enqueue = [&](Conn& c, const std::string& line) {
    c.outq.push_back(line + "\n");
  };

  // ---------- Event loop ----------
  static bool seeded = false;
  while (true) {
    // One-time outbound connect to seed peer, if provided
    // to seed the peer means we connect to a known server to get the ball rolling
    if (!seeded && seed_host && seed_port > 0) {
      connect_peer(seed_host, seed_port);
      seeded = true;
    }
    // Build pollfd list: index 0 = listener, then one entry per active client.
    std::vector<pollfd> pfds; pfds.push_back({ls, POLLIN, 0});
    for (auto& [fd, c] : conns) {
      short ev = POLLIN;
      if (!c.outq.empty()) ev |= POLLOUT;
      pfds.push_back({fd, ev, 0});
    }
    // Also monitor P2P peer sockets
    for (auto& [pfd, p] : peers) {
      short ev = POLLIN;
      if (!p.outq.empty()) ev |= POLLOUT;
      pfds.push_back({pfd, ev, 0});
    }
    int rc = poll(pfds.data(), pfds.size(), 1000); if (rc < 0) { perror("poll"); break; }

    // Periodic P2P housekeeping: KEEPALIVE + occasional STATUSREQ
    if (clock::now() - last_ka >= std::chrono::seconds(60)) {
      for (auto& kv : peers) {
        Peer& p = kv.second;
        int pending_for_them = 0;
        if (!p.name.empty()) {
          auto it = hold.find(p.name);
          if (it != hold.end()) pending_for_them = (int)it->second.size();
        }
        p.outq.push_back(p2p::frame("KEEPALIVE," + std::to_string(pending_for_them)));
        if (toggle_statusreq) p.outq.push_back(p2p::frame("STATUSREQ"));
      }
      toggle_statusreq = !toggle_statusreq;
      last_ka = clock::now();
    }

    // If we somehow have too few peers, nudge by asking existing peers again
    if (peers.size() < 3) {
      for (auto& kv : peers) {
        kv.second.outq.push_back(p2p::frame("STATUSREQ"));
      }
    }

    // New inbound connections ready?
    if (pfds[0].revents & POLLIN) {
      sockaddr_in cli{}; socklen_t cl = sizeof(cli);
      // Accept all pending connections (drain the accept queue)
      while (true) {
        int fd = accept(ls, (sockaddr*)&cli, &cl);
        if (fd < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          perror("accept"); break;
        }
        set_nonblock(fd);
        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof(ip));
        int cport = ntohs(cli.sin_port);
        Conn c{fd, {}, {}, std::string(ip) + ":" + std::to_string(cport)};
        conns.emplace(fd, std::move(c));
        std::cout << now() << " ACCEPT " << ip << ":" << cport << " fd=" << fd << "\n";
      }
    }

    // Handle readable/writable client sockets
    // pfds is the list of pollfd structures we built earlier
    for (size_t i = 1; i < pfds.size(); ++i) {
      int fd = pfds[i].fd;
      auto it = conns.find(fd); if (it == conns.end()) continue;
      Conn& c = it->second;

      if (pfds[i].revents & (POLLIN | POLLERR | POLLHUP)) {
        char buf[4096];
        while (true) {
          ssize_t n = recv(fd, buf, sizeof(buf), 0);
          if (n > 0) {
            // If we don't yet have any buffered data and the first new byte looks like SOH,
            // this is a framed P2P connection: promote this socket from Conn -> Peer.
            if (c.inbuf.empty() && uint8_t(buf[0]) == p2p::SOH) {
              Peer p;
              p.fd   = fd;
              p.peer = c.peer;
              p.inbuf.assign(buf, buf + n);
              peers.emplace(fd, std::move(p));
              std::cout << now() << " PROMOTE " << c.peer << " fd=" << fd << " to P2P\n";
              conns.erase(it);
              goto next_fd; // will be handled in the peers section
            } else {
              c.inbuf.append(buf, buf + n);
            }
          } else if (n == 0) {
            std::cout << now() << " CLOSE " << c.peer << " fd=" << fd << "\n";
            close(fd); conns.erase(it); goto next_fd;
          } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            perror("recv"); close(fd); conns.erase(it); goto next_fd;
          }
        }

        // Guard against unbounded input growth (protects server memory)
        if (c.inbuf.size() > MAX_INBUF) {
          std::cerr << now() << " WARN closing " << c.peer << " due to oversized input buffer (" << c.inbuf.size() << " bytes)\n";
          close(fd); conns.erase(it); goto next_fd;
        }

        // Extract complete lines (LF-terminated; strip CR if present)
        size_t pos;
        while ((pos = c.inbuf.find('\n')) != std::string::npos) {
          std::string line = c.inbuf.substr(0, pos); c.inbuf.erase(0, pos + 1);
          if (!line.empty() && line.back() == '\r') line.pop_back();
          std::cout << now() << " RX " << c.peer << " \"" << line << "\"\n";

          if (line == "LISTSERVERS") {
            // Early-bonus demo: advertise only this node.
            // NOTE: uses PUB_IP for local testing; replace with the public TSAM IP when required by spec.
            enqueue(c, std::string("SERVERS,") + MY_GROUP + "," + PUB_IP + "," + std::to_string(port));

          } else if (line.rfind("SENDMSG,", 0) == 0) {
            // SENDMSG,<GROUPID>,<text>
            // Parse two commas after "SENDMSG," then normalize fields (trim spaces/CR and surrounding quotes)
            size_t p1 = line.find(',', 7); // p1 is the position of the first comma after SENDMSG, we will use that to find the <groupid>
            if (p1 != std::string::npos) {
              size_t p2 = line.find(',', p1 + 1);
              if (p2 != std::string::npos) {
                std::string to   = line.substr(p1 + 1, p2 - (p1 + 1));
                std::string text = line.substr(p2 + 1);
                size_t p3 = line.find(',', p2 + 1);


                // THIS IS WHAT I ADDED TO HANDLE THE 3-PARAMETER FORMAT
                if (p3 != std::string::npos) {
                  // Extended format: SENDMSG,<TO_GROUP>,<FROM_GROUP>,<text>
                  std::string from = line.substr(p2 + 1, p3 - (p2 + 1));
                  text = line.substr(p3 + 1);
                  if (to == MY_GROUP) {
                    inbox.push_back(text);
                    enqueue(c, "OK");
                    continue;
                  }
                  // Send to other group if we have a peer connection
                  bool sent = false;
                  for (auto& kv : peers) {
                    Peer& p = kv.second;
                    if (p.name == to) {
                      std::string payload = std::string("SENDMSG,") + to + "," + from + "," + text;
                      p.outq.push_back(p2p::frame(payload));
                      sent = true;
                    }
                  }
                  if (sent) {
                    enqueue(c, "OK");
                  } else {
                    // Hold for later delivery
                    hold[to].emplace_back(from, text);
                    enqueue(c, "OK");
                  }
                  continue;
                }
                // END OF WHAT I ADDED

                auto normalize = [](std::string& s){
                  // trim left
                  size_t a = 0; while (a < s.size() && (s[a]==' '||s[a]=='\t'||s[a]=='\r')) ++a;
                  // trim right
                  size_t b = s.size(); while (b > a && (s[b-1]==' '||s[b-1]=='\t'||s[b-1]=='\r')) --b;
                  s = s.substr(a, b - a);
                  // strip matching surrounding quotes (repeat to tolerate doubled quotes)
                  while (s.size() >= 2 && s.front()=='"' && s.back()=='"') {
                    s = s.substr(1, s.size()-2);
                  }
                  // drop a stray trailing quote if present
                  if (!s.empty() && s.back()=='"') s.pop_back();
                };
                normalize(to);
                normalize(text);

                // Debug: show parsed/normalized fields (comment out later if too verbose)
                std::cout << now() << " PARSED to=[" << to << "] text=[" << text << "]\n";

                if (to == MY_GROUP) {
                  inbox.push_back(text);
                }
                enqueue(c, "OK");
              } else {
                enqueue(c, "ERR,BADFORMAT");
              }
            } else {
              enqueue(c, "ERR,BADFORMAT");
            }

          } else if (line == "GETMSG") {
            if (!inbox.empty()) { std::string msg = inbox.front(); inbox.pop_front(); enqueue(c, std::string("MSG,") + msg); }
            else enqueue(c, "EMPTY");

          } else {
            enqueue(c, "ERR,UNKNOWN");
          }
        }
      }

      // Writable: flush as much of the out queue as the kernel will take (handles partial writes)
      if (pfds[i].revents & POLLOUT) {
        while (!c.outq.empty()) {
          const std::string& front = c.outq.front();
          ssize_t n = send(fd, front.data(), front.size(), 0);
          if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            perror("send"); close(fd); conns.erase(it); goto next_fd;
          }
          // Kernel accepted only part of the buffer; keep the remainder in-place for next POLLOUT
          if ((size_t)n < front.size()) { c.outq.front() = front.substr(n); break; }
          else {
            std::string log = front; if (!log.empty() && log.back() == '\n') log.pop_back();
            std::cout << now() << " TX " << c.peer << " \"" << log << "\"\n";
            c.outq.pop_front();
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

      for (int pfd : pfds_peers) {
        // Find this pfd's poll entry
        size_t pidx = 0;
        bool found = false;
        for (size_t k = 0; k < pfds.size(); ++k) { if (pfds[k].fd == pfd) { pidx = k; found = true; break; } }
        if (!found) continue;

        auto pit = peers.find(pfd);
        if (pit == peers.end()) continue;
        Peer& p = pit->second;
        std::string payload;

        // Read
        if (pfds[pidx].revents & (POLLIN | POLLERR | POLLHUP)) {
          char buf[4096];
          while (true) {
            ssize_t n = recv(pfd, buf, sizeof(buf), 0);
            if (n > 0) {
              p.inbuf.append(buf, buf + n);
            } else if (n == 0) {
              std::cout << now() << " PEER-CLOSE " << p.peer << " fd=" << pfd << "\n";
              close(pfd); peers.erase(pit); goto next_peer;
            } else {
              if (errno == EAGAIN || errno == EWOULDBLOCK) break;
              perror("peer recv"); close(pfd); peers.erase(pit); goto next_peer;
            }
          }

          // Parse all complete frames
          while (p2p::pop(p.inbuf, payload)) {
            std::cout << now() << " P2P-RX " << p.peer << " \"" << payload << "\"\n";

            // Handle HELO: reply SERVERS with our public reachability
            if (payload.rfind("HELO,", 0) == 0) {
              p.name = payload.substr(5); // remember their group name
              std::string resp = std::string("SERVERS,") + MY_GROUP + "," + PUB_IP + "," + std::to_string(port);
              p.outq.push_back(p2p::frame(resp));
            }
            // Auto-connect to peers advertised by others
            else if (payload.rfind("SERVERS,", 0) == 0) {
              // payload: SERVERS,Name,IP,Port;Name,IP,Port;...
              std::string list = payload.substr(8);
              std::stringstream ss(list);
              std::string entry;
              int connected = 0;

              auto is_ip = [](const std::string& s){
                in_addr tmp{};
                return inet_pton(AF_INET, s.c_str(), &tmp) == 1;
              };

              while (std::getline(ss, entry, ';')) {
                if (entry.empty()) continue;

                // Tokenize robustly (some peers send weird orders/extra commas)
                std::vector<std::string> tok;
                std::stringstream es(entry);
                std::string t;
                while (std::getline(es, t, ',')) if (!t.empty()) tok.push_back(t);

                if (tok.size() < 3) continue;

                std::string name = tok[0];
                std::string ip   = tok[1];
                std::string portstr = tok[2];

                // Heuristic: if tok[1] is not an IP but tok[2] is, swap (seen in the wild)
                if (!is_ip(ip) && is_ip(portstr)) {
                  std::swap(ip, portstr);
                }

                // Validate IP
                if (!is_ip(ip)) continue;

                int prt = -1;
                try { prt = std::stoi(portstr); } catch (...) { prt = -1; }

                // Validate port range (avoid -1, ephemeral junk, and privileged ports)
                if (prt < 1024 || prt > 65535) continue;

                // Skip ourselves
                if (name == MY_GROUP) continue;

                // Dedup/limit: do not fan out uncontrollably
                std::string key = ip + ":" + std::to_string(prt);
                if (known_endpoints.count(key)) continue;
                if (connected >= 3) break; // keep it modest

                int nfd = connect_peer(ip, prt);
                if (nfd >= 0) ++connected;
              }
            }
            // Handle SENDMSG,<TO>,<FROM>,<Message...>
            else if (payload.rfind("SENDMSG,", 0) == 0) {
              size_t c1 = payload.find(',', 8);
              size_t c2 = (c1 == std::string::npos) ? std::string::npos : payload.find(',', c1 + 1);
              if (c1 != std::string::npos && c2 != std::string::npos) {
                std::string to   = trim(payload.substr(8, c1 - 8));
                std::string from = trim(payload.substr(c1 + 1, c2 - (c1 + 1)));
                std::string body = payload.substr(c2 + 1);
                if (to == MY_GROUP) {
                  inbox.push_back(body);
                  std::cout << now() << " MSG-ENQUEUE from [" << from << "] -> [" << to << "]: " << body << "\n";
                } else {
                  // Hold for other groups until they ask via GETMSGS,<GROUP>
                  hold[to].push_back({from, body});
                  std::cout << now() << " RELAY-HOLD for [" << to << "] from [" << from << "]\n";
                }
              }
              // no ACK required by spec
            }
            else if (payload == "STATUSREQ") {
              // Report what we are holding for others
              std::string resp = "STATUSRESP";
              for (auto& kv : hold) {
                resp += "," + kv.first + "," + std::to_string(kv.second.size());
              }
              p.outq.push_back(p2p::frame(resp));
            }
            else if (payload.rfind("KEEPALIVE,", 0) == 0) {
              // If peer says they have messages for us (>0), ask for them.
              // Format: KEEPALIVE,<num>
              size_t comma = payload.find(',');
              int n = 0;
              if (comma != std::string::npos) {
                try { n = std::stoi(payload.substr(comma+1)); } catch(...) { n = 0; }
              }
              if (n > 0) {
                // Request pending messages for our group
                p.outq.push_back(p2p::frame(std::string("GETMSGS,") + MY_GROUP));
              }
            }
            else if (payload.rfind("GETMSGS,", 0) == 0) {
              // Peer is asking us to deliver messages we hold for them
              std::string who = trim(payload.substr(8));
              auto it = hold.find(who);
              int sent = 0;
              if (it != hold.end()) {
                while (!it->second.empty() && sent < 20) { // be nice; cap per tick
                  auto [from, body] = it->second.front();
                  it->second.pop_front();
                  std::string msg = "SENDMSG," + who + "," + from + "," + body;
                  p.outq.push_back(p2p::frame(msg));
                  ++sent;
                }
                if (it->second.empty()) hold.erase(it);
              }
            }
          } // end while (p2p::pop)
        } // end if (POLLIN | POLLERR | POLLHUP)

        // Write any pending framed data
        if (pfds[pidx].revents & POLLOUT) {
          while (!p.outq.empty()) {
            const std::string& b = p.outq.front();
            ssize_t n = send(pfd, b.data(), b.size(), 0);
            if (n < 0) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) break;
              perror("peer send"); close(pfd); peers.erase(pit); goto next_peer;
            }
            if ((size_t)n < b.size()) {
              p.outq.front() = b.substr(n); break;
            } else {
              // Pretty log: peel payload for display
              std::string tmp = b, pl;
              if (p2p::pop(tmp, pl)) std::cout << now() << " P2P-TX " << p.peer << " \"" << pl << "\"\n";
              else std::cout << now() << " P2P-TX " << p.peer << " (" << b.size() << " bytes)\n";
              p.outq.pop_front();
            }
          }
        }
        next_peer: ;
      }
    }
  }
  // (unreachable in this simple loop) — on program exit, OS will close descriptors
}