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
#include <fstream>


// A peer connection that uses framed server-to-server protocol.
struct Peer {
  int fd = -1;
  std::string inbuf;              // raw framed bytes
  std::deque<std::string> outq;  // framed buffers ready to send
  std::string peer;               // ip:port string for logs
  std::string name;               // learned group name from HELO (e.g., "A5 42")
};

// Per-connection state for client sockets
struct Conn {
  int fd;                         // socket fd
  std::string inbuf;              // bytes accumulated from recv() until newline
  std::deque<std::string> outq;   // lines pending to send (each ends with '\n')
  std::string peer;               // "ip:port" for logs
};

std::string myGroup = "A5_21";
std::string PUB_IP = "130.208.246.98";
int port = 0; // default port, it will be set in main

using clock = std::chrono::steady_clock;

// Active client connections indexed by fd
std::unordered_map<int, Conn> conns;
// P2P peers (framed protocol) indexed by fd
std::unordered_map<int, Peer> peers;

static const size_t MAX_PEERS = 12;
std::unordered_set<std::string> known_endpoints; // "ip:port" we've connected (or tried) recently, we keep it in a set to avoid duplicates
std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_attempt; // last connect attempt time
static const std::chrono::seconds CONNECT_BACKOFF(30); // min time between connect attempts to same endpoint
// Global log file stream
static std::ofstream logFile;

std::deque<std::string> inbox; // Simple FIFO for messages addressed to MY_GROUP (one-node demo "mailbox")

std::unordered_map<std::string, std::deque<std::tuple<std::string,std::string>>> hold;  // Messages we hold for other groups: key = TO group, value = deque of (FROM, BODY)
// Deduplication for flooded/relayed SENDMSG to avoid loops
std::unordered_set<std::string> seen_msgs; // key: from|to|body


// Human-readable timestamp "YYYY-MM-DD HH:MM:SS" for logging
static std::string now() {
  using namespace std::chrono;
  auto t = system_clock::to_time_t(system_clock::now());
  char buf[32];
  strftime(buf, sizeof(buf), "%F %T", std::localtime(&t));
  return buf;
}

// Initialize logging to file (append mode)
static void initLogging() {
  logFile.open("server.log", std::ios::app); // append mode - won't erase previous logs
  if (logFile.is_open()) {
    logFile << "\n========== SERVER STARTED " << now() << " ==========\n";
    logFile.flush();
  }
}

// Log to both console and file
static void logMessage(const std::string& msg) {
  std::cout << msg; // to console
  if (logFile.is_open()) {
    logFile << msg; // to file
    logFile.flush(); // ensure immediate write
  }
}

// Put a socket/file descriptor into non-blocking mode (so recv/accept/send never block the event loop)
static int set_nonblock(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0) return -1;
  return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

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

std::string serverForwardMsg(const std::string& to_group, const std::string& from_group, const std::string& text) {
  // this function will be used when we receive a SENDMSG for a different group than our own, we will then check if we are connected to that group; if we are we send them the message, otherwise we forward it to all our peers
  std::string msg = "SENDMSG," + to_group + "," + text;
  if (peers.empty()) {
    logMessage(now() + " no peers to forward message to group " + to_group + text + "\n");
    // we should then hold the message for later forwarding when we connect to more peers; using our hold map
    hold[to_group].emplace_back(from_group, text);
    return ""; // no peers to forward to
  }
  // check if we are connected to the target group
  for (auto& kv : peers) {
    Peer& p = kv.second;
    if (p.name == to_group) {
      p.outq.push_back(p2p::frame(msg));
      logMessage(now() + " forwarded message to connected group " + to_group + " via peer " + p.peer + "\n");
    }
  }
  // If not connected to the target group, forward to all peers
  for (auto& kv : peers) {
    Peer& p = kv.second;
    p.outq.push_back(p2p::frame(msg));
    logMessage(now() + " forwarded message to all peers for group " + to_group + "\n");
  }

  return "Message was forwarded"; 
}

std::string listServers() {
  // we should return a SERVERS message with our group name, public IP and port + the same for all known peers
  std::string msg = "SERVERS," + std::string(myGroup) + "," + PUB_IP + "," + std::to_string(port);
  for (const auto& kv : peers) {
    const Peer& p = kv.second;
    msg += "," + p.name + "," + p.peer;
  }
  return msg;
}

int connectPeer(const std::string& host, int port) {
  if (peers.size() >= MAX_PEERS) {
    logMessage(now() + " connectPeer: max peers reached\n");
    return -1;
  }
  std::string key = host + ":" + std::to_string(port);
  auto now_tp = std::chrono::steady_clock::now();
  auto iterator = last_attempt.find(key);

  if (iterator != last_attempt.end() && now_tp - iterator->second < CONNECT_BACKOFF) {
    return -1; // too soon to try again
  }
  if (known_endpoints.count(key)) {
    // already connected/attempted recently
    return -1;
  }
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) { 
    perror("socket(connect_peer)"); 
    return -1; 
  }
  // We can do blocking connect; set non-block afterwards to keep event loop simple.
  sockaddr_in remoteAddr{}; remoteAddr.sin_family = AF_INET; remoteAddr.sin_port = htons(port);
  if (inet_pton(AF_INET, host.c_str(), &remoteAddr.sin_addr) != 1) { std::cerr << "Bad seed host: " << host << "\n"; close(sockfd); return -1; }
  if (connect(sockfd, (sockaddr*)&remoteAddr, sizeof(remoteAddr)) < 0) { perror("connect(seed)"); close(sockfd); return -1; }
  set_nonblock(sockfd);
  known_endpoints.insert(key); // the connection succeeded (we add it to known endpoints)
  last_attempt[key] = now_tp; // record last attempt time for this endpoint
  char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &remoteAddr.sin_addr, ip, sizeof(ip));

  return sockfd;
}

int main(int argc, char* argv[]) {
  if (argc != 2 && argc != 4) { std::cerr << "Usage: tsamgroup21 <port> [seed_host seed_port]\n"; return 1; }
  std::string myGroup = "A5_21";
  int port = std::atoi(argv[1]);
  // Optional seed peer (e.g., instructor server) to proactively connect to.
  std::string seed_host;
  int seed_port = 0; // no seed port by default
  if (argc == 4) { 
    seed_host = argv[2]; 
    seed_port = std::atoi(argv[3]); 
  }

  // Safety limit: drop connections that try to buffer excessively (basic DoS guard)
  const size_t MAX_INBUF = 64 * 1024; // 64 KiB
  // Group label used by SENDMSG matching and LISTSERVERS reply

  // ---------- Create and prepare listening socket ----------
  int ls = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) { 
    perror("socket"); 
    return 1; 
  }
  int on = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if (set_nonblock(ls) < 0) { 
    perror("fcntl"); 
    return 1; 
  }

  sockaddr_in addr{}; 
  addr.sin_family = AF_INET; 
  addr.sin_addr.s_addr = INADDR_ANY; 
  addr.sin_port = htons(port);

  if (bind(ls, (sockaddr*)&addr, sizeof(addr)) < 0) { 
    perror("bind"); 
    return 1; 
  }
  if (listen(ls, 16) < 0) { 
    perror("listen"); 
    return 1; 
  }

  // Initialize logging
  initLogging();
  logMessage(now() + " SERVER listening on port " + std::to_string(port) + "\n");

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
    logMessage(now() + " OUTBOUND " + host + ":" + std::to_string(rport) + " fd=" + std::to_string(fd) + " (HELLO queued)\n");
    return fd;
  };

  // Public IP to disclose in SERVERS (change to TSAM IP when deployed)
  auto last_ka = clock::now();
  bool toggle_statusreq = true; // alternate STATUSREQ to reduce noise

  auto dedup_key = [](const std::string& from, const std::string& to, const std::string& body){
    return from + "|" + to + "|" + body;
  };

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
    for (auto& kv : conns) {
      int fd = kv.first;
      Conn& c = kv.second;
      short ev = POLLIN;
      if (!c.outq.empty()) ev |= POLLOUT;
      pfds.push_back({fd, ev, 0});
    }
    // Also monitor P2P peer sockets
    for (auto& kv : peers) {
      int pfd = kv.first;
      Peer& p = kv.second;
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

    // If we have too few peers, nudge by asking existing peers more frequently
    static auto last_peer_nudge = clock::now();
    auto nudge_interval = peers.size() < 2 ? std::chrono::seconds(120) : std::chrono::seconds(300); // Reduced frequency
    if (peers.size() < 2 && clock::now() - last_peer_nudge >= nudge_interval) { // Only if very few peers
      for (auto& kv : peers) {
        kv.second.outq.push_back(p2p::frame("STATUSREQ"));
      }
      last_peer_nudge = clock::now();
      logMessage(now() + " PEER-NUDGE: asking " + std::to_string(peers.size()) + " peers for more connections\n");
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
        logMessage(now() + " ACCEPT " + ip + ":" + std::to_string(cport) + " fd=" + std::to_string(fd) + "\n");
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
              logMessage(now() + " PROMOTE " + c.peer + " fd=" + std::to_string(fd) + " to P2P\n");
              conns.erase(it);
              goto next_fd; // will be handled in the peers section
            } else {
              c.inbuf.append(buf, buf + n);
            }
          } else if (n == 0) {
            logMessage(now() + " CLOSE " + c.peer + " fd=" + std::to_string(fd) + "\n");
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
          logMessage(now() + " RX " + c.peer + " \"" + line + "\"\n");

          if (line == "LISTSERVERS") {
            // Start with our own server info
            std::string response = std::string("SERVERS,") + MY_GROUP + "," + PUB_IP + "," + std::to_string(port);
            
            // Add all connected peers that have identified themselves
            for (const auto& kv : peers) {
              const Peer& p = kv.second;
              if (!p.name.empty()) {
                // Extract IP and port from peer.peer string (format: "ip:port")
                size_t colon_pos = p.peer.find(':');
                if (colon_pos != std::string::npos) {
                  std::string peer_ip = p.peer.substr(0, colon_pos);
                  std::string peer_port = p.peer.substr(colon_pos + 1);
                  response += ";" + p.name + "," + peer_ip + "," + peer_port;
                }
              }
            }
            
            enqueue(c, response);

          } else if (line.rfind("SENDMSG,", 0) == 0) {
            // SENDMSG,<GROUPID>,<text>
            // Parse two commas after "SENDMSG," then normalize fields (trim spaces/CR and surrounding quotes)
            size_t p1 = line.find(',', 7); // p1 is the position of the first comma after SENDMSG, we will use that to find the <groupid>
            if (p1 != std::string::npos) {
              size_t p2 = line.find(',', p1 + 1);
              if (p2 != std::string::npos) {
                std::string to   = line.substr(p1 + 1, p2 - (p1 + 1));
                std::string text = line.substr(p2 + 1);

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
                logMessage(now() + " PARSED to=[" + to + "] text=[" + text + "]\n");

                // Enforce assignment limit: whole command <= 5000 bytes (conservative cap on text)
                if (text.size() > 4800) text.resize(4800);

                // Dedup: avoid re-forwarding the same content around the mesh
                std::string key = dedup_key(MY_GROUP, to, text);
                if (!seen_msgs.insert(key).second) {
                  logMessage(now() + std::string(" DUPLICATE SUPPRESSED SENDMSG to [") + to + "] body size=" + std::to_string(text.size()) + "\n");
                  enqueue(c, "OK");
                  goto after_sendmsg_client;
                }

                if (to == MY_GROUP) {
                  inbox.push_back(text);
                } else {
                  // Hold for destination and forward to all known peers
                  hold[to].push_back({MY_GROUP, text});
                  std::string p2p_msg = "SENDMSG," + to + "," + MY_GROUP + "," + text;
                  for (auto& kv : peers) {
                    kv.second.outq.push_back(p2p::frame(p2p_msg));
                  }
                  logMessage(now() + " RELAY-HOLD for [" + to + "] from [" + MY_GROUP + "]\n");
                }
                enqueue(c, "OK");
                after_sendmsg_client: ;
              } else {
                enqueue(c, "ERR,BADFORMAT");
              }
            } else {
              enqueue(c, "ERR,BADFORMAT");
            }

          } else if (line.rfind("GETMSGS,", 0) == 0) {
            // Client asks: GETMSGS,<GROUP>
            std::string who = trim(line.substr(8));
            auto it = hold.find(who);
            int sent = 0;
            if (it != hold.end()) {
              while (!it->second.empty() && sent < 50) { // cap per reply burst
                std::string from = std::get<0>(it->second.front());
                std::string body = std::get<1>(it->second.front());
                it->second.pop_front();
                enqueue(c, std::string("SENDMSG,") + who + "," + from + "," + body);
                ++sent;
              }
              if (it->second.empty()) hold.erase(it);
              if (sent == 0) enqueue(c, "EMPTY");
            } else {
              enqueue(c, "EMPTY");
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
            logMessage(now() + " TX " + c.peer + " \"" + log + "\"\n");
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
              logMessage(now() + " PEER-CLOSE " + p.peer + " fd=" + std::to_string(pfd) + "\n");
              close(pfd); peers.erase(pit); goto next_peer;
            } else {
              if (errno == EAGAIN || errno == EWOULDBLOCK) break;
              perror("peer recv"); close(pfd); peers.erase(pit); goto next_peer;
            }
          }

          // Parse all complete frames
          while (p2p::pop(p.inbuf, payload)) {
            logMessage(now() + " P2P-RX " + p.peer + " \"" + payload + "\"\n");

            // Handle HELO: reply SERVERS with our public reachability and all connected peers
            if (payload.rfind("HELO,", 0) == 0) {
              p.name = payload.substr(5); // remember their group name
              
              // Start with our own server info
              std::string resp = std::string("SERVERS,") + MY_GROUP + "," + PUB_IP + "," + std::to_string(port);
              
              // Add all connected peers that have identified themselves
              for (const auto& kv : peers) {
                int peer_fd = kv.first;
                const Peer& peer = kv.second;
                if (peer_fd != pfd && !peer.name.empty()) { // Don't include the peer we're responding to, and only include named peers
                  // Extract IP and port from peer.peer string (format: "ip:port")
                  size_t colon_pos = peer.peer.find(':');
                  if (colon_pos != std::string::npos) {
                    std::string peer_ip = peer.peer.substr(0, colon_pos);
                    std::string peer_port = peer.peer.substr(colon_pos + 1);
                    resp += ";" + peer.name + "," + peer_ip + "," + peer_port;
                  }
                }
              }
              
              p.outq.push_back(p2p::frame(resp));
            }
            // Auto-connect to peers advertised by others
            else if (payload.rfind("SERVERS,", 0) == 0) {
              // CONTROLLED AUTO-CONNECT: Very conservative to prevent connection explosion
              // Only connect if we have very few peers and with strict limits
              if (peers.size() < 3 && peers.size() < 8){
                // payload: SERVERS,Name,IP,Port;Name,IP,Port;...
                std::string list = payload.substr(8);
                std::stringstream ss(list);
                std::string entry;
                int connected = 0;
                int max_new_connections = 1; // Only 1 new connection per SERVERS message

                auto is_ip = [](const std::string& s){
                  in_addr tmp{};
                  return inet_pton(AF_INET, s.c_str(), &tmp) == 1;
                };

                while (std::getline(ss, entry, ';') && connected < max_new_connections) {
                  if (entry.empty()) continue;

                  // Tokenize robustly
                  std::vector<std::string> tok;
                  std::stringstream es(entry);
                  std::string t;
                  while (std::getline(es, t, ',')) if (!t.empty()) tok.push_back(t);

                  if (tok.size() < 3) continue;

                  std::string name = tok[0];
                  std::string ip   = tok[1];
                  std::string portstr = tok[2];

                  // Validate IP
                  if (!is_ip(ip)) continue;

                  int prt = -1;
                  try { prt = std::stoi(portstr); } catch (...) { prt = -1; }

                  // Validate port range
                  if (prt < 1024 || prt > 65535) continue;

                  // Skip ourselves
                  if (name == MY_GROUP) continue;

                  // Dedup/limit
                  std::string key = ip + ":" + std::to_string(prt);
                  if (known_endpoints.count(key)) continue;

                  int nfd = connect_peer(ip, prt);
                  if (nfd >= 0) {
                    ++connected;
                    logMessage(now() + " CONTROLLED-AUTO-CONNECT to " + name + " (" + std::to_string(peers.size()) + "/3 peers)\n");
                  }
                }
              } else {
                logMessage(now() + " DEBUG: SERVERS received but we have enough peers (" + std::to_string(peers.size()) + "/3)\n");
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
                // Dedup first
                std::string key = dedup_key(from, to, body);
                if (!seen_msgs.insert(key).second) {
                  logMessage(now() + std::string(" DUPLICATE SUPPRESSED P2P SENDMSG ") + from + "->" + to + "\n");
                } else if (to == MY_GROUP) {
                  inbox.push_back(body);
                  logMessage(now() + " MSG-ENQUEUE from [" + from + "] -> [" + to + "]: " + body + "\n");
                } else {
                  // Hold for target and conservatively forward to other peers (simple flood)
                  hold[to].push_back({from, body});
                  for (auto& kvf : peers) {
                    if (kvf.first == pfd) continue; // don't echo straight back to origin
                    kvf.second.outq.push_back(p2p::frame(payload));
                  }
                  logMessage(now() + " RELAY-HOLD for [" + to + "] from [" + from + "]\n");
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
              std::string who = trim(payload.substr(8)); // extract the group name
              auto it = hold.find(who);
              int sent = 0;
              if (it != hold.end()) {
                while (!it->second.empty() && sent < 20) { // be nice; cap per tick
                  std::string from = std::get<0>(it->second.front());
                  std::string body = std::get<1>(it->second.front());
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
              if (p2p::pop(tmp, pl)) logMessage(now() + " P2P-TX " + p.peer + " \"" + pl + "\"\n");
              else logMessage(now() + " P2P-TX " + p.peer + " (" + std::to_string(b.size()) + " bytes)\n");
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