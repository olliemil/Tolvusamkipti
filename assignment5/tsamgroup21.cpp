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

int main(int argc, char* argv[]) {
  if (argc != 2) { std::cerr << "Usage: tsamgroup21 <port>\n"; return 1; }
  const char* MY_GROUP = "A5 21";
  int port = std::atoi(argv[1]);

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
  // Simple FIFO for messages addressed to MY_GROUP (one-node demo "mailbox")
  std::deque<std::string> inbox;

  // Queue a line for sending (appends '\n' so the client receives one line per reply)
  auto enqueue = [&](Conn& c, const std::string& line) {
    c.outq.push_back(line + "\n");
  };

  // ---------- Event loop ----------
  while (true) {
    // Build pollfd list: index 0 = listener, then one entry per active client.
    std::vector<pollfd> pfds; pfds.push_back({ls, POLLIN, 0});
    for (auto& [fd, c] : conns) {
      short ev = POLLIN;
      if (!c.outq.empty()) ev |= POLLOUT;
      pfds.push_back({fd, ev, 0});
    }
    int rc = poll(pfds.data(), pfds.size(), 1000); if (rc < 0) { perror("poll"); break; }

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
    for (size_t i = 1; i < pfds.size(); ++i) {
      int fd = pfds[i].fd;
      auto it = conns.find(fd); if (it == conns.end()) continue;
      Conn& c = it->second;

      if (pfds[i].revents & (POLLIN | POLLERR | POLLHUP)) {
        char buf[4096];
        while (true) {
          ssize_t n = recv(fd, buf, sizeof(buf), 0);
          if (n > 0) {
            c.inbuf.append(buf, buf + n);
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
            // NOTE: uses 127.0.0.1 for local testing; replace with the public TSAM IP when required by spec.
            enqueue(c, std::string("SERVERS,") + MY_GROUP + ",127.0.0.1," + std::to_string(port));

          } else if (line.rfind("SENDMSG,", 0) == 0) {
            // SENDMSG,<GROUPID>,<text>
            // Parse two commas after "SENDMSG," then normalize fields (trim spaces/CR and surrounding quotes)
            size_t p1 = line.find(',', 7);
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
  }
  // (unreachable in this simple loop) — on program exit, OS will close descriptors
}