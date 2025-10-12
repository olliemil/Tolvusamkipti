// client.cpp — single-shot client with timestamps for A5 (A5_21)
// Features:
//  - Friendly subcommands: LISTSERVERS | GETMSG | SENDMSG <GROUP> <MESSAGE...>
//  - For SENDMSG, auto-formats as: SENDMSG,"<GROUP>","<MESSAGE>"
//  - Still supports raw pass-through if you provide a full command after host/port
//    e.g. ./client 127.0.0.1 4100 'SENDMSG,A5 21,Hello there'
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static std::string now() {
  using namespace std::chrono;
  auto t = system_clock::to_time_t(system_clock::now());
  char buf[32];
  strftime(buf, sizeof(buf), "%F %T", std::localtime(&t));
  return buf;
}

static void print_usage() {
  std::cerr <<
R"(Usage:
  # Friendly forms
  client <host> <port> LISTSERVERS
  client <host> <port> GETMSG
  client <host> <port> SENDMSG <GROUP> <MESSAGE...>

  # Raw pass-through (advanced)
  client <host> <port> <FULL_COMMAND...>

Examples:
  client 127.0.0.1 4100 LISTSERVERS
  client 127.0.0.1 4100 SENDMSG "A5 21" Weekend grind!
  client 127.0.0.1 4100 GETMSG
)";
}

static std::string join(const std::vector<std::string>& v, size_t from = 0, const char* sep = " ") {
  std::string out;
  for (size_t i = from; i < v.size(); ++i) {
    if (i > from) out += sep;
    out += v[i];
  }
  return out;
}

// Build command string based on friendly subcommands or pass-through.
static std::string build_command(const std::vector<std::string>& args) {
  // args: [host, port, ...]
  if (args.size() < 3) return std::string();

  if (args[2] == "LISTSERVERS") {
    if (args.size() != 3) {
      // extra tokens after LISTSERVERS -> treat as pass-through
    } else {
      return "LISTSERVERS\n";
    }
  }

  if (args[2] == "GETMSG") {
    if (args.size() != 3) {
      // extra tokens -> pass-through
    } else {
      return "GETMSG\n";
    }
  }

  if (args[2] == "SENDMSG") {
    if (args.size() < 5) {
      // Need at least group and one word of message
      return std::string();
    }
    const std::string& group = args[3];
    std::string message = join(args, 4, " ");

    // Quote group/message to be robust with spaces/commas
    std::string cmd = "SENDMSG,\"";
    cmd += group;
    cmd += "\",\"";
    cmd += message;
    cmd += "\"\n";
    return cmd;
  }

  // Otherwise: pass-through. Join all tokens after host/port with spaces and add newline.
  std::string raw = join(args, 2, " ");
  if (raw.empty() || raw.back() != '\n') raw.push_back('\n');
  return raw;
}

int main(int argc, char* argv[]) {
  if (argc < 4) {
    print_usage();
    return 1;
  }
  const char* host = argv[1];
  const char* port = argv[2];

  // Collect remaining args into vector<string>
  std::vector<std::string> toks;
  toks.reserve(static_cast<size_t>(argc - 1));
  for (int i = 0; i < argc; ++i) toks.emplace_back(argv[i]);

  std::string cmd = build_command({toks.begin() + 1, toks.end()}); // host,port,subargs...
  if (cmd.empty()) {
    print_usage();
    return 1;
  }

  struct addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_INET;      // IPv4
  hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo(host, port, &hints, &res);
  if (rc != 0) {
    std::cerr << "getaddrinfo: " << gai_strerror(rc) << "\n";
    return 1;
  }

  int fd = -1;
  for (auto p = res; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    close(fd); fd = -1;
  }
  freeaddrinfo(res);

  if (fd < 0) {
    std::cerr << "connect failed\n";
    return 1;
  }

  // Log and send
  std::string printable = cmd;
  if (!printable.empty() && printable.back() == '\n') printable.pop_back();
  std::cout << now() << " TX \"" << printable << "\"\n";

  if (send(fd, cmd.data(), cmd.size(), 0) < 0) {
    perror("send");
    close(fd);
    return 1;
  }

  // Receive one line
  std::string resp;
  char buf[1024];
  while (true) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0) { perror("recv"); close(fd); return 1; }
    if (n == 0) break;
    resp.append(buf, buf + n);
    if (!resp.empty() && resp.back() == '\n') break; // single-line protocol
  }
  if (!resp.empty() && resp.back() == '\n') resp.pop_back();
  std::cout << now() << " RX \"" << resp << "\"\n";

  close(fd);
  return 0;
}