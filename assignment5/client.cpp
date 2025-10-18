// client.cpp — simple command-line client for tsamgroup21 server
// Usage:
//   ./client <group-id> <message>
// Example:
//   ./client "A5 29" "Weekend grind with the boys!"
//
// Optional full form for manual commands:
//   ./client <ip> <port> <command> [args...]
//
// Automatically connects to localhost:4100 unless IP/port provided.

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

static std::string now() {
  using namespace std::chrono;
  auto t = system_clock::to_time_t(system_clock::now());
  char buf[32];
  strftime(buf, sizeof(buf), "%F %T", std::localtime(&t));
  return buf;
}

int main(int argc, char* argv[]) {
  // Mode 1: simplified "send message"
  if (argc == 3) {
    const char* ip = "127.0.0.1";
    int port = 4100;
    std::string toGroup = argv[1];
    std::string message = argv[2];
    std::ostringstream cmd;
    cmd << "SENDMSG," << toGroup << "," << message;
    std::string command = cmd.str();

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv.sin_addr);

    if (connect(s, (sockaddr*)&serv, sizeof(serv)) < 0) {
      perror("connect"); return 1;
    }

    std::cout << now() << " TX \"" << command << "\"\n";
    command += "\n";
    send(s, command.data(), command.size(), 0);

    char buf[4096];
    ssize_t n = recv(s, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
      buf[n] = 0;
      std::string reply(buf);
      if (!reply.empty() && reply.back() == '\n') reply.pop_back();
      std::cout << now() << " RX \"" << reply << "\"\n";
    }
    close(s);
    return 0;
  }

  // Mode 2: full manual command mode
  if (argc < 4) {
    std::cerr << "Usage:\n"
              << "  ./client <target-group> <message>\n"
              << "  or ./client <ip> <port> <command> [args...]\n";
    return 1;
  }

  std::string ip = argv[1];
  int port = std::atoi(argv[2]);
  std::ostringstream ss;
  for (int i = 3; i < argc; ++i) {
    if (i > 3) ss << " ";
    ss << argv[i];
  }
  std::string command = ss.str();

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) { perror("socket"); return 1; }

  sockaddr_in serv{};
  serv.sin_family = AF_INET;
  serv.sin_port = htons(port);
  inet_pton(AF_INET, ip.c_str(), &serv.sin_addr);

  if (connect(s, (sockaddr*)&serv, sizeof(serv)) < 0) {
    perror("connect"); return 1;
  }

  std::cout << now() << " TX \"" << command << "\"\n";
  command += "\n";
  send(s, command.data(), command.size(), 0);

  char buf[4096];
  ssize_t n = recv(s, buf, sizeof(buf) - 1, 0);
  if (n > 0) {
    buf[n] = 0;
    std::string reply(buf);
    if (!reply.empty() && reply.back() == '\n') reply.pop_back();
    std::cout << now() << " RX \"" << reply << "\"\n";
  }
  close(s);
  return 0;
}