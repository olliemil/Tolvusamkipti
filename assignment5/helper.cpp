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
#include <functional>


static std::ofstream logFile;

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


bool isInstructorServer(const std::string& peer) {
  // ports we know are 5001, 5002, 5003
  size_t colon_pos = peer.find(':');
  if (colon_pos == std::string::npos) return false;
  int port = std::stoi(peer.substr(colon_pos + 1));
  return (port == 5001 || port == 5002 || port == 5003);
}