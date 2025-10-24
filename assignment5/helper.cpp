#include "helper.hpp"
#include <arpa/inet.h>
#include <fcntl.h>
#include <cstring>
#include <ctime>

using steady_clock = std::chrono::steady_clock;

std::string now_timestamp() {
  using namespace std::chrono;
  auto t = std::chrono::system_clock::to_time_t(system_clock::now());
  char buf[32];
  std::strftime(buf, sizeof(buf), "%F %T", std::localtime(&t));
  return buf;
}

int set_nonblock(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0) return -1;
  return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r')) ++a;
  while (b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r')) --b;
  return s.substr(a, b - a);
}

namespace p2p {
  std::string frame(const std::string& payload) {
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

  bool pop(std::string& buf, std::string& payload) {
    while (!buf.empty() && uint8_t(buf[0]) != SOH) buf.erase(buf.begin());
    if (buf.size() < 4) return false;
    uint16_t nbo;
    std::memcpy(&nbo, buf.data()+1, 2);
    uint16_t total = ntohs(nbo);
    if (total < 5) { buf.erase(buf.begin()); return false; }
    if (buf.size() < total) return false;
    if (uint8_t(buf[3]) != STX || uint8_t(buf[total-1]) != ETX) { buf.erase(buf.begin()); return false; }
    payload.assign(buf.data()+4, total-5);
    buf.erase(0, total);
    return true;
  }
}

bool is_valid_ipv4(const std::string& s) {
  in_addr tmp{};
  return inet_pton(AF_INET, s.c_str(), &tmp) == 1;
}

std::string make_dedup_key(const std::string& from,
                           const std::string& to,
                           const std::string& body) {
  return from + "|" + to + "|" + body;
}