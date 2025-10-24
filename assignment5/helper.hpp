#pragma once
#include <string>
#include <chrono>

//time
std::string now_timestamp();

//IO helpers
int set_nonblock(int fd);

//strings
std::string trim(const std::string& s);

//P2P framing
namespace p2p {
    constexpr uint8_t SOH = 0x01, STX = 0x02, ETX = 0x03;
    std::string frame(const std::string& payload);
    bool pop(std::string& buf, std::string& payload);
}

//Net
bool is_valid_ipv4(const std::string& s);

//dedup keys
std::string make_dedup_key(const std::string& from,
                           const std::string& to,
                           const std::string& body);
