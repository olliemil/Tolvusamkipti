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


struct Peer {
  int fd = -1;
  std::string inbuf;              // raw framed bytes
  std::deque<std::string> outq;  // framed buffers ready to send
  std::string peer;               // ip:port string for logs
  std::string name;               // learned group name from HELO (e.g., "A5 42")
};

struct Conn {
  int fd;                         // socket fd
  std::string inbuf;              // bytes accumulated from recv() until newline
  std::deque<std::string> outq;   // lines pending to send (each ends with '\n')
  std::string peer;               // "ip:port" for logs
};

const char* MY_GROUP = "A5_21";  // Add this constant
std::string PUB_IP = "130.208.246.98";
int port = 0; // default port, it will be set in main
const size_t MAX_PEERS = 8;
std::unordered_map<int, Peer> peers;
std::unordered_map<int, Conn> conns;
std::unordered_set<std::string> known_endpoints; // "ip:port" we've connected (or tried) recently
std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_attempt; // last connect attempt time
static const std::chrono::seconds CONNECT_BACKOFF(30); // min time between connect attempts to same endpoint
std::ofstream logFile;
std::deque<std::string> inbox; // Simple FIFO for messages addressed to MY_GROUP (one-node demo "mailbox")

// forward declarations
std::string now();
void logMessage(const std::string& msg);
std::string serverForwardMsg(const std::string& to_group, const std::string& from_group, const std::string& text);
std::string listServers();
void serverSendMsg(const std::string& line, Conn& c, const std::string& from_group);
int connectPeer(const std::string& host, int port);
void receiveHelo();
void sendHelo(Peer& p);


int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        std::cerr << "Usage: ./tsamgroup21 <port> <seed-ip> <seed-port>\n";
        return 1;
    }
    port = std::atoi(argv[1]);
    std::string seed_host = argv[2];
    int seed_port; 
    if (argc == 4) {
        seed_port = std::atoi(argv[3]);
    } else {
        seed_port = 5001; // default seed port
    }

}