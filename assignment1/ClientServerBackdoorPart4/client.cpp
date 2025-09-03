#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static const size_t BUFSZ = 4096;

static bool connectTo(const char* ip, int port, int &fd) {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return false; }

    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port   = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        std::cerr << "inet_pton failed for " << ip << "\n";
        ::close(fd);
        return false;
    }
    if (::connect(fd, (sockaddr*)&a, sizeof(a)) < 0) {
        perror("connect");
        ::close(fd);
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }
    const char* ip = argv[1];
    int port = std::atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        std::cerr << "Invalid port.\n";
        return 1;
    }

    std::string line;
    while (true) {
        std::cout << "cmd> ";
        if (!std::getline(std::cin, line)) break;

        // trim
        auto l = line.find_first_not_of(" \t\r\n");
        if (l == std::string::npos) continue;
        auto r = line.find_last_not_of(" \t\r\n");
        line = line.substr(l, r - l + 1);

        if (line == "exit" || line == "quit") break;

        int fd;
        if (!connectTo(ip, port, fd)) {
            std::cerr << "Failed to connect. Try again.\n";
            continue;
        }

        std::string payload = "SYS " + line + "\n";
        const char* p = payload.c_str();
        size_t left = payload.size();
        while (left > 0) {
            ssize_t s = ::send(fd, p, left, 0);
            if (s < 0) { perror("send"); ::close(fd); fd = -1; break; }
            p += s; left -= static_cast<size_t>(s);
        }
        if (fd < 0) continue;

        // Read response until server closes
        char buf[BUFSZ];
        ssize_t n;
        std::string accum;
        while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0) {
            std::cout.write(buf, n);
            accum.append(buf, buf + n);
        }
        ::close(fd);

        // Optional: a separator for readability
        if (accum.size() && accum.back() != '\n') std::cout << "\n";
    }

    return 0;
}
