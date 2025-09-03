#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>         
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>     
#include <arpa/inet.h>      

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port>\n";
        return EXIT_FAILURE;
    }

    const char* server_ip = argv[1];
    int port = std::atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        std::cerr << "Invalid port: " << argv[2] << "\n";
        return EXIT_FAILURE;
    }

    // 1) Create socket
    int sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    // 2) Build server address
    sockaddr_in servAddr{};
    servAddr.sin_family = AF_INET;
    servAddr.sin_port   = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET, server_ip, &servAddr.sin_addr) != 1) {
        std::cerr << "inet_pton failed for IP: " << server_ip << "\n";
        ::close(sockfd);
        return EXIT_FAILURE;
    }

    // 3) Connect
    if (::connect(sockfd, reinterpret_cast<sockaddr*>(&servAddr), sizeof(servAddr)) < 0) {
        perror("connect");
        ::close(sockfd);
        return EXIT_FAILURE;
    }

    // 4) Read one command from stdin without the SYS
    std::cout << "Enter command to run on server: ";
    std::string cmd;
    if (!std::getline(std::cin, cmd)) {
        std::cerr << "No input read.\n";
        ::close(sockfd);
        return EXIT_FAILURE;
    }

    // Trim leading/trailing spaces (simple)
    auto l = cmd.find_first_not_of(" \t\r\n");
    auto r = cmd.find_last_not_of(" \t\r\n");
    if (l == std::string::npos) {
        std::cerr << "Empty command.\n";
        ::close(sockfd);
        return EXIT_FAILURE;
    }
    cmd = cmd.substr(l, r - l + 1);

    // 5) SYS + command and a newline followed
    std::string line = "SYS " + cmd + "\n";

    // 6) Send
    const char* data = line.c_str();
    size_t toSend = line.size();
    while (toSend > 0) {
        ssize_t sent = ::send(sockfd, data, toSend, 0);
        if (sent < 0) {
            perror("send");
            ::close(sockfd);
            return EXIT_FAILURE;
        }
        data   += sent;
        toSend -= static_cast<size_t>(sent);
    }

    // In part 3 the only requirements where to send then close and exit.
    ::close(sockfd);
    std::cout << "Command sent.\n";
    return EXIT_SUCCESS;
}
