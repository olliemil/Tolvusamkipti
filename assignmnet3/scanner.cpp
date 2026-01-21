#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <sstream>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <IP address> <low port> <high port>\n";
        return 1;
    }

    // Parse arguments
    const char* ip = argv[1];
    int low_port = std::atoi(argv[2]);
    int high_port = std::atoi(argv[3]);

    // Validate port range
    std::vector<int> open_ports;

    // Scan ports in the specified range
    for (int port = low_port; port <= high_port; port++) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;

        // Set timeout
        timeval tv{0, 250000}; // 250ms
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Setup destination address
        sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &dest_addr.sin_addr);

        // Try sending a message and waiting for a response twice
        bool found = false;
        for (int attempt = 0; attempt < 2 && !found; attempt++) {
            // Send a message to the target port
            sendto(sock, "Hello!", 6, 0, (sockaddr*)&dest_addr, sizeof(dest_addr));

            // Wait for a response
            char buffer[1024];
            sockaddr_in sender_addr{};
            socklen_t sender_len = sizeof(sender_addr);
            
            int received = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (sockaddr*)&sender_addr, &sender_len);
            
            if (received > 0 && sender_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr) {
                open_ports.push_back(port);
                found = true;
            }
            usleep(50000);
        }
        close(sock);
        usleep(10000);
    }

    // Build output string
    std::stringstream ss;
    for (size_t i = 0; i < open_ports.size(); i++) {
        ss << open_ports[i];
        if (i < open_ports.size() - 1) ss << " ";
    }
    
    // Print result if any open ports found
    if (!open_ports.empty()) {
        std::cout << ss.str() << std::endl;
    }
    
    return 0;
}
