#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <IP address> <low port> <high port>\n";
        return 1;
    }

    const char* ip = argv[1];
    int low_port  = std::atoi(argv[2]);
    int high_port = std::atoi(argv[3]);

    const int MAX_RETRIES = 4;
    const int TIMEOUT_MS  = 1200;
    const char* PROBE     = "Hello!!"; // >= 6 bytes per spec

    for (int port = low_port; port <= high_port; ++port) {
        bool got = false;

        for (int attempt = 0; attempt < MAX_RETRIES && !got; ++attempt) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) { perror("socket"); break; }

            // timeout
            struct timeval tv;
            tv.tv_sec  = TIMEOUT_MS / 1000;
            tv.tv_usec = (TIMEOUT_MS % 1000) * 1000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

            // destination
            struct sockaddr_in dest_addr{};
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port   = htons(port);
            inet_pton(AF_INET, ip, &dest_addr.sin_addr);

            // send probe
            (void)sendto(sock, PROBE, strlen(PROBE), 0,
                         (const sockaddr*)&dest_addr, sizeof(dest_addr));

            // receive once
            char buffer[4096];
            struct sockaddr_in sender_addr{};
            socklen_t sender_len = sizeof(sender_addr);
            int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr*)&sender_addr, &sender_len);

            if (n > 0) {
                buffer[n] = '\0';
                std::cout << "Port " << port << " responded: " << buffer << std::endl;
                got = true;
            }

            close(sock);

            // jitter between tries to avoid bursts
            usleep(120 * 1000); // 120ms
        }

        // small pacing between ports
        usleep(30 * 1000); // 30ms
    }

    return 0;
}
