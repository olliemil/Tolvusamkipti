#include <iostream>
// Include necessary headers
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    // 1. Parse command-line arguments (IP, low port, high port)
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <IP address> <low port> <high [port]>\n";
        return 1;
    }

    // Using std::atoi() to convert a string to an integer
    const char* ip = argv[1];
    int low_port = std::atoi(argv[2]);
    int high_port = std::atoi(argv[3]);

    int secretPort = -1;
    int signaturePort = -1;

    // 2. Loop over each port in the range
    for (int port = low_port; port<=high_port; port++) { 
        // a. Create UDP socket
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket");
            continue;
        }

        // b. Set socket timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        // c. Prepare destination address structure
        // for where to send the UDP packet
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr)); // Always zero out the struct first
        dest_addr.sin_family = AF_INET; 
        dest_addr.sin_port = htons(port); // Convert port to network byte order
        inet_pton(AF_INET, ip, &dest_addr.sin_addr); // Convert IP string to binary

        // d. Send UDP packet (at least 6 bytes)
        if (sendto(sock, "Hello!", 6, 0, (const sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto");
            // Optionally: continue; or handle the error as needed
        }        

        // e. Try to receive a response
        char buffer[1024];
        struct sockaddr_in sender_addr;
        socklen_t sender_addr_len = sizeof(sender_addr);
        int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender_addr, &sender_addr_len);
        
        // f. If response received, print port and response
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0'; // must add after the last received byte to print as string
            std::cout << "Port " << port << " responded: " << buffer << std::endl;
            if (strstr(buffer, "Greetings from S.E.C.R.E.T.") != nullptr) {
                secretPort = port; 
            } else if (strstr(buffer, "Send me a 4-byte message containing the signature") != nullptr) {
                signaturePort = port;  // Port 4011
            }
        }



        // g. Close socket
        close(sock);

    }
    std::string command = "./puzzlesolver " + std::to_string(secretPort) + " " + std::to_string(signaturePort);
    int result = system(command.c_str());
    if (result < 0) {
        perror("Running ./puzzlesolver <portnum> failed!!!");
        return -1;
    }

    // 3. Return/exit
    return 0;
}


                
                