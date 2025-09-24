#include <iostream>
// Include necessary headers
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>

std::string get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];
    std::string result = "127.0.0.1"; // fallback

    if (getifaddrs(&ifaddr) == -1)
        return result;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET &&
            !(ifa->ifa_flags & IFF_LOOPBACK)) {
            getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                        host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            result = host;
            break;
        }
    }
    freeifaddrs(ifaddr);
    return result;
}

// Calculate IP checksum
unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Send a UDP packet with the evil bit set
bool send_evil_probe(const char* src_ip, const char* dst_ip, int dst_port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("raw socket");
        return false;
    }

    // IP_HDRINCL tells the kernel that headers are included in the packet
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sock);
        return false;
    }

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct ip *iph = (struct ip *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip));
    char *data = packet + sizeof(struct ip) + sizeof(struct udphdr);
    strcpy(data, "Evil!"); // Payload

    // Fill IP header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + strlen(data));
    iph->ip_id = htons(54321);
    iph->ip_off = htons(0x8000); // Set the evil bit (highest bit of fragment offset)
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = inet_addr(src_ip);
    iph->ip_dst.s_addr = inet_addr(dst_ip);
    iph->ip_sum = checksum((unsigned short *)iph, sizeof(struct ip) / 2);

    // Fill UDP header
    udph->uh_sport = htons(55555); // Arbitrary source port
    udph->uh_dport = htons(dst_port);
    udph->uh_ulen = htons(sizeof(struct udphdr) + strlen(data));
    udph->uh_sum = 0; // Optional for UDP

    // Destination address
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = udph->uh_dport;
    sin.sin_addr.s_addr = iph->ip_dst.s_addr;

    // Send the packet
    int packet_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);
    if (sendto(sock, packet, packet_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
        close(sock);
        return false;
    }

    close(sock);
    return true;
}

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

    // 2. Loop over each port in the range
    for (int port = low_port; port<=high_port; port++) { 
        // a. Create UDP socket
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket");
            continue;
        }

        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = htons(55555); // Must match evil probe source port
        if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
            perror("bind");
            close(sock);
            continue;
        }

        // b. Set socket timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 250000; // 250ms timeout
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        // c. Prepare destination address structure
        // for where to send the UDP packet
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr)); // Always zero out the struct first
        dest_addr.sin_family = AF_INET; 
        dest_addr.sin_port = htons(port); // Convert port to network byte order
        inet_pton(AF_INET, ip, &dest_addr.sin_addr); // Convert IP string to binary

        int max_retries = 3; // Try to send the probe up to 3 times
        bool port_is_open = false;
        for (int attempt = 0; attempt < max_retries && !port_is_open; attempt++) {
            // d. Send UDP packet (at least 6 bytes)
            if (sendto(sock, "Hello!", 6, 0, (const sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
                perror("sendto");
                continue; // Try again on the next attempt
            }        
    
            // e. Try to receive a response
            char buffer[1024];
            struct sockaddr_in sender_addr;
            socklen_t sender_addr_len = sizeof(sender_addr);
            int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender_addr, &sender_addr_len);
            
            // f. If response received, print port and response
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                // Check if the response is actually from our target IP and port
                // This is important to avoid accepting random packets from the internet
                if (sender_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr) {
                    std::cout << "Port " << port << " responded: " << buffer << std::endl;
                    // std::cout << port << " "; // Output just the number to stdout for the script
                    port_is_open = true; // Mark success and break out of the retry loop
                }
            } else {
                // recvfrom timed out (or failed). We'll just try again.
                usleep(100000); // Sleep for 100ms before retrying

            }
        }
        // If no response after retries, send the evil probe
        if (!port_is_open) {
            std::cout << "Port " << port << " did not respond after " << max_retries << " attempts. Sending evil probe." << std::endl;
            std::string local_ip = get_local_ip();
            send_evil_probe(local_ip.c_str(), ip, port);

            // listen for a response here using your UDP socket
            char buffer[1024];
            struct sockaddr_in sender_addr;
            socklen_t sender_addr_len = sizeof(sender_addr);
            int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender_addr, &sender_addr_len);
            
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                if (sender_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr) {
                    std::cout << "Port " << port << " responded after evil probe: " << buffer << std::endl;
                }
            } else {
                std::cout << "Port " << port << " did not respond even after evil probe." << std::endl;
            }
        }

        // g. Close socket
        close(sock);

    }

    // 3. Return/exit
    return 0;
}