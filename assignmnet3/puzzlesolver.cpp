#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <random>
#include <map>
#include <netinet/ip.h>
#include <netinet/udp.h>

using namespace std;

// ===== DATA STRUCTURES =====
// struct PortInfo {
//     int port;
//     string type; // "secret", "evil", "checksum", "oracle"
//     string response;
// };

// struct PuzzleData {
//     uint8_t group_id;
//     uint32_t signature;
//     int hidden_port;
//     map<string, string> secret_phrases; // port_type -> phrase
// };

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

// secret, evil bit, checksum, knock i einhverri roð?



// Function declarations
bool solve_secret_port(const string& ip, int port, uint8_t& group_id, uint32_t& signature, int& secret_hidden_port);
string send_and_receive(int sock, const sockaddr_in& addr, const string& message, int timeout_sec = 2);
int extract_port_from_response(const string& response);
string identify_port_with_retry(const string& ip, int port, int max_retries = 3);
bool probe_hidden_port(const string& ip, int port, uint32_t signature, uint8_t group_id);
bool solve_evil_port_with_raw_socket(const string& ip, int port, uint32_t signature, uint8_t group_id, int& evil_hidden_port);
bool solve_checksum_port(const string& ip, int port, uint32_t signature, string& secret_phrase);
uint16_t compute_udp_checksum(const u_char *const buffer, int buffer_len);
// unsigned short calculate_ip_checksum(unsigned short* buf, int nwords);

// bool knocking_port(const string& ip, int port, uint8_t group_id, int secret_hidden_port, int evil_hidden_port, const string& secret_phrase);


// ===== MAIN CONTROLLER =====
// class PuzzleSolver {
// private:
//     string server_ip;
//     map<string, PortInfo> ports;
//     PuzzleData data;
    
// public:
//     PuzzleSolver(const string& ip, const vector<int>& port_list) : server_ip(ip) {
    
//     }


int main(int argc, char* argv[]) {
    // function to call
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <IP address> <port1> <port2> <port3> <port4>" << endl;
        return 1;
    }

    string ip = argv[1]; // second argument is the IP address
    vector<int> ports;
    for (int i = 2; i < 6; i++) {
        ports.push_back(atoi(argv[i])); // convert to integer and store in ports vector
    }

    // Identify which port is which
    int secret_port = -1, evil_port = -1, checksum_port = -1, knocking_port = -1;
    for (int port : ports) {
        string response = identify_port_with_retry(ip, port, 3);
        
        if (response.find("Greetings from S.E.C.R.E.T.") != string::npos) {
            secret_port = port;
            cout << "Found S.E.C.R.E.T. port: " << port << endl;
        }
        else if (response.find("The dark side") != string::npos) {
            evil_port = port;
            cout << "Found Evil port: " << port << endl;
        }
        else if (response.find("Send me a 4-byte message") != string::npos) {
            checksum_port = port;
            cout << "Found Checksum port: " << port << endl;
        }
        else if (response.find("Greetings! I am E.X.P.S.T.N") != string::npos) {
            knocking_port = port;
            cout << "Found E.X.P.S.T.N + knocking port: " << port << endl;
        }
        else if (!response.empty()) {
            cout << "Unknown response from port " << port << ": " << response.substr(0, 100) << endl;
        }
    }

    if (secret_port == -1) {
        cerr << "Could not find S.E.C.R.E.T. port." << endl;
        return 2;
    }
    else if (evil_port == -1) {
        cerr << "Could not find Evil port." << endl;
        return 3;
    }
    else if (checksum_port == -1) {
        cerr << "Could not find Checksum port." << endl;
        return 4;
    }
    else if (knocking_port == -1) {
        cerr << "Could not find E.X.P.S.T.N + knocking port." << endl;
        return 5;
    }

    cout << "\n=== Port Identification Complete ===" << endl;
    cout << "Secret Port: " << secret_port << endl;
    cout << "Evil Port: " << evil_port << endl;
    cout << "Checksum Port: " << checksum_port << endl;
    cout << "Knocking Port: " << knocking_port << endl;

    // Setting up variables to hold puzzle data
    uint8_t group_id;         // not set yet
    uint32_t signature;       // not set yet
    int secret_hidden_port;   // not set yet
    int evil_hidden_port;     // not set yet
    string secret_phrase; // not set yet
    
    // Now solve the S.E.C.R.E.T. port first
    if (secret_port > 0) {
        cout << "\n=== Solving Secret Port ===" << endl;
        if (solve_secret_port(ip, secret_port, group_id, signature, secret_hidden_port)) {
            // Now group_id, signature, and hidden_port are set!
            cout << "SUCCESS: Secret port solved!" << endl;
            cout << "Group ID: " << (int)group_id << endl;
            cout << "Signature: " << signature << endl;
            cout << "Secret Hidden Port: " << secret_hidden_port << endl;
        } else {
            cerr << "FAILED: Could not solve secret port" << endl;
            return 1;
        }
    }

    // Now solve the Evil port
    if (evil_port > 0) {
        cout << "\n=== Solving Evil Port with raw socket ===" << endl;
        if (solve_evil_port_with_raw_socket(ip, evil_port, signature, group_id, evil_hidden_port)) {
            cout << "SUCCESS: Evil port solved!" << endl;
            cout << "Evil Hidden Port: " << evil_hidden_port << endl;
        } else {
            cerr << "FAILED: Could not solve evil port" << endl;
            return 1;
        }
    }

    // Now solve the Checksum port
    if (checksum_port > 0) {
        cout << "\n=== Solving Checksum Port ===" << endl;
        if (solve_checksum_port(ip, checksum_port, signature, secret_phrase)) {
            cout << "SUCCESS: Checksum port solved!" << endl;
            cout << "Checksum Secret Phrase: " << secret_phrase << endl;
        } else {
            cerr << "FAILED: Could not solve checksum port" << endl;
            return 1;
        }
    }


    // knocking_port(ip, knocking_port, group_id, signature);

    return 0;


}

// secret function
// Function to solve the S.E.C.R.E.T. port puzzle (implementation to be added)
bool solve_secret_port(const string& ip, int port, uint8_t& group_id, uint32_t& signature, int& secret_hidden_port) {
    cout << "[DEBUG] solve_secret_port called for IP: " << ip << ", port: " << port << endl;
    // 1. Generate a 32 bit secret number (and remember it for later)
    // first gennerate a random 32 bit number
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint32_t> dis(1, 0xFFFFFFFF);
    uint32_t secret_number = dis(gen); // here is our secret number generated
    cout << "[DEBUG] Generated secret number: " << secret_number << endl;

    int sock = socket(AF_INET, SOCK_DGRAM, 0); // Create UDP socket
    if (sock < 0) {
        perror("socket creation failed");
        return false;
    }

    // setting the timeout
    timeval tv{};
    tv.tv_sec = 2; // 2 seconds timeout
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
        close(sock);
        return false;
    }

    // Here we set up the server address structure
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    // 2. Send me a message where the first byte is the letter 'S' followed by 4 bytes containing your secret number (in network byte order),
    // and the rest of the message is a comma-separated list of the RU usernames of all your group members.
    string usernames = "benjaminr23,sindrib23,oliver23";

    bool step1_success = false;
    for (int attempt = 0; attempt < 3 && !step1_success; attempt++) {
        char message[1 + 4 + usernames.size()];
        message[0] = 'S'; // first byte is 'S'
        uint32_t net_secret = htonl(secret_number); // convert to network byte order
        memcpy(message + 1, &net_secret, 4); // putting the secret number in next 4 bytes as network byte order
        strcpy(message + 1 + 4, usernames.c_str()); // copy usernames after that

        int message_len = 1 + 4 + usernames.size();

        cout << "Sending initial message (attempt " << (attempt + 1) << ")..." << endl;
        if (sendto(sock, message, message_len, 0, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Send failed");
            continue; // try again
        }

        // 3. I will reply with a 5-byte message, where the first byte is your group ID and the remaining 4 bytes are a 32 bit challenge number (in network byte order)
        char challenge_response_message[5]; // the 5 byte response message
        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr); 

        // Set timeout for receiving challenge
        timeval tv{};
        tv.tv_sec = 4;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));


        int received = recvfrom(sock, challenge_response_message, 5, 0, (sockaddr*)&from_addr, &from_len);

        if (received == 5) {
            group_id = challenge_response_message[0];
            uint32_t challenge;
            memcpy(&challenge, challenge_response_message + 1, 4);
            challenge = ntohl(challenge); // convert from network byte order to host byte order
        
            cout << "[DEBUG] Received group ID: " << (int)group_id << ", challenge: " << challenge << endl;
            
            // 4. Combine this challenge using the XOR operation with the secret number you generated in step 1 to obtain a 4 byte signature.
            signature = challenge ^ secret_number;
            cout << "[DEBUG] Computed signature: " << signature << endl;
            step1_success = true; // we succeeded in step 1
        }
        else {
            usleep(100000); // wait 100ms before retrying
            cout << "Did not receive valid challenge response, retrying..." << endl;
        }
    }

    if (!step1_success) {
        cerr << "Failed to complete step 1 after 3 attempts." << endl;
        close(sock);
        return false;
    }

    // 5. Reply with a 5-byte message: the first byte is your group number, followed by the 4-byte signature (in network byte order).
    bool step2_success = false;
    for (int attempt = 0; attempt < 3 && !step2_success; attempt++) {
        char reply_message[5];
        reply_message[0] = group_id;
        uint32_t net_signature = htonl(signature); // convert signature to network byte order
        memcpy(reply_message + 1, &net_signature, 4); // copy signature into message

        // send the reply message
        cout << "Sending signature reply (attempt " << (attempt + 1) << ")..." << endl;
        if (sendto(sock, reply_message, 5, 0, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Send failed");
            continue; // try again
        }

        // 6. If your signature is correct, I will respond with a secret port number. Good luck!
        char port_response[1024];
        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);
        
        // Set timeout for receiving port
        timeval tv{};
        tv.tv_sec = 4;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int received = recvfrom(sock, port_response, sizeof(port_response) - 1, 0, (sockaddr*)&from_addr, &from_len);
        
        if (received > 0) {
            port_response[received] = '\0'; // null-terminate the response
            string response_str(port_response);
            cout << "[DEBUG] Received port response: " << response_str << endl;
            
            secret_hidden_port = extract_port_from_response(response_str);

            if (secret_hidden_port > 0) {
                cout << "Extracted hidden port: " << secret_hidden_port << endl;
                step2_success = true; // we succeeded in step 2
                break; // exit the retry loop
            }
            else {
                cerr << "Could not extract hidden port from response, retrying" << endl;
                usleep(100000); // wait 100ms before retrying
            }
        }
        else {
            usleep(100000); // wait 100ms before retrying
            cout << "Did not receive valid port response, retrying..." << endl;
        }
    }
    close(sock);
    return step2_success;
    // 7. Remember to keep your group ID and signature for later, you will need them for
    // this was done with the reference variables passed in
}

int extract_port_from_response(const string& response) {
    // Simple parsing to find the port number in the response string
    for (size_t i = 0; i < response.size(); i++) {
        if (isdigit(response[i])) {
            size_t j = i;
            while (j < response.length() && isdigit(response[j])) {
                j++;
            }
            string number_str = response.substr(i, j - i);
            int port = stoi(number_str);
            
            // Basic validation
            if (port > 1024 && port < 65536) {
                return port;
            }
        }
    }
    return -1; // could not find port
}

string send_and_receive(int sock, const sockaddr_in& addr, const string& message, int timeout_sec) {
    timeval tv{};
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sendto(sock, message.c_str(), message.length(), 0, (const sockaddr*)&addr, sizeof(addr));

    char buffer[1024];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);
    
    int received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (sockaddr*)&from_addr, &from_len);
    
    if (received > 0) {
        buffer[received] = '\0';
        return string(buffer);
    }
    return "";
}

string identify_port_with_retry(const string& ip, int port, int max_retries) {
    for (int attempt = 1; attempt <= max_retries; ++attempt) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0); // Create UDP socket
        if (sock < 0) {
            perror("socket creation failed");
            continue;
        }

        // Setting up the sockaddr_in structure for the server
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        // Set shorter timeout for identification
        timeval tv{};
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        string response = send_and_receive(sock, addr, "Hello", 1);
        close(sock);

        if (!response.empty()) {
            return response; // Successfully received a response
        } else {
            cout << "Attempt " << attempt << " failed for port " << port << ". Retrying..." << endl;
        }
        // Wait before retry
        usleep(100000); // 100ms delay
    }
    return ""; // All attempts failed
}

bool solve_evil_port_with_raw_socket(const string& ip, int port, uint32_t signature, uint8_t group_id, int& evil_hidden_port) {
    cout << "[DEBUG] solve_evil_port called for IP: " << ip << ", port: " << port << endl;
    
    // Create a normal UDP socket for receiving responses
    int recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sock < 0) {
        perror("Receive socket creation failed");
        return false;
    }

    // Bind the socket to any local address and port 55555
    sockaddr_in recv_addr{};
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = INADDR_ANY;
    recv_addr.sin_port = 0; // Let OS choose the port

    // Here we bind the socket to the address
    if (bind(recv_sock, (sockaddr*)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("Bind failed");
        close(recv_sock);
        return false;
    }

    // Get the port assigned by the OS
    socklen_t addr_len = sizeof(recv_addr);
    if (getsockname(recv_sock, (sockaddr*)&recv_addr, &addr_len) < 0) {
        perror("getsockname failed");
        close(recv_sock);
        return false;
    }
    cout << "[DEBUG] Receive socket bound to port: " << ntohs(recv_addr.sin_port) << endl;

    // Create the raw socket for sending evil packet
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_sock < 0) {
        perror("Raw socket creation failed");
        close(recv_sock);
        return false;
    }

    // Enable IP_HDRINCL to manually provide IP header
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        close(raw_sock);
        close(recv_sock);
        return false;
    }

    // Build the evil packet
    char packet[1024];
    memset(packet, 0, sizeof(packet));

    // IP header
    struct iphdr* ip_header = (struct iphdr*)packet;
    ip_header->ihl = 5; // Header length (5 * 4 = 20 bytes)
    ip_header->version = 4; // IPv4
    ip_header->tos = 0; // Type of service: normal
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 4); // Total length (+ 4 because of the payload)
    ip_header->id = htons(12345); // Identification: random
    ip_header->frag_off = htons(0x8000); // Set the evil bit (highest bit of fragment offset)
    ip_header->ttl = 64; // Time to live: 64 hops
    ip_header->protocol = IPPROTO_UDP; // Protocol: UDP

    // Source and destination IP addresses
    ip_header->saddr = inet_addr("172.29.175.97");

    // Destination IP address
    ip_header->daddr = inet_addr(ip.c_str());

    // UDP header
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct iphdr));
    udp_header->source = recv_addr.sin_port; // Source port (the one we bound to)
    udp_header->dest = htons(port); // Destination port
    udp_header->len = htons(sizeof(struct udphdr) + 4); // Length of UDP header + payload
    udp_header->check = 0; // Checksum (optional for UDP)

    // Data (4-byte signature)
    char* data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    uint32_t net_signature = htonl(signature);
    memcpy(data, &net_signature, 4); // Copy signature into data (4 bytes and network byte order)

    // Send the packet

    // Destination address structure
    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(ip.c_str());

    cout << "[DEBUG] Sending evil packet with evil bit set..." << endl;

    const int max_attempts = 3;
    bool success = false;
    for (int attempt = 0; attempt < max_attempts && !success; attempt++) {
        ssize_t sent = sendto(raw_sock, packet, ntohs(ip_header->tot_len), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
        
        if (sent < 0) {
            perror("send evil packet failed");
            close(raw_sock);
            close(recv_sock);
            return false;
        }

        cout << "[DEBUG] Evil packet sent, waiting for response..." << endl;

        // wait for response on the normal UDP socket
        char response[1024];
        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);

        timeval tv{};
        tv.tv_sec = 4; // 4 seconds timeout
        tv.tv_usec = 0;
        setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int received = recvfrom(recv_sock, response, sizeof(response) - 1, 0, (sockaddr*)&from_addr, &from_len);

        if (received > 0) {
            response[received] = '\0';
            string response_str(response);
            cout << "Received response from evil port: " << response_str << endl;

            evil_hidden_port = extract_port_from_response(response_str);

            if (evil_hidden_port > 0) {
                cout << "Extracted hidden port: " << evil_hidden_port << endl;
                success = true; // we succeeded
                break; // exit the retry loop
            } 
            else {
                cout << "Could not extract hidden port from response." << endl;
                usleep(100000); // wait 100ms before retrying
            }
        } 
        else {
            usleep(100000); // wait 100ms before retrying
            cout << "No response received from evil port, retrying..." << endl;
        }
    }
    close(raw_sock);
    close(recv_sock);
    return success;
}

bool solve_checksum_port(const string& ip, int port, uint32_t signature, string& secret_phrase) {
    cout << "[DEBUG] solve_checksum_port called for IP: " << ip << ", port: " << port << endl;

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        return false;
    }

    // Setting the timeout
    timeval tv{};
    tv.tv_sec = 2; // 2 seconds timeout
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
        close(sock);
        return false;
    }

    // Setting up the sockaddr_in structure for the server
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    bool success = false;
    const int max_attempts = 3;
    string response;
    for (int attempt = 0; attempt < max_attempts && !success; attempt++) {
        // Send me a 4-byte message containing the signature you got from S.E.C.R.E.T in the first 4 bytes (in network byte order).
        uint32_t net_signature = htonl(signature);
        cout << "Sending signature to checksum port (attempt " << attempt + 1 << ")" << endl;

        response = send_and_receive(sock, server_addr, string((char*)&net_signature, 4), 2);

        if (!response.empty()) {
            cout << "Received response from checksum port: " << response << endl;
            success = true;
            break; // exit the retry loop
        } 
        else {
            usleep(100000); // wait 100ms before retrying
            cout << "No response received from checksum port, retrying..." << endl;
        }
    }
    
    if (!success) {
        cerr << "Failed to get response from checksum port after " << max_attempts << " attempts." << endl;
        close(sock);
        return false;
    }

    cout << "Successfully communicated with checksum port." << endl;
    // (Hint: all you need is a normal UDP socket which you use to send the IPv4 and UDP headers possibly with a payload) 
    // (the last 6 bytes of this message contain the checksum and ip address in network byte order for your convenience)R�+j�y
    if (response.size() < 6) {
        cerr << "Response too short to extract checksum and IP." << endl;
        close(sock);
        return false;
    }

    // Using the last 6 bytes to extract the checksum and IP address from the response without having to parse the string
    const char* resp_data = response.data();
    uint16_t checksum;
    uint32_t ip_addr;
    memcpy(&checksum, resp_data + response.size() - 6, 2); // first 2 bytes of the last 6 bytes
    memcpy(&ip_addr, resp_data + response.size() - 4, 4); // remaining 4 bytes of the last 6 bytes
    // convert from network byte order to host byte order
    checksum = ntohs(checksum);
    ip_addr = ntohl(ip_addr);

    cout << "[DEBUG] Extracted checksum: 0x" << hex << checksum << dec << ", IP: " 
            << ((ip_addr >> 24) & 0xFF) << "." 
            << ((ip_addr >> 16) & 0xFF) << "." 
            << ((ip_addr >> 8) & 0xFF) << "." 
            << (ip_addr & 0xFF) << endl;
    
    // build the checksum packet
    char packet[1024];
    memset(packet, 0, sizeof(packet));

    // UDP message where the payload is an encapsulated, valid UDP IPv4 packet,
    // that has a valid UDP checksum of 0x52ba, and with the source address being 43.106.205.121! 

    // IP header
    struct iphdr* ip_header = (struct iphdr*)packet;
    ip_header->ihl = 5; // Header length (5 * 4 = 20 bytes)
    ip_header->version = 4; // IPv4
    ip_header->tos = 0; // Type of service: normal
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 2); // Total length
    ip_header->id = htons(13245); // Identification: random
    ip_header->frag_off = 0; // No fragmentation
    ip_header->ttl = 64; // Time to live: 64 hops
    ip_header->protocol = IPPROTO_UDP; // Protocol: UDP
    ip_header->check = 0; // IP checksum does not matter here
    ip_header->saddr = htonl(ip_addr); // Source IP address from response, converted from integer to network byte order
    ip_header->daddr = inet_addr(ip.c_str()); // Destination IP address, converted from string to network byte order
    

    // Inner UDP header
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct iphdr));
    udp_header->source = htons(14235); // Source port: random
    udp_header->dest = htons(port); // Destination port: the checksum port
    udp_header->len = htons(sizeof(struct udphdr) + 2); // Length of UDP header (no payload)
    udp_header->check = 0; // Checksum (to be calculated)
    
    // data
    uint16_t data_len = 2;
    uint16_t* data = (uint16_t*)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));
    *data = 0; // initial dummy data

    // pseudoheader
    struct pseudo_header psh;
    psh.source_address = ip_header->saddr;
    psh.dest_address = ip_header->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + data_len);

    u_char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct udphdr) + data_len];
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), udp_header, sizeof(struct udphdr) + data_len);

    // Properly calculate the checksum
    // Lets go over the cheksum with different data and check if we get the same result as the extracted checksum 
    // for loop will go to 65535 and calculate the checksum each time
    u_int16_t calculated_checksum = compute_udp_checksum(pseudo_packet, sizeof(pseudo_packet));

    for (int i = 0; i < 65536; i++) {
        // print here for iteration
        udp_header->check = 0; // reset checksum field
        *data = i;
        memcpy(pseudo_packet + sizeof(struct pseudo_header) + sizeof(struct udphdr), data, sizeof(data_len));
        uint16_t calculated_checksum = compute_udp_checksum(pseudo_packet, sizeof(pseudo_packet));
        // cout << "[DEBUG] checksum: 0x" << hex << checksum << dec << endl;
        // cout << "[DEBUG] Calculated checksum: 0x" << hex << calculated_checksum << dec << endl;
        if (calculated_checksum == checksum) {
            cout << "[DEBUG] Found matching checksum with value: 0x" << hex << i << dec << endl;
            // Set UDP header checksum field
            udp_header->check = htons(calculated_checksum);
            break;
        }
    }

    cout << "[DEBUG] calculate_udp_checksum: " << udp_header->check << endl;
    cout << "[DEBUG] data bytes: " << hex << *data << dec << endl;
    cout << "[DEBUG] ip_header->check: " << hex << ip_header->check << dec << endl;
    cout << "[DEBUG] udp_header->check: " << hex << udp_header->check << dec << endl;
    
    // Send the packet as a normal UDP message
    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, 0, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Send encapsulated packet failed");
        close(sock);
        return false;
    }

    // Wait for the secret phrase response
    char phrase_response[1024];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);

    // Wait for a response 
    int received = recvfrom(sock, phrase_response, sizeof(phrase_response) - 1, 0, (sockaddr*)&from_addr, &from_len);

    if (received > 0) {
        phrase_response[received] = '\0';
        secret_phrase = string(phrase_response);
        cout << "Received secret phrase from checksum port: " << secret_phrase << endl;
        close(sock);
        return true;
    } 
    else {
        cerr << "No response received for secret phrase." << endl;
    }


    return false;
}

uint16_t compute_udp_checksum(const u_char *const buffer, int buffer_len) {
    u_int32_t sum = 0;
    
    u_int16_t *word = (u_int16_t *)buffer;

    while (buffer_len > 1) {
        sum += ntohs(*word++);
        buffer_len -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(buffer_len == 1) {
        uint16_t pad = 0;
        *((u_char*)&pad) = *(u_char*)word;
        sum += ntohs(pad);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum;
}

bool probe_hidden_port(const string& ip, int port, uint32_t signature, uint8_t group_id) {
    cout << "[DEBUG] probe_hidden_port called for IP: " << ip << ", port: " << port << endl;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // Try sending just the signature first (as other ports expect)
    uint32_t net_signature = htonl(signature);
    string response = send_and_receive(sock, addr, string((char*)&net_signature, 4), 2);
    
    if (!response.empty()) {
        cout << "Hidden port response: " << response << endl;
    } else {
        cout << "No response from hidden port (might need knocking)" << endl;
    }
    
    close(sock);
    return false;
}