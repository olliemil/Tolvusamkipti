// puzzlesolver.cpp  (fixed & commented)
// Build on Linux: g++ -std=c++17 -O2 -Wall -o puzzlesolver puzzlesolver.cpp
// Run (example):  sudo ./puzzlesolver 130.208.246.98 4008 4022 4034 4080

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cctype>          // isdigit
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <random>
#include <map>
#include <netinet/ip.h>    // struct iphdr (Linux)
#include <netinet/udp.h>   // struct udphdr (Linux)
#include <netinet/ip_icmp.h>

using namespace std;

// ===== Pseudo header for UDP checksum (RFC 768) =====
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t udp_length;
};

// ====== Forward decls ======
bool solve_secret_port(const string& ip, int port, uint8_t& group_id, uint32_t& signature, int& secret_hidden_port);
string send_and_receive(int sock, const sockaddr_in& addr, const string& message, int timeout_sec = 2);
int extract_port_from_response(const string& response);
string identify_port_with_retry(const string& ip, int port, int max_retries = 3);
bool solve_evil_port_with_raw_socket(const string& ip, int port, uint32_t signature, uint8_t group_id, int& evil_hidden_port);
bool solve_checksum_port(const string& ip, int port, uint32_t signature, string& secret_phrase);
uint16_t compute_udp_checksum(const uint8_t* buffer, int buffer_len);
bool solve_knocking_port(const string& ip, int port, uint32_t signature, int secret_hidden_port, int evil_hidden_port, const string& secret_phrase);
bool knock_hidden_port(const string& ip, int port, uint32_t signature, const string& secret_phrase);
bool send_icmp_bonus(const string& ip, uint8_t group_id);
uint16_t compute_icmp_checksum(uint16_t* data, int length);

// === NEW: helper to compute IPv4 header checksum (because IP_HDRINCL means we must fill it) ===
static uint16_t ip_checksum(const void* vdata, size_t length) {
    const uint16_t* data = static_cast<const uint16_t*>(vdata);
    uint32_t acc = 0;
    // sum 16-bit words
    for (size_t i = 0; i < length / 2; ++i) acc += ntohs(data[i]);
    // fold carries
    acc = (acc & 0xFFFF) + (acc >> 16);
    acc = (acc & 0xFFFF) + (acc >> 16);
    return htons(~acc);
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <IP address> <port1> <port2> <port3> <port4>" << endl;
        return 1;
    }

    string ip = argv[1];
    vector<int> ports;
    for (int i = 2; i < 6; i++) ports.push_back(atoi(argv[i]));

    int secret_port = -1, evil_port = -1, checksum_port = -1, knocking_port = -1;

    // Identify which puzzle is on which port (order unknown)
    for (int port : ports) {
        string response = identify_port_with_retry(ip, port, 3);

        if (response.find("Greetings from S.E.C.R.E.T.") != string::npos) {
            secret_port = port;
            cout << "Found S.E.C.R.E.T. port: " << port << endl;
        } else if (response.find("The dark side") != string::npos) {
            evil_port = port;
            cout << "Found Evil port: " << port << endl;
        } else if (response.find("Send me a 4-byte message") != string::npos) {
            checksum_port = port;
            cout << "Found Checksum port: " << port << endl;
        } else if (response.find("Greetings! I am E.X.P.S.T.N") != string::npos) {
            knocking_port = port;
            cout << "Found E.X.P.S.T.N + knocking port: " << port << endl;
        } else if (!response.empty()) {
            cout << "Unknown response from port " << port << ": " << response.substr(0, 100) << endl;
        }
    }

    if (secret_port == -1)  { cerr << "Could not find S.E.C.R.E.T. port.\n";       return 2; }
    if (evil_port == -1)    { cerr << "Could not find Evil port.\n";               return 3; }
    if (checksum_port == -1){ cerr << "Could not find Checksum port.\n";          return 4; }
    if (knocking_port == -1){ cerr << "Could not find E.X.P.S.T.N port.\n";       return 5; }

    cout << "\n=== Port Identification Complete ===\n";
    cout << "Secret Port: "   << secret_port   << "\n";
    cout << "Evil Port: "     << evil_port     << "\n";
    cout << "Checksum Port: " << checksum_port << "\n";
    cout << "Knocking Port: " << knocking_port << "\n";

    uint8_t  group_id        = 0;
    uint32_t signature       = 0;
    int      secret_hidden   = -1;
    int      evil_hidden     = -1;
    string   secret_phrase;

    // 1) S.E.C.R.E.T.
    cout << "\n=== Solving Secret Port ===\n";
    if (!solve_secret_port(ip, secret_port, group_id, signature, secret_hidden)) {
        cerr << "FAILED: Could not solve secret port\n";
        return 1;
    }
    cout << "SUCCESS: Secret port solved!\n";
    cout << "Group ID: " << (int)group_id << "\n";
    cout << "Signature: " << signature    << "\n";
    cout << "Secret Hidden Port: " << secret_hidden << "\n";

    // 2) Evil (raw IP with evil bit)
    cout << "\n=== Solving Evil Port with raw socket ===\n";
    if (!solve_evil_port_with_raw_socket(ip, evil_port, signature, group_id, evil_hidden)) {
        cerr << "FAILED: Could not solve evil port\n";
        return 1;
    }
    cout << "SUCCESS: Evil port solved!\n";
    cout << "Evil Hidden Port: " << evil_hidden << "\n";

    // 3) Checksum
    cout << "\n=== Solving Checksum Port ===\n";
    if (!solve_checksum_port(ip, checksum_port, signature, secret_phrase)) {
        cerr << "FAILED: Could not solve checksum port\n";
        return 1;
    }
    cout << "SUCCESS: Checksum port solved!\n";
    cout << "Checksum Secret Phrase: " << secret_phrase << "\n";

    // Extract phrase between quotes (as per assignment hint)
    if (!secret_phrase.empty()) {
        size_t first_quote = secret_phrase.find('"');
        size_t last_quote  = secret_phrase.rfind('"');
        if (first_quote != string::npos && last_quote != string::npos && last_quote > first_quote) {
            secret_phrase = secret_phrase.substr(first_quote + 1, last_quote - first_quote - 1);
            cout << "Extracted Secret Phrase: " << secret_phrase << endl;
        } else {
            cerr << "Could not extract secret phrase from response.\n";
            return 1;
        }
    } else {
        cerr << "Secret phrase is empty, cannot proceed with port knocking.\n";
        return 1;
    }

    // 4) Knocking
    cout << "\n=== Performing Port Knocking ===\n";
    if (!solve_knocking_port(ip, knocking_port, signature, secret_hidden, evil_hidden, secret_phrase)) {
        cerr << "FAILED: Port knocking\n";
        return 1;
    }
    cout << "SUCCESS: Port knocking completed!\n";

    // 5) Bonus (ICMP)
    cout << "\n=== Sending ICMP Bonus Packet ===\n";
    if (!send_icmp_bonus(ip, group_id)) {
        cerr << "FAILED: ICMP bonus\n";
        return 1;
    }
    cout << "SUCCESS: ICMP packet sent!\n";

    cout << "\n=== Puzzle Solved Successfully! ===\n";
    return 0;
}

// ===================== S.E.C.R.E.T. =====================
bool solve_secret_port(const string& ip, int port, uint8_t& group_id, uint32_t& signature, int& secret_hidden_port) {
    cout << "[DEBUG] solve_secret_port called for IP: " << ip << ", port: " << port << endl;

    // (unchanged) random 32-bit secret:
    random_device rd; mt19937 gen(rd());
    uniform_int_distribution<uint32_t> dis(1, 0xFFFFFFFF);
    uint32_t secret_number = dis(gen);
    cout << "[DEBUG] Generated secret number: " << secret_number << endl;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket creation failed"); return false; }

    timeval tv{}; tv.tv_sec = 2; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in server_addr{}; server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    // Provide usernames (≥ 6 chars total msg anyway)
    string usernames = "benjaminr23,sindrib23,oliver23";

    bool step1_ok = false;
    for (int attempt = 0; attempt < 3 && !step1_ok; attempt++) {
        vector<char> message(1 + 4 + usernames.size());
        message[0] = 'S';
        uint32_t net_secret = htonl(secret_number);
        memcpy(message.data() + 1, &net_secret, 4);
        memcpy(message.data() + 5, usernames.data(), usernames.size());

        cout << "Sending initial message (attempt " << (attempt + 1) << ")...\n";
        if (sendto(sock, message.data(), (int)message.size(), 0, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Send failed");
            continue;
        }

        char challenge_buf[5];
        sockaddr_in from{}; socklen_t flen = sizeof(from);

        tv.tv_sec = 4; tv.tv_usec = 0; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int received = recvfrom(sock, challenge_buf, 5, 0, (sockaddr*)&from, &flen);
        if (received == 5) {
            group_id = (uint8_t)challenge_buf[0];
            uint32_t challenge; memcpy(&challenge, challenge_buf + 1, 4);
            challenge = ntohl(challenge);
            cout << "[DEBUG] Received group ID: " << (int)group_id << ", challenge: " << challenge << endl;
            signature = challenge ^ secret_number;
            cout << "[DEBUG] Computed signature: " << signature << endl;
            step1_ok = true;
        } else {
            cout << "Did not receive valid challenge response, retrying...\n";
            usleep(100000);
        }
    }
    if (!step1_ok) { cerr << "Failed step 1.\n"; close(sock); return false; }

    bool step2_ok = false;
    for (int attempt = 0; attempt < 3 && !step2_ok; attempt++) {
        char reply[5];
        reply[0] = (char)group_id;
        uint32_t net_sig = htonl(signature);
        memcpy(reply + 1, &net_sig, 4);

        cout << "Sending signature reply (attempt " << (attempt + 1) << ")...\n";
        if (sendto(sock, reply, 5, 0, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Send failed");
            continue;
        }

        char port_resp[1024];
        sockaddr_in from{}; socklen_t flen = sizeof(from);
        timeval tv2{}; tv2.tv_sec = 4; tv2.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));

        int received = recvfrom(sock, port_resp, sizeof(port_resp)-1, 0, (sockaddr*)&from, &flen);
        if (received > 0) {
            port_resp[received] = '\0';
            string resp(port_resp);
            cout << "[DEBUG] Received port response: " << resp << endl;
            secret_hidden_port = extract_port_from_response(resp);
            if (secret_hidden_port > 0) {
                cout << "Extracted hidden port: " << secret_hidden_port << endl;
                step2_ok = true;
                break;
            } else {
                cerr << "Could not extract hidden port, retrying...\n";
                usleep(100000);
            }
        } else {
            cout << "No port response, retrying...\n";
            usleep(100000);
        }
    }
    close(sock);
    return step2_ok;
}

// Find first integer-looking token that’s a valid port
int extract_port_from_response(const string& response) {
    for (size_t i = 0; i < response.size(); i++) {
        if (isdigit((unsigned char)response[i])) {
            size_t j = i;
            while (j < response.size() && isdigit((unsigned char)response[j])) j++;
            int port = stoi(response.substr(i, j - i));
            if (port > 1024 && port < 65536) return port;
            i = j;
        }
    }
    return -1;
}

// Send a message, wait with timeout, return response (if any)
string send_and_receive(int sock, const sockaddr_in& addr, const string& message, int timeout_sec) {
    timeval tv{}; tv.tv_sec = timeout_sec; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sendto(sock, message.c_str(), (int)message.size(), 0, (const sockaddr*)&addr, sizeof(addr));

    char buffer[2048];
    sockaddr_in from{}; socklen_t flen = sizeof(from);
    int received = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (sockaddr*)&from, &flen);
    if (received > 0) {
        buffer[received] = '\0';
        return string(buffer);
    }
    return "";
}

// === CHANGED: use >= 6 chars so all puzzle ports answer consistently ===
string identify_port_with_retry(const string& ip, int port, int max_retries) {
    for (int attempt = 1; attempt <= max_retries; ++attempt) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); continue; }

        sockaddr_in addr{}; addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        timeval tv{}; tv.tv_sec = 2; tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // *** CHANGED HERE: "Hello!!" (>= 6 chars) ***
        string response = send_and_receive(sock, addr, "Hello!!", 1);
        close(sock);

        if (!response.empty()) return response;
        cout << "Attempt " << attempt << " failed for port " << port << ". Retrying...\n";
        usleep(100000);
    }
    return "";
}

// ===================== EVIL PORT (raw IP with evil bit) =====================
// IMPORTANT FIXES:
//  - No hard-coded source IP. We get the local IP via getsockname() on our recv socket.
//  - We compute ip_header->check (IPv4 header checksum) because IP_HDRINCL is set.
//  - dest_addr.sin_port is set to 0 (ignored for raw IP, but avoids confusion).
bool solve_evil_port_with_raw_socket(const string& ip, int port, uint32_t signature, uint8_t /*group_id*/, int& evil_hidden_port) {
    cout << "[DEBUG] solve_evil_port called for IP: " << ip << ", port: " << port << endl;

    // Normal UDP socket to receive replies
    int recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sock < 0) { perror("Receive socket creation failed"); return false; }

    sockaddr_in recv_addr{}; recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = INADDR_ANY;
    recv_addr.sin_port = 0; // OS chooses port

    if (bind(recv_sock, (sockaddr*)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("Bind failed"); close(recv_sock); return false;
    }

    // Discover the local ephemeral UDP source port AND the local IP (*** CHANGED HERE ***)
    socklen_t addr_len = sizeof(recv_addr);
    if (getsockname(recv_sock, (sockaddr*)&recv_addr, &addr_len) < 0) {
        perror("getsockname failed"); close(recv_sock); return false;
    }
    cout << "[DEBUG] Receive socket bound to port: " << ntohs(recv_addr.sin_port) << endl;

    // Create RAW socket for crafting IP+UDP
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_sock < 0) { perror("Raw socket creation failed"); close(recv_sock); return false; }

    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed"); close(raw_sock); close(recv_sock); return false;
    }

    // Build packet
    char packet[1024]; memset(packet, 0, sizeof(packet));

    // IP header
    struct iphdr* ip_header = (struct iphdr*)packet;
    ip_header->ihl      = 5;
    ip_header->version  = 4;
    ip_header->tos      = 0;
    ip_header->tot_len  = htons((uint16_t)(sizeof(struct iphdr) + sizeof(struct udphdr) + 4));
    ip_header->id       = htons(12345);
    ip_header->frag_off = htons(0x8000); // EVIL BIT set (highest bit of frag_off)
    ip_header->ttl      = 64;
    ip_header->protocol = IPPROTO_UDP;

    // *** CHANGED HERE: dynamic local source IP instead of a hard-coded string ***
    ip_header->saddr    = recv_addr.sin_addr.s_addr;     // local IP we’re bound on
    ip_header->daddr    = inet_addr(ip.c_str());         // TSAM server IP

    // UDP header
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct iphdr));
    udp_header->source = recv_addr.sin_port;             // same ephemeral port so reply returns to recv_sock
    udp_header->dest   = htons(port);
    udp_header->len    = htons((uint16_t)(sizeof(struct udphdr) + 4));
    udp_header->check  = 0;  // UDP checksum optional; evil port cares about IP evil bit

    // Payload: 4-byte signature (network byte order)
    char* data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    uint32_t net_signature = htonl(signature);
    memcpy(data, &net_signature, 4);

    // *** CHANGED HERE: compute IPv4 header checksum since IP_HDRINCL is set ***
    ip_header->check = 0;
    ip_header->check = ip_checksum(ip_header, sizeof(struct iphdr));

    // Destination (raw IP ignores sin_port, but set to 0 to avoid confusion)
    sockaddr_in dest_addr{}; dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = 0;  // ignored for raw IP
    dest_addr.sin_addr.s_addr = ip_header->daddr;

    cout << "[DEBUG] Sending evil packet with evil bit set...\n";

    const int max_attempts = 3;
    bool success = false;

    for (int attempt = 0; attempt < max_attempts && !success; attempt++) {
        ssize_t sent = sendto(raw_sock, packet, ntohs(ip_header->tot_len), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
        if (sent < 0) {
            perror("send evil packet failed");
            break;
        }

        cout << "[DEBUG] Evil packet sent, waiting for response...\n";

        // Wait for response on recv_sock
        char response[1024];
        sockaddr_in from_addr{}; socklen_t from_len = sizeof(from_addr);

        timeval tv{}; tv.tv_sec = 4; tv.tv_usec = 0;
        setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int received = recvfrom(recv_sock, response, sizeof(response) - 1, 0, (sockaddr*)&from_addr, &from_len);
        if (received > 0) {
            response[received] = '\0';
            string response_str(response);
            cout << "Received response from evil port: " << response_str << endl;

            evil_hidden_port = extract_port_from_response(response_str);
            if (evil_hidden_port > 0) {
                cout << "Extracted hidden port: " << evil_hidden_port << endl;
                success = true;
                break;
            } else {
                cout << "Could not extract hidden port from response.\n";
                usleep(100000);
            }
        } else {
            cout << "No response received from evil port, retrying...\n";
            usleep(100000);
        }
    }

    close(raw_sock);
    close(recv_sock);
    return success;
}

// ===================== CHECKSUM PORT =====================
// We:
//  1) Send 4-byte S.E.C.R.E.T. signature -> receive a line whose LAST 6 BYTES encode (checksum(2) + ip(4))
//  2) Build an *inner* IPv4+UDP packet whose UDP checksum must equal that checksum (0x????)
//  3) Send that inner packet as the payload of a normal UDP datagram to the checksum port
bool solve_checksum_port(const string& ip, int port, uint32_t signature, string& secret_phrase) {
    cout << "[DEBUG] solve_checksum_port called for IP: " << ip << ", port: " << port << endl;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket creation failed"); return false; }

    timeval tv{}; tv.tv_sec = 2; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in server{}; server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

    // Step 1: get (checksum, ip) from response’s last 6 bytes
    bool ok = false;
    string response;
    for (int attempt = 0; attempt < 3 && !ok; attempt++) {
        uint32_t net_sig = htonl(signature);
        cout << "Sending signature to checksum port (attempt " << attempt + 1 << ")\n";
        response = send_and_receive(sock, server, string((char*)&net_sig, 4), 2);
        if (!response.empty()) {
            cout << "Received response from checksum port: " << response << endl;
            ok = true;
        } else {
            cout << "No response, retrying...\n";
            usleep(100000);
        }
    }
    if (!ok) { cerr << "Failed to get checksum hint.\n"; close(sock); return false; }

    if ((int)response.size() < 6) {
        cerr << "Response too short to extract checksum+IP.\n"; close(sock); return false;
    }

    uint16_t target_checksum;  // network order in message -> convert to host below
    uint32_t src_ip_from_server;
    memcpy(&target_checksum, response.data() + response.size() - 6, 2);
    memcpy(&src_ip_from_server, response.data() + response.size() - 4, 4);
    target_checksum = ntohs(target_checksum);
    src_ip_from_server = ntohl(src_ip_from_server);

    cout << "[DEBUG] Extracted checksum: 0x" << hex << target_checksum << dec << ", IP: "
         << ((src_ip_from_server >> 24) & 0xFF) << "."
         << ((src_ip_from_server >> 16) & 0xFF) << "."
         << ((src_ip_from_server >> 8)  & 0xFF) << "."
         << ( src_ip_from_server        & 0xFF) << "\n";

    // Step 2: Build inner IPv4+UDP packet; 2-byte payload is unknown (we brute force)
    const uint16_t data_len = 2;         // we're going to find 2 bytes that make the checksum match
    const uint16_t inner_udp_len = (uint16_t)(sizeof(udphdr) + data_len);
    const uint16_t inner_ip_len  = (uint16_t)(sizeof(iphdr)  + inner_udp_len);

    // Inner packet buffer
    vector<uint8_t> inner(inner_ip_len, 0);

    // Map struct pointers onto it
    iphdr*  ip_in  = (iphdr*) inner.data();
    udphdr* udp_in = (udphdr*)(inner.data() + sizeof(iphdr));
    uint16_t* payload2 = (uint16_t*)(inner.data() + sizeof(iphdr) + sizeof(udphdr));

    // Fill inner IP header (minimal)
    ip_in->ihl      = 5;
    ip_in->version  = 4;
    ip_in->tos      = 0;
    ip_in->tot_len  = htons(inner_ip_len);
    ip_in->id       = htons(13245);
    ip_in->frag_off = 0;
    ip_in->ttl      = 64;
    ip_in->protocol = IPPROTO_UDP;
    ip_in->check    = 0; // not strictly required for this puzzle (but we’ll fill it anyway)
    ip_in->saddr    = htonl(src_ip_from_server); // *** from hint ***
    ip_in->daddr    = inet_addr(ip.c_str());     // destination is the TSAM host

    // Inner UDP header
    udp_in->source  = htons(14235);      // any source
    udp_in->dest    = htons(port);       // to checksum port
    udp_in->len     = htons(inner_udp_len);
    udp_in->check   = 0;                 // will compute

    // Pseudo header (for UDP checksum)
    pseudo_header psh{};
    psh.source_address = ip_in->saddr;
    psh.dest_address   = ip_in->daddr;
    psh.placeholder    = 0;
    psh.protocol       = IPPROTO_UDP;
    psh.udp_length     = htons(inner_udp_len);

    // Buffer for checksum computation: pseudo hdr + UDP hdr + payload
    vector<uint8_t> pseudo(sizeof(pseudo_header) + sizeof(udphdr) + data_len);

    // Brute-force the 2-byte payload that yields the target UDP checksum
    bool matched = false;
    for (int v = 0; v <= 0xFFFF; ++v) {
        *payload2 = htons((uint16_t)v);  // *** IMPORTANT: write payload in network order ***

        // rebuild pseudo-buffer each iteration
        memcpy(pseudo.data(),                          &psh, sizeof(psh));
        memcpy(pseudo.data() + sizeof(psh),            udp_in, sizeof(udphdr));
        memcpy(pseudo.data() + sizeof(psh) + sizeof(udphdr), payload2, data_len);

        uint16_t calc = compute_udp_checksum(pseudo.data(), (int)pseudo.size());
        // 'calc' is returned in host order by our helper — compare to host-order target
        if (calc == target_checksum) {
            udp_in->check = htons(calc);   // write checksum in network order
            matched = true;
            cout << "[DEBUG] Found matching payload value 0x" << hex << v << dec
                 << " with checksum 0x" << hex << calc << dec << "\n";
            break;
        }
    }

    if (!matched) {
        cerr << "Could not find matching payload for target checksum.\n";
        close(sock);
        return false;
    }

    // (Optional) fill inner IP checksum for neatness:
    ip_in->check = 0;
    ip_in->check = ip_checksum(ip_in, sizeof(iphdr));

    // Step 3: Send inner packet bytes as the payload of a normal UDP datagram to the checksum port
    ssize_t sent = sendto(sock, inner.data(), inner.size(), 0, (sockaddr*)&server, sizeof(server));
    if (sent < 0) {
        perror("Send encapsulated packet failed");
        close(sock);
        return false;
    }

    // Receive the secret phrase
    char phrase[2048];
    sockaddr_in from{}; socklen_t flen = sizeof(from);
    int rec = recvfrom(sock, phrase, sizeof(phrase) - 1, 0, (sockaddr*)&from, &flen);
    if (rec > 0) {
        phrase[rec] = '\0';
       
