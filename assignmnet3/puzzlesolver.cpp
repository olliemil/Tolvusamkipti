#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <regex>
#include <vector>
#include <string>        // for std::string
#include <cctype>        // for std::isxdigit
#include <sys/time.h>    // for struct timeval
#include <netinet/ip.h>  // for struct iphdr
#include <netinet/udp.h> // for struct udphdr


// --- internet checksum over arbitrary buffer ---
static uint16_t inet_checksum(const void* data, size_t len) {
    const uint16_t* w = reinterpret_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) {
        sum += *w++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = 0;
        *reinterpret_cast<uint8_t*>(&last) = *reinterpret_cast<const uint8_t*>(w);
        sum += last;
    }
    // fold 32->16
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

// --- UDP checksum using IPv4 pseudo-header ---
static uint16_t udp_checksum(uint32_t saddr, uint32_t daddr,
                             const udphdr* uh, const uint8_t* payload, size_t plen) {
    struct pseudo {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t udp_len;
    } __attribute__((packed));

    pseudo p { saddr, daddr, 0, IPPROTO_UDP, htons(static_cast<uint16_t>(sizeof(udphdr) + plen)) };

    // Build a contiguous buffer: pseudo + udp hdr + payload
    std::vector<uint8_t> buf(sizeof(pseudo) + sizeof(udphdr) + plen);
    memcpy(buf.data(), &p, sizeof(p));
    memcpy(buf.data() + sizeof(p), uh, sizeof(udphdr));
    if (plen) memcpy(buf.data() + sizeof(pseudo) + sizeof(udphdr), payload, plen);

    return inet_checksum(buf.data(), buf.size());
}

// --- IP header checksum (header only) ---
static uint16_t ip_header_checksum(iphdr* ip) {
    ip->check = 0;
    return inet_checksum(ip, ip->ihl * 4);
}

// --- convert hex like "48656c6c6f21" -> bytes "Hello!" ---
static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    auto is_hex = [](char c){ return std::isxdigit(static_cast<unsigned char>(c)); };
    std::string h;
    h.reserve(hex.size());
    for (char c : hex) if (is_hex(c)) h.push_back(c);
    if (h.size() % 2) return out;
    out.reserve(h.size()/2);
    for (size_t i=0;i<h.size();i+=2) {
        uint8_t b = static_cast<uint8_t>(std::stoul(h.substr(i,2), nullptr, 16));
        out.push_back(b);
    }
    return out;
}

// --- get local IPv4 used to reach a remote IPv4 ---
static uint32_t get_local_ipv4_for(const std::string& dst_ip) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return INADDR_ANY;
    sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_port=htons(9); // discard
    inet_pton(AF_INET, dst_ip.c_str(), &dst.sin_addr);
    connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    sockaddr_in local{}; socklen_t len=sizeof(local);
    getsockname(s, reinterpret_cast<sockaddr*>(&local), &len);
    close(s);
    return local.sin_addr.s_addr; // already in network byte order
}


// Detects & solves the checksum port challenge.
// Strategy:
// 1) probe with "checksum?" (>=6 bytes) -> read instructions
// 2) parse optional SRC, DST, PAYLOAD (hex/text). Fallbacks if missing
// 3) craft IP+UDP, compute UDP checksum, send via raw socket
// 4) bind a normal UDP socket on src_port to receive confirmation
void handleChecksumPort(const std::string& ip, int checksum_port) {
    // --- Step 1: probe for instructions
    int usock = socket(AF_INET, SOCK_DGRAM, 0);
    if (usock < 0) { perror("socket"); return; }
    timeval tv{2,0};
    setsockopt(usock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in server{}; server.sin_family=AF_INET;
    server.sin_port = htons(checksum_port);
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

    const char* probe = "checksum?";
    sendto(usock, probe, strlen(probe), 0, (sockaddr*)&server, sizeof(server));

    char instr[2048];
    sockaddr_in from{}; socklen_t flen=sizeof(from);
    int n = recvfrom(usock, instr, sizeof(instr)-1, 0, (sockaddr*)&from, &flen);
    if (n <= 0) { perror("recvfrom (checksum instr)"); close(usock); return; }
    instr[n] = '\0';
    std::string text = instr;
    std::cout << "[Checksum] Instructions: " << text << "\n";

    // --- Step 2: parse flexible instruction format (best effort)
    // Accept patterns like:
    //  SRC:12345  DST:4xxx  PAYLOAD_HEX:48656c6c6f21
    //  SRC=12345, PAYLOAD="Hello!"
    int src_port = 54321;               // fallback
    int dst_port = checksum_port;       // usually the checksum port itself
    std::vector<uint8_t> payload;       // will fill below

    std::smatch m;
    std::regex r_src(R"(SRC\s*[:=]\s*(\d+))", std::regex::icase);
    std::regex r_dst(R"(DST\s*[:=]\s*(\d+))", std::regex::icase);
    std::regex r_hex(R"(PAYLOAD[_ ]?HEX\s*[:=]\s*([0-9A-Fa-f\s]+))");
    std::regex r_txt(R"(PAYLOAD\s*[:=]\s*\"([^\"]+)\"|PAYLOAD\s*[:=]\s*'([^']+)')", std::regex::icase);

    if (std::regex_search(text, m, r_src)) src_port = std::stoi(m[1]);
    if (std::regex_search(text, m, r_dst)) dst_port = std::stoi(m[1]);

    if (std::regex_search(text, m, r_hex)) {
        payload = hex_to_bytes(m[1]);
    } else if (std::regex_search(text, m, r_txt)) {
        std::string s = m[1].matched ? m[1].str() : m[2].str();
        payload.assign(s.begin(), s.end());
    } else {
        // minimal valid payload (>= 1 byte). Use ≥6 to be safe.
        const char* def = "hello!!";
        payload.assign(def, def + strlen(def));
    }

    close(usock);

    // --- Step 3: craft raw IP+UDP packet
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw < 0) { perror("socket raw"); return; }

    int one = 1;
    if (setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(raw);
        return;
    }

    uint32_t saddr = get_local_ipv4_for(ip);        // network byte order
    uint32_t daddr; inet_pton(AF_INET, ip.c_str(), &daddr); // network byte order

    size_t ip_len   = sizeof(iphdr);
    size_t udp_len  = sizeof(udphdr);
    size_t data_len = payload.size();
    size_t pkt_len  = ip_len + udp_len + data_len;

    std::vector<uint8_t> pkt(pkt_len, 0);

    // IP header
    auto* iphdrp = reinterpret_cast<iphdr*>(pkt.data());
    iphdrp->ihl      = 5;          // 5 * 4 = 20 bytes
    iphdrp->version  = 4;
    iphdrp->tos      = 0;
    iphdrp->tot_len  = htons(static_cast<uint16_t>(pkt_len));
    iphdrp->id       = htons(0x4444);
    iphdrp->frag_off = 0;
    iphdrp->ttl      = 64;
    iphdrp->protocol = IPPROTO_UDP;
    iphdrp->saddr    = saddr;      // already network order
    iphdrp->daddr    = daddr;

    // UDP header
    auto* udph = reinterpret_cast<udphdr*>(pkt.data() + ip_len);
    udph->source = htons(static_cast<uint16_t>(src_port));
    udph->dest   = htons(static_cast<uint16_t>(dst_port));
    udph->len    = htons(static_cast<uint16_t>(udp_len + data_len));
    udph->check  = 0;

    // payload
    if (data_len) memcpy(pkt.data() + ip_len + udp_len, payload.data(), data_len);

    // checksums
    udph->check  = udp_checksum(iphdrp->saddr, iphdrp->daddr, udph,
                                reinterpret_cast<uint8_t*>(pkt.data() + ip_len + udp_len), data_len);

    iphdrp->check = ip_header_checksum(iphdrp);

    // --- Step 4: send raw packet
    sockaddr_in dst{}; dst.sin_family=AF_INET;
    dst.sin_port = htons(dst_port);         // not strictly used, header has the real port
    inet_pton(AF_INET, ip.c_str(), &dst.sin_addr);

    ssize_t sent = sendto(raw, pkt.data(), pkt.size(), 0, (sockaddr*)&dst, sizeof(dst));
    if (sent < 0) { perror("sendto raw"); close(raw); return; }
    std::cout << "[Checksum] Raw packet sent (" << sent << " bytes) src "
              << src_port << " -> dst " << dst_port << "\n";
    close(raw);

    // --- Step 5: receive confirmation on src_port (normal UDP)
    int rxsock = socket(AF_INET, SOCK_DGRAM, 0);
    if (rxsock < 0) { perror("socket rx"); return; }
    setsockopt(rxsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in bindaddr{}; bindaddr.sin_family=AF_INET;
    bindaddr.sin_port = htons(src_port);
    bindaddr.sin_addr.s_addr = saddr;  // bind to the same local IP used to send
    if (bind(rxsock, (sockaddr*)&bindaddr, sizeof(bindaddr)) < 0) {
        // fallback: INADDR_ANY
        bindaddr.sin_addr.s_addr = INADDR_ANY;
        if (bind(rxsock, (sockaddr*)&bindaddr, sizeof(bindaddr)) < 0) {
            perror("bind rxsock");
            close(rxsock);
            return;
        }
    }

    char buf[2048];
    sockaddr_in src{}; socklen_t sl=sizeof(src);
    int rn = recvfrom(rxsock, buf, sizeof(buf)-1, 0, (sockaddr*)&src, &sl);
    if (rn <= 0) {
        perror("[Checksum] recvfrom reply");
    } else {
        buf[rn] = '\0';
        std::cout << "[Checksum] Reply: " << buf << "\n";
    }
    close(rxsock);
}






// --- GLOBALS ---
static const std::int32_t SECRET_NUMBER = 7;
static const std::string USERNAMES = "sindrib23,benjaminr23,oliver23";

// --- Function prototypes ---
void handleSecretPort(const std::string& ip, int port);
void handleSignaturePort(const std::string& ip, int port, uint32_t netSignature);
// TODO: void handleChecksumPort(...);
// TODO: void handleEvilPort(...);
// TODO: void handleExpstnPort(...);

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <IP> <port1> <port2> <port3> <port4>\n";
        return 1;
    }

    std::string ip = argv[1];
    int ports[4] = { std::atoi(argv[2]), std::atoi(argv[3]),
                     std::atoi(argv[4]), std::atoi(argv[5]) };

    // Probe each port with ≥6 bytes to identify type
    for (int i = 0; i < 4; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket");
            continue;
        }

        // Set timeout
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        // Destination
        struct sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(ports[i]);
        inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

        // Send probe
        const char* probe = "Hello!";
        sendto(sock, probe, strlen(probe), 0,
               (const sockaddr*)&dest_addr, sizeof(dest_addr));

        // Receive response
        char buffer[1024];
        struct sockaddr_in sender_addr{};
        socklen_t sender_len = sizeof(sender_addr);
        int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&sender_addr, &sender_len);
        close(sock);

        if (n <= 0) continue;
        buffer[n] = '\0';
        std::string resp = buffer;

        std::cout << "[*] Port " << ports[i] << " says: " << resp << std::endl;

        if (resp.find("S.E.C.R.E.T.") != std::string::npos) {
            handleSecretPort(ip, ports[i]);
        } else if (resp.find("signature") != std::string::npos) {
            // handled after SECRET gives us the signature
        } else if (resp.find("checksum") != std::string::npos) {
            std::cout << "Checksum port detected: " << ports[i] << std::endl;
            // handleChecksumPort(ip, ports[i]);
        } else if (resp.find("EVIL") != std::string::npos) {
            std::cout << "Evil port detected: " << ports[i] << std::endl;
            // handleEvilPort(ip, ports[i]);
        } else if (resp.find("EXPS") != std::string::npos) {
            std::cout << "EXPSTN port detected: " << ports[i] << std::endl;
            // handleExpstnPort(ip, ports[i]);
        }
    }

    return 0;
}

// --- SECRET handler ---
void handleSecretPort(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return; }

    struct timeval tv{1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &dest.sin_addr);

    // Build message
    char msg[1024];
    msg[0] = 'S';
    uint32_t netSecret = htonl(SECRET_NUMBER);
    memcpy(msg + 1, &netSecret, sizeof(netSecret));
    strcpy(msg + 5, USERNAMES.c_str());
    int msglen = 5 + USERNAMES.size();

    sendto(sock, msg, msglen, 0, (sockaddr*)&dest, sizeof(dest));

    char buf[1024];
    struct sockaddr_in sender{};
    socklen_t slen = sizeof(sender);
    int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&sender, &slen);
    if (n <= 0) { perror("recvfrom"); close(sock); return; }
    buf[n] = '\0';

    if (n == 5) {
        uint8_t group_id = buf[0];
        uint32_t challenge;
        memcpy(&challenge, buf + 1, 4);
        challenge = ntohl(challenge);

        std::cout << "Group ID: " << (int)group_id
                  << ", Challenge: " << challenge << std::endl;

        uint32_t signature = challenge ^ SECRET_NUMBER;
        uint32_t netSig = htonl(signature);

        char resp[5];
        resp[0] = group_id;
        memcpy(resp + 1, &netSig, 4);

        sendto(sock, resp, 5, 0, (sockaddr*)&dest, sizeof(dest));

        n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&sender, &slen);
        if (n > 0) {
            buf[n] = '\0';
            std::cout << "SUCCESS! " << buf << std::endl;
        }
    }

    close(sock);
}

void handleSignaturePort(const std::string& ip, int port, uint32_t netSignature) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return; }

    struct timeval tv{1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &dest.sin_addr);

    sendto(sock, &netSignature, sizeof(netSignature), 0,
           (sockaddr*)&dest, sizeof(dest));

    char buf[1024];
    struct sockaddr_in sender{};
    socklen_t slen = sizeof(sender);
    int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&sender, &slen);
    if (n > 0) {
        buf[n] = '\0';
        std::cout << "Message from signature port: " << buf << std::endl;
    }
    close(sock);
}

