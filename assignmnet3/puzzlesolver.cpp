#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>


static const int TIMEOUT_MS = 1200;               // 1.2s per receive
static const int RETRIES    = 3;                  // try a few times
static const char* PROBE    = "Hello!!";          // ≥ 6 bytes
static const std::int32_t SECRET_NUMBER = 7;      // your chosen number
static const std::string  USERNAMES     = "sindrib23,benjaminr23,oliver23";

enum PortType { PT_UNKNOWN, PT_SECRET, PT_SIGNATURE, PT_EVIL, PT_EXPS, PT_CHECKSUM };

static int udp_send(const std::string& ip, int port, const void* data, size_t len) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return -1; }
    sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_port=htons(port);
    inet_pton(AF_INET, ip.c_str(), &dst.sin_addr);
    ssize_t n = sendto(s, data, len, 0, (sockaddr*)&dst, sizeof(dst));
    if (n < 0) perror("sendto");
    close(s);
    return (n < 0) ? -1 : 0;
}

static bool udp_probe_recv(const std::string& ip, int port, std::string& out) {
    out.clear();
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return false; }

    // timeout
    timeval tv{};
    tv.tv_sec  = TIMEOUT_MS / 1000;
    tv.tv_usec = (TIMEOUT_MS % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // dest
    sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_port=htons(port);
    inet_pton(AF_INET, ip.c_str(), &dst.sin_addr);

    // send probe
    (void)sendto(s, PROBE, strlen(PROBE), 0, (sockaddr*)&dst, sizeof(dst));

    // receive (single try here; caller may retry)
    char buf[4096];
    sockaddr_in from{}; socklen_t flen=sizeof(from);
    int n = recvfrom(s, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &flen);
    if (n > 0) {
        buf[n] = '\0';
        out.assign(buf, n);
    }
    close(s);
    return n > 0;
}

static PortType classify(const std::string& text) {
    std::string s = text;
    // lower-ish check without allocating too much
    for (char& c : s) c = (char)tolower((unsigned char)c);
    if (s.find("s.e.c.r.e.t") != std::string::npos)           return PT_SECRET;
    if (s.find("send me a 4-byte message") != std::string::npos ||
        s.find("signature") != std::string::npos)             return PT_SIGNATURE;
    if (s.find("e.x.p.s.t.n") != std::string::npos ||
        s.find("knock") != std::string::npos)                 return PT_EXPS;
    if (s.find("evil") != std::string::npos)                  return PT_EVIL;
    if (s.find("checksum") != std::string::npos)              return PT_CHECKSUM;
    return PT_UNKNOWN;
}

// --- SECRET handler: returns (ok, group_id, signature_host, signature_network) ---
struct SecretResult { bool ok; uint8_t gid; uint32_t sig_host; uint32_t sig_net; };
static SecretResult handle_secret(const std::string& ip, int port) {
    SecretResult R{false, 0, 0, 0};

    // one socket for the whole handshake
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return R; }

    timeval tv{}; tv.tv_sec = TIMEOUT_MS/1000; tv.tv_usec = (TIMEOUT_MS%1000)*1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_port=htons(port);
    inet_pton(AF_INET, ip.c_str(), &dst.sin_addr);

    // Build 'S' + 4 bytes secret (network order) + usernames
    char msg[1024];
    msg[0] = 'S';
    uint32_t netSecret = htonl(SECRET_NUMBER);
    memcpy(msg+1, &netSecret, 4);
    std::memcpy(msg+5, USERNAMES.c_str(), USERNAMES.size());
    int msglen = 5 + (int)USERNAMES.size();

    if (sendto(s, msg, msglen, 0, (sockaddr*)&dst, sizeof(dst)) < 0) {
        perror("sendto (secret init)"); close(s); return R;
    }
    std::cout << "[SECRET] Sent init to port " << port << " (len=" << msglen << ")\n";

    // Expect exactly 5 bytes: [gid][challenge (4 bytes, net order)]
    unsigned char buf[1024];
    sockaddr_in from{}; socklen_t flen=sizeof(from);
    int n = -1;
    int tries = 0;
    for (; tries < RETRIES; ++tries) {
        n = recvfrom(s, buf, sizeof(buf), 0, (sockaddr*)&from, &flen);
        if (n >= 0) break; // got data
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            // timed out or interrupted — try again
            continue;
        }
        // some other socket error — bail
        break;
    }
    if (n != 5) {
        perror("[SECRET] recv challenge");
        close(s);
        return R;
    }
    uint8_t gid = buf[0];
    uint32_t challenge;
    memcpy(&challenge, buf+1, 4);
    challenge = ntohl(challenge);
    std::cout << "[SECRET] GID=" << (int)gid << " challenge=" << challenge << "\n";

    // signature = challenge XOR secretNumber
    uint32_t signature = challenge ^ (uint32_t)SECRET_NUMBER;
    uint32_t netSig    = htonl(signature);
    char resp[5];
    resp[0] = gid;
    memcpy(resp+1, &netSig, 4);

    if (sendto(s, resp, 5, 0, (sockaddr*)&dst, sizeof(dst)) < 0) {
        perror("sendto (secret signature)"); close(s); return R;
    }

    // Final response should be text (e.g. secret port). We just print it.
    n = -1; tries = 0;
    for (; tries < RETRIES && n < 0; ++tries) {
        n = recvfrom(s, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &flen);
    }
    if (n > 0) {
        buf[n] = '\0';
        std::cout << "[SECRET] Final: " << buf << "\n";
    } else {
        perror("[SECRET] recv final");
    }

    close(s);
    R.ok = true; R.gid = gid; R.sig_host = signature; R.sig_net = netSig;
    return R;
}

static void handle_signature_port(const std::string& ip, int port, uint32_t netSignature) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return; }
    timeval tv{}; tv.tv_sec = TIMEOUT_MS/1000; tv.tv_usec=(TIMEOUT_MS%1000)*1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_port=htons(port);
    inet_pton(AF_INET, ip.c_str(), &dst.sin_addr);
    if (sendto(s, &netSignature, sizeof(netSignature), 0, (sockaddr*)&dst, sizeof(dst)) < 0) {
        perror("sendto (signature port)"); close(s); return;
    }
    char buf[1024]; sockaddr_in from{}; socklen_t flen=sizeof(from);
    int n = recvfrom(s, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &flen);
    if (n > 0) { buf[n]='\0'; std::cout << "[SIGNATURE] Reply: " << buf << "\n"; }
    else perror("[SIGNATURE] recv");
    close(s);
}

// Stubs for teammates:
static void handle_evil_port(const std::string& ip, int port, uint8_t gid, uint32_t netSig) {
    std::cout << "[EVIL] Port " << port << " (stub). Read instructions, transform data, send back.\n";
}
static void handle_exps_port(const std::string& ip, int port, uint8_t gid, uint32_t netSig) {
    std::cout << "[EXPS] Port " << port << " (stub). Will use knocking later.\n";
}
static void handle_checksum_port(const std::string& ip, int port, uint8_t gid, uint32_t netSig) {
    std::cout << "[CHECKSUM] Port " << port << " (stub). Use raw sockets + UDP checksum.\n";
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <IP> <port1> <port2> <port3> <port4>\n";
        return 1;
    }
    std::string ip = argv[1];
    int ports[4] = { std::atoi(argv[2]), std::atoi(argv[3]),
                     std::atoi(argv[4]), std::atoi(argv[5]) };
    for (int i=0;i<4;i++) {
        if (ports[i] <= 0 || ports[i] > 65535) {
            std::cerr << "Bad port: " << argv[2+i] << "\n"; return 1;
        }
    }
    std::cout << "[puzzlesolver] IP=" << ip
              << " ports=" << ports[0] << " " << ports[1]
              << " " << ports[2] << " " << ports[3] << "\n";

    // Probe & classify each
    int port_secret=-1, port_signature=-1, port_evil=-1, port_exps=-1, port_checksum=-1;
    for (int i=0;i<4;i++) {
        std::string resp;
        bool got = false;
        for (int t=0; t<RETRIES && !got; ++t) got = udp_probe_recv(ip, ports[i], resp);
        if (!got) continue;
        std::cout << "[*] Port " << ports[i] << " says: " << resp << "\n";
        switch (classify(resp)) {
            case PT_SECRET:    port_secret    = ports[i]; break;
            case PT_SIGNATURE: port_signature = ports[i]; break;
            case PT_EVIL:      port_evil      = ports[i]; break;
            case PT_EXPS:      port_exps      = ports[i]; break;
            case PT_CHECKSUM:  port_checksum  = ports[i]; break;
            default: break;
        }
    }

    if (port_secret < 0) { std::cerr << "Could not find S.E.C.R.E.T. port.\n"; return 1; }

    // Do SECRET handshake → get signature
    auto R = handle_secret(ip, port_secret);
    if (!R.ok) { std::cerr << "SECRET handshake failed.\n"; return 1; }
    std::cout << "[puzzlesolver] signature(host)=" << R.sig_host
              << " signature(net)=0x" << std::hex << R.sig_net << std::dec
              << " gid=" << (int)R.gid << "\n";

    // Send signature to the signature port if found
    if (port_signature >= 0) {
        handle_signature_port(ip, port_signature, R.sig_net);
    } else {
        std::cout << "[puzzlesolver] No signature port detected this run.\n";
    }

    // Hand off to teammates’ parts (stubs):
    if (port_evil      >= 0) handle_evil_port(ip, port_evil, R.gid, R.sig_net);
    if (port_exps      >= 0) handle_exps_port(ip, port_exps, R.gid, R.sig_net);
    if (port_checksum  >= 0) handle_checksum_port(ip, port_checksum, R.gid, R.sig_net);

    return 0;
}


